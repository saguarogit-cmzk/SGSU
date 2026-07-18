// Package s2s models WireGuard site-to-site (net-to-net) tunnels and renders
// the wgs2s.conf the root adapter (/usr/sbin/saguaro-s2s) applies with
// wg-quick. It is separate from the road-warrior VPN (wizard W7) so the two
// have independent interfaces and lifecycles. Generation is pure; secrets
// (server private key, per-site preshared keys) are unsealed by the caller and
// passed in, never handled here in stored form.
package s2s

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	wg "saguaro.local/network-manager/internal/adapters/wireguard"
)

var siteNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,30}[a-z0-9])?$`)

// Site is one remote WireGuard endpoint whose networks are reachable through
// the tunnel. Endpoint may be empty when this appliance is the passive
// responder and the remote initiates.
type Site struct {
	Name           string   `json:"name"`
	PubKey         string   `json:"pubKey"`
	Endpoint       string   `json:"endpoint"` // host:port, optional (responder side)
	RemoteNetworks []string `json:"remoteNetworks"`
	Keepalive      int      `json:"keepalive"` // seconds; 0 = off
	// PSKEnc is an optional preshared key sealed with the appliance secret key.
	PSKEnc string `json:"pskEnc,omitempty"`
}

type Config struct {
	Enabled       bool     `json:"enabled"`
	ListenPort    int      `json:"listenPort"`    // default 51821
	TunnelAddress string   `json:"tunnelAddress"` // optional local wg addr, e.g. 10.9.0.1/30
	LocalNetworks []string `json:"localNetworks"` // our LANs, advertised to remotes (for their AllowedIPs)
	ServerPub     string   `json:"serverPub"`
	ServerPrivEnc string   `json:"serverPrivEnc,omitempty"`
	Sites         []Site   `json:"sites"`
}

func validCIDR(s string) bool {
	ip, _, err := net.ParseCIDR(strings.TrimSpace(s))
	return err == nil && ip.To4() != nil
}

func (c Config) Validate() error {
	if c.ListenPort < 1 || c.ListenPort > 65535 {
		return fmt.Errorf("listenPort must be 1-65535")
	}
	if c.TunnelAddress != "" && !validCIDR(c.TunnelAddress) {
		return fmt.Errorf("tunnelAddress must be an IPv4 CIDR (e.g. 10.9.0.1/30)")
	}
	for _, n := range c.LocalNetworks {
		if !validCIDR(n) {
			return fmt.Errorf("invalid local network %q", n)
		}
	}
	seen := map[string]bool{}
	for _, s := range c.Sites {
		if !siteNameRe.MatchString(s.Name) {
			return fmt.Errorf("invalid site name %q", s.Name)
		}
		if seen[s.Name] {
			return fmt.Errorf("duplicate site %q", s.Name)
		}
		seen[s.Name] = true
		if !wg.ValidKey(s.PubKey) {
			return fmt.Errorf("invalid public key for site %q", s.Name)
		}
		if s.Endpoint != "" {
			host, port, err := net.SplitHostPort(strings.TrimSpace(s.Endpoint))
			if err != nil || host == "" || port == "" {
				return fmt.Errorf("site %q endpoint must be host:port", s.Name)
			}
			if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
				return fmt.Errorf("site %q endpoint port invalid", s.Name)
			}
		}
		if len(s.RemoteNetworks) == 0 {
			return fmt.Errorf("site %q needs at least one remote network", s.Name)
		}
		for _, n := range s.RemoteNetworks {
			if !validCIDR(n) {
				return fmt.Errorf("site %q has invalid remote network %q", s.Name, n)
			}
		}
		if s.Keepalive < 0 || s.Keepalive > 65535 {
			return fmt.Errorf("site %q keepalive out of range", s.Name)
		}
	}
	return nil
}

// GenerateConf renders wgs2s.conf. serverPriv is the unsealed interface private
// key; psks maps a site name to its unsealed preshared key (absent = none).
func (c Config) GenerateConf(serverPriv string, psks map[string]string) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	if !wg.ValidKey(serverPriv) {
		return "", fmt.Errorf("invalid server private key")
	}
	var b strings.Builder
	b.WriteString("# Managed by Saguaro (generated). Manual edits are overwritten on apply.\n")
	b.WriteString("[Interface]\n")
	if c.TunnelAddress != "" {
		fmt.Fprintf(&b, "Address = %s\n", c.TunnelAddress)
	}
	fmt.Fprintf(&b, "ListenPort = %d\n", c.ListenPort)
	fmt.Fprintf(&b, "PrivateKey = %s\n", serverPriv)
	for _, s := range c.Sites {
		fmt.Fprintf(&b, "\n# site: %s\n[Peer]\n", s.Name)
		fmt.Fprintf(&b, "PublicKey = %s\n", s.PubKey)
		if psk, ok := psks[s.Name]; ok && psk != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", psk)
		}
		if s.Endpoint != "" {
			fmt.Fprintf(&b, "Endpoint = %s\n", s.Endpoint)
		}
		fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(s.RemoteNetworks, ", "))
		if s.Keepalive > 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", s.Keepalive)
		}
	}
	return b.String(), nil
}

// RemotePeerSnippet renders the [Peer] block the operator pastes into the
// remote WireGuard device so it can reach this appliance. endpointHost is the
// public host:port clients use to reach us (may be empty if unknown).
func (c Config) RemotePeerSnippet(endpointHost string) string {
	allowed := append([]string{}, c.LocalNetworks...)
	if c.TunnelAddress != "" {
		allowed = append(allowed, c.TunnelAddress)
	}
	if len(allowed) == 0 {
		allowed = []string{"<our-LAN-CIDR>"}
	}
	var b strings.Builder
	b.WriteString("[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", c.ServerPub)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(allowed, ", "))
	if endpointHost != "" {
		fmt.Fprintf(&b, "Endpoint = %s:%d\n", endpointHost, c.ListenPort)
	}
	b.WriteString("PersistentKeepalive = 25\n")
	return b.String()
}
