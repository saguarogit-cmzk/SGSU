// Package wireguard implements the SNA VPN module (wizard W7): key
// generation in-process (curve25519 — the client private key exists only in
// the moment of creation and is never persisted), server and client config
// generation, and unique peer address allocation. Applying goes through the
// root adapter /usr/sbin/saguaro-vpn.
package wireguard

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

// GenerateKeypair returns a WireGuard (base64) private/public key pair.
func GenerateKeypair() (privB64, pubB64 string, err error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return "", "", err
	}
	// RFC 7748 clamping, as wg genkey does.
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv[:]), base64.StdEncoding.EncodeToString(pub), nil
}

var keyRe = regexp.MustCompile(`^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$`)

// ValidKey reports whether s looks like a WireGuard base64 key.
func ValidKey(s string) bool { return keyRe.MatchString(s) }

var peerNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,30}[a-z0-9])?$`)

type Peer struct {
	Name       string    `json:"name"`
	PubKey     string    `json:"pubKey"`
	Address    string    `json:"address"` // unique host address inside Subnet
	FullTunnel bool      `json:"fullTunnel"`
	CreatedAt  time.Time `json:"createdAt"`
	ExpiresAt  time.Time `json:"expiresAt,omitempty"` // zero = no expiry
}

func (p Peer) Expired(now time.Time) bool {
	return !p.ExpiresAt.IsZero() && now.After(p.ExpiresAt)
}

type Config struct {
	Enabled       bool     `json:"enabled"`
	Subnet        string   `json:"subnet"`     // e.g. 10.8.0.0/24; server takes the first host
	ListenPort    int      `json:"listenPort"` // default 51820
	Endpoint      string   `json:"endpoint"`   // public host:port clients connect to
	DNS           string   `json:"dns"`        // resolver pushed to clients
	SplitNetworks []string `json:"splitNetworks"`
	ServerPub     string   `json:"serverPub"`
	// ServerPrivEnc holds the server private key sealed with the appliance
	// secret key (AES-256-GCM); plaintext appears only in the staged config.
	ServerPrivEnc string `json:"serverPrivEnc,omitempty"`
	Peers         []Peer `json:"peers"`
}

func (c Config) Validate() error {
	ip, ipnet, err := net.ParseCIDR(strings.TrimSpace(c.Subnet))
	if err != nil || ip.To4() == nil {
		return fmt.Errorf("subnet must be an IPv4 CIDR (e.g. 10.8.0.0/24)")
	}
	ones, _ := ipnet.Mask.Size()
	if ones > 30 {
		return fmt.Errorf("subnet is too small for peers")
	}
	if c.ListenPort < 1 || c.ListenPort > 65535 {
		return fmt.Errorf("listenPort must be 1-65535")
	}
	if c.Enabled {
		host, port, err := net.SplitHostPort(strings.TrimSpace(c.Endpoint))
		if err != nil || host == "" || port == "" {
			return fmt.Errorf("endpoint must be host:port reachable by clients")
		}
	}
	if c.DNS != "" && net.ParseIP(c.DNS) == nil {
		return fmt.Errorf("dns must be an IP address")
	}
	for _, s := range c.SplitNetworks {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(s)); err != nil {
			return fmt.Errorf("invalid split network %q", s)
		}
	}
	for _, p := range c.Peers {
		if !peerNameRe.MatchString(p.Name) {
			return fmt.Errorf("invalid peer name %q", p.Name)
		}
		if !ValidKey(p.PubKey) {
			return fmt.Errorf("invalid public key for peer %q", p.Name)
		}
		if net.ParseIP(p.Address) == nil || !ipnet.Contains(net.ParseIP(p.Address)) {
			return fmt.Errorf("peer %q address outside the VPN subnet", p.Name)
		}
	}
	return nil
}

// ServerAddress returns the appliance address inside the VPN subnet (first
// host) with the subnet prefix length.
func (c Config) ServerAddress() (string, error) {
	ip, ipnet, err := net.ParseCIDR(c.Subnet)
	if err != nil {
		return "", err
	}
	v4 := ip.Mask(ipnet.Mask).To4()
	v4[3]++
	ones, _ := ipnet.Mask.Size()
	return fmt.Sprintf("%s/%d", v4, ones), nil
}

// AllocateAddress picks the lowest free host address for a new peer.
func (c Config) AllocateAddress() (string, error) {
	ip, ipnet, err := net.ParseCIDR(c.Subnet)
	if err != nil {
		return "", err
	}
	used := map[string]bool{}
	server, _ := c.ServerAddress()
	used[strings.Split(server, "/")[0]] = true
	for _, p := range c.Peers {
		used[p.Address] = true
	}
	base := ip.Mask(ipnet.Mask).To4()
	ones, bits := ipnet.Mask.Size()
	hostCount := 1 << (bits - ones)
	for i := 2; i < hostCount-1; i++ {
		cand := make(net.IP, 4)
		copy(cand, base)
		v := (int(base[0])<<24 | int(base[1])<<16 | int(base[2])<<8 | int(base[3])) + i
		cand[0], cand[1], cand[2], cand[3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
		if !used[cand.String()] {
			return cand.String(), nil
		}
	}
	return "", fmt.Errorf("no free addresses left in %s", c.Subnet)
}

// GenerateServerConf renders wg0.conf; expired peers are excluded, which is
// how peer validity is enforced on re-apply.
func (c Config) GenerateServerConf(serverPriv string, now time.Time) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	if !ValidKey(serverPriv) {
		return "", fmt.Errorf("invalid server private key")
	}
	addr, err := c.ServerAddress()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("# Managed by Saguaro (generated). Manual edits are overwritten on apply.\n")
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "Address = %s\n", addr)
	fmt.Fprintf(&b, "ListenPort = %d\n", c.ListenPort)
	fmt.Fprintf(&b, "PrivateKey = %s\n", serverPriv)
	for _, p := range c.Peers {
		if p.Expired(now) {
			continue
		}
		fmt.Fprintf(&b, "\n# peer: %s\n[Peer]\n", p.Name)
		fmt.Fprintf(&b, "PublicKey = %s\n", p.PubKey)
		fmt.Fprintf(&b, "AllowedIPs = %s/32\n", p.Address)
	}
	return b.String(), nil
}

// GenerateClientConf renders the one-time client configuration.
func (c Config) GenerateClientConf(clientPriv string, p Peer) (string, error) {
	if !ValidKey(clientPriv) {
		return "", fmt.Errorf("invalid client private key")
	}
	allowed := "0.0.0.0/0"
	if !p.FullTunnel {
		nets := append([]string{c.Subnet}, c.SplitNetworks...)
		allowed = strings.Join(nets, ", ")
	}
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", clientPriv)
	fmt.Fprintf(&b, "Address = %s/32\n", p.Address)
	if c.DNS != "" {
		fmt.Fprintf(&b, "DNS = %s\n", c.DNS)
	}
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", c.ServerPub)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", allowed)
	fmt.Fprintf(&b, "Endpoint = %s\n", c.Endpoint)
	b.WriteString("PersistentKeepalive = 25\n")
	return b.String(), nil
}
