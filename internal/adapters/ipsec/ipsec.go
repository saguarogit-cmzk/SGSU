// Package ipsec models IKEv2 site-to-site tunnels and renders the strongSwan
// swanctl.conf the root adapter (/usr/sbin/saguaro-ipsec) loads. It targets
// interop with third-party gateways (Sophos, FortiGate, etc.) over IKEv2 with
// preshared-key authentication. Generation is pure; the preshared keys are
// unsealed by the caller and passed in, never stored here.
package ipsec

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// Interop-friendly defaults: AES-256 / SHA2-256 / DH group 14 (modp2048),
// which most modern gateways accept out of the box.
const (
	DefaultIKEProposal = "aes256-sha256-modp2048"
	DefaultESPProposal = "aes256-sha256-modp2048"
)

var (
	nameRe     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)
	proposalRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	idRe       = regexp.MustCompile(`^[A-Za-z0-9.@_:-]{1,128}$`)
	hostRe     = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$`)
)

type Connection struct {
	Name          string   `json:"name"`
	RemoteAddr    string   `json:"remoteAddr"` // peer public IP or FQDN
	LocalID       string   `json:"localId"`    // optional (default: our IP)
	RemoteID      string   `json:"remoteId"`   // optional (default: remoteAddr)
	LocalSubnets  []string `json:"localSubnets"`
	RemoteSubnets []string `json:"remoteSubnets"`
	IKEProposal   string   `json:"ikeProposal"`
	ESPProposal   string   `json:"espProposal"`
	Initiate      bool     `json:"initiate"` // true: start on boot; false: on-demand (trap)
	PSKEnc        string   `json:"pskEnc,omitempty"`
}

type Config struct {
	Enabled     bool         `json:"enabled"`
	Connections []Connection `json:"connections"`
}

func validCIDR(s string) bool {
	ip, _, err := net.ParseCIDR(strings.TrimSpace(s))
	return err == nil && ip.To4() != nil
}

func (c Connection) proposals() (ike, esp string) {
	ike, esp = c.IKEProposal, c.ESPProposal
	if ike == "" {
		ike = DefaultIKEProposal
	}
	if esp == "" {
		esp = DefaultESPProposal
	}
	return ike, esp
}

func (c Config) Validate() error {
	seen := map[string]bool{}
	for _, conn := range c.Connections {
		if !nameRe.MatchString(conn.Name) {
			return fmt.Errorf("invalid connection name %q", conn.Name)
		}
		if seen[conn.Name] {
			return fmt.Errorf("duplicate connection %q", conn.Name)
		}
		seen[conn.Name] = true
		if net.ParseIP(strings.TrimSpace(conn.RemoteAddr)) == nil && !hostRe.MatchString(strings.TrimSpace(conn.RemoteAddr)) {
			return fmt.Errorf("connection %q: remoteAddr must be an IP or hostname", conn.Name)
		}
		if conn.LocalID != "" && !idRe.MatchString(conn.LocalID) {
			return fmt.Errorf("connection %q: invalid localId", conn.Name)
		}
		if conn.RemoteID != "" && !idRe.MatchString(conn.RemoteID) {
			return fmt.Errorf("connection %q: invalid remoteId", conn.Name)
		}
		if len(conn.LocalSubnets) == 0 || len(conn.RemoteSubnets) == 0 {
			return fmt.Errorf("connection %q needs at least one local and one remote subnet", conn.Name)
		}
		for _, s := range append(append([]string{}, conn.LocalSubnets...), conn.RemoteSubnets...) {
			if !validCIDR(s) {
				return fmt.Errorf("connection %q: invalid subnet %q", conn.Name, s)
			}
		}
		ike, esp := conn.proposals()
		if !proposalRe.MatchString(ike) || !proposalRe.MatchString(esp) {
			return fmt.Errorf("connection %q: invalid proposal", conn.Name)
		}
	}
	return nil
}

func remoteID(conn Connection) string {
	if conn.RemoteID != "" {
		return conn.RemoteID
	}
	return conn.RemoteAddr
}

// GenerateConf renders swanctl.conf. psks maps a connection name to its
// unsealed preshared key.
func (c Config) GenerateConf(psks map[string]string) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("# Managed by Saguaro (generated). Manual edits are overwritten on apply.\n")
	b.WriteString("connections {\n")
	for _, conn := range c.Connections {
		ike, esp := conn.proposals()
		start := "trap"
		if conn.Initiate {
			start = "start"
		}
		fmt.Fprintf(&b, "   conn-%s {\n", conn.Name)
		b.WriteString("      version = 2\n")
		b.WriteString("      local_addrs = %any\n")
		fmt.Fprintf(&b, "      remote_addrs = %s\n", conn.RemoteAddr)
		fmt.Fprintf(&b, "      proposals = %s\n", ike)
		b.WriteString("      dpd_delay = 30s\n")
		b.WriteString("      local {\n         auth = psk\n")
		if conn.LocalID != "" {
			fmt.Fprintf(&b, "         id = %s\n", conn.LocalID)
		}
		b.WriteString("      }\n")
		b.WriteString("      remote {\n         auth = psk\n")
		fmt.Fprintf(&b, "         id = %s\n", remoteID(conn))
		b.WriteString("      }\n")
		b.WriteString("      children {\n")
		fmt.Fprintf(&b, "         %s {\n", conn.Name)
		fmt.Fprintf(&b, "            local_ts = %s\n", strings.Join(conn.LocalSubnets, ", "))
		fmt.Fprintf(&b, "            remote_ts = %s\n", strings.Join(conn.RemoteSubnets, ", "))
		fmt.Fprintf(&b, "            esp_proposals = %s\n", esp)
		fmt.Fprintf(&b, "            start_action = %s\n", start)
		b.WriteString("            dpd_action = restart\n")
		b.WriteString("            rekey_time = 1h\n")
		b.WriteString("         }\n")
		b.WriteString("      }\n")
		b.WriteString("   }\n")
	}
	b.WriteString("}\n")
	b.WriteString("secrets {\n")
	for _, conn := range c.Connections {
		fmt.Fprintf(&b, "   ike-%s {\n", conn.Name)
		fmt.Fprintf(&b, "      id = %s\n", remoteID(conn))
		if conn.LocalID != "" {
			fmt.Fprintf(&b, "      id = %s\n", conn.LocalID)
		}
		fmt.Fprintf(&b, "      secret = \"%s\"\n", psks[conn.Name])
		b.WriteString("   }\n")
	}
	b.WriteString("}\n")
	return b.String(), nil
}
