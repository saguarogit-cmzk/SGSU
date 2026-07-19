// Package wancfg models the WAN uplink addressing (DHCP or static) and renders
// the netplan the root adapter (/usr/sbin/saguaro-net wan-apply) installs.
// Generation is pure; every value is charset-validated before it reaches YAML.
package wancfg

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

var ifaceRe = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,15}$`)

type WAN struct {
	Interface string   `json:"interface"`
	Mode      string   `json:"mode"` // dhcp | static
	Address   string   `json:"address"`
	Gateway   string   `json:"gateway"`
	DNS       []string `json:"dns"`
	// Aliases are extra IPv4 addresses (CIDR) bound to the same WAN interface
	// (e.g. an ISP-provided /29 block) for 1:1 NAT / per-address SNAT.
	Aliases []string `json:"aliases"`
}

func validIP4(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	return ip != nil && ip.To4() != nil
}

func validCIDR4(s string) bool {
	ip, _, err := net.ParseCIDR(strings.TrimSpace(s))
	return err == nil && ip.To4() != nil
}

func (w WAN) Validate() error {
	if !ifaceRe.MatchString(w.Interface) {
		return fmt.Errorf("invalid WAN interface name")
	}
	switch w.Mode {
	case "dhcp":
		return nil
	case "static":
		if !validCIDR4(w.Address) {
			return fmt.Errorf("static WAN address must be an IPv4 CIDR (e.g. 203.0.113.5/24)")
		}
		if !validIP4(w.Gateway) {
			return fmt.Errorf("static WAN gateway must be an IPv4 address")
		}
		for _, d := range w.DNS {
			if !validIP4(d) {
				return fmt.Errorf("invalid DNS server %q", d)
			}
		}
		for _, a := range w.Aliases {
			if !validCIDR4(a) {
				return fmt.Errorf("WAN alias %q must be an IPv4 CIDR", a)
			}
		}
		return nil
	default:
		return fmt.Errorf("WAN mode must be dhcp or static")
	}
}

// GenerateNetplan renders /etc/netplan/60-saguaro-wan.yaml for this uplink.
func (w WAN) GenerateNetplan() (string, error) {
	if err := w.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("# Managed by Saguaro (generated). Manual edits are overwritten on apply.\n")
	b.WriteString("network:\n  version: 2\n  ethernets:\n")
	fmt.Fprintf(&b, "    %s:\n", w.Interface)
	if w.Mode == "dhcp" {
		b.WriteString("      dhcp4: true\n")
		return b.String(), nil
	}
	b.WriteString("      dhcp4: false\n")
	b.WriteString("      addresses:\n")
	fmt.Fprintf(&b, "        - %s\n", strings.TrimSpace(w.Address))
	for _, a := range w.Aliases {
		fmt.Fprintf(&b, "        - %s\n", strings.TrimSpace(a))
	}
	b.WriteString("      routes:\n        - to: default\n")
	fmt.Fprintf(&b, "          via: %s\n", strings.TrimSpace(w.Gateway))
	if len(w.DNS) > 0 {
		b.WriteString("      nameservers:\n        addresses:\n")
		for _, d := range w.DNS {
			fmt.Fprintf(&b, "          - %s\n", strings.TrimSpace(d))
		}
	}
	return b.String(), nil
}
