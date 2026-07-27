// Package wancfg models WAN uplink addressing (DHCP or static) for one or more
// WAN interfaces and renders the netplan the root adapter (saguaro-net
// wan-apply) installs. Generation is pure; every value is charset-validated
// before it reaches YAML.
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
	// Metric orders default routes across WANs (lower = preferred). 0 -> 100.
	Metric int `json:"metric"`
}

func validIP4(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	return ip != nil && ip.To4() != nil
}

func validCIDR4(s string) bool {
	ip, _, err := net.ParseCIDR(strings.TrimSpace(s))
	return err == nil && ip.To4() != nil
}

func (w WAN) metric() int {
	if w.Metric <= 0 {
		return 100
	}
	return w.Metric
}

func (w WAN) Validate() error {
	if !ifaceRe.MatchString(w.Interface) {
		return fmt.Errorf("invalid WAN interface name")
	}
	if w.Metric < 0 || w.Metric > 4000 {
		return fmt.Errorf("WAN metric out of range")
	}
	switch w.Mode {
	case "dhcp":
		// A DHCP uplink may still carry extra static public IPs (e.g. an ISP /29
		// block bound alongside the DHCP-assigned primary) for 1:1 NAT / SNAT.
		for _, a := range w.Aliases {
			if !validCIDR4(a) {
				return fmt.Errorf("WAN alias %q must be an IPv4 CIDR", a)
			}
		}
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

// ethernetBlock renders this WAN's `<iface>: ...` block (indented under
// network.ethernets).
func (w WAN) ethernetBlock() string {
	var b strings.Builder
	fmt.Fprintf(&b, "    %s:\n", w.Interface)
	// A WAN that is down must never hold up the boot. Without this, an uplink
	// with no cable (or no DHCP answer) makes systemd-networkd-wait-online block
	// for its full timeout -- and on a multi-WAN appliance a backup uplink being
	// down is a normal state, not a fault worth stalling every boot for.
	b.WriteString("      optional: true\n")
	if w.Mode == "dhcp" {
		b.WriteString("      dhcp4: true\n")
		fmt.Fprintf(&b, "      dhcp4-overrides:\n        route-metric: %d\n", w.metric())
		// Extra static public IPs sit alongside the DHCP primary on the same port.
		if len(w.Aliases) > 0 {
			b.WriteString("      addresses:\n")
			for _, a := range w.Aliases {
				fmt.Fprintf(&b, "        - %s\n", strings.TrimSpace(a))
			}
		}
		return b.String()
	}
	b.WriteString("      dhcp4: false\n")
	b.WriteString("      addresses:\n")
	fmt.Fprintf(&b, "        - %s\n", strings.TrimSpace(w.Address))
	for _, a := range w.Aliases {
		fmt.Fprintf(&b, "        - %s\n", strings.TrimSpace(a))
	}
	fmt.Fprintf(&b, "      routes:\n        - to: default\n          via: %s\n          metric: %d\n",
		strings.TrimSpace(w.Gateway), w.metric())
	if len(w.DNS) > 0 {
		b.WriteString("      nameservers:\n        addresses:\n")
		for _, d := range w.DNS {
			fmt.Fprintf(&b, "          - %s\n", strings.TrimSpace(d))
		}
	}
	return b.String()
}

// GenerateNetplan renders the netplan for a single WAN (kept for compatibility).
func (w WAN) GenerateNetplan() (string, error) {
	return GenerateNetplanMulti([]WAN{w})
}

// GenerateNetplanMulti renders one netplan covering every WAN interface.
func GenerateNetplanMulti(wans []WAN) (string, error) {
	seen := map[string]bool{}
	var body strings.Builder
	for _, w := range wans {
		if err := w.Validate(); err != nil {
			return "", err
		}
		if seen[w.Interface] {
			return "", fmt.Errorf("duplicate WAN interface %q", w.Interface)
		}
		seen[w.Interface] = true
		body.WriteString(w.ethernetBlock())
	}
	var b strings.Builder
	b.WriteString("# Managed by Saguaro (generated). Manual edits are overwritten on apply.\n")
	b.WriteString("network:\n  version: 2\n  ethernets:\n")
	b.WriteString(body.String())
	return b.String(), nil
}
