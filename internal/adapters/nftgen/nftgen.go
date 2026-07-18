// Package nftgen generates the complete /etc/nftables.conf for the
// appliance: the host firewall (as the installer lays it down) plus, in
// gateway mode, forward and NAT chains with port forwarding. Generation is
// pure — applying happens through the root adapter /usr/sbin/saguaro-firewall
// with a 120-second confirm-or-rollback window.
package nftgen

import (
	"fmt"
	"net"
	"strings"
)

type PortForward struct {
	Proto    string `json:"proto"` // tcp | udp
	ExtPort  int    `json:"extPort"`
	DestIP   string `json:"destIp"`
	DestPort int    `json:"destPort"`
}

type Config struct {
	AdminNetwork  string `json:"adminNetwork"`  // CIDR allowed to SSH/HTTPS
	ClientNetwork string `json:"clientNetwork"` // CIDR allowed to query DNS
	DHCPInterface string `json:"dhcpInterface"` // optional: interface serving DHCP

	GatewayEnabled bool          `json:"gatewayEnabled"`
	WANInterface   string        `json:"wanInterface"`
	LANInterface   string        `json:"lanInterface"`
	NATEnabled     bool          `json:"natEnabled"`
	PortForwards   []PortForward `json:"portForwards"`
}

func validIface(name string) bool {
	if name == "" || len(name) > 15 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func validCIDR4(s string) bool {
	ip, _, err := net.ParseCIDR(s)
	return err == nil && ip.To4() != nil
}

func (c Config) Validate() error {
	if !validCIDR4(c.AdminNetwork) {
		return fmt.Errorf("adminNetwork must be an IPv4 CIDR")
	}
	if !validCIDR4(c.ClientNetwork) {
		return fmt.Errorf("clientNetwork must be an IPv4 CIDR")
	}
	if c.DHCPInterface != "" && !validIface(c.DHCPInterface) {
		return fmt.Errorf("invalid DHCP interface name")
	}
	if !c.GatewayEnabled {
		return nil
	}
	if !validIface(c.WANInterface) || !validIface(c.LANInterface) {
		return fmt.Errorf("gateway mode requires valid WAN and LAN interface names")
	}
	if c.WANInterface == c.LANInterface {
		return fmt.Errorf("WAN and LAN must be different interfaces")
	}
	for _, pf := range c.PortForwards {
		if pf.Proto != "tcp" && pf.Proto != "udp" {
			return fmt.Errorf("port forward protocol must be tcp or udp")
		}
		if pf.ExtPort < 1 || pf.ExtPort > 65535 || pf.DestPort < 1 || pf.DestPort > 65535 {
			return fmt.Errorf("port forward ports must be 1-65535")
		}
		ip := net.ParseIP(pf.DestIP)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("port forward destination must be an IPv4 address")
		}
		// The GUI must not forward the management ports of the appliance.
		if pf.ExtPort == 22 || pf.ExtPort == 443 {
			return fmt.Errorf("refusing to forward the appliance management port %d", pf.ExtPort)
		}
	}
	return nil
}

// Generate renders the full nftables.conf.
func (c Config) Generate() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("#!/usr/sbin/nft -f\n")
	b.WriteString("# Managed by Saguaro (generated). Manual edits are overwritten on apply.\n")
	b.WriteString("flush ruleset\n")
	b.WriteString("table inet saguaro {\n")
	fmt.Fprintf(&b, "  set mgmt4 { type ipv4_addr; flags interval; elements = { %s } }\n", c.AdminNetwork)
	fmt.Fprintf(&b, "  set clients4 { type ipv4_addr; flags interval; elements = { %s } }\n\n", c.ClientNetwork)
	b.WriteString("  chain input {\n")
	b.WriteString("    type filter hook input priority filter; policy drop;\n")
	b.WriteString("    ct state established,related accept\n")
	b.WriteString("    ct state invalid drop\n")
	b.WriteString("    iif \"lo\" accept\n")
	b.WriteString("    ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded, parameter-problem } accept\n")
	b.WriteString("    ip6 nexthdr ipv6-icmp accept\n")
	b.WriteString("    ip saddr @mgmt4 tcp dport { 22, 443 } accept\n")
	b.WriteString("    ip saddr @clients4 udp dport 53 accept\n")
	b.WriteString("    ip saddr @clients4 tcp dport 53 accept\n")
	if c.DHCPInterface != "" {
		fmt.Fprintf(&b, "    iifname %q udp dport 67 accept\n", c.DHCPInterface)
	}
	b.WriteString("    counter log prefix \"SNA-INPUT-DROP \" drop\n")
	b.WriteString("  }\n\n")
	b.WriteString("  chain forward {\n")
	b.WriteString("    type filter hook forward priority filter; policy drop;\n")
	if c.GatewayEnabled {
		b.WriteString("    ct state established,related accept\n")
		b.WriteString("    ct state invalid drop\n")
		fmt.Fprintf(&b, "    iifname %q oifname %q accept\n", c.LANInterface, c.WANInterface)
		for _, pf := range c.PortForwards {
			fmt.Fprintf(&b, "    iifname %q ip daddr %s %s dport %d ct state new accept\n",
				c.WANInterface, pf.DestIP, pf.Proto, pf.DestPort)
		}
		b.WriteString("    counter log prefix \"SNA-FWD-DROP \" drop\n")
	}
	b.WriteString("  }\n")
	b.WriteString("}\n")
	if c.GatewayEnabled && (c.NATEnabled || len(c.PortForwards) > 0) {
		b.WriteString("\ntable ip saguaro-nat {\n")
		if len(c.PortForwards) > 0 {
			b.WriteString("  chain prerouting {\n")
			b.WriteString("    type nat hook prerouting priority dstnat;\n")
			for _, pf := range c.PortForwards {
				fmt.Fprintf(&b, "    iifname %q %s dport %d dnat to %s:%d\n",
					c.WANInterface, pf.Proto, pf.ExtPort, pf.DestIP, pf.DestPort)
			}
			b.WriteString("  }\n")
		}
		if c.NATEnabled {
			b.WriteString("  chain postrouting {\n")
			b.WriteString("    type nat hook postrouting priority srcnat;\n")
			fmt.Fprintf(&b, "    oifname %q masquerade\n", c.WANInterface)
			b.WriteString("  }\n")
		}
		b.WriteString("}\n")
	}
	return b.String(), nil
}
