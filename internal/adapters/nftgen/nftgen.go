// Package nftgen generates the complete /etc/nftables.conf for the
// appliance: the host firewall (as the installer lays it down) plus, in
// gateway mode, forward and NAT chains with port forwarding. Generation is
// pure — applying happens through the root adapter /usr/sbin/saguaro-firewall
// with a 120-second confirm-or-rollback window.
package nftgen

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

type PortForward struct {
	Proto    string `json:"proto"` // tcp | udp
	ExtPort  int    `json:"extPort"`
	DestIP   string `json:"destIp"`
	DestPort int    `json:"destPort"`
}

// Alias is a named host/network/range object (like a Sophos/pfSense alias) so
// firewall rules can reference addresses by name. It renders to an nft set
// "alias_<name>"; the name is constrained to a valid nft identifier.
type Alias struct {
	Name   string   `json:"name"`
	Type   string   `json:"type"` // host | network | range
	Values []string `json:"values"`
}

// Rule is a custom forward-chain rule that references aliases by name. An empty
// SrcAlias/DstAlias means "any". Rules are evaluated in order, before the
// gateway's blanket LAN→WAN accept, so a drop/reject takes precedence.
type Rule struct {
	Name     string `json:"name"`
	Action   string `json:"action"` // accept | drop | reject
	Proto    string `json:"proto"`  // any | tcp | udp
	SrcAlias string `json:"srcAlias"`
	DstAlias string `json:"dstAlias"`
	DstPort  int    `json:"dstPort"`  // 0 = any (requires tcp/udp when set)
	Category string `json:"category"` // traffic group: lan2wan|wan2lan|wan2dmz|vpn|local|other
	Enabled  bool   `json:"enabled"`
}

// RuleCategories are the allowed traffic groupings for organising/filtering
// rules (Sophos/OPNsense-style). An empty category means "uncategorised".
var RuleCategories = map[string]bool{
	"": true, "lan2wan": true, "wan2lan": true, "wan2dmz": true, "vpn": true, "local": true, "other": true,
}

var aliasNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)
var ruleNameRe = regexp.MustCompile(`^[A-Za-z0-9 ._-]{1,40}$`)

type Config struct {
	AdminNetwork  string `json:"adminNetwork"`  // CIDR allowed to SSH/HTTPS
	ClientNetwork string `json:"clientNetwork"` // CIDR allowed to query DNS
	DHCPInterface string `json:"dhcpInterface"` // optional: interface serving DHCP

	GatewayEnabled bool          `json:"gatewayEnabled"`
	WANInterface   string        `json:"wanInterface"`
	LANInterface   string        `json:"lanInterface"`
	NATEnabled     bool          `json:"natEnabled"`
	PortForwards   []PortForward `json:"portForwards"`
	// HairpinNAT lets LAN clients reach a port-forwarded service via the WAN
	// (public) address — NAT reflection.
	HairpinNAT bool `json:"hairpinNat"`
	// IPSEnabled queues new forwarded connections to NFQUEUE 0 for Suricata
	// inline inspection; `bypass` keeps traffic flowing if Suricata dies
	// (fail-open by design — W9).
	IPSEnabled bool `json:"ipsEnabled"`

	// Aliases are named address objects; Rules are custom forward-chain rules
	// that reference them. Both are edited in the Firewall objects/rules pages.
	Aliases []Alias `json:"aliases,omitempty"`
	Rules   []Rule  `json:"rules,omitempty"`

	// TunnelNets carries the local/remote subnet pairs of active VPN tunnels
	// (WireGuard site-to-site and IPsec) so the forward chain lets that traffic
	// through the gateway policy. Populated at generate time, not user-edited.
	TunnelNets []TunnelNet `json:"-"`
	// PBRUplinks marks connections per WAN for Dual-WAN policy routing.
	PBRUplinks []PBRUplink `json:"-"`
}

// TunnelNet is one tunnel's local and remote subnets.
type TunnelNet struct {
	Local  []string
	Remote []string
}

// PBRUplink marks new connections arriving on a WAN interface with a conntrack
// mark so replies are routed back out the same uplink (Dual-WAN policy routing,
// paired with `ip rule fwmark` tables set up by the root adapter).
type PBRUplink struct {
	Interface string
	Mark      int
}

func validAliasValue(typ, v string) bool {
	v = strings.TrimSpace(v)
	switch typ {
	case "host":
		ip := net.ParseIP(v)
		return ip != nil && ip.To4() != nil
	case "network":
		return validCIDR4(v)
	case "range":
		parts := strings.SplitN(v, "-", 2)
		if len(parts) != 2 {
			return false
		}
		a, b := net.ParseIP(strings.TrimSpace(parts[0])), net.ParseIP(strings.TrimSpace(parts[1]))
		return a != nil && a.To4() != nil && b != nil && b.To4() != nil
	}
	return false
}

// ValidateObjects checks only the aliases and rules (not the base firewall
// config), so they can be edited before the gateway is fully configured.
func (c Config) ValidateObjects() error { return c.validateObjects() }

// validateObjects checks aliases and the rules that reference them.
func (c Config) validateObjects() error {
	names := map[string]bool{}
	for _, a := range c.Aliases {
		if !aliasNameRe.MatchString(a.Name) {
			return fmt.Errorf("invalid alias name %q (start with a letter; a-z 0-9 _)", a.Name)
		}
		if names[a.Name] {
			return fmt.Errorf("duplicate alias %q", a.Name)
		}
		names[a.Name] = true
		if a.Type != "host" && a.Type != "network" && a.Type != "range" {
			return fmt.Errorf("alias %q type must be host, network or range", a.Name)
		}
		if len(a.Values) == 0 {
			return fmt.Errorf("alias %q needs at least one value", a.Name)
		}
		for _, v := range a.Values {
			if !validAliasValue(a.Type, v) {
				return fmt.Errorf("alias %q has an invalid %s value %q", a.Name, a.Type, v)
			}
		}
	}
	ruleNames := map[string]bool{}
	for _, r := range c.Rules {
		if !ruleNameRe.MatchString(r.Name) {
			return fmt.Errorf("rule name must be 1-40 characters (letters, digits, space . _ -)")
		}
		if ruleNames[r.Name] {
			return fmt.Errorf("duplicate rule %q", r.Name)
		}
		ruleNames[r.Name] = true
		if r.Action != "accept" && r.Action != "drop" && r.Action != "reject" {
			return fmt.Errorf("rule %q action must be accept, drop or reject", r.Name)
		}
		if r.Proto != "any" && r.Proto != "tcp" && r.Proto != "udp" {
			return fmt.Errorf("rule %q protocol must be any, tcp or udp", r.Name)
		}
		if r.DstPort != 0 {
			if r.Proto != "tcp" && r.Proto != "udp" {
				return fmt.Errorf("rule %q: a destination port requires tcp or udp", r.Name)
			}
			if r.DstPort < 1 || r.DstPort > 65535 {
				return fmt.Errorf("rule %q port out of range", r.Name)
			}
		}
		if !RuleCategories[r.Category] {
			return fmt.Errorf("rule %q has an invalid category %q", r.Name, r.Category)
		}
		if r.SrcAlias != "" && !names[r.SrcAlias] {
			return fmt.Errorf("rule %q references unknown source alias %q", r.Name, r.SrcAlias)
		}
		if r.DstAlias != "" && !names[r.DstAlias] {
			return fmt.Errorf("rule %q references unknown destination alias %q", r.Name, r.DstAlias)
		}
	}
	return nil
}

// aliasSetType returns the nft set declaration body for an alias.
func aliasSetType(a Alias) string {
	interval := a.Type == "network" || a.Type == "range"
	body := "type ipv4_addr;"
	if interval {
		body += " flags interval;"
	}
	elems := make([]string, 0, len(a.Values))
	for _, v := range a.Values {
		v = strings.TrimSpace(v)
		if a.Type == "range" {
			parts := strings.SplitN(v, "-", 2)
			v = strings.TrimSpace(parts[0]) + "-" + strings.TrimSpace(parts[1])
		}
		elems = append(elems, v)
	}
	return fmt.Sprintf("%s elements = { %s }", body, strings.Join(elems, ", "))
}

// nftSet renders one CIDR bare, or several as an anonymous nft set { a, b }.
func nftSet(cidrs []string) string {
	if len(cidrs) == 1 {
		return strings.TrimSpace(cidrs[0])
	}
	parts := make([]string, len(cidrs))
	for i, c := range cidrs {
		parts[i] = strings.TrimSpace(c)
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}

// ruleMatch renders the match+verdict for a custom rule (without indentation).
func ruleMatch(r Rule) string {
	var parts []string
	if r.SrcAlias != "" {
		parts = append(parts, "ip saddr @alias_"+r.SrcAlias)
	}
	if r.DstAlias != "" {
		parts = append(parts, "ip daddr @alias_"+r.DstAlias)
	}
	switch {
	case r.DstPort != 0:
		parts = append(parts, fmt.Sprintf("%s dport %d", r.Proto, r.DstPort))
	case r.Proto == "tcp" || r.Proto == "udp":
		parts = append(parts, "meta l4proto "+r.Proto)
	}
	parts = append(parts, "counter", r.Action)
	return strings.Join(parts, " ")
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
	if err := c.validateObjects(); err != nil {
		return err
	}
	for _, tn := range c.TunnelNets {
		for _, s := range append(append([]string{}, tn.Local...), tn.Remote...) {
			if !validCIDR4(strings.TrimSpace(s)) {
				return fmt.Errorf("tunnel subnet %q is not an IPv4 CIDR", s)
			}
		}
	}
	for _, p := range c.PBRUplinks {
		if !validIface(p.Interface) {
			return fmt.Errorf("PBR uplink has an invalid interface %q", p.Interface)
		}
		if p.Mark < 1 || p.Mark > 255 {
			return fmt.Errorf("PBR uplink %q mark out of range", p.Interface)
		}
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
	fmt.Fprintf(&b, "  set clients4 { type ipv4_addr; flags interval; elements = { %s } }\n", c.ClientNetwork)
	for _, a := range c.Aliases {
		fmt.Fprintf(&b, "  set alias_%s { %s }\n", a.Name, aliasSetType(a))
	}
	b.WriteString("\n")
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
	hasRules := false
	for _, r := range c.Rules {
		if r.Enabled {
			hasRules = true
			break
		}
	}
	forwardActive := c.GatewayEnabled || hasRules || len(c.TunnelNets) > 0
	if forwardActive {
		b.WriteString("    ct state established,related accept\n")
		b.WriteString("    ct state invalid drop\n")
	}
	if c.GatewayEnabled && c.IPSEnabled {
		b.WriteString("    ct state new queue num 0 bypass\n")
	}
	// Custom rules first, so an explicit drop/reject wins over the blanket
	// LAN→WAN accept and tunnel accepts that follow.
	for _, r := range c.Rules {
		if !r.Enabled {
			continue
		}
		label := r.Name
		if r.Category != "" {
			label += " [" + r.Category + "]"
		}
		fmt.Fprintf(&b, "    %s comment %q\n", ruleMatch(r), label)
	}
	// VPN tunnel traffic (WireGuard site-to-site, IPsec): allow the configured
	// local↔remote subnets through the forward policy in both directions.
	for _, tn := range c.TunnelNets {
		if len(tn.Local) == 0 || len(tn.Remote) == 0 {
			continue
		}
		local, remote := nftSet(tn.Local), nftSet(tn.Remote)
		fmt.Fprintf(&b, "    ip saddr %s ip daddr %s counter accept comment \"tunnel\"\n", local, remote)
		fmt.Fprintf(&b, "    ip saddr %s ip daddr %s counter accept comment \"tunnel\"\n", remote, local)
	}
	if c.GatewayEnabled {
		fmt.Fprintf(&b, "    iifname %q oifname %q accept\n", c.LANInterface, c.WANInterface)
		for _, pf := range c.PortForwards {
			fmt.Fprintf(&b, "    iifname %q ip daddr %s %s dport %d ct state new accept\n",
				c.WANInterface, pf.DestIP, pf.Proto, pf.DestPort)
		}
	}
	if forwardActive {
		b.WriteString("    counter log prefix \"SNA-FWD-DROP \" drop\n")
	}
	b.WriteString("  }\n")
	// Dual-WAN policy routing: mark new connections with the uplink they arrive
	// on, and restore the mark on established connections so `ip rule fwmark`
	// routes replies back out the same WAN.
	if len(c.PBRUplinks) > 0 {
		b.WriteString("  chain mangle_pre {\n")
		b.WriteString("    type filter hook prerouting priority mangle; policy accept;\n")
		for _, p := range c.PBRUplinks {
			fmt.Fprintf(&b, "    iifname %q ct state new ct mark set 0x%x\n", p.Interface, p.Mark)
		}
		b.WriteString("    ct mark != 0x0 meta mark set ct mark\n")
		b.WriteString("  }\n")
	}
	b.WriteString("}\n")
	hairpin := c.HairpinNAT && len(c.PortForwards) > 0
	if c.GatewayEnabled && (c.NATEnabled || len(c.PortForwards) > 0) {
		b.WriteString("\ntable ip saguaro-nat {\n")
		if len(c.PortForwards) > 0 {
			b.WriteString("  chain prerouting {\n")
			b.WriteString("    type nat hook prerouting priority dstnat;\n")
			for _, pf := range c.PortForwards {
				fmt.Fprintf(&b, "    iifname %q %s dport %d dnat to %s:%d\n",
					c.WANInterface, pf.Proto, pf.ExtPort, pf.DestIP, pf.DestPort)
			}
			// Hairpin: LAN clients hitting the appliance's own (public/local)
			// address on the forwarded port get DNAT'd to the internal host too.
			if hairpin {
				for _, pf := range c.PortForwards {
					fmt.Fprintf(&b, "    iifname %q fib daddr type local %s dport %d dnat to %s:%d\n",
						c.LANInterface, pf.Proto, pf.ExtPort, pf.DestIP, pf.DestPort)
				}
			}
			b.WriteString("  }\n")
		}
		if c.NATEnabled || hairpin {
			b.WriteString("  chain postrouting {\n")
			b.WriteString("    type nat hook postrouting priority srcnat;\n")
			if c.NATEnabled {
				fmt.Fprintf(&b, "    oifname %q masquerade\n", c.WANInterface)
			}
			// Hairpin: masquerade the reflected flows so the internal host
			// replies via the appliance (source becomes the appliance LAN IP).
			if hairpin {
				for _, pf := range c.PortForwards {
					fmt.Fprintf(&b, "    ip saddr %s ip daddr %s %s dport %d masquerade\n",
						c.ClientNetwork, pf.DestIP, pf.Proto, pf.DestPort)
				}
			}
			b.WriteString("  }\n")
		}
		b.WriteString("}\n")
	}
	return b.String(), nil
}
