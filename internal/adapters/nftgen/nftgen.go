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

// SNATRule pins outbound traffic from a specific internal source (IP or CIDR)
// to a specific WAN address (typically one of the WAN aliases) instead of the
// default masquerade — per-WAN / 1:1 source NAT.
type SNATRule struct {
	Source    string `json:"source"`    // IPv4 or CIDR
	ToAddress string `json:"toAddress"` // WAN (alias) IPv4
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
	FromZone string `json:"fromZone"` // optional: match traffic entering from this zone
	ToZone   string `json:"toZone"`   // optional: match traffic leaving to this zone
	Enabled  bool   `json:"enabled"`
}

// Zone is a named network segment bound to an interface with a trust kind. The
// forward policy is derived from trust: a higher-trust zone may initiate to a
// lower-trust one, never the reverse — so a DMZ can reach the internet but not
// the LAN, and a guest network is isolated from both. Everything not explicitly
// allowed falls through to the drop policy.
type Zone struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`      // wan | lan | dmz | guest
	Interface string `json:"interface"` // bound NIC (the VLAN parent when VLANID>0)
	Network   string `json:"network"`   // CIDR of the segment (optional for wan)
	// VLANID tags the zone onto an 802.1Q VLAN on the parent Interface. 0 means
	// untagged (the physical interface). When set (1-4094) the effective forward
	// interface is "<Interface>.<VLANID>" (e.g. enp2.30).
	VLANID int `json:"vlanId,omitempty"`
	// Address is the appliance's own IP/CIDR on this zone's sub-interface. It is
	// required for VLAN zones (used to create the sub-interface via netplan) and
	// ignored for untagged zones, whose addressing is configured elsewhere.
	Address string `json:"address,omitempty"`
}

// IfaceName is the effective forwarding interface for a zone: the physical NIC
// when untagged, or the 802.1Q sub-interface "<parent>.<vlan>" when tagged.
func (z Zone) IfaceName() string {
	if z.VLANID > 0 {
		return fmt.Sprintf("%s.%d", z.Interface, z.VLANID)
	}
	return z.Interface
}

// zoneTrust ranks zone kinds; a zone may initiate to any strictly lower rank.
var zoneTrust = map[string]int{"wan": 0, "guest": 1, "dmz": 2, "lan": 3}

var zoneNameRe = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,20}$`)

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

	GatewayEnabled bool   `json:"gatewayEnabled"`
	WANInterface   string `json:"wanInterface"`
	LANInterface   string `json:"lanInterface"`
	// MgmtOnWAN/MgmtOnLAN decide on which side the appliance answers its own
	// management ports (SSH 22, GUI 443). They are interface-bound (iifname on
	// the WAN/LAN port) so they keep working when the LAN or WAN subnet changes,
	// unlike AdminNetwork which pins a fixed source CIDR. At least one management
	// path (a toggle or AdminNetwork) must remain or the drop-policy input chain
	// would lock everyone out — Validate enforces that.
	MgmtOnWAN    bool          `json:"mgmtOnWan"`
	MgmtOnLAN    bool          `json:"mgmtOnLan"`
	NATEnabled   bool          `json:"natEnabled"`
	PortForwards []PortForward `json:"portForwards"`
	// HairpinNAT lets LAN clients reach a port-forwarded service via the WAN
	// (public) address — NAT reflection.
	HairpinNAT bool `json:"hairpinNat"`
	// SNATRules pin specific sources to specific WAN addresses on egress.
	SNATRules []SNATRule `json:"snatRules"`
	// IPSEnabled queues new forwarded connections to NFQUEUE 0 for Suricata
	// inline inspection; `bypass` keeps traffic flowing if Suricata dies
	// (fail-open by design — W9).
	IPSEnabled bool `json:"ipsEnabled"`

	// Aliases are named address objects; Rules are custom forward-chain rules
	// that reference them. Both are edited in the Firewall objects/rules pages.
	Aliases []Alias `json:"aliases,omitempty"`
	Rules   []Rule  `json:"rules,omitempty"`
	// Zones are named network segments (LAN/DMZ/GUEST/WAN) whose trust ranks
	// drive the default inter-zone forward policy. Edited in the Firewall zones
	// page; rules may additionally scope by from/to zone.
	Zones []Zone `json:"zones,omitempty"`

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
	// Zones: unique names and interfaces, valid kind and (for internal zones) a
	// CIDR network so the rule tester can place traffic.
	zoneNames := map[string]bool{}
	zoneIfaces := map[string]bool{}
	for _, z := range c.Zones {
		if !zoneNameRe.MatchString(z.Name) {
			return fmt.Errorf("invalid zone name %q (start with a letter; a-z 0-9 _ -)", z.Name)
		}
		if zoneNames[z.Name] {
			return fmt.Errorf("duplicate zone %q", z.Name)
		}
		zoneNames[z.Name] = true
		if _, ok := zoneTrust[z.Kind]; !ok {
			return fmt.Errorf("zone %q kind must be wan, lan, dmz or guest", z.Name)
		}
		if !validIface(z.Interface) {
			return fmt.Errorf("zone %q has an invalid interface %q", z.Name, z.Interface)
		}
		if z.VLANID < 0 || z.VLANID > 4094 {
			return fmt.Errorf("zone %q VLAN id must be 0 (untagged) or 1-4094", z.Name)
		}
		// The effective interface (incl. the VLAN suffix) must be a valid,
		// unique kernel interface name; two zones may share a parent NIC only on
		// different VLANs.
		ifn := z.IfaceName()
		if !validIface(ifn) {
			return fmt.Errorf("zone %q interface name %q is invalid (too long?)", z.Name, ifn)
		}
		if zoneIfaces[ifn] {
			return fmt.Errorf("interface %q is already assigned to another zone", ifn)
		}
		zoneIfaces[ifn] = true
		if z.Kind != "wan" && !validCIDR4(z.Network) {
			return fmt.Errorf("zone %q needs an IPv4 CIDR network", z.Name)
		}
		if z.VLANID > 0 && !validCIDR4(z.Address) {
			return fmt.Errorf("VLAN zone %q needs the appliance's IPv4 CIDR address on that VLAN", z.Name)
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
		if r.FromZone != "" && !zoneNames[r.FromZone] {
			return fmt.Errorf("rule %q references unknown source zone %q", r.Name, r.FromZone)
		}
		if r.ToZone != "" && !zoneNames[r.ToZone] {
			return fmt.Errorf("rule %q references unknown destination zone %q", r.Name, r.ToZone)
		}
	}
	return nil
}

// zoneIfaceMap maps zone name to its interface for rule rendering.
func (c Config) zoneIfaceMap() map[string]string {
	m := map[string]string{}
	for _, z := range c.Zones {
		m[z.Name] = z.IfaceName()
	}
	return m
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

// Packet is a synthetic packet for the rule tester.
type Packet struct {
	Src     string `json:"src"`
	Dst     string `json:"dst"`
	Proto   string `json:"proto"` // any | tcp | udp
	DstPort int    `json:"dstPort"`
}

// RuleEval is the tester's verdict for a Packet.
type RuleEval struct {
	Matched   bool   `json:"matched"`
	RuleName  string `json:"ruleName"`
	RuleIndex int    `json:"ruleIndex"` // 1-based position among enabled rules
	Action    string `json:"action"`    // accept | drop | reject | default
	Reason    string `json:"reason"`
}

func ip4ToU32(ip net.IP) (uint32, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return 0, false
	}
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3]), true
}

// aliasContains reports whether ip is a member of the alias.
func aliasContains(a Alias, ip net.IP) bool {
	for _, v := range a.Values {
		v = strings.TrimSpace(v)
		switch a.Type {
		case "host":
			if p := net.ParseIP(v); p != nil && p.Equal(ip) {
				return true
			}
		case "network":
			if _, n, err := net.ParseCIDR(v); err == nil && n.Contains(ip) {
				return true
			}
		case "range":
			parts := strings.SplitN(v, "-", 2)
			if len(parts) != 2 {
				continue
			}
			lo := net.ParseIP(strings.TrimSpace(parts[0]))
			hi := net.ParseIP(strings.TrimSpace(parts[1]))
			li, ok1 := ip4ToU32(lo)
			hiu, ok2 := ip4ToU32(hi)
			ci, ok3 := ip4ToU32(ip)
			if ok1 && ok2 && ok3 && ci >= li && ci <= hiu {
				return true
			}
		}
	}
	return false
}

// EvaluateForward walks the enabled custom forward rules in order and reports
// the first one that matches the packet (and its verdict), or that the default
// gateway policy applies. It mirrors the generated rule matching but does not
// touch the kernel.
// zoneOf returns the name of the first zone whose network contains ip, or "".
func (c Config) zoneOf(ip net.IP) string {
	if ip == nil {
		return ""
	}
	for _, z := range c.Zones {
		if z.Network == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(z.Network); err == nil && n.Contains(ip) {
			return z.Name
		}
	}
	return ""
}

func (c Config) EvaluateForward(p Packet) RuleEval {
	aliases := map[string]Alias{}
	for _, a := range c.Aliases {
		aliases[a.Name] = a
	}
	src := net.ParseIP(strings.TrimSpace(p.Src))
	dst := net.ParseIP(strings.TrimSpace(p.Dst))
	srcZone, dstZone := c.zoneOf(src), c.zoneOf(dst)
	idx := 0
	for _, r := range c.Rules {
		if !r.Enabled {
			continue
		}
		idx++
		if r.FromZone != "" && r.FromZone != srcZone {
			continue
		}
		if r.ToZone != "" && r.ToZone != dstZone {
			continue
		}
		if r.SrcAlias != "" {
			a, ok := aliases[r.SrcAlias]
			if !ok || src == nil || !aliasContains(a, src) {
				continue
			}
		}
		if r.DstAlias != "" {
			a, ok := aliases[r.DstAlias]
			if !ok || dst == nil || !aliasContains(a, dst) {
				continue
			}
		}
		if r.Proto != "any" && p.Proto != "any" && r.Proto != p.Proto {
			continue
		}
		if r.DstPort != 0 && p.DstPort != 0 && r.DstPort != p.DstPort {
			continue
		}
		return RuleEval{Matched: true, RuleName: r.Name, RuleIndex: idx, Action: r.Action,
			Reason: fmt.Sprintf("prvo pravilo koje odgovara je #%d %q → %s", idx, r.Name, r.Action)}
	}
	return RuleEval{Matched: false, Action: "default",
		Reason: "nijedno custom pravilo ne odgovara — vrijedi zadana politika (u gateway modu: LAN→WAN se propušta, ostalo se odbacuje)"}
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
// zoneIface maps a zone name to its interface so from/to-zone rules match on
// iifname/oifname.
func ruleMatch(r Rule, zoneIface map[string]string) string {
	var parts []string
	if r.FromZone != "" {
		if ifn := zoneIface[r.FromZone]; ifn != "" {
			parts = append(parts, fmt.Sprintf("iifname %q", ifn))
		}
	}
	if r.ToZone != "" {
		if ifn := zoneIface[r.ToZone]; ifn != "" {
			parts = append(parts, fmt.Sprintf("oifname %q", ifn))
		}
	}
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
	// AdminNetwork is optional: management can instead be bound to the WAN/LAN
	// interface via MgmtOnWAN/MgmtOnLAN. When set it must still be a valid CIDR.
	if c.AdminNetwork != "" && !validCIDR4(c.AdminNetwork) {
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
		// Without gateway mode there are no WAN/LAN interfaces to bind the
		// management toggles to, so an explicit admin source network is the only
		// way in and cannot be omitted.
		if c.AdminNetwork == "" {
			return fmt.Errorf("adminNetwork is required")
		}
		return nil
	}
	if !validIface(c.WANInterface) || !validIface(c.LANInterface) {
		return fmt.Errorf("gateway mode requires valid WAN and LAN interface names")
	}
	if c.WANInterface == c.LANInterface {
		return fmt.Errorf("WAN and LAN must be different interfaces")
	}
	// The input chain drops by default; if no management path is allowed the
	// appliance answers SSH/GUI on no interface and locks everyone out. Require
	// at least one: management on WAN, management on LAN, or an admin network.
	if c.AdminNetwork == "" && !c.MgmtOnWAN && !c.MgmtOnLAN {
		return fmt.Errorf("enable management on WAN or LAN, or set an admin network")
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
	for _, s := range c.SNATRules {
		if !validCIDR4(strings.TrimSpace(s.Source)) {
			if ip := net.ParseIP(strings.TrimSpace(s.Source)); ip == nil || ip.To4() == nil {
				return fmt.Errorf("SNAT source %q must be an IPv4 address or CIDR", s.Source)
			}
		}
		if ip := net.ParseIP(strings.TrimSpace(s.ToAddress)); ip == nil || ip.To4() == nil {
			return fmt.Errorf("SNAT target %q must be an IPv4 address", s.ToAddress)
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
	if c.AdminNetwork != "" {
		fmt.Fprintf(&b, "  set mgmt4 { type ipv4_addr; flags interval; elements = { %s } }\n", c.AdminNetwork)
	}
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
	if c.AdminNetwork != "" {
		b.WriteString("    ip saddr @mgmt4 tcp dport { 22, 443 } accept\n")
	}
	// Interface-bound management: answer SSH/GUI on the LAN and/or WAN port. This
	// survives a LAN/WAN subnet change because it matches the port, not a CIDR.
	if c.MgmtOnLAN && c.LANInterface != "" {
		fmt.Fprintf(&b, "    iifname %q tcp dport { 22, 443 } accept\n", c.LANInterface)
	}
	if c.MgmtOnWAN && c.WANInterface != "" {
		fmt.Fprintf(&b, "    iifname %q tcp dport { 22, 443 } accept\n", c.WANInterface)
	}
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
	zoneIface := c.zoneIfaceMap()
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
		fmt.Fprintf(&b, "    %s comment %q\n", ruleMatch(r, zoneIface), label)
	}
	// Inter-zone default policy: a zone may initiate to any strictly lower-trust
	// zone (LAN→DMZ, DMZ→internet, LAN→GUEST…), never the reverse. Internal zones
	// also egress to the WAN interface. Everything else falls through to drop, so
	// a DMZ cannot reach the LAN and guests are isolated.
	if c.GatewayEnabled && len(c.Zones) > 0 {
		for _, z := range c.Zones {
			if z.Kind != "wan" && c.WANInterface != "" && z.IfaceName() != c.WANInterface {
				fmt.Fprintf(&b, "    iifname %q oifname %q accept comment \"zone %s->wan\"\n",
					z.IfaceName(), c.WANInterface, z.Name)
			}
		}
		for _, sz := range c.Zones {
			if sz.Kind == "wan" {
				continue
			}
			for _, dz := range c.Zones {
				if dz.Kind == "wan" || sz.Name == dz.Name {
					continue
				}
				if zoneTrust[sz.Kind] > zoneTrust[dz.Kind] {
					fmt.Fprintf(&b, "    iifname %q oifname %q accept comment \"zone %s->%s\"\n",
						sz.IfaceName(), dz.IfaceName(), sz.Name, dz.Name)
				}
			}
		}
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
	if c.GatewayEnabled && (c.NATEnabled || len(c.PortForwards) > 0 || len(c.SNATRules) > 0) {
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
		if c.NATEnabled || hairpin || len(c.SNATRules) > 0 {
			b.WriteString("  chain postrouting {\n")
			b.WriteString("    type nat hook postrouting priority srcnat;\n")
			// Per-WAN / 1:1 SNAT first, so specific sources get their fixed WAN
			// address before the catch-all masquerade.
			for _, s := range c.SNATRules {
				fmt.Fprintf(&b, "    oifname %q ip saddr %s snat to %s\n",
					c.WANInterface, strings.TrimSpace(s.Source), strings.TrimSpace(s.ToAddress))
			}
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
