package nftgen

import (
	"strings"
	"testing"
)

func baseWithObjects() Config {
	return Config{
		AdminNetwork: "192.168.50.0/24", ClientNetwork: "10.10.10.0/24",
		GatewayEnabled: true, WANInterface: "enp1", LANInterface: "enp2", NATEnabled: true,
		Aliases: []Alias{
			{Name: "servers", Type: "host", Values: []string{"192.168.10.5", "192.168.10.6"}},
			{Name: "guests", Type: "network", Values: []string{"192.168.30.0/24"}},
		},
		Rules: []Rule{
			{Name: "block guests to servers", Action: "drop", Proto: "any", SrcAlias: "guests", DstAlias: "servers", Enabled: true},
			{Name: "allow web", Action: "accept", Proto: "tcp", DstAlias: "servers", DstPort: 443, Enabled: true},
			{Name: "disabled one", Action: "accept", Proto: "any", Enabled: false},
		},
	}
}

func TestGenerateObjects(t *testing.T) {
	out, err := baseWithObjects().Generate()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"set alias_servers { type ipv4_addr; elements = { 192.168.10.5, 192.168.10.6 } }",
		"set alias_guests { type ipv4_addr; flags interval; elements = { 192.168.30.0/24 } }",
		`ip saddr @alias_guests ip daddr @alias_servers counter drop comment "block guests to servers"`,
		`ip daddr @alias_servers tcp dport 443 counter accept comment "allow web"`,
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("generated ruleset missing %q:\n%s", w, out)
		}
	}
	if strings.Contains(out, "disabled one") {
		t.Error("disabled rule should not be rendered")
	}
}

func TestSNATRules(t *testing.T) {
	c := Config{AdminNetwork: "192.168.50.0/24", ClientNetwork: "192.168.10.0/24",
		GatewayEnabled: true, WANInterface: "enp1", LANInterface: "enp2", NATEnabled: true,
		SNATRules: []SNATRule{
			{Source: "192.168.10.5", ToAddress: "203.0.113.6"},
			{Source: "192.168.10.0/28", ToAddress: "203.0.113.7"},
		}}
	out, err := c.Generate()
	if err != nil {
		t.Fatal(err)
	}
	snat := `oifname "enp1" ip saddr 192.168.10.5 snat to 203.0.113.6`
	if !strings.Contains(out, snat) || !strings.Contains(out, `oifname "enp1" ip saddr 192.168.10.0/28 snat to 203.0.113.7`) {
		t.Fatalf("SNAT rules missing:\n%s", out)
	}
	// specific SNAT must precede the catch-all masquerade
	if strings.Index(out, snat) > strings.Index(out, `oifname "enp1" masquerade`) {
		t.Errorf("SNAT rule must come before masquerade:\n%s", out)
	}
	bad := c
	bad.SNATRules = []SNATRule{{Source: "192.168.10.5", ToAddress: "not-an-ip"}}
	if err := bad.Validate(); err == nil {
		t.Error("expected invalid SNAT target error")
	}
}

func TestHairpinNAT(t *testing.T) {
	base := Config{AdminNetwork: "192.168.50.0/24", ClientNetwork: "192.168.10.0/24",
		GatewayEnabled: true, WANInterface: "enp1", LANInterface: "enp2", NATEnabled: true,
		PortForwards: []PortForward{{Proto: "tcp", ExtPort: 8443, DestIP: "192.168.10.5", DestPort: 443}}}
	off, err := base.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(off, "fib daddr type local") {
		t.Errorf("hairpin rules present while disabled:\n%s", off)
	}
	base.HairpinNAT = true
	on, err := base.Generate()
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{
		`iifname "enp2" fib daddr type local tcp dport 8443 dnat to 192.168.10.5:443`,
		`ip saddr 192.168.10.0/24 ip daddr 192.168.10.5 tcp dport 443 masquerade`,
	} {
		if !strings.Contains(on, w) {
			t.Errorf("hairpin ruleset missing %q:\n%s", w, on)
		}
	}
}

func TestPBRMangle(t *testing.T) {
	c := Config{
		AdminNetwork: "192.168.50.0/24", ClientNetwork: "10.10.10.0/24",
		GatewayEnabled: true, WANInterface: "enp1", LANInterface: "enp2",
		PBRUplinks: []PBRUplink{{Interface: "enp1", Mark: 1}, {Interface: "enp3", Mark: 2}},
	}
	out, err := c.Generate()
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{
		"chain mangle_pre {",
		"type filter hook prerouting priority mangle;",
		`iifname "enp1" ct state new ct mark set 0x1`,
		`iifname "enp3" ct state new ct mark set 0x2`,
		"ct mark != 0x0 meta mark set ct mark",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("PBR mangle missing %q:\n%s", w, out)
		}
	}
	bad := Config{AdminNetwork: "192.168.50.0/24", ClientNetwork: "10.10.10.0/24",
		PBRUplinks: []PBRUplink{{Interface: "enp1", Mark: 0}}}
	if err := bad.Validate(); err == nil {
		t.Error("expected invalid PBR mark error")
	}
}

func TestEvaluateForward(t *testing.T) {
	c := Config{
		Aliases: []Alias{
			{Name: "guests", Type: "network", Values: []string{"192.168.30.0/24"}},
			{Name: "servers", Type: "host", Values: []string{"192.168.10.5"}},
			{Name: "pool", Type: "range", Values: []string{"10.0.0.10-10.0.0.20"}},
		},
		Rules: []Rule{
			{Name: "block guests", Action: "drop", Proto: "any", SrcAlias: "guests", DstAlias: "servers", Enabled: true},
			{Name: "allow web", Action: "accept", Proto: "tcp", DstAlias: "servers", DstPort: 443, Enabled: true},
			{Name: "pool ssh", Action: "reject", Proto: "tcp", SrcAlias: "pool", DstPort: 22, Enabled: true},
			{Name: "disabled", Action: "accept", Proto: "any", Enabled: false},
		},
	}
	// guest -> server:443 hits the first (drop) rule
	if r := c.EvaluateForward(Packet{Src: "192.168.30.10", Dst: "192.168.10.5", Proto: "tcp", DstPort: 443}); !r.Matched || r.Action != "drop" || r.RuleIndex != 1 {
		t.Fatalf("guest->server: %+v", r)
	}
	// other src -> server:443 tcp hits allow web
	if r := c.EvaluateForward(Packet{Src: "192.168.40.10", Dst: "192.168.10.5", Proto: "tcp", DstPort: 443}); !r.Matched || r.Action != "accept" || r.RuleName != "allow web" {
		t.Fatalf("other->server:443: %+v", r)
	}
	// range alias member on tcp/22 -> reject
	if r := c.EvaluateForward(Packet{Src: "10.0.0.15", Dst: "8.8.8.8", Proto: "tcp", DstPort: 22}); !r.Matched || r.Action != "reject" {
		t.Fatalf("pool->:22: %+v", r)
	}
	// no rule matches -> default policy
	if r := c.EvaluateForward(Packet{Src: "192.168.40.10", Dst: "192.168.10.5", Proto: "tcp", DstPort: 8080}); r.Matched || r.Action != "default" {
		t.Fatalf("expected default: %+v", r)
	}
}

func TestRuleCategory(t *testing.T) {
	c := Config{
		AdminNetwork: "192.168.50.0/24", ClientNetwork: "10.10.10.0/24",
		GatewayEnabled: true, WANInterface: "enp1", LANInterface: "enp2",
		Aliases: []Alias{{Name: "web", Type: "host", Values: []string{"192.168.10.5"}}},
		Rules:   []Rule{{Name: "allow web", Action: "accept", Proto: "tcp", DstAlias: "web", DstPort: 443, Category: "wan2lan", Enabled: true}},
	}
	out, err := c.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `comment "allow web [wan2lan]"`) {
		t.Errorf("category not in rule comment:\n%s", out)
	}
	bad := Config{Rules: []Rule{{Name: "x", Action: "accept", Proto: "any", Category: "bogus"}}}
	if err := bad.ValidateObjects(); err == nil {
		t.Error("expected invalid category error")
	}
}

func TestGenerateTunnels(t *testing.T) {
	c := Config{
		AdminNetwork: "192.168.50.0/24", ClientNetwork: "10.10.10.0/24",
		GatewayEnabled: true, WANInterface: "enp1", LANInterface: "enp2", NATEnabled: true,
		TunnelNets: []TunnelNet{{Local: []string{"192.168.10.0/24"}, Remote: []string{"192.168.20.0/24", "10.50.0.0/16"}}},
	}
	out, err := c.Generate()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		`ip saddr 192.168.10.0/24 ip daddr { 192.168.20.0/24, 10.50.0.0/16 } counter accept comment "tunnel"`,
		`ip saddr { 192.168.20.0/24, 10.50.0.0/16 } ip daddr 192.168.10.0/24 counter accept comment "tunnel"`,
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("missing tunnel rule %q:\n%s", w, out)
		}
	}
	// Tunnels alone (no gateway) still activate the forward chain.
	router := Config{AdminNetwork: "192.168.50.0/24", ClientNetwork: "10.10.10.0/24",
		TunnelNets: []TunnelNet{{Local: []string{"192.168.10.0/24"}, Remote: []string{"192.168.20.0/24"}}}}
	rout, err := router.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rout, `ip saddr 192.168.10.0/24 ip daddr 192.168.20.0/24 counter accept`) {
		t.Errorf("tunnel rule missing without gateway:\n%s", rout)
	}
	// invalid tunnel CIDR is rejected (base config valid so we hit the tunnel check)
	bad := Config{AdminNetwork: "192.168.50.0/24", ClientNetwork: "10.10.10.0/24",
		TunnelNets: []TunnelNet{{Local: []string{"nope"}, Remote: []string{"10.0.0.0/8"}}}}
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "tunnel subnet") {
		t.Errorf("expected tunnel CIDR error, got %v", err)
	}
}

func TestZones(t *testing.T) {
	c := Config{
		AdminNetwork: "192.168.50.0/24", ClientNetwork: "10.10.10.0/24",
		GatewayEnabled: true, WANInterface: "enp1", LANInterface: "enp2", NATEnabled: true,
		Zones: []Zone{
			{Name: "lan", Kind: "lan", Interface: "enp2", Network: "10.10.10.0/24"},
			{Name: "dmz", Kind: "dmz", Interface: "enp3", Network: "10.20.0.0/24"},
			{Name: "guest", Kind: "guest", Interface: "enp4", Network: "10.30.0.0/24"},
		},
		Rules: []Rule{{Name: "dmz web from lan", Action: "accept", Proto: "tcp", DstPort: 443,
			FromZone: "lan", ToZone: "dmz", Enabled: true}},
	}
	out, err := c.Generate()
	if err != nil {
		t.Fatal(err)
	}
	// Higher trust may initiate to lower; internal zones egress to WAN.
	want := []string{
		`iifname "enp2" oifname "enp3" accept comment "zone lan->dmz"`,   // LAN -> DMZ
		`iifname "enp2" oifname "enp4" accept comment "zone lan->guest"`, // LAN -> GUEST
		`iifname "enp3" oifname "enp4" accept comment "zone dmz->guest"`, // DMZ -> GUEST
		`iifname "enp3" oifname "enp1" accept comment "zone dmz->wan"`,   // DMZ -> internet
		`iifname "enp4" oifname "enp1" accept comment "zone guest->wan"`, // GUEST -> internet
		`iifname "enp2" oifname "enp3" tcp dport 443 counter accept`,     // zone-scoped rule
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q:\n%s", w, out)
		}
	}
	// DMZ and guest must NOT be able to initiate to the LAN (isolation): no accept
	// rule from their interface to the LAN interface.
	for _, forbidden := range []string{
		`iifname "enp3" oifname "enp2" accept`, // DMZ -> LAN
		`iifname "enp4" oifname "enp2" accept`, // GUEST -> LAN
		`iifname "enp4" oifname "enp3" accept`, // GUEST -> DMZ
	} {
		if strings.Contains(out, forbidden) {
			t.Errorf("zone isolation broken, found %q:\n%s", forbidden, out)
		}
	}
}

func TestZoneEvaluateForward(t *testing.T) {
	c := Config{
		Zones: []Zone{
			{Name: "lan", Kind: "lan", Interface: "enp2", Network: "10.10.10.0/24"},
			{Name: "dmz", Kind: "dmz", Interface: "enp3", Network: "10.20.0.0/24"},
		},
		Rules: []Rule{
			{Name: "lan to dmz", Action: "accept", Proto: "any", FromZone: "lan", ToZone: "dmz", Enabled: true},
		},
	}
	// LAN host -> DMZ host matches the zone-scoped rule.
	if r := c.EvaluateForward(Packet{Src: "10.10.10.5", Dst: "10.20.0.5", Proto: "tcp", DstPort: 80}); !r.Matched || r.Action != "accept" {
		t.Fatalf("lan->dmz should match: %+v", r)
	}
	// DMZ host -> LAN host does NOT match (wrong direction) -> default.
	if r := c.EvaluateForward(Packet{Src: "10.20.0.5", Dst: "10.10.10.5", Proto: "tcp", DstPort: 80}); r.Matched {
		t.Fatalf("dmz->lan must not match the lan->dmz rule: %+v", r)
	}
}

func TestZoneValidationErrors(t *testing.T) {
	bad := []Config{
		{Zones: []Zone{{Name: "dmz", Kind: "bogus", Interface: "enp3", Network: "10.20.0.0/24"}}}, // bad kind
		{Zones: []Zone{{Name: "dmz", Kind: "dmz", Interface: "enp3", Network: "nope"}}},           // bad CIDR
		{Zones: []Zone{{Name: "a", Kind: "lan", Interface: "enp2", Network: "10.0.0.0/24"}, // dup interface
			{Name: "b", Kind: "dmz", Interface: "enp2", Network: "10.1.0.0/24"}}},
		{Rules: []Rule{{Name: "r", Action: "accept", Proto: "any", FromZone: "ghost", Enabled: true}}}, // unknown zone ref
	}
	for i, c := range bad {
		if err := c.ValidateObjects(); err == nil {
			t.Errorf("zone case %d expected invalid", i)
		}
	}
}

func TestValidateObjectsErrors(t *testing.T) {
	bad := []Config{
		{Aliases: []Alias{{Name: "1bad", Type: "host", Values: []string{"1.2.3.4"}}}},     // name starts with digit
		{Aliases: []Alias{{Name: "a", Type: "host", Values: []string{"not-ip"}}}},         // bad host value
		{Aliases: []Alias{{Name: "a", Type: "network", Values: []string{"10.0.0.1"}}}},    // network needs CIDR
		{Rules: []Rule{{Name: "r", Action: "accept", Proto: "any", SrcAlias: "missing"}}}, // unknown alias ref
		{Rules: []Rule{{Name: "r", Action: "nope", Proto: "any"}}},                        // bad action
		{Rules: []Rule{{Name: "r", Action: "accept", Proto: "any", DstPort: 80}}},         // port needs tcp/udp
	}
	for i, c := range bad {
		if err := c.ValidateObjects(); err == nil {
			t.Errorf("case %d expected invalid", i)
		}
	}
	// a valid range alias referenced by a rule passes
	ok := Config{
		Aliases: []Alias{{Name: "pool", Type: "range", Values: []string{"192.168.1.10-192.168.1.20"}}},
		Rules:   []Rule{{Name: "r", Action: "reject", Proto: "udp", DstAlias: "pool", DstPort: 53, Enabled: true}},
	}
	if err := ok.ValidateObjects(); err != nil {
		t.Fatalf("expected valid: %v", err)
	}
}
