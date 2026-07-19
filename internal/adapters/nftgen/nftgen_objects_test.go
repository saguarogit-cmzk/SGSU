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
