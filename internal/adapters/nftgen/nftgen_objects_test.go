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
