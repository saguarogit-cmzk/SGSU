package nftgen

import (
	"strings"
	"testing"
)

func baseCfg() Config {
	return Config{AdminNetwork: "192.168.10.0/24", ClientNetwork: "192.168.10.0/24", DHCPInterface: "enp2s0"}
}

func gwCfg() Config {
	c := baseCfg()
	c.GatewayEnabled = true
	c.WANInterface = "enp1s0"
	c.LANInterface = "enp2s0"
	c.NATEnabled = true
	c.PortForwards = []PortForward{{Proto: "tcp", ExtPort: 8443, DestIP: "192.168.10.5", DestPort: 443}}
	return c
}

func TestValidate(t *testing.T) {
	if err := baseCfg().Validate(); err != nil {
		t.Fatalf("base: %v", err)
	}
	if err := gwCfg().Validate(); err != nil {
		t.Fatalf("gateway: %v", err)
	}
	cases := map[string]func(*Config){
		"bad admin cidr":  func(c *Config) { c.AdminNetwork = "nope" },
		"bad client cidr": func(c *Config) { c.ClientNetwork = "10.0.0.1" },
		"wan==lan":        func(c *Config) { c.LANInterface = c.WANInterface },
		"no wan":          func(c *Config) { c.WANInterface = "" },
		"bad iface chars": func(c *Config) { c.WANInterface = "eth0; rm -rf /" },
		"bad pf proto":    func(c *Config) { c.PortForwards[0].Proto = "icmp" },
		"bad pf port":     func(c *Config) { c.PortForwards[0].ExtPort = 70000 },
		"bad pf ip":       func(c *Config) { c.PortForwards[0].DestIP = "fe80::1" },
		"mgmt port 443":   func(c *Config) { c.PortForwards[0].ExtPort = 443 },
		"mgmt port 22":    func(c *Config) { c.PortForwards[0].ExtPort = 22 },
	}
	for name, mutate := range cases {
		c := gwCfg()
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Fatalf("%s: expected validation error", name)
		}
	}
}

func TestGenerateHostOnly(t *testing.T) {
	text, err := baseCfg().Generate()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"flush ruleset", "table inet saguaro", "policy drop",
		"ip saddr @mgmt4 tcp dport { 22, 443 } accept", `iifname "enp2s0" udp dport 67 accept`} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}
	if strings.Contains(text, "saguaro-nat") || strings.Contains(text, "masquerade") {
		t.Fatal("host-only config must not contain NAT")
	}
}

func TestGenerateGateway(t *testing.T) {
	text, err := gwCfg().Generate()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`iifname "enp2s0" oifname "enp1s0" accept`,
		"table ip saguaro-nat",
		`iifname "enp1s0" tcp dport 8443 dnat to 192.168.10.5:443`,
		`oifname "enp1s0" masquerade`,
		`iifname "enp1s0" ip daddr 192.168.10.5 tcp dport 443 ct state new accept`,
		`counter log prefix "SNA-FWD-DROP " drop`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}
}

func TestGenerateIPSQueueRule(t *testing.T) {
	c := gwCfg()
	c.IPSEnabled = true
	text, err := c.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "ct state new queue num 0 bypass") {
		t.Fatalf("missing IPS queue rule:\n%s", text)
	}
	c.IPSEnabled = false
	text, _ = c.Generate()
	if strings.Contains(text, "queue num 0") {
		t.Fatal("queue rule must be absent without IPS")
	}
}

func TestGenerateGatewayWithoutNAT(t *testing.T) {
	c := gwCfg()
	c.NATEnabled = false
	c.PortForwards = nil
	text, err := c.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text, "saguaro-nat") {
		t.Fatal("no NAT and no forwards must skip the nat table entirely")
	}
}

// TestMgmtOnInterface covers the interface-bound management toggles: with no
// AdminNetwork the appliance still answers SSH/GUI on the chosen port, and the
// @mgmt4 source set is omitted entirely.
func TestMgmtOnInterface(t *testing.T) {
	c := gwCfg()
	c.AdminNetwork = "" // no fixed admin source; rely on the LAN toggle
	c.MgmtOnLAN = true
	text, err := c.Generate()
	if err != nil {
		t.Fatalf("mgmt-on-lan should validate: %v", err)
	}
	if !strings.Contains(text, `iifname "enp2s0" tcp dport { 22, 443 } accept`) {
		t.Fatalf("missing LAN management rule:\n%s", text)
	}
	if strings.Contains(text, "@mgmt4") || strings.Contains(text, "set mgmt4") {
		t.Fatalf("no admin network was set, so @mgmt4 must not appear:\n%s", text)
	}

	// The WAN toggle answers on the WAN port instead.
	c = gwCfg()
	c.AdminNetwork = ""
	c.MgmtOnWAN = true
	text, _ = c.Generate()
	if !strings.Contains(text, `iifname "enp1s0" tcp dport { 22, 443 } accept`) {
		t.Fatalf("missing WAN management rule:\n%s", text)
	}
}

// TestMgmtLockoutGuard rejects configs that would leave the drop-policy input
// chain with no way for an administrator to reach SSH or the GUI.
// TestRuleLog checks that a rule with Log set emits an nft log prefix before its
// verdict, and that a rule without it does not.
func TestRuleLog(t *testing.T) {
	c := gwCfg()
	c.Rules = []Rule{
		{Name: "trace-guests", Action: "drop", Proto: "any", Log: true, Enabled: true},
		{Name: "quiet", Action: "accept", Proto: "any", Enabled: true},
	}
	text, err := c.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, `log prefix "SNA:trace-guests "`) {
		t.Fatalf("logged rule missing log prefix:\n%s", text)
	}
	if strings.Contains(text, "SNA:quiet") {
		t.Fatalf("non-logged rule must not emit a log prefix:\n%s", text)
	}
}

// TestNATPerIP covers a port forward bound to one public IP and a 1:1 NAT.
func TestNATPerIP(t *testing.T) {
	c := gwCfg()
	c.PortForwards = []PortForward{{Proto: "tcp", ExtPort: 8443, DestIP: "192.168.10.5", DestPort: 443, ExtIP: "203.0.113.5"}}
	c.NAT11 = []NAT11Rule{{ExtIP: "203.0.113.7", IntIP: "192.168.10.7"}}
	text, err := c.Generate()
	if err != nil {
		t.Fatal(err)
	}
	// per-IP DNAT, then 1:1 inbound DNAT, outbound SNAT and forward accept.
	for _, want := range []string{
		`iifname "enp1s0" ip daddr 203.0.113.5 tcp dport 8443 dnat to 192.168.10.5:443`,
		`iifname "enp1s0" ip daddr 203.0.113.7 dnat to 192.168.10.7`,
		`oifname "enp1s0" ip saddr 192.168.10.7 snat to 203.0.113.7`,
		`iifname "enp1s0" ip daddr 192.168.10.7 ct state new accept`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}
	bad := gwCfg()
	bad.NAT11 = []NAT11Rule{{ExtIP: "nope", IntIP: "192.168.10.7"}}
	if err := bad.Validate(); err == nil {
		t.Fatal("invalid 1:1 NAT external IP must be rejected")
	}
}

// TestGeoBlock checks that resolved geo CIDRs produce a set and drop rules, and
// that a bad country code is rejected.
func TestGeoBlock(t *testing.T) {
	c := gwCfg()
	c.GeoCountries = []string{"cn"}
	c.GeoCIDRs = []string{"1.2.3.0/24", "5.6.0.0/16"}
	text, err := c.Generate()
	if err != nil {
		t.Fatalf("geo config should generate: %v", err)
	}
	for _, want := range []string{
		"set geo4 { type ipv4_addr; flags interval; elements = { 1.2.3.0/24, 5.6.0.0/16 } }",
		"ip saddr @geo4 drop",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("geo output missing %q:\n%s", want, text)
		}
	}
	bad := gwCfg()
	bad.GeoCountries = []string{"XX"}
	if err := bad.Validate(); err == nil {
		t.Fatal("uppercase/invalid country code must be rejected")
	}
}

func TestMgmtLockoutGuard(t *testing.T) {
	// Gateway with no admin network and neither toggle: total lockout.
	c := gwCfg()
	c.AdminNetwork = ""
	if err := c.Validate(); err == nil {
		t.Fatal("gateway with no management path must be rejected")
	}
	// Host-only (no gateway) always needs an explicit admin network — there are
	// no WAN/LAN interfaces for the toggles to bind to.
	h := baseCfg()
	h.AdminNetwork = ""
	if err := h.Validate(); err == nil {
		t.Fatal("host-only config without an admin network must be rejected")
	}
}
