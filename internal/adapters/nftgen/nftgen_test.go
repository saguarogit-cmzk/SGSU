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
