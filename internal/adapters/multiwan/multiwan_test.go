package multiwan

import (
	"strings"
	"testing"
)

func cfgOK() Config {
	return Config{Enabled: true, Uplinks: []Uplink{
		{Name: "wan1", Interface: "enp1s0", Gateway: "192.0.2.1", Weight: 3, HealthCheck: "1.1.1.1"},
		{Name: "wan2", Interface: "enp3s0", Gateway: "198.51.100.1", Weight: 1, HealthCheck: "8.8.8.8"},
	}}
}

func TestValidate(t *testing.T) {
	if err := cfgOK().Validate(); err != nil {
		t.Fatalf("valid: %v", err)
	}
	if err := (Config{Enabled: false}).Validate(); err != nil {
		t.Fatalf("disabled empty must validate: %v", err)
	}
	cases := map[string]func(*Config){
		"one uplink":  func(c *Config) { c.Uplinks = c.Uplinks[:1] },
		"dup name":    func(c *Config) { c.Uplinks[1].Name = "wan1" },
		"bad iface":   func(c *Config) { c.Uplinks[0].Interface = "eth0; rm" },
		"bad gateway": func(c *Config) { c.Uplinks[0].Gateway = "nope" },
		"bad weight":  func(c *Config) { c.Uplinks[0].Weight = 0 },
		"bad hc":      func(c *Config) { c.Uplinks[0].HealthCheck = "not-ip" },
	}
	for name, mutate := range cases {
		c := cfgOK()
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
}

func TestDefaultRouteArgs(t *testing.T) {
	c := cfgOK()
	all, err := c.DefaultRouteArgs(nil)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(all, " ")
	if !strings.Contains(joined, "nexthop via 192.0.2.1 dev enp1s0 weight 3") ||
		!strings.Contains(joined, "nexthop via 198.51.100.1 dev enp3s0 weight 1") {
		t.Fatalf("route args wrong: %s", joined)
	}
	// Only wan2 healthy → single nexthop.
	one, err := c.DefaultRouteArgs(map[string]bool{"wan2": true})
	if err != nil {
		t.Fatal(err)
	}
	oj := strings.Join(one, " ")
	if strings.Contains(oj, "enp1s0") || !strings.Contains(oj, "enp3s0") {
		t.Fatalf("failover route wrong: %s", oj)
	}
	// All down → error.
	if _, err := c.DefaultRouteArgs(map[string]bool{}); err == nil {
		t.Fatal("no healthy uplinks must error")
	}
}

func TestGenerateSpec(t *testing.T) {
	spec, err := cfgOK().GenerateSpec()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(spec, "wan1 enp1s0 192.0.2.1 3 1.1.1.1") ||
		!strings.Contains(spec, "wan2 enp3s0 198.51.100.1 1 8.8.8.8") {
		t.Fatalf("spec wrong:\n%s", spec)
	}
}
