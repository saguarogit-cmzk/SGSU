package wireguard

import (
	"strings"
	"testing"
	"time"
)

func TestGenerateKeypair(t *testing.T) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if !ValidKey(priv) || !ValidKey(pub) {
		t.Fatalf("generated keys not valid: %q %q", priv, pub)
	}
	priv2, pub2, _ := GenerateKeypair()
	if priv == priv2 || pub == pub2 {
		t.Fatal("keypairs must be unique")
	}
}

func cfgOK() Config {
	_, pub, _ := GenerateKeypair()
	return Config{Enabled: true, Subnet: "10.8.0.0/24", ListenPort: 51820,
		Endpoint: "vpn.example.com:51820", DNS: "192.168.10.1",
		SplitNetworks: []string{"192.168.10.0/24"}, ServerPub: pub}
}

func TestValidate(t *testing.T) {
	if err := cfgOK().Validate(); err != nil {
		t.Fatalf("valid: %v", err)
	}
	cases := map[string]func(*Config){
		"bad subnet":    func(c *Config) { c.Subnet = "10.8.0.0" },
		"tiny subnet":   func(c *Config) { c.Subnet = "10.8.0.0/31" },
		"bad port":      func(c *Config) { c.ListenPort = 0 },
		"no endpoint":   func(c *Config) { c.Endpoint = "" },
		"bad dns":       func(c *Config) { c.DNS = "not-ip" },
		"bad split":     func(c *Config) { c.SplitNetworks = []string{"10.0.0.1"} },
		"bad peer name": func(c *Config) { c.Peers = []Peer{{Name: "Bad Name", PubKey: c.ServerPub, Address: "10.8.0.2"}} },
		"peer outside":  func(c *Config) { c.Peers = []Peer{{Name: "ok", PubKey: c.ServerPub, Address: "10.9.0.2"}} },
	}
	for name, mutate := range cases {
		c := cfgOK()
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
}

func TestAllocateAddress(t *testing.T) {
	c := cfgOK()
	a1, err := c.AllocateAddress()
	if err != nil || a1 != "10.8.0.2" {
		t.Fatalf("first allocation: %q %v", a1, err)
	}
	c.Peers = append(c.Peers, Peer{Name: "p1", PubKey: c.ServerPub, Address: "10.8.0.2"})
	a2, _ := c.AllocateAddress()
	if a2 != "10.8.0.3" {
		t.Fatalf("second allocation: %q", a2)
	}
	// Gap reuse.
	c.Peers = []Peer{{Name: "p2", PubKey: c.ServerPub, Address: "10.8.0.3"}}
	a3, _ := c.AllocateAddress()
	if a3 != "10.8.0.2" {
		t.Fatalf("gap allocation: %q", a3)
	}
}

func TestServerConfExcludesExpiredPeers(t *testing.T) {
	c := cfgOK()
	priv, _, _ := GenerateKeypair()
	now := time.Now().UTC()
	c.Peers = []Peer{
		{Name: "live", PubKey: c.ServerPub, Address: "10.8.0.2", CreatedAt: now},
		{Name: "dead", PubKey: c.ServerPub, Address: "10.8.0.3", CreatedAt: now.AddDate(0, 0, -30), ExpiresAt: now.AddDate(0, 0, -1)},
	}
	conf, err := c.GenerateServerConf(priv, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Address = 10.8.0.1/24", "ListenPort = 51820", "# peer: live", "AllowedIPs = 10.8.0.2/32"} {
		if !strings.Contains(conf, want) {
			t.Fatalf("missing %q in:\n%s", want, conf)
		}
	}
	if strings.Contains(conf, "dead") || strings.Contains(conf, "10.8.0.3/32") {
		t.Fatalf("expired peer must be excluded:\n%s", conf)
	}
}

func TestClientConfProfiles(t *testing.T) {
	c := cfgOK()
	priv, _, _ := GenerateKeypair()
	full := Peer{Name: "f", Address: "10.8.0.2", FullTunnel: true}
	conf, err := c.GenerateClientConf(priv, full)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"AllowedIPs = 0.0.0.0/0", "DNS = 192.168.10.1", "Endpoint = vpn.example.com:51820", "PersistentKeepalive = 25", "Address = 10.8.0.2/32"} {
		if !strings.Contains(conf, want) {
			t.Fatalf("missing %q in:\n%s", want, conf)
		}
	}
	split := Peer{Name: "s", Address: "10.8.0.3", FullTunnel: false}
	conf, _ = c.GenerateClientConf(priv, split)
	if !strings.Contains(conf, "AllowedIPs = 10.8.0.0/24, 192.168.10.0/24") {
		t.Fatalf("split tunnel AllowedIPs wrong:\n%s", conf)
	}
}
