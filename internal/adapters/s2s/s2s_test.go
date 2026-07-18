package s2s

import (
	"strings"
	"testing"

	wg "saguaro.local/network-manager/internal/adapters/wireguard"
)

func testKeys(t *testing.T) (priv, pub string) {
	t.Helper()
	priv, pub, err := wg.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func TestValidate(t *testing.T) {
	_, pub := testKeys(t)
	ok := Config{ListenPort: 51821, TunnelAddress: "10.9.0.1/30", LocalNetworks: []string{"192.168.10.0/24"},
		Sites: []Site{{Name: "site-b", PubKey: pub, Endpoint: "203.0.113.5:51821", RemoteNetworks: []string{"192.168.20.0/24"}, Keepalive: 25}}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("expected valid: %v", err)
	}
	bad := []Config{
		{ListenPort: 0, Sites: nil},                                    // bad port
		{ListenPort: 51821, TunnelAddress: "nope"},                     // bad tunnel
		{ListenPort: 51821, Sites: []Site{{Name: "x", PubKey: "bad"}}}, // bad key
		{ListenPort: 51821, Sites: []Site{{Name: "x", PubKey: pub}}},   // no remote nets
		{ListenPort: 51821, Sites: []Site{{Name: "x", PubKey: pub, Endpoint: "hostonly", RemoteNetworks: []string{"10.0.0.0/8"}}}}, // bad endpoint
	}
	for i, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("case %d expected invalid", i)
		}
	}
	// duplicate site names
	dup := Config{ListenPort: 51821, Sites: []Site{
		{Name: "s", PubKey: pub, RemoteNetworks: []string{"10.0.0.0/8"}},
		{Name: "s", PubKey: pub, RemoteNetworks: []string{"10.1.0.0/16"}},
	}}
	if err := dup.Validate(); err == nil {
		t.Error("expected duplicate site error")
	}
}

func TestGenerateConf(t *testing.T) {
	priv, pub := testKeys(t)
	c := Config{Enabled: true, ListenPort: 51821, TunnelAddress: "10.9.0.1/30", ServerPub: "x",
		Sites: []Site{{Name: "site-b", PubKey: pub, Endpoint: "203.0.113.5:51821",
			RemoteNetworks: []string{"192.168.20.0/24", "10.50.0.0/16"}, Keepalive: 25}}}
	conf, err := c.GenerateConf(priv, map[string]string{"site-b": "presharedkeypresharedkeypresharedkeypreshar="})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[Interface]", "Address = 10.9.0.1/30", "ListenPort = 51821",
		"PrivateKey = " + priv, "# site: site-b", "PublicKey = " + pub,
		"PresharedKey = presharedkey", "Endpoint = 203.0.113.5:51821",
		"AllowedIPs = 192.168.20.0/24, 10.50.0.0/16", "PersistentKeepalive = 25"} {
		if !strings.Contains(conf, want) {
			t.Errorf("conf missing %q:\n%s", want, conf)
		}
	}
}

func TestRemotePeerSnippet(t *testing.T) {
	c := Config{ListenPort: 51821, ServerPub: "OURPUBKEY", LocalNetworks: []string{"192.168.10.0/24"}, TunnelAddress: "10.9.0.1/30"}
	snip := c.RemotePeerSnippet("198.51.100.9")
	for _, want := range []string{"PublicKey = OURPUBKEY", "AllowedIPs = 192.168.10.0/24, 10.9.0.1/30", "Endpoint = 198.51.100.9:51821"} {
		if !strings.Contains(snip, want) {
			t.Errorf("snippet missing %q:\n%s", want, snip)
		}
	}
}
