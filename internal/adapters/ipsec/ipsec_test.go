package ipsec

import (
	"strings"
	"testing"
)

func validConn() Connection {
	return Connection{Name: "sophos-hq", RemoteAddr: "203.0.113.5",
		LocalSubnets: []string{"192.168.10.0/24"}, RemoteSubnets: []string{"192.168.20.0/24"}, Initiate: true}
}

func TestValidate(t *testing.T) {
	if err := (Config{Connections: []Connection{validConn()}}).Validate(); err != nil {
		t.Fatalf("expected valid: %v", err)
	}
	bad := []Config{
		{Connections: []Connection{{Name: "bad name", RemoteAddr: "1.2.3.4", LocalSubnets: []string{"10.0.0.0/8"}, RemoteSubnets: []string{"10.1.0.0/16"}}}},
		{Connections: []Connection{{Name: "c", RemoteAddr: "not a host!", LocalSubnets: []string{"10.0.0.0/8"}, RemoteSubnets: []string{"10.1.0.0/16"}}}},
		{Connections: []Connection{{Name: "c", RemoteAddr: "1.2.3.4", LocalSubnets: nil, RemoteSubnets: []string{"10.1.0.0/16"}}}},
		{Connections: []Connection{{Name: "c", RemoteAddr: "1.2.3.4", LocalSubnets: []string{"nope"}, RemoteSubnets: []string{"10.1.0.0/16"}}}},
		{Connections: []Connection{{Name: "c", RemoteAddr: "1.2.3.4", LocalSubnets: []string{"10.0.0.0/8"}, RemoteSubnets: []string{"10.1.0.0/16"}, IKEProposal: "aes256 sha256"}}},
	}
	for i, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("case %d expected invalid", i)
		}
	}
	dup := Config{Connections: []Connection{validConn(), validConn()}}
	if err := dup.Validate(); err == nil {
		t.Error("expected duplicate connection error")
	}
}

func TestGenerateConf(t *testing.T) {
	c := Config{Enabled: true, Connections: []Connection{validConn(),
		{Name: "responder", RemoteAddr: "gw.example.com", RemoteID: "gw.example.com",
			LocalSubnets: []string{"10.0.0.0/24"}, RemoteSubnets: []string{"10.9.0.0/24"}, Initiate: false}}}
	conf, err := c.GenerateConf(map[string]string{"sophos-hq": "s3cret-psk!", "responder": "another-psk"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"connections {", "conn-sophos-hq {", "version = 2", "remote_addrs = 203.0.113.5",
		"proposals = aes256-sha256-modp2048", // default IKE applied
		"local_ts = 192.168.10.0/24", "remote_ts = 192.168.20.0/24",
		"esp_proposals = aes256-sha256-modp2048", // default ESP applied
		"start_action = start",                   // initiate=true
		"start_action = trap",                    // initiate=false (responder)
		"id = gw.example.com",                    // remote id explicit
		"secrets {", "ike-sophos-hq {", `secret = "s3cret-psk!"`,
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("conf missing %q:\n%s", want, conf)
		}
	}
}
