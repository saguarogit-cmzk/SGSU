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

const fakeCert = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"

func TestGenerateConfCert(t *testing.T) {
	c := Config{Enabled: true, Connections: []Connection{{
		Name: "certconn", RemoteAddr: "203.0.113.9", LocalID: "vpn.local", RemoteID: "peer.remote",
		LocalSubnets: []string{"10.0.0.0/24"}, RemoteSubnets: []string{"10.9.0.0/24"},
		Auth: "cert", LocalCert: fakeCert, RemoteCA: fakeCert, Initiate: true,
	}}}
	conf, err := c.GenerateConf(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"auth = pubkey", "certs = saguaro-certconn.pem", "id = vpn.local", "id = peer.remote"} {
		if !strings.Contains(conf, want) {
			t.Errorf("cert conf missing %q:\n%s", want, conf)
		}
	}
	// certificate connections carry no secrets{} entry
	if strings.Contains(conf, "ike-certconn") {
		t.Errorf("cert connection must not emit a PSK secret:\n%s", conf)
	}
}

func TestValidateCertErrors(t *testing.T) {
	base := Connection{Name: "c", RemoteAddr: "1.2.3.4", LocalSubnets: []string{"10.0.0.0/24"}, RemoteSubnets: []string{"10.1.0.0/16"}, Auth: "cert"}
	noID := base
	noID.LocalCert, noID.RemoteCA = fakeCert, fakeCert // missing IDs
	if err := (Config{Connections: []Connection{noID}}).Validate(); err == nil {
		t.Error("cert without IDs should be invalid")
	}
	badPEM := base
	badPEM.LocalID, badPEM.RemoteID = "a", "b"
	badPEM.LocalCert, badPEM.RemoteCA = "not pem", fakeCert
	if err := (Config{Connections: []Connection{badPEM}}).Validate(); err == nil {
		t.Error("cert with a non-PEM localCert should be invalid")
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
