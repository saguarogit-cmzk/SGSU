package squidcfg

import (
	"strings"
	"testing"
)

func TestGenerate(t *testing.T) {
	c := Config{Enabled: true, FilterPort: 8080, AllowedNetwork: "192.168.10.0/24", Filtering: true,
		BannedSites: []string{"ads.example.com", "BAD.example"}, ExceptionSites: []string{"ok.example.com"}}
	d, err := c.GenerateSquidDropIn()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d, "acl saguaro_lan src 192.168.10.0/24") || !strings.Contains(d, "http_access allow saguaro_lan") {
		t.Fatalf("squid drop-in wrong:\n%s", d)
	}
	b, _ := c.GenerateBanned()
	if !strings.Contains(b, "ads.example.com") || !strings.Contains(b, "bad.example") { // lower-cased
		t.Fatalf("banned list wrong:\n%s", b)
	}
	x, _ := c.GenerateExceptions()
	if !strings.Contains(x, "ok.example.com") {
		t.Fatalf("exception list wrong:\n%s", x)
	}
}

func TestGenerateSSLBump(t *testing.T) {
	c := Config{Enabled: true, FilterPort: 8080, AllowedNetwork: "192.168.10.0/24",
		SSLBump: true, SSLBumpPort: 3130, SpliceSites: []string{"bank.example", "health.example"}}
	d, err := c.GenerateSquidDropIn()
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{
		"http_port 3130 ssl-bump generate-host-certificates=on",
		"tls-cert=" + BumpCACert, "tls-key=" + BumpCAKey,
		"sslcrtd_program /usr/lib/squid/security_file_certgen -s /var/lib/squid/ssl_db",
		"acl saguaro_step1 at_step SslBump1",
		"acl saguaro_splice ssl::server_name .bank.example .health.example",
		"ssl_bump peek saguaro_step1", "ssl_bump splice saguaro_splice", "ssl_bump bump all",
	} {
		if !strings.Contains(d, w) {
			t.Errorf("SSL-bump drop-in missing %q:\n%s", w, d)
		}
	}
	// A bump port clashing with the Squid port is rejected.
	bad := c
	bad.SSLBumpPort = SquidPort
	if err := bad.Validate(); err == nil {
		t.Error("expected clash with Squid port to be rejected")
	}
	// Without SSL-bump the block is absent.
	plain := Config{Enabled: true, AllowedNetwork: "192.168.10.0/24"}
	if d, _ := plain.GenerateSquidDropIn(); strings.Contains(d, "ssl-bump") {
		t.Errorf("ssl-bump present while disabled:\n%s", d)
	}
}

func TestValidate(t *testing.T) {
	if err := (Config{Enabled: false}).Validate(); err != nil {
		t.Fatalf("disabled should validate: %v", err)
	}
	bad := []Config{
		{Enabled: true, AllowedNetwork: "nope"},
		{Enabled: true, AllowedNetwork: "192.168.10.0/24", BannedSites: []string{"bad domain!"}},
		{Enabled: true, AllowedNetwork: "192.168.10.0/24", FilterPort: 70000},
	}
	for i, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("case %d expected invalid", i)
		}
	}
	// default filter port applies when unset
	if (Config{FilterPort: 0}).FilterPortOrDefault() != 8080 {
		t.Fatal("default filter port wrong")
	}
}
