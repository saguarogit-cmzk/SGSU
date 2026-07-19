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
