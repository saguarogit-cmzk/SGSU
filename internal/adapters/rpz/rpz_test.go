package rpz

import (
	"strings"
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	for in, want := range map[string]string{
		"Ads.Example.COM": "ads.example.com",
		"tracker.net.":    "tracker.net",
		"*.bad.example":   "*.bad.example",
		" spaced.org ":    "spaced.org",
	} {
		got, err := NormalizeDomain(in)
		if err != nil || got != want {
			t.Fatalf("NormalizeDomain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "no-tld", "-bad.com", "exa mple.com", "http://x.com", "a..b.com"} {
		if _, err := NormalizeDomain(bad); err == nil {
			t.Fatalf("NormalizeDomain(%q): expected error", bad)
		}
	}
}

func TestValidate(t *testing.T) {
	ok := Config{Enabled: true, Domains: []string{"ads.example.com"}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid: %v", err)
	}
	if err := (Config{Enabled: true}).Validate(); err == nil {
		t.Fatal("enabled without domains or feeds must fail")
	}
	if err := (Config{Enabled: true, Feeds: []string{"ftp://x.example/z"}}).Validate(); err == nil {
		t.Fatal("non-http feed must fail")
	}
	if err := (Config{Enabled: false}).Validate(); err != nil {
		t.Fatalf("disabled empty config must validate: %v", err)
	}
}

func TestGenerateZone(t *testing.T) {
	cfg := Config{Enabled: true, Domains: []string{"Tracker.NET", "ads.example.com", "*.ads.example.com"}}
	zone, err := cfg.GenerateZone(42)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"IN SOA localhost. root.localhost. 42",
		"ads.example.com CNAME .",
		"*.ads.example.com CNAME .",
		"tracker.net CNAME .",
		"*.tracker.net CNAME .",
	} {
		if !strings.Contains(zone, want) {
			t.Fatalf("missing %q in:\n%s", want, zone)
		}
	}
	// The wildcard duplicate must not produce a doubled entry.
	if strings.Count(zone, "ads.example.com CNAME .") != 2 { // exact + wildcard
		t.Fatalf("dedup failed:\n%s", zone)
	}
}

func TestGenerateConf(t *testing.T) {
	cfg := Config{Enabled: true, Domains: []string{"ads.example.com"}, Feeds: []string{"https://feeds.example.org/list.rpz"}}
	conf, err := cfg.GenerateConf("/var/lib/unbound/saguaro-rpz.zone")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`module-config: "respip validator iterator"`,
		"name: saguaro-rpz.",
		"zonefile: /var/lib/unbound/saguaro-rpz.zone",
		"rpz-action-override: nxdomain",
		"rpz-log: yes",
		"name: saguaro-rpz-feed-1.",
		"url: https://feeds.example.org/list.rpz",
	} {
		if !strings.Contains(conf, want) {
			t.Fatalf("missing %q in:\n%s", want, conf)
		}
	}
}
