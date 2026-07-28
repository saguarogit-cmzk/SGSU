package main

import (
	"strings"
	"testing"
)

func TestDNSForwardGenerate(t *testing.T) {
	c := dnsForwardConfig{Enabled: true, Upstreams: []dnsUpstream{
		{Address: "1.1.1.1", Port: 853, Name: "cloudflare-dns.com"},
		{Address: "9.9.9.9", Name: "dns.quad9.net"}, // port defaults to 853
	}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	out := c.GenerateConf()
	for _, w := range []string{
		"forward-tls-upstream: yes",
		"forward-addr: 1.1.1.1@853#cloudflare-dns.com",
		"forward-addr: 9.9.9.9@853#dns.quad9.net",
		"tls-cert-bundle:",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("conf missing %q:\n%s", w, out)
		}
	}
}

func TestDNSForwardValidate(t *testing.T) {
	if err := (dnsForwardConfig{Enabled: true}).Validate(); err == nil {
		t.Error("enabled with no upstreams should fail")
	}
	if err := (dnsForwardConfig{Enabled: true, Upstreams: []dnsUpstream{{Address: "not-ip"}}}).Validate(); err == nil {
		t.Error("bad ip should fail")
	}
	if err := (dnsForwardConfig{Enabled: true, Upstreams: []dnsUpstream{{Address: "1.1.1.1", Name: "bad name!"}}}).Validate(); err == nil {
		t.Error("bad TLS name should fail")
	}
	if err := (dnsForwardConfig{Enabled: false}).Validate(); err != nil {
		t.Errorf("disabled should always be valid: %v", err)
	}
	if err := (dnsForwardConfig{Enabled: true, Upstreams: []dnsUpstream{{Address: "2606:4700:4700::1111", Name: "cloudflare-dns.com"}}}).Validate(); err != nil {
		t.Errorf("ipv6 upstream should be valid: %v", err)
	}
}
