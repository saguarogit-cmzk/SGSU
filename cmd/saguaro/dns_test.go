package main

import "testing"

func TestReverseZoneForCIDR(t *testing.T) {
	cases := []struct {
		cidr, want string
		ok         bool
	}{
		{"192.168.50.0/24", "50.168.192.in-addr.arpa.", true},
		{"10.0.0.0/8", "10.in-addr.arpa.", true},
		{"172.16.0.0/16", "16.172.in-addr.arpa.", true},
		{"192.168.50.128/25", "", false}, // RFC2317 territory, not supported
		{"192.168.50.0/23", "", false},
		{"not-a-cidr", "", false},
		{"2001:db8::/32", "", false}, // IPv6 unsupported
	}
	for _, c := range cases {
		got, err := reverseZoneForCIDR(c.cidr)
		if c.ok {
			if err != nil || got != c.want {
				t.Errorf("reverseZoneForCIDR(%q) = %q,%v; want %q,nil", c.cidr, got, err, c.want)
			}
		} else if err == nil {
			t.Errorf("reverseZoneForCIDR(%q) = %q,nil; want error", c.cidr, got)
		}
	}
}

func TestPTRNameForIP(t *testing.T) {
	got, err := ptrNameForIP("192.168.50.10")
	if err != nil || got != "10.50.168.192.in-addr.arpa." {
		t.Errorf("ptrNameForIP = %q,%v; want 10.50.168.192.in-addr.arpa.", got, err)
	}
	if _, err := ptrNameForIP("bad"); err == nil {
		t.Error("ptrNameForIP(bad) should error")
	}
	if _, err := ptrNameForIP("2001:db8::1"); err == nil {
		t.Error("ptrNameForIP(ipv6) should error")
	}
}
