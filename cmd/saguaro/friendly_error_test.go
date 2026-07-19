package main

import (
	"errors"
	"strings"
	"testing"
)

func TestFriendlyError(t *testing.T) {
	// Transport failures are rewritten into operator-readable text; the raw
	// "connection refused"/"dial tcp" detail must not survive.
	transport := []string{
		`Post "http://127.0.0.1:8000/": dial tcp 127.0.0.1:8000: connect: connection refused`,
		`Get "http://[::1]:8081": read tcp: i/o timeout`,
		`dial tcp: lookup pdns.local: no such host`,
		`dial tcp 10.0.0.1:53: connect: network is unreachable`,
	}
	for _, m := range transport {
		got := friendlyError(errors.New(m), "Kea DHCP")
		if strings.Contains(got, "connection refused") || strings.Contains(got, "dial tcp") ||
			strings.Contains(got, "i/o timeout") || strings.Contains(got, "no such host") {
			t.Errorf("raw transport detail leaked for %q -> %q", m, got)
		}
		if !strings.HasPrefix(got, "Kea DHCP") {
			t.Errorf("friendly message missing service name for %q -> %q", m, got)
		}
	}
	// Non-transport errors (validation, adapter stderr) pass through unchanged so
	// useful detail is preserved.
	passthrough := "subnet 192.168.10.0/24 overlaps an existing subnet"
	if got := friendlyError(errors.New(passthrough), "Kea DHCP"); got != passthrough {
		t.Errorf("non-transport error should pass through: got %q", got)
	}
	if got := friendlyError(nil, "x"); got != "" {
		t.Errorf("nil error should map to empty string, got %q", got)
	}
}
