package routes

import (
	"strings"
	"testing"
)

func TestRouteValidate(t *testing.T) {
	ok := []Route{
		{Destination: "10.20.0.0/16", Gateway: "192.168.50.254"},
		{Destination: "default", Gateway: "192.168.50.1", Interface: "enp1s0", Metric: 100},
	}
	for _, r := range ok {
		if err := r.Validate(); err != nil {
			t.Errorf("expected valid, got %v for %+v", err, r)
		}
	}
	bad := []Route{
		{Destination: "10.20.0.0", Gateway: "192.168.50.254"}, // not CIDR
		{Destination: "10.20.0.0/16", Gateway: "not-an-ip"},   // bad gw
		{Destination: "10.20.0.0/16", Gateway: "2001:db8::1"}, // IPv6 gw
		{Destination: "10.20.0.0/16", Gateway: "1.1.1.1", Interface: "bad iface"},
	}
	for _, r := range bad {
		if err := r.Validate(); err == nil {
			t.Errorf("expected invalid: %+v", r)
		}
	}
}

func TestGenerateSpec(t *testing.T) {
	c := Config{Routes: []Route{
		{Destination: "10.20.0.0/16", Gateway: "192.168.50.254"},
		{Destination: "default", Gateway: "192.168.50.1", Interface: "enp1s0", Metric: 200},
	}}
	spec, err := c.GenerateSpec()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(spec, "10.20.0.0/16 192.168.50.254 - 0") {
		t.Errorf("missing first route line: %q", spec)
	}
	if !strings.Contains(spec, "default 192.168.50.1 enp1s0 200") {
		t.Errorf("missing second route line: %q", spec)
	}
}

func TestConfigDuplicate(t *testing.T) {
	c := Config{Routes: []Route{
		{Destination: "10.0.0.0/8", Gateway: "192.168.1.1"},
		{Destination: "10.0.0.0/8", Gateway: "192.168.1.2"},
	}}
	if err := c.Validate(); err == nil {
		t.Fatal("expected duplicate destination error")
	}
}

func TestIPRouteArgs(t *testing.T) {
	got := Route{Destination: "10.20.0.0/16", Gateway: "1.2.3.4", Interface: "enp1s0", Metric: 50}.IPRouteArgs()
	want := "route replace 10.20.0.0/16 via 1.2.3.4 dev enp1s0 metric 50"
	if strings.Join(got, " ") != want {
		t.Errorf("got %q want %q", strings.Join(got, " "), want)
	}
	// no iface, no metric -> minimal args
	got = Route{Destination: "default", Gateway: "1.2.3.4"}.IPRouteArgs()
	if strings.Join(got, " ") != "route replace default via 1.2.3.4" {
		t.Errorf("minimal args wrong: %q", strings.Join(got, " "))
	}
}
