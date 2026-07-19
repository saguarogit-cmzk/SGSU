package wancfg

import (
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	ok := []WAN{
		{Interface: "enp1s0", Mode: "dhcp"},
		{Interface: "enp1s0", Mode: "static", Address: "203.0.113.5/24", Gateway: "203.0.113.1", DNS: []string{"1.1.1.1"}},
	}
	for _, w := range ok {
		if err := w.Validate(); err != nil {
			t.Errorf("expected valid: %+v -> %v", w, err)
		}
	}
	bad := []WAN{
		{Interface: "bad iface", Mode: "dhcp"},
		{Interface: "enp1s0", Mode: "other"},
		{Interface: "enp1s0", Mode: "static", Address: "203.0.113.5", Gateway: "203.0.113.1"}, // not CIDR
		{Interface: "enp1s0", Mode: "static", Address: "203.0.113.5/24", Gateway: "nope"},
		{Interface: "enp1s0", Mode: "static", Address: "203.0.113.5/24", Gateway: "203.0.113.1", DNS: []string{"x"}},
	}
	for i, w := range bad {
		if err := w.Validate(); err == nil {
			t.Errorf("case %d expected invalid: %+v", i, w)
		}
	}
}

func TestGenerateNetplan(t *testing.T) {
	dhcp, err := WAN{Interface: "enp1s0", Mode: "dhcp"}.GenerateNetplan()
	if err != nil || !strings.Contains(dhcp, "enp1s0:") || !strings.Contains(dhcp, "dhcp4: true") {
		t.Fatalf("dhcp netplan wrong: %v\n%s", err, dhcp)
	}
	st, err := WAN{Interface: "enp1s0", Mode: "static", Address: "203.0.113.5/24",
		Gateway: "203.0.113.1", DNS: []string{"1.1.1.1", "8.8.8.8"}}.GenerateNetplan()
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"dhcp4: false", "- 203.0.113.5/24", "to: default", "via: 203.0.113.1", "- 1.1.1.1", "- 8.8.8.8"} {
		if !strings.Contains(st, w) {
			t.Errorf("static netplan missing %q:\n%s", w, st)
		}
	}
}

func TestNetplanAliases(t *testing.T) {
	w := WAN{Interface: "enp1s0", Mode: "static", Address: "203.0.113.5/24", Gateway: "203.0.113.1",
		Aliases: []string{"203.0.113.6/24", "203.0.113.7/24"}}
	out, err := w.GenerateNetplan()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"- 203.0.113.5/24", "- 203.0.113.6/24", "- 203.0.113.7/24"} {
		if !strings.Contains(out, a) {
			t.Errorf("alias %q missing:\n%s", a, out)
		}
	}
	bad := WAN{Interface: "enp1s0", Mode: "static", Address: "203.0.113.5/24", Gateway: "203.0.113.1", Aliases: []string{"nope"}}
	if err := bad.Validate(); err == nil {
		t.Error("expected invalid alias error")
	}
}
