package dnszones

import (
	"strings"
	"testing"

	"saguaro.local/network-manager/internal/adapters/nftgen"
)

func TestGenerateAccessConf(t *testing.T) {
	zones := []nftgen.Zone{
		{Name: "lan", Kind: "lan", Network: "10.10.10.0/24"},
		{Name: "dmz", Kind: "dmz", Network: "10.20.0.0/24", VLANID: 20, Address: "10.20.0.1/24"},
		{Name: "wan", Kind: "wan"},                            // WAN never granted
		{Name: "dup", Kind: "guest", Network: "10.20.0.0/24"}, // duplicate network deduped
		{Name: "bad", Kind: "guest", Network: "not-a-cidr"},   // invalid ignored
	}
	out := GenerateAccessConf(zones, nil, "")
	if !strings.Contains(out, "server:\n") {
		t.Fatalf("missing server clause:\n%s", out)
	}
	for _, w := range []string{
		"  access-control: 10.10.10.0/24 allow\n",
		"  access-control: 10.20.0.0/24 allow\n",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q:\n%s", w, out)
		}
	}
	if strings.Count(out, "access-control:") != 2 {
		t.Errorf("expected 2 access-control lines (deduped), got:\n%s", out)
	}
}

func TestGenerateAccessConfEmpty(t *testing.T) {
	out := GenerateAccessConf([]nftgen.Zone{{Name: "wan", Kind: "wan"}}, nil, "")
	if strings.Contains(out, "access-control:") {
		t.Errorf("no internal zones should yield no access-control lines:\n%s", out)
	}
	if !strings.Contains(out, "server:") {
		t.Errorf("expected a valid server drop-in:\n%s", out)
	}
}

// TestSplitHorizon checks that a split-horizon record renders both the external
// (global) answer and the internal view answer, and assigns the LAN network to
// the internal view even with no firewall zones defined.
func TestSplitHorizon(t *testing.T) {
	split := []SplitRecord{
		{Name: "mail.company.com", Type: "A", Internal: "10.10.10.10", External: "203.0.113.10"},
		{Name: "bad name", Type: "A", Internal: "10.0.0.1"},      // invalid host ignored
		{Name: "v6.company.com", Type: "A", Internal: "fe80::1"}, // family mismatch ignored
	}
	out := GenerateAccessConf(nil, split, "192.168.10.0/24")
	for _, w := range []string{
		`  local-data: "mail.company.com. A 203.0.113.10"`, // external, global
		`  access-control-view: 192.168.10.0/24 saguaro-internal`,
		"view:\n",
		`  name: "saguaro-internal"`,
		"  view-first: yes\n",
		`  local-data: "mail.company.com. A 10.10.10.10"`, // internal, in view
	} {
		if !strings.Contains(out, w) {
			t.Errorf("split-horizon output missing %q:\n%s", w, out)
		}
	}
	if strings.Contains(out, "bad name") || strings.Contains(out, "fe80::1") {
		t.Errorf("invalid split records must be dropped:\n%s", out)
	}
	// A record with no external address appears only in the internal view (no
	// global local-data), so external clients resolve it normally.
	noExt := GenerateAccessConf(nil, []SplitRecord{{Name: "x.company.com", Type: "A", Internal: "10.1.1.1"}}, "192.168.10.0/24")
	if strings.Count(noExt, "A 10.1.1.1") != 1 {
		t.Errorf("record without external should appear only in the internal view:\n%s", noExt)
	}
}
