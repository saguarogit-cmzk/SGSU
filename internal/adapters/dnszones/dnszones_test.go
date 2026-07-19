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
	out := GenerateAccessConf(zones)
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
	out := GenerateAccessConf([]nftgen.Zone{{Name: "wan", Kind: "wan"}})
	if strings.Contains(out, "access-control:") {
		t.Errorf("no internal zones should yield no access-control lines:\n%s", out)
	}
	if !strings.Contains(out, "server:") {
		t.Errorf("expected a valid server drop-in:\n%s", out)
	}
}
