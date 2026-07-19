package vlangen

import (
	"strings"
	"testing"

	"saguaro.local/network-manager/internal/adapters/nftgen"
)

func TestGenerate(t *testing.T) {
	zones := []nftgen.Zone{
		{Name: "lan", Kind: "lan", Interface: "enp2", Network: "10.10.10.0/24"}, // untagged, ignored
		{Name: "dmz", Kind: "dmz", Interface: "enp2", Network: "10.20.0.0/24", VLANID: 20, Address: "10.20.0.1/24"},
		{Name: "guest", Kind: "guest", Interface: "enp2", Network: "10.30.0.0/24", VLANID: 30, Address: "10.30.0.1/24"},
	}
	out, err := Generate(zones)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{
		"  vlans:\n",
		"    enp2.20:\n", "      id: 20\n", "      link: enp2\n", "        - 10.20.0.1/24\n",
		"    enp2.30:\n", "      id: 30\n", "        - 10.30.0.1/24\n",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q:\n%s", w, out)
		}
	}
	// The untagged LAN must not appear as a VLAN.
	if strings.Contains(out, "enp2:\n      id:") {
		t.Errorf("untagged interface rendered as VLAN:\n%s", out)
	}
}

func TestGenerateEmpty(t *testing.T) {
	out, err := Generate([]nftgen.Zone{{Name: "lan", Kind: "lan", Interface: "enp2", Network: "10.0.0.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "vlans:") {
		t.Errorf("no VLAN zones should yield an empty netplan:\n%s", out)
	}
	if !strings.Contains(out, "version: 2") {
		t.Errorf("expected a valid empty netplan:\n%s", out)
	}
}

func TestGenerateBadAddress(t *testing.T) {
	_, err := Generate([]nftgen.Zone{{Name: "dmz", Kind: "dmz", Interface: "enp2", VLANID: 20, Address: "nope"}})
	if err == nil {
		t.Fatal("expected error for invalid VLAN address")
	}
}
