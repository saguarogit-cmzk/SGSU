package portmap

import (
	"strings"
	"testing"
)

func fixture() []Port {
	return []Port{
		{Kernel: "enp11s0f0", MAC: "7C:5A:1C:73:03:42"},
		{Kernel: "enp11s0f1", MAC: "7c:5a:1c:73:03:43"},
		{Kernel: "enp2s0", MAC: "7c:5a:1c:73:03:46"},
		{Kernel: "enp3s0", MAC: "7c:5a:1c:73:03:47"},
	}
}

func byName(as []Assignment) map[string]Assignment {
	m := map[string]Assignment{}
	for _, a := range as {
		m[a.Name] = a
	}
	return m
}

func TestAutoAssignsRolesAndSpares(t *testing.T) {
	as, err := Auto(fixture(), "enp11s0f1", "enp11s0f0")
	if err != nil {
		t.Fatal(err)
	}
	m := byName(as)
	if m["lan0"].Kernel != "enp11s0f1" || m["wan1"].Kernel != "enp11s0f0" {
		t.Fatalf("roles wrong: %+v", as)
	}
	// Spares are numbered in kernel-name order, so the map is reproducible.
	if m["net1"].Kernel != "enp2s0" || m["net2"].Kernel != "enp3s0" {
		t.Fatalf("spares wrong: %+v", as)
	}
	// MACs are normalized so a mixed-case /sys read still matches netplan.
	if m["wan1"].MAC != "7c:5a:1c:73:03:42" {
		t.Errorf("MAC not normalized: %q", m["wan1"].MAC)
	}
}

func TestAutoSkipsPortsWithoutUsableMAC(t *testing.T) {
	ports := append(fixture(), Port{Kernel: "bond0", MAC: "00:00:00:00:00:00"}, Port{Kernel: "tun0"})
	as, err := Auto(ports, "enp11s0f1", "enp11s0f0")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range as {
		if a.Kernel == "bond0" || a.Kernel == "tun0" {
			t.Fatalf("unmatched port must not be renamed: %+v", a)
		}
	}
	if len(as) != 4 {
		t.Fatalf("expected the four real ports, got %+v", as)
	}
}

func TestAutoRejectsUnusableRolePort(t *testing.T) {
	// Naming a role port we cannot match would silently leave it unrenamed and
	// every generated config pointing at a name that never appears.
	ports := []Port{{Kernel: "enp1s0", MAC: "7c:5a:1c:73:03:42"}, {Kernel: "enp2s0"}}
	if _, err := Auto(ports, "enp2s0", "enp1s0"); err == nil {
		t.Fatal("LAN port without a MAC must be refused")
	}
	if _, err := Auto(fixture(), "enp2s0", "enp2s0"); err == nil {
		t.Fatal("LAN == WAN must be refused")
	}
}

func TestValidateRejectsCollisions(t *testing.T) {
	bad := [][]Assignment{
		{{MAC: "7c:5a:1c:73:03:42", Name: "wan1"}, {MAC: "7c:5a:1c:73:03:43", Name: "wan1"}},
		{{MAC: "7c:5a:1c:73:03:42", Name: "wan1"}, {MAC: "7c:5a:1c:73:03:42", Name: "lan0"}},
		{{MAC: "7c:5a:1c:73:03:42", Name: "WAN1"}},
		{{MAC: "7c:5a:1c:73:03:42", Name: "lan0.20"}},
		{{MAC: "nonsense", Name: "wan1"}},
		// wan1 is another mapped port's current kernel name: at rename time the
		// two would race for it.
		{{MAC: "7c:5a:1c:73:03:42", Name: "wan1"}, {MAC: "7c:5a:1c:73:03:43", Name: "lan0", Kernel: "wan1"}},
	}
	for i, as := range bad {
		if err := Validate(as); err == nil {
			t.Errorf("case %d should be invalid: %+v", i, as)
		}
	}
	if err := Validate(nil); err == nil {
		t.Error("empty map should be invalid")
	}
}

func TestGenerateNetplan(t *testing.T) {
	as, err := Auto(fixture(), "enp11s0f1", "enp11s0f0")
	if err != nil {
		t.Fatal(err)
	}
	out, err := GenerateNetplan(as)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"    wan1:", "macaddress: 7c:5a:1c:73:03:42", "set-name: wan1", "    lan0:", "    net1:"} {
		if !strings.Contains(out, want) {
			t.Errorf("netplan missing %q:\n%s", want, out)
		}
	}
	// The saguaro-net charset guard rejects quotes and anything exotic; keep the
	// generated file inside what the adapter will accept.
	const allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ._:/#(),-\n"
	for _, r := range out {
		if !strings.ContainsRune(allowed, r) {
			t.Fatalf("generated netplan contains %q, which the root adapter refuses:\n%s", r, out)
		}
	}
	// Addressing belongs to the WAN/LAN files, keyed on these names.
	if strings.Contains(out, "dhcp4") || strings.Contains(out, "addresses:") {
		t.Errorf("port map must carry no addressing:\n%s", out)
	}
}

func TestRenamePlanSkipsPortsAlreadyNamed(t *testing.T) {
	as := []Assignment{
		{MAC: "7c:5a:1c:73:03:42", Name: "wan1", Kernel: "enp11s0f0"},
		{MAC: "7c:5a:1c:73:03:43", Name: "lan0", Kernel: "lan0"},
	}
	plan := RenamePlan(as)
	if len(plan) != 1 || plan[0].Name != "wan1" {
		t.Fatalf("only unrenamed ports belong in the plan: %+v", plan)
	}
}
