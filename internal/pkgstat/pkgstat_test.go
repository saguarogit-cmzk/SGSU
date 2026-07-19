package pkgstat

import "testing"

func TestParseList(t *testing.T) {
	out := []byte(`unbound unbound 1.19.2-1 1.19.2-2 yes
pdns pdns-server 4.9.0-1 4.9.0-1 no
squid squid - - na
nginx nginx 1.24.0-1 1.24.0-2 yes
garbage line here
`)
	pkgs := ParseList(out)
	if len(pkgs) != 4 {
		t.Fatalf("want 4 packages, got %d: %+v", len(pkgs), pkgs)
	}
	if pkgs[0].Key != "unbound" || pkgs[0].Installed != "1.19.2-1" || !pkgs[0].Upgradable {
		t.Errorf("unbound parsed wrong: %+v", pkgs[0])
	}
	if pkgs[1].Upgradable {
		t.Errorf("pdns should not be upgradable: %+v", pkgs[1])
	}
	if pkgs[2].Installed != "" || pkgs[2].Candidate != "" || pkgs[2].Upgradable {
		t.Errorf("not-installed squid parsed wrong: %+v", pkgs[2])
	}
	if n := UpgradableCount(pkgs); n != 2 {
		t.Errorf("upgradable count = %d, want 2", n)
	}
}

func TestParseUnattended(t *testing.T) {
	off := ParseUnattended([]byte("installed no\nenabled no\n"))
	if off.Installed || off.Enabled {
		t.Errorf("expected all off: %+v", off)
	}
	on := ParseUnattended([]byte("installed yes\nenabled yes\n"))
	if !on.Installed || !on.Enabled {
		t.Errorf("expected all on: %+v", on)
	}
	half := ParseUnattended([]byte("installed yes\nenabled no\n"))
	if !half.Installed || half.Enabled {
		t.Errorf("expected installed-not-enabled: %+v", half)
	}
}
