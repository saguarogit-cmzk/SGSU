package main

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func hasStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func TestConfigVersioning(t *testing.T) {
	dir := t.TempDir()
	s := &store{path: filepath.Join(dir, "state.json"), data: state{Version: 1, Services: defaultServices()}}
	if err := s.saveLocked(); err != nil { // verDir empty -> no snapshot yet
		t.Fatal(err)
	}
	s.initVersions() // baseline snapshot
	if got := len(s.listVersions()); got != 1 {
		t.Fatalf("baseline: want 1 version, got %d", got)
	}

	// An audit-only change must NOT create a new version.
	s.data.Audit = append(s.data.Audit, auditEvent{Action: "login"})
	if err := s.saveLocked(); err != nil {
		t.Fatal(err)
	}
	if got := len(s.listVersions()); got != 1 {
		t.Fatalf("audit-only change should not snapshot, got %d versions", got)
	}

	// A real config change must create a version labelled with the section.
	s.data.SystemProfile = "gateway"
	if err := s.saveLocked(); err != nil {
		t.Fatal(err)
	}
	vs := s.listVersions()
	if len(vs) != 2 {
		t.Fatalf("config change should snapshot, got %d versions", len(vs))
	}
	changed, _ := vs[0]["changed"].([]string)
	if !hasStr(changed, "Profil sustava") {
		t.Fatalf("newest version should list the changed section, got %v", changed)
	}

	// The restore target (baseline) must round-trip: read it back and confirm the
	// profile is absent there.
	id, _ := vs[1]["id"].(string)
	v, err := s.readVersion(id)
	if err != nil {
		t.Fatalf("readVersion: %v", err)
	}
	var restored state
	if err := json.Unmarshal(v.State, &restored); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	if restored.SystemProfile != "" {
		t.Fatalf("baseline should predate the profile change, got %q", restored.SystemProfile)
	}
}

func TestChangedSections(t *testing.T) {
	prev := map[string]string{"a": "1", "b": "2"}
	cur := map[string]string{"a": "1", "b": "9", "c": "3"} // b modified, c added
	got := changedSections(prev, cur)
	if !hasStr(got, "b") || !hasStr(got, "c") || hasStr(got, "a") {
		t.Fatalf("changedSections = %v; want b,c not a", got)
	}
	// a removed section is also a change
	if got := changedSections(map[string]string{"x": "1"}, map[string]string{}); !hasStr(got, "x") {
		t.Fatalf("removal not detected: %v", got)
	}
}
