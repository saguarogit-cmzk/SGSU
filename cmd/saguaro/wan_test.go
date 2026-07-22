package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"saguaro.local/network-manager/internal/adapters/wancfg"
)

func TestWANConfigApply(t *testing.T) {
	srv, c, a := newTestServer(t)
	var calls []string
	a.runNet = func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		return []byte("ok"), nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	// two WAN interfaces: DHCP primary + static secondary
	body := `{"wans":[
		{"interface":"enp1s0","mode":"dhcp","metric":100},
		{"interface":"enp2s0","mode":"static","address":"203.0.113.5/24","gateway":"203.0.113.1","dns":["1.1.1.1"],"metric":200}
	]}`
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/wan/apply", body); r.StatusCode != http.StatusOK {
		t.Fatalf("wan apply: got %d", r.StatusCode)
	}
	if len(calls) != 1 || calls[0] != "wan-apply" {
		t.Fatalf("adapter call wrong: %v", calls)
	}
	yaml, err := os.ReadFile(filepath.Join(filepath.Dir(a.store.path), stagedWANNetplanName))
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"enp1s0:", "route-metric: 100", "enp2s0:", "203.0.113.5/24", "via: 203.0.113.1", "metric: 200"} {
		if !strings.Contains(string(yaml), w) {
			t.Fatalf("staged netplan missing %q:\n%s", w, yaml)
		}
	}
	if wans := a.getWANs(); len(wans) != 2 {
		t.Fatalf("WANs not persisted: %+v", wans)
	}
	// invalid static address rejected before the adapter runs
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/wan/apply",
		`{"wans":[{"interface":"enp1s0","mode":"static","address":"203.0.113.5","gateway":"203.0.113.1"}]}`); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad address: got %d, want 400", r.StatusCode)
	}
}

func TestWANLegacyMigration(t *testing.T) {
	_, _, a := newTestServer(t)
	// simulate a pre-list install with a single WANConfig
	legacy := wancfg.WAN{Interface: "enp1s0", Mode: "dhcp"}
	a.store.mu.Lock()
	a.store.data.WANConfig = &legacy
	a.store.mu.Unlock()
	wans := a.getWANs()
	if len(wans) != 1 || wans[0].Interface != "enp1s0" {
		t.Fatalf("legacy WAN not migrated: %+v", wans)
	}
	if a.store.data.WANConfig != nil {
		t.Fatal("legacy field not cleared after migration")
	}
}

func TestWANConfigRequiresRole(t *testing.T) {
	srv, admin, a := newTestServer(t)
	a.runNet = func(context.Context, ...string) ([]byte, error) { return nil, nil }
	if r := doLogin(t, srv, admin, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("admin login: %d", r.StatusCode)
	}
	createUser(t, srv, admin, a, "auditor1", roleAuditor)
	aud := loginAs(t, srv, "auditor1", operatorPassword)
	if r := reqJSON(t, srv, aud, http.MethodGet, "/api/wan", ""); r.StatusCode != http.StatusOK {
		t.Fatalf("auditor get: got %d, want 200", r.StatusCode)
	}
	if r := reqJSON(t, srv, aud, http.MethodPost, "/api/wan/apply", `{"wans":[{"interface":"enp1s0","mode":"dhcp"}]}`); r.StatusCode != http.StatusForbidden {
		t.Fatalf("auditor apply: got %d, want 403", r.StatusCode)
	}
}

func TestWANGetSeedsFromLiveRoutes(t *testing.T) {
	srv, c, a := newTestServer(t)
	// The store is empty, but the box already routes through two uplinks. The
	// form must open on both: applying it rewrites the whole netplan, so an
	// uplink missing from the list is an uplink about to be switched off.
	a.readDefaultRoutes = func(context.Context) ([]defaultRoute, error) {
		return []defaultRoute{
			{Dev: "net4", Gateway: "192.168.205.1", Protocol: "dhcp", Metric: 200},
			{Dev: "wan1", Gateway: "192.168.50.1", Protocol: "dhcp", Metric: 100},
			{Dev: "net9", Gateway: "10.9.9.1", Protocol: "static", Metric: 300},
		}, nil
	}
	a.readInterfaces = func(context.Context) ([]nicInfo, error) {
		return []nicInfo{{Name: "net9", Addresses: []string{"10.9.9.2/24"}}}, nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	resp, err := c.Get(srv.URL + "/api/wan")
	if err != nil {
		t.Fatal(err)
	}
	var out struct{ WANs []wancfg.WAN }
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if len(out.WANs) != 3 {
		t.Fatalf("expected all three uplinks, got %+v", out.WANs)
	}
	// Ordered by metric, so the primary uplink reads first.
	if out.WANs[0].Interface != "wan1" || out.WANs[0].Mode != "dhcp" || out.WANs[0].Metric != 100 {
		t.Errorf("primary uplink wrong: %+v", out.WANs[0])
	}
	// A route the kernel did not learn from DHCP is static, and keeps its address.
	if out.WANs[2].Mode != "static" || out.WANs[2].Address != "10.9.9.2/24" || out.WANs[2].Gateway != "10.9.9.1" {
		t.Errorf("static uplink wrong: %+v", out.WANs[2])
	}
}

func TestWANGetPrefersStoredConfig(t *testing.T) {
	srv, c, a := newTestServer(t)
	// Detection must never override what the operator saved: it only fills a
	// store that has nothing at all.
	if err := a.setWANs([]wancfg.WAN{{Interface: "wan1", Mode: "dhcp", Metric: 100}}); err != nil {
		t.Fatal(err)
	}
	a.readDefaultRoutes = func(context.Context) ([]defaultRoute, error) {
		return []defaultRoute{{Dev: "net4", Gateway: "192.168.205.1", Protocol: "dhcp", Metric: 200}}, nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	resp, _ := c.Get(srv.URL + "/api/wan")
	var out struct{ WANs []wancfg.WAN }
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if len(out.WANs) != 1 || out.WANs[0].Interface != "wan1" {
		t.Fatalf("stored config must win: %+v", out.WANs)
	}
}
