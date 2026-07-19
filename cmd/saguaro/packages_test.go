package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestPackageInventory(t *testing.T) {
	srv, c, a := newTestServer(t)
	a.runPkg = func(_ context.Context, args ...string) ([]byte, error) {
		switch args[0] {
		case "list":
			return []byte("unbound unbound 1.19.2-1 1.19.2-2 yes\npdns pdns-server 4.9.0-1 4.9.0-1 no\n"), nil
		case "unattended-status":
			return []byte("installed yes\nenabled no\n"), nil
		}
		return nil, nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	resp, _ := c.Get(srv.URL + "/api/packages")
	var view struct {
		Packages []struct {
			Key, Name, Installed, Candidate string
			Upgradable                      bool
		}
		Upgradable int
		Unattended struct{ Installed, Enabled bool }
	}
	json.NewDecoder(resp.Body).Decode(&view)
	resp.Body.Close()
	if len(view.Packages) != 2 || view.Upgradable != 1 {
		t.Fatalf("inventory wrong: %+v", view)
	}
	if view.Packages[0].Name != "Unbound (resolver)" || !view.Packages[0].Upgradable {
		t.Errorf("unbound row wrong: %+v", view.Packages[0])
	}
	if !view.Unattended.Installed || view.Unattended.Enabled {
		t.Errorf("unattended wrong: %+v", view.Unattended)
	}
}

func TestPackageUpgrade(t *testing.T) {
	srv, c, a := newTestServer(t)
	var got []string
	a.runPkg = func(_ context.Context, args ...string) ([]byte, error) {
		got = append(got, strings.Join(args, " "))
		return []byte("1.19.2-2\n"), nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	// Unknown package key is refused before touching the adapter.
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/packages/upgrade/bogus", `{}`); r.StatusCode != http.StatusNotFound {
		t.Fatalf("bogus key: got %d, want 404", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/packages/upgrade/unbound", `{}`); r.StatusCode != http.StatusOK {
		t.Fatalf("upgrade unbound: got %d", r.StatusCode)
	}
	if len(got) != 1 || got[0] != "upgrade unbound" {
		t.Fatalf("adapter calls wrong: %v", got)
	}
}

func TestPackageUnattendedToggle(t *testing.T) {
	srv, c, a := newTestServer(t)
	var got []string
	a.runPkg = func(_ context.Context, args ...string) ([]byte, error) {
		got = append(got, args[0])
		return []byte("ok"), nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/packages/unattended", `{"enabled":true}`); r.StatusCode != http.StatusOK {
		t.Fatalf("enable: got %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/packages/unattended", `{"enabled":false}`); r.StatusCode != http.StatusOK {
		t.Fatalf("disable: got %d", r.StatusCode)
	}
	if strings.Join(got, ",") != "unattended-enable,unattended-disable" {
		t.Fatalf("adapter sequence wrong: %v", got)
	}
}

func TestPackagesRequireAdmin(t *testing.T) {
	srv, admin, a := newTestServer(t)
	a.runPkg = func(_ context.Context, _ ...string) ([]byte, error) { return []byte("ok"), nil }
	if r := doLogin(t, srv, admin, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("admin login: %d", r.StatusCode)
	}
	createUser(t, srv, admin, a, "netpkg", roleNetworkOperator)
	netop := loginAs(t, srv, "netpkg", operatorPassword)
	// A network-operator may read the inventory (service:check) ...
	if r := reqJSON(t, srv, netop, http.MethodGet, "/api/packages", ""); r.StatusCode != http.StatusOK {
		t.Fatalf("netop list: got %d, want 200", r.StatusCode)
	}
	// ... but may NOT upgrade (packages:write is admin-only).
	if r := reqJSON(t, srv, netop, http.MethodPost, "/api/packages/upgrade/unbound", `{}`); r.StatusCode != http.StatusForbidden {
		t.Fatalf("netop upgrade: got %d, want 403", r.StatusCode)
	}
}
