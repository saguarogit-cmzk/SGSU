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

func TestSelfUpdateStatus(t *testing.T) {
	srv, c, a := newTestServer(t)
	a.runSelfUpdate = func(_ context.Context, args ...string) ([]byte, error) {
		if args[0] == "check" {
			return []byte("gitrepo yes\ncurrent abc1234\nremote def5678\nbehind 3\nprevious 0123456789ab\nbuildable yes\n"), nil
		}
		return nil, nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	resp, _ := c.Get(srv.URL + "/api/selfupdate")
	var st struct {
		Version         string
		GitRepo         bool
		Current, Remote string
		Behind          int
		Previous        string
		Buildable       bool
	}
	json.NewDecoder(resp.Body).Decode(&st)
	resp.Body.Close()
	if !st.GitRepo || st.Current != "abc1234" || st.Behind != 3 || !st.Buildable || st.Version == "" {
		t.Fatalf("self-update status wrong: %+v", st)
	}
	if st.Previous != "0123456789ab" {
		t.Errorf("previous not surfaced: %+v", st)
	}
}

func TestSelfUpdateRefs(t *testing.T) {
	srv, c, a := newTestServer(t)
	a.runSelfUpdate = func(_ context.Context, args ...string) ([]byte, error) {
		if args[0] == "refs" {
			return []byte("branch origin/main\nbranch origin/dev\ntag v0.57.0\ntag v0.56.0\n"), nil
		}
		return nil, nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	resp, _ := c.Get(srv.URL + "/api/selfupdate/refs")
	var out struct{ Branches, Tags []string }
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if len(out.Branches) != 2 || out.Branches[1] != "origin/dev" {
		t.Errorf("branches wrong: %v", out.Branches)
	}
	if len(out.Tags) != 2 || out.Tags[0] != "v0.57.0" {
		t.Errorf("tags wrong: %v", out.Tags)
	}
}

func TestSelfUpdateApplyRef(t *testing.T) {
	srv, admin, a := newTestServer(t)
	var got []string
	a.runSelfUpdate = func(_ context.Context, args ...string) ([]byte, error) {
		got = append(got, strings.Join(args, " "))
		return []byte("updated"), nil
	}
	if r := doLogin(t, srv, admin, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("admin login: %d", r.StatusCode)
	}
	// A specific tag is forwarded to the adapter.
	if r := reqJSON(t, srv, admin, http.MethodPost, "/api/selfupdate/apply", `{"ref":"v0.56.0"}`); r.StatusCode != http.StatusOK {
		t.Fatalf("apply ref: got %d", r.StatusCode)
	}
	// An empty ref means the adapter's default (origin/main): no second arg.
	if r := reqJSON(t, srv, admin, http.MethodPost, "/api/selfupdate/apply", `{}`); r.StatusCode != http.StatusOK {
		t.Fatalf("apply default: got %d", r.StatusCode)
	}
	// A ref failing the charset guard is rejected before the adapter runs.
	if r := reqJSON(t, srv, admin, http.MethodPost, "/api/selfupdate/apply", `{"ref":"; rm -rf /"}`); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad ref: got %d, want 400", r.StatusCode)
	}
	if len(got) != 2 || got[0] != "apply v0.56.0" || got[1] != "apply" {
		t.Fatalf("adapter calls wrong: %v", got)
	}
}

func TestSelfUpdateRollback(t *testing.T) {
	srv, admin, a := newTestServer(t)
	var got []string
	a.runSelfUpdate = func(_ context.Context, args ...string) ([]byte, error) {
		got = append(got, args[0])
		return []byte("rolled back"), nil
	}
	if r := doLogin(t, srv, admin, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("admin login: %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, admin, http.MethodPost, "/api/selfupdate/rollback", `{}`); r.StatusCode != http.StatusOK {
		t.Fatalf("rollback: got %d", r.StatusCode)
	}
	// A network-operator may not roll back (packages:write is admin-only).
	createUser(t, srv, admin, a, "netrb", roleNetworkOperator)
	netop := loginAs(t, srv, "netrb", operatorPassword)
	if r := reqJSON(t, srv, netop, http.MethodPost, "/api/selfupdate/rollback", `{}`); r.StatusCode != http.StatusForbidden {
		t.Fatalf("netop rollback: got %d, want 403", r.StatusCode)
	}
	if len(got) != 1 || got[0] != "rollback" {
		t.Fatalf("adapter calls wrong: %v", got)
	}
}

func TestSelfUpdateApplyRequiresAdmin(t *testing.T) {
	srv, admin, a := newTestServer(t)
	a.runSelfUpdate = func(_ context.Context, _ ...string) ([]byte, error) { return []byte("ok"), nil }
	if r := doLogin(t, srv, admin, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("admin login: %d", r.StatusCode)
	}
	createUser(t, srv, admin, a, "netsu", roleNetworkOperator)
	netop := loginAs(t, srv, "netsu", operatorPassword)
	if r := reqJSON(t, srv, netop, http.MethodPost, "/api/selfupdate/apply", `{}`); r.StatusCode != http.StatusForbidden {
		t.Fatalf("network-operator self-update: got %d, want 403", r.StatusCode)
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
