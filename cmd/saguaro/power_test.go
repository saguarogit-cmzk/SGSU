package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestSystemPower(t *testing.T) {
	srv, c, a := newTestServer(t)
	var actions []string
	a.runPower = func(_ context.Context, action string) ([]byte, error) {
		actions = append(actions, action)
		return []byte("ok"), nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	// Unknown action is rejected before touching the adapter.
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/system/power/halt", `{}`); r.StatusCode != http.StatusNotFound {
		t.Fatalf("bad action: got %d, want 404", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/system/power/reboot", `{}`); r.StatusCode != http.StatusOK {
		t.Fatalf("reboot: got %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/system/power/poweroff", `{}`); r.StatusCode != http.StatusOK {
		t.Fatalf("poweroff: got %d", r.StatusCode)
	}
	if strings.Join(actions, ",") != "reboot,poweroff" {
		t.Fatalf("adapter calls wrong: %v", actions)
	}
}

func TestSystemPowerRequiresAdmin(t *testing.T) {
	srv, admin, a := newTestServer(t)
	a.runPower = func(_ context.Context, _ string) ([]byte, error) { return []byte("ok"), nil }
	if r := doLogin(t, srv, admin, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("admin login: %d", r.StatusCode)
	}
	createUser(t, srv, admin, a, "netpow", roleNetworkOperator)
	netop := loginAs(t, srv, "netpow", operatorPassword)
	if r := reqJSON(t, srv, netop, http.MethodPost, "/api/system/power/reboot", `{}`); r.StatusCode != http.StatusForbidden {
		t.Fatalf("network-operator reboot: got %d, want 403", r.StatusCode)
	}
}
