package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// A netplan apply must leave a confirm window behind — the adapter arms a 120 s
// auto-rollback, so the handler has to tell the GUI, and confirm/rollback must
// reach the matching adapter subcommand.
func TestNetplanConfirmRollback(t *testing.T) {
	srv, c, a := newTestServer(t)
	var calls []string
	a.runNet = func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		if len(args) == 1 && args[0] == "pending" {
			return []byte("wan yes\nvlan no\n"), nil
		}
		return []byte("ok"), nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}

	// Issued by hand (not via reqJSON) because the response body carries the
	// confirm window and reqJSON closes it.
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/wan/apply",
		strings.NewReader(`{"wans":[{"interface":"enp1s0","mode":"dhcp","metric":100}]}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrfCookie(t, srv, c))
	r, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != http.StatusOK {
		t.Fatalf("wan apply: got %d", r.StatusCode)
	}
	var applied struct {
		ConfirmWindowSeconds int `json:"confirmWindowSeconds"`
	}
	json.NewDecoder(r.Body).Decode(&applied)
	r.Body.Close()
	if applied.ConfirmWindowSeconds != netplanConfirmWindow {
		t.Fatalf("apply must report the confirm window, got %d", applied.ConfirmWindowSeconds)
	}

	// The pending state survives a page reload, so the GUI can re-render the bar.
	resp, err := c.Get(srv.URL + "/api/net/pending")
	if err != nil {
		t.Fatal(err)
	}
	var pending map[string]bool
	json.NewDecoder(resp.Body).Decode(&pending)
	resp.Body.Close()
	if !pending["wan"] || pending["vlan"] {
		t.Fatalf("pending state wrong: %+v", pending)
	}

	if r := reqJSON(t, srv, c, http.MethodPost, "/api/wan/confirm", `{}`); r.StatusCode != http.StatusOK {
		t.Fatalf("wan confirm: got %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/firewall/zones/vlans-rollback", `{}`); r.StatusCode != http.StatusOK {
		t.Fatalf("vlan rollback: got %d", r.StatusCode)
	}
	want := []string{"wan-apply", "pending", "wan-confirm", "vlan-rollback"}
	if len(calls) != len(want) {
		t.Fatalf("adapter calls wrong: %v", calls)
	}
	for i, w := range want {
		if calls[i] != w {
			t.Fatalf("adapter call %d = %q, want %q (all: %v)", i, calls[i], w, calls)
		}
	}
}

// A failing adapter must surface as an error, not a silent success that leaves
// the operator believing the window was closed.
func TestNetplanConfirmAdapterFailure(t *testing.T) {
	srv, c, a := newTestServer(t)
	a.runNet = func(context.Context, ...string) ([]byte, error) {
		return []byte("boom"), context.DeadlineExceeded
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/wan/confirm", `{}`); r.StatusCode != http.StatusBadGateway {
		t.Fatalf("confirm failure: got %d, want 502", r.StatusCode)
	}
}
