package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestToolRun(t *testing.T) {
	srv, c, a := newTestServer(t)
	var calls []string
	a.runTools = func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		return []byte("tool output"), nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	// ping bound to an interface
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/tools", `{"tool":"ping","host":"1.1.1.1","iface":"enp2s0"}`); r.StatusCode != http.StatusOK {
		t.Fatalf("ping: got %d", r.StatusCode)
	}
	// dns uses the server arg, not the interface
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/tools", `{"tool":"dns","host":"example.com","server":"192.168.50.1","iface":"enp2s0"}`); r.StatusCode != http.StatusOK {
		t.Fatalf("dns: got %d", r.StatusCode)
	}
	if len(calls) != 2 || calls[0] != "ping 1.1.1.1 enp2s0" || calls[1] != "dns example.com 192.168.50.1" {
		t.Fatalf("adapter calls wrong: %v", calls)
	}
	// unknown tool and empty host are rejected before the adapter runs
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/tools", `{"tool":"nmap","host":"x"}`); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad tool: got %d, want 400", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/tools", `{"tool":"ping","host":""}`); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty host: got %d, want 400", r.StatusCode)
	}
}

func TestToolRequiresRole(t *testing.T) {
	srv, admin, a := newTestServer(t)
	if r := doLogin(t, srv, admin, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("admin login: %d", r.StatusCode)
	}
	createUser(t, srv, admin, a, "auditor1", roleAuditor) // no service:check
	aud := loginAs(t, srv, "auditor1", operatorPassword)
	if r := reqJSON(t, srv, aud, http.MethodPost, "/api/tools", `{"tool":"ping","host":"1.1.1.1"}`); r.StatusCode != http.StatusForbidden {
		t.Fatalf("auditor tools: got %d, want 403", r.StatusCode)
	}
}
