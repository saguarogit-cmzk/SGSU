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

func TestDiagCapture(t *testing.T) {
	srv, c, a := newTestServer(t)
	var calls []string
	a.runTools = func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		return []byte("cap output"), nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	// full filter: iface, count, proto, host, port
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/diag/capture", `{"interface":"enp2s0","proto":"tcp","host":"10.0.0.5","port":443,"count":20}`); r.StatusCode != http.StatusOK {
		t.Fatalf("capture: got %d", r.StatusCode)
	}
	// empty host/port become the "-" sentinel; empty proto defaults to any; count clamps to 500
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/diag/capture", `{"interface":"enp2s0","count":9000}`); r.StatusCode != http.StatusOK {
		t.Fatalf("capture defaults: got %d", r.StatusCode)
	}
	if len(calls) != 2 || calls[0] != "capture enp2s0 20 tcp 10.0.0.5 443" || calls[1] != "capture enp2s0 500 any - -" {
		t.Fatalf("adapter calls wrong: %v", calls)
	}
	// invalid inputs are rejected before the adapter runs
	for _, body := range []string{
		`{"interface":"bad iface","count":10}`,
		`{"interface":"enp2s0","proto":"raw"}`,
		`{"interface":"enp2s0","host":"not-an-ip"}`,
		`{"interface":"enp2s0","port":99999}`,
	} {
		if r := reqJSON(t, srv, c, http.MethodPost, "/api/diag/capture", body); r.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 for %s, got %d", body, r.StatusCode)
		}
	}
	if len(calls) != 2 {
		t.Fatalf("adapter ran on invalid input: %v", calls)
	}
}

func TestDiagConntrack(t *testing.T) {
	srv, c, a := newTestServer(t)
	var calls []string
	a.runTools = func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		return []byte("tcp 6 431997 ESTABLISHED src=10.0.0.1 dst=1.1.1.1 sport=1 dport=443\n"), nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	// default limit (200), explicit limit, and over-cap clamp to 2000
	if r := reqJSON(t, srv, c, http.MethodGet, "/api/diag/conntrack", ""); r.StatusCode != http.StatusOK {
		t.Fatalf("conntrack: got %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodGet, "/api/diag/conntrack?limit=50", ""); r.StatusCode != http.StatusOK {
		t.Fatalf("conntrack limit: got %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodGet, "/api/diag/conntrack?limit=99999", ""); r.StatusCode != http.StatusOK {
		t.Fatalf("conntrack clamp: got %d", r.StatusCode)
	}
	if len(calls) != 3 || calls[0] != "conntrack 200" || calls[1] != "conntrack 50" || calls[2] != "conntrack 2000" {
		t.Fatalf("adapter calls wrong: %v", calls)
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
