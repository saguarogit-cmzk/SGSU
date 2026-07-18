package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoutesPutApply(t *testing.T) {
	srv, c, a := newTestServer(t)
	var calls []string
	a.runRoute = func(_ context.Context, action string) ([]byte, error) {
		calls = append(calls, action)
		return []byte("ok"), nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	body := `{"routes":[{"destination":"10.20.0.0/16","gateway":"192.168.50.254","interface":"enp1s0","metric":100}]}`
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/routes", body); r.StatusCode != http.StatusOK {
		t.Fatalf("put routes: got %d", r.StatusCode)
	}
	if len(calls) != 1 || calls[0] != "apply" {
		t.Fatalf("adapter calls wrong: %v", calls)
	}
	// staged spec written to the state dir
	staged := filepath.Join(filepath.Dir(a.store.path), stagedRoutesName)
	spec, err := os.ReadFile(staged)
	if err != nil {
		t.Fatalf("staged spec: %v", err)
	}
	if !strings.Contains(string(spec), "10.20.0.0/16 192.168.50.254 enp1s0 100") {
		t.Fatalf("staged spec content wrong: %q", spec)
	}
	// persisted and returned by GET
	got := reqJSON(t, srv, c, http.MethodGet, "/api/routes", "")
	if got.StatusCode != http.StatusOK {
		t.Fatalf("get routes: %d", got.StatusCode)
	}
	if a.getRoutes().Routes[0].Destination != "10.20.0.0/16" {
		t.Fatalf("route not persisted: %+v", a.getRoutes())
	}
}

func TestRoutesPutInvalid(t *testing.T) {
	srv, c, a := newTestServer(t)
	a.runRoute = func(context.Context, string) ([]byte, error) {
		t.Fatal("adapter must not run on invalid input")
		return nil, nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/routes",
		`{"routes":[{"destination":"10.20.0.0","gateway":"192.168.50.254"}]}`); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad destination: got %d, want 400", r.StatusCode)
	}
}

func TestRoutesFlush(t *testing.T) {
	srv, c, a := newTestServer(t)
	var calls []string
	a.runRoute = func(_ context.Context, action string) ([]byte, error) {
		calls = append(calls, action)
		return nil, nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/routes", `{"routes":[]}`); r.StatusCode != http.StatusOK {
		t.Fatalf("flush: got %d", r.StatusCode)
	}
	if len(calls) != 1 || calls[0] != "flush" {
		t.Fatalf("expected flush, got %v", calls)
	}
}

func TestRoutesRequiresRole(t *testing.T) {
	srv, admin, a := newTestServer(t)
	a.runRoute = func(context.Context, string) ([]byte, error) { return nil, nil }
	if r := doLogin(t, srv, admin, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("admin login: %d", r.StatusCode)
	}
	createUser(t, srv, admin, a, "auditor1", roleAuditor)
	aud := loginAs(t, srv, "auditor1", operatorPassword)
	if r := reqJSON(t, srv, aud, http.MethodGet, "/api/routes", ""); r.StatusCode != http.StatusOK {
		t.Fatalf("auditor get: got %d, want 200", r.StatusCode)
	}
	if r := reqJSON(t, srv, aud, http.MethodPut, "/api/routes",
		`{"routes":[{"destination":"10.0.0.0/8","gateway":"1.2.3.4"}]}`); r.StatusCode != http.StatusForbidden {
		t.Fatalf("auditor put: got %d, want 403", r.StatusCode)
	}
}
