package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWebProxyApply(t *testing.T) {
	srv, c, a := newTestServer(t)
	var calls []string
	a.runWebProxy = func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		return []byte("ok"), nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	body := `{"enabled":true,"filterPort":8080,"allowedNetwork":"192.168.10.0/24","filtering":true,"bannedSites":["ads.example.com"],"exceptionSites":["ok.example.com"]}`
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/webproxy", body); r.StatusCode != http.StatusOK {
		t.Fatalf("apply: got %d", r.StatusCode)
	}
	if len(calls) != 1 || calls[0] != "apply 8080 1" {
		t.Fatalf("adapter call wrong: %v", calls)
	}
	dir := filepath.Dir(a.store.path)
	squid, _ := os.ReadFile(filepath.Join(dir, "staged-squid.conf"))
	if !strings.Contains(string(squid), "acl saguaro_lan src 192.168.10.0/24") {
		t.Fatalf("staged squid conf wrong: %s", squid)
	}
	banned, _ := os.ReadFile(filepath.Join(dir, "staged-e2g-banned"))
	if !strings.Contains(string(banned), "ads.example.com") {
		t.Fatalf("staged banned list wrong: %s", banned)
	}
	// disable
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/webproxy", `{"enabled":false}`); r.StatusCode != http.StatusOK {
		t.Fatalf("disable: got %d", r.StatusCode)
	}
	if calls[len(calls)-1] != "disable" {
		t.Fatalf("expected disable, got %v", calls)
	}
	// invalid network rejected
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/webproxy", `{"enabled":true,"allowedNetwork":"nope"}`); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad network: got %d, want 400", r.StatusCode)
	}
}

func TestWebProxyRequiresRole(t *testing.T) {
	srv, admin, a := newTestServer(t)
	if r := doLogin(t, srv, admin, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("admin login: %d", r.StatusCode)
	}
	createUser(t, srv, admin, a, "auditor1", roleAuditor)
	aud := loginAs(t, srv, "auditor1", operatorPassword)
	if r := reqJSON(t, srv, aud, http.MethodGet, "/api/webproxy", ""); r.StatusCode != http.StatusOK {
		t.Fatalf("auditor get: got %d, want 200", r.StatusCode)
	}
	if r := reqJSON(t, srv, aud, http.MethodPut, "/api/webproxy", `{"enabled":false}`); r.StatusCode != http.StatusForbidden {
		t.Fatalf("auditor put: got %d, want 403", r.StatusCode)
	}
}
