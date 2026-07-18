package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestSvcCtlList(t *testing.T) {
	srv, c, a := newTestServer(t)
	a.runSvc = func(_ context.Context, args ...string) ([]byte, error) {
		if len(args) == 1 && args[0] == "statusall" {
			return []byte("postgresql active\nunbound inactive\nnginx failed\n"), nil
		}
		return nil, nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	resp, err := c.Get(srv.URL + "/api/svcctl")
	if err != nil {
		t.Fatal(err)
	}
	var list []map[string]any
	json.NewDecoder(resp.Body).Decode(&list)
	resp.Body.Close()
	if len(list) != len(controllableServices) {
		t.Fatalf("expected %d services, got %d", len(controllableServices), len(list))
	}
	states := map[string]string{}
	for _, s := range list {
		states[s["key"].(string)] = s["state"].(string)
	}
	if states["postgresql"] != "active" || states["unbound"] != "inactive" || states["nginx"] != "failed" {
		t.Fatalf("states parsed wrong: %v", states)
	}
	// a service not reported by statusall falls back to "unknown"
	if states["step-ca"] != "unknown" {
		t.Fatalf("expected unknown fallback, got %q", states["step-ca"])
	}
}

func TestSvcCtlAction(t *testing.T) {
	srv, c, a := newTestServer(t)
	var calls []string
	a.runSvc = func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		return []byte("active\n"), nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/svcctl/nginx/restart", `{}`); r.StatusCode != http.StatusOK {
		t.Fatalf("restart nginx: got %d", r.StatusCode)
	}
	if len(calls) != 1 || calls[0] != "restart nginx" {
		t.Fatalf("adapter call wrong: %v", calls)
	}
	// unknown service and bad action are rejected before the adapter runs
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/svcctl/saguaro/restart", `{}`); r.StatusCode != http.StatusNotFound {
		t.Fatalf("self-control should 404: got %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/svcctl/nginx/reload", `{}`); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad action: got %d, want 400", r.StatusCode)
	}
}

func TestSvcCtlRequiresControlRole(t *testing.T) {
	srv, admin, a := newTestServer(t)
	a.runSvc = func(context.Context, ...string) ([]byte, error) { return []byte("active"), nil }
	if r := doLogin(t, srv, admin, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("admin login: %d", r.StatusCode)
	}
	// DNS operator can read state (service:check) but not control (service:control)
	createUser(t, srv, admin, a, "dnsop1", roleDNSOperator)
	dns := loginAs(t, srv, "dnsop1", operatorPassword)
	if r := reqJSON(t, srv, dns, http.MethodGet, "/api/svcctl", ""); r.StatusCode != http.StatusOK {
		t.Fatalf("dnsop list: got %d, want 200", r.StatusCode)
	}
	if r := reqJSON(t, srv, dns, http.MethodPost, "/api/svcctl/nginx/restart", `{}`); r.StatusCode != http.StatusForbidden {
		t.Fatalf("dnsop control: got %d, want 403", r.StatusCode)
	}
	// auditor cannot even read (no service:check)
	createUser(t, srv, admin, a, "auditor1", roleAuditor)
	aud := loginAs(t, srv, "auditor1", operatorPassword)
	if r := reqJSON(t, srv, aud, http.MethodGet, "/api/svcctl", ""); r.StatusCode != http.StatusForbidden {
		t.Fatalf("auditor list: got %d, want 403", r.StatusCode)
	}
}
