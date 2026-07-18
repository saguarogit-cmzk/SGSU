package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIPsecConnAndApply(t *testing.T) {
	srv, c, a := newTestServer(t)
	var actions []string
	a.runIPsec = func(_ context.Context, action string) ([]byte, error) {
		actions = append(actions, action)
		return []byte("ok"), nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	// Add a connection with a PSK while IPsec is off: persisted, not applied.
	body := `{"name":"sophos-hq","remoteAddr":"203.0.113.5","localSubnets":["192.168.10.0/24"],"remoteSubnets":["192.168.20.0/24"],"initiate":true,"psk":"s3cret-psk!"}`
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/ipsec/connections", body); r.StatusCode != http.StatusOK {
		t.Fatalf("add conn: got %d", r.StatusCode)
	}
	cfg := a.getIPsec()
	if len(cfg.Connections) != 1 || cfg.Connections[0].PSKEnc == "" || cfg.Connections[0].PSKEnc == "s3cret-psk!" {
		t.Fatalf("psk not sealed: %+v", cfg.Connections)
	}
	if len(actions) != 0 {
		t.Fatalf("adapter should not run while disabled: %v", actions)
	}
	// Enable: stages swanctl.conf and runs apply.
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/ipsec/apply", `{"enabled":true}`); r.StatusCode != http.StatusOK {
		t.Fatalf("enable: got %d", r.StatusCode)
	}
	if len(actions) != 1 || actions[0] != "apply" {
		t.Fatalf("expected apply, got %v", actions)
	}
	staged, err := os.ReadFile(filepath.Join(filepath.Dir(a.store.path), stagedIPsecName))
	if err != nil {
		t.Fatalf("staged: %v", err)
	}
	for _, want := range []string{"conn-sophos-hq {", "remote_addrs = 203.0.113.5", `secret = "s3cret-psk!"`} {
		if !strings.Contains(string(staged), want) {
			t.Fatalf("staged missing %q:\n%s", want, staged)
		}
	}
	// View must not leak the sealed PSK.
	resp, _ := c.Get(srv.URL + "/api/ipsec")
	var view map[string]any
	json.NewDecoder(resp.Body).Decode(&view)
	resp.Body.Close()
	if b, _ := json.Marshal(view); strings.Contains(string(b), a.getIPsec().Connections[0].PSKEnc) {
		t.Fatal("view leaked the sealed PSK")
	}
	// Editing without a PSK keeps the sealed one.
	edit := `{"name":"sophos-hq","remoteAddr":"203.0.113.9","localSubnets":["192.168.10.0/24"],"remoteSubnets":["192.168.20.0/24"],"initiate":true}`
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/ipsec/connections", edit); r.StatusCode != http.StatusOK {
		t.Fatalf("edit conn: got %d", r.StatusCode)
	}
	if a.getIPsec().Connections[0].PSKEnc == "" {
		t.Fatal("edit dropped the sealed PSK")
	}
}

func TestIPsecEnableRequiresConnection(t *testing.T) {
	srv, c, a := newTestServer(t)
	a.runIPsec = func(context.Context, string) ([]byte, error) { return nil, nil }
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/ipsec/apply", `{"enabled":true}`); r.StatusCode != http.StatusConflict {
		t.Fatalf("enable with no conns: got %d, want 409", r.StatusCode)
	}
}

func TestIPsecConnRequiresPSK(t *testing.T) {
	srv, c, _ := newTestServer(t)
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	body := `{"name":"x","remoteAddr":"1.2.3.4","localSubnets":["10.0.0.0/8"],"remoteSubnets":["10.1.0.0/16"]}`
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/ipsec/connections", body); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("new conn without psk: got %d, want 400", r.StatusCode)
	}
	// invalid PSK charset rejected
	bad := `{"name":"x","remoteAddr":"1.2.3.4","localSubnets":["10.0.0.0/8"],"remoteSubnets":["10.1.0.0/16"],"psk":"has \"quote"}`
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/ipsec/connections", bad); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad psk: got %d, want 400", r.StatusCode)
	}
}

func TestIPsecRequiresRole(t *testing.T) {
	srv, admin, a := newTestServer(t)
	a.runIPsec = func(context.Context, string) ([]byte, error) { return nil, nil }
	if r := doLogin(t, srv, admin, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("admin login: %d", r.StatusCode)
	}
	createUser(t, srv, admin, a, "auditor1", roleAuditor)
	aud := loginAs(t, srv, "auditor1", operatorPassword)
	if r := reqJSON(t, srv, aud, http.MethodGet, "/api/ipsec", ""); r.StatusCode != http.StatusOK {
		t.Fatalf("auditor get: got %d, want 200", r.StatusCode)
	}
	if r := reqJSON(t, srv, aud, http.MethodPost, "/api/ipsec/apply", `{"enabled":false}`); r.StatusCode != http.StatusForbidden {
		t.Fatalf("auditor apply: got %d, want 403", r.StatusCode)
	}
}
