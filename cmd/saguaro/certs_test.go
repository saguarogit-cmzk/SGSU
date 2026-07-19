package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"saguaro.local/network-manager/internal/adapters/nginxgen"
)

func TestCertIssueFlow(t *testing.T) {
	srv, c, a := newTestServer(t)
	var calls []string
	a.runCert = func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		return []byte("ok"), nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}

	// Validation failures never reach the adapter.
	for name, body := range map[string]string{
		"bad name": `{"type":"internal","name":"Bad Name","sans":["a.example.com"],"deployGui":false}`,
		"no sans":  `{"type":"internal","name":"wiki","sans":[],"deployGui":false}`,
		"bad san":  `{"type":"internal","name":"wiki","sans":["not a san"],"deployGui":false}`,
	} {
		if r := reqJSON(t, srv, c, http.MethodPost, "/api/certs/issue", body); r.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s: got %d, want 400", name, r.StatusCode)
		}
	}
	// public without a domain/email is a validation error (400), handled before the adapter
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/certs/issue", `{"type":"public","name":"pub","deployGui":false}`); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("public without domain: got %d, want 400", r.StatusCode)
	}
	if len(calls) != 0 {
		t.Fatalf("adapter must not run on validation failures: %v", calls)
	}

	// Successful issue stages the request and records state.
	body := `{"type":"internal","name":"wiki","sans":["wiki.example.internal","192.168.10.5"],"deployGui":true}`
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/certs/issue", body); r.StatusCode != http.StatusOK {
		t.Fatalf("issue: got %d", r.StatusCode)
	}
	staged, err := os.ReadFile(filepath.Join(filepath.Dir(a.store.path), stagedCertRequestName))
	if err != nil || string(staged) != "wiki\nwiki.example.internal\n192.168.10.5\n" {
		t.Fatalf("staged request wrong: %v %q", err, staged)
	}
	if strings.Join(calls, ",") != "issue,deploy-gui wiki" {
		t.Fatalf("adapter sequence wrong: %v", calls)
	}
	certs := a.getCerts()
	if len(certs) != 1 || certs[0].Name != "wiki" || len(certs[0].SANs) != 2 {
		t.Fatalf("state wrong: %+v", certs)
	}

	// Re-issue replaces instead of duplicating.
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/certs/issue", `{"type":"internal","name":"wiki","sans":["wiki.example.internal"],"deployGui":false}`); r.StatusCode != http.StatusOK {
		t.Fatalf("re-issue: got %d", r.StatusCode)
	}
	if certs := a.getCerts(); len(certs) != 1 || len(certs[0].SANs) != 1 {
		t.Fatalf("re-issue must replace: %+v", certs)
	}
}

func TestCertDeleteGuardedByProxyReference(t *testing.T) {
	srv, c, a := newTestServer(t)
	a.runCert = func(_ context.Context, _ ...string) ([]byte, error) { return nil, nil }
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	if err := a.setCerts([]certRecord{{Name: "wiki", SANs: []string{"wiki.example.internal"}}}); err != nil {
		t.Fatal(err)
	}
	if err := a.setProxyApps([]nginxgen.App{{Name: "wiki", Hostname: "wiki.example.internal",
		UpstreamIP: "192.168.10.5", UpstreamPort: 8080, TLS: nginxgen.TLSManaged, CertName: "wiki"}}); err != nil {
		t.Fatal(err)
	}
	if r := reqJSON(t, srv, c, http.MethodDelete, "/api/certs/wiki", ""); r.StatusCode != http.StatusConflict {
		t.Fatalf("delete referenced cert: got %d, want 409", r.StatusCode)
	}
	if err := a.setProxyApps(nil); err != nil {
		t.Fatal(err)
	}
	if r := reqJSON(t, srv, c, http.MethodDelete, "/api/certs/wiki", ""); r.StatusCode != http.StatusOK {
		t.Fatalf("delete unreferenced cert: got %d", r.StatusCode)
	}
	if len(a.getCerts()) != 0 {
		t.Fatal("cert must be removed from state")
	}
}

func TestCertsAdminOnly(t *testing.T) {
	srv, admin, a := newTestServer(t)
	a.runCert = func(_ context.Context, _ ...string) ([]byte, error) { return nil, nil }
	if r := doLogin(t, srv, admin, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("admin login: %d", r.StatusCode)
	}
	createUser(t, srv, admin, a, "netcert", roleNetworkOperator)
	netop := loginAs(t, srv, "netcert", operatorPassword)
	if r := reqJSON(t, srv, netop, http.MethodPost, "/api/certs/issue", `{"type":"internal","name":"x","sans":["x.example.com"],"deployGui":false}`); r.StatusCode != http.StatusForbidden {
		t.Fatalf("network-operator cert issue: got %d, want 403", r.StatusCode)
	}
	// Reads stay open.
	if r := reqJSON(t, srv, netop, http.MethodGet, "/api/certs", ""); r.StatusCode != http.StatusOK {
		t.Fatalf("cert list read: got %d, want 200", r.StatusCode)
	}
}
