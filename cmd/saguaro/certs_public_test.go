package main

import (
	"context"
	"net/http"
	"testing"
)

func TestPublicCertIssue(t *testing.T) {
	srv, c, a := newTestServer(t)
	var calls [][]string
	a.runCert = func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		return []byte("ok"), nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	body := `{"type":"public","name":"wiki","domain":"WIKI.example.com","email":"admin@example.com"}`
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/certs/issue", body); r.StatusCode != http.StatusOK {
		t.Fatalf("public issue: got %d", r.StatusCode)
	}
	if len(calls) != 1 || calls[0][0] != "acme" || calls[0][1] != "wiki" || calls[0][2] != "wiki.example.com" || calls[0][3] != "admin@example.com" {
		t.Fatalf("adapter call wrong: %v", calls)
	}
	found := false
	for _, cr := range a.getCerts() {
		if cr.Name == "wiki" {
			found = true
			if !cr.Public || len(cr.SANs) != 1 || cr.SANs[0] != "wiki.example.com" {
				t.Fatalf("cert record wrong: %+v", cr)
			}
		}
	}
	if !found {
		t.Fatal("public cert not recorded")
	}
	// validation failures are rejected before the adapter runs
	for _, bad := range []string{
		`{"type":"public","name":"x","domain":"not_a_domain","email":"a@b.com"}`,
		`{"type":"public","name":"x","domain":"*.example.com","email":"a@b.com"}`,
		`{"type":"public","name":"x","domain":"ok.example.com","email":"bogus"}`,
	} {
		if r := reqJSON(t, srv, c, http.MethodPost, "/api/certs/issue", bad); r.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 for %s, got %d", bad, r.StatusCode)
		}
	}
}
