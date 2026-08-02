package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mintToken creates a token through the API and returns its secret and id.
func mintToken(t *testing.T, srv *httptest.Server, c *http.Client, body string) (string, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/tokens", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrfCookie(t, srv, c))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create token: got %d", resp.StatusCode)
	}
	var out struct {
		Secret string         `json:"secret"`
		Token  map[string]any `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	id, _ := out.Token["id"].(string)
	return out.Secret, id
}

// bearerReq issues a request authenticated only by a bearer token — no cookies,
// no CSRF header, which is the whole point of the feature.
func bearerReq(t *testing.T, url, method, secret, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestAPITokenAuthentication(t *testing.T) {
	srv, c, a := newTestServer(t)
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	secret, id := mintToken(t, srv, c, `{"name":"ansible","role":"admin"}`)
	if !strings.HasPrefix(secret, "sgs_") || len(secret) < 40 {
		t.Fatalf("secret looks wrong: %q", secret)
	}
	// The secret is never stored: only its hash.
	for _, tok := range a.getAPITokens() {
		if strings.Contains(tok.Hash, secret) || tok.Hash == secret {
			t.Fatal("the plaintext secret must not be stored")
		}
		if !strings.HasPrefix(secret, tok.Preview) {
			t.Fatalf("preview %q should be a prefix of the secret", tok.Preview)
		}
	}

	// A token works with no cookie and no CSRF header.
	resp := bearerReq(t, srv.URL+"/api/services", http.MethodGet, secret, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET with token: got %d", resp.StatusCode)
	}
	// Mutations too — CSRF pairing is a cookie-auth concern only.
	resp = bearerReq(t, srv.URL+"/api/services/unbound/actions/check", http.MethodPost, secret, "{}")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST with token: got %d", resp.StatusCode)
	}
	// Use is recorded.
	if a.getAPITokens()[0].LastUsed.IsZero() {
		t.Error("token use should be recorded")
	}

	// Garbage and empty tokens are refused.
	for _, bad := range []string{"sgs_totally-wrong", "not-even-prefixed"} {
		resp = bearerReq(t, srv.URL+"/api/services", http.MethodGet, bad, "")
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("token %q: got %d, want 401", bad, resp.StatusCode)
		}
	}

	// A token cannot manage tokens, even with the admin role: a leaked
	// automation credential must not be able to mint a permanent replacement.
	resp = bearerReq(t, srv.URL+"/api/tokens", http.MethodPost, secret, `{"name":"sneaky","role":"admin"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("token minting a token: got %d, want 403", resp.StatusCode)
	}
	resp = bearerReq(t, srv.URL+"/api/tokens/"+id, http.MethodDelete, secret, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("token revoking a token: got %d, want 403", resp.StatusCode)
	}

	// Revoking through an interactive session kills it immediately.
	if r := reqJSON(t, srv, c, http.MethodDelete, "/api/tokens/"+id, ""); r.StatusCode != http.StatusOK {
		t.Fatalf("revoke: got %d", r.StatusCode)
	}
	resp = bearerReq(t, srv.URL+"/api/services", http.MethodGet, secret, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked token: got %d, want 401", resp.StatusCode)
	}
}

// The token's role is enforced exactly like a user's.
func TestAPITokenRoleIsEnforced(t *testing.T) {
	srv, c, _ := newTestServer(t)
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	ro, _ := mintToken(t, srv, c, `{"name":"monitoring","role":"read-only"}`)

	resp := bearerReq(t, srv.URL+"/api/services", http.MethodGet, ro, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("read-only token reading: got %d", resp.StatusCode)
	}
	resp = bearerReq(t, srv.URL+"/api/services/unbound/actions/check", http.MethodPost, ro, "{}")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("read-only token mutating: got %d, want 403", resp.StatusCode)
	}
}

// An expired token is refused, and validation rejects bad input.
func TestAPITokenExpiryAndValidation(t *testing.T) {
	srv, c, a := newTestServer(t)
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	secret, _ := mintToken(t, srv, c, `{"name":"short-lived","role":"admin","days":1}`)
	toks := a.getAPITokens()
	if toks[0].ExpiresAt.IsZero() {
		t.Fatal("days should set an expiry")
	}
	// Move the expiry into the past.
	toks[0].ExpiresAt = time.Now().Add(-time.Hour)
	if err := a.setAPITokens(toks); err != nil {
		t.Fatal(err)
	}
	resp := bearerReq(t, srv.URL+"/api/services", http.MethodGet, secret, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired token: got %d, want 401", resp.StatusCode)
	}

	for _, bad := range []string{
		`{"name":"","role":"admin"}`,
		`{"name":"bad name!","role":"admin"}`,
		`{"name":"ok","role":"sudo"}`,
		`{"name":"ok","days":99999,"role":"admin"}`,
	} {
		if r := reqJSON(t, srv, c, http.MethodPost, "/api/tokens", bad); r.StatusCode != http.StatusBadRequest {
			t.Errorf("input %s: got %d, want 400", bad, r.StatusCode)
		}
	}
	// Duplicate names are refused so a revocation is unambiguous.
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/tokens",
		`{"name":"short-lived","role":"admin"}`); r.StatusCode != http.StatusConflict {
		t.Errorf("duplicate name: got %d, want 409", r.StatusCode)
	}
}
