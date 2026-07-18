package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testPassword = "correct-horse-battery-14"

func newTestServer(t *testing.T) (*httptest.Server, *http.Client, *app) {
	t.Helper()
	dir := t.TempDir()
	st, err := openStore(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	sess, err := openFileSessions(filepath.Join(dir, "sessions.json"))
	if err != nil {
		t.Fatal(err)
	}
	phc, err := hashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	a := &app{
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:       st,
		adminUser:   "admin",
		passPHC:     phc,
		sessions:    sess,
		sessionTTL:  time.Hour,
		secure:      false,
		ipLimiter:   newLoginLimiter(),
		userLimiter: newLoginLimiter(),
	}
	srv := httptest.NewServer(a.handler())
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return srv, &http.Client{Jar: jar}, a
}

func doLogin(t *testing.T, srv *httptest.Server, c *http.Client, password string) *http.Response {
	t.Helper()
	body := `{"username":"admin","password":"` + password + `"}`
	resp, err := c.Post(srv.URL+"/api/login", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func csrfCookie(t *testing.T, srv *httptest.Server, c *http.Client) string {
	t.Helper()
	u, _ := url.Parse(srv.URL)
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == "saguaro_csrf" {
			return ck.Value
		}
	}
	t.Fatal("saguaro_csrf cookie not set")
	return ""
}

func TestCSRFEnforcedOnMutatingRequests(t *testing.T) {
	srv, c, _ := newTestServer(t)
	if resp := doLogin(t, srv, c, testPassword); resp.StatusCode != http.StatusOK {
		t.Fatalf("login: got %d", resp.StatusCode)
	}
	csrf := csrfCookie(t, srv, c)

	// GET needs no CSRF token.
	resp, err := c.Get(srv.URL + "/api/services")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET without token: got %d, want 200", resp.StatusCode)
	}

	// POST without the header is rejected.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/services/unbound/actions/check", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST without token: got %d, want 403", resp.StatusCode)
	}

	// A wrong token is also rejected.
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/api/services/unbound/actions/check", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "bogus")
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST with wrong token: got %d, want 403", resp.StatusCode)
	}

	// The real token passes.
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/api/services/unbound/actions/check", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST with valid token: got %d, want 200", resp.StatusCode)
	}
}

func TestDeepHealthRequiresAuthAndReportsAllComponents(t *testing.T) {
	srv, c, _ := newTestServer(t)
	resp, err := c.Get(srv.URL + "/api/health/deep")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated deep health: got %d, want 401", resp.StatusCode)
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: got %d", r.StatusCode)
	}
	resp, err = c.Get(srv.URL + "/api/health/deep")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("deep health: got %d, want 200", resp.StatusCode)
	}
	var out struct {
		Healthy int           `json:"healthy"`
		Total   int           `json:"total"`
		Checks  []checkResult `json:"checks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Total != 9 || len(out.Checks) != 9 {
		t.Fatalf("expected 9 component checks, got total=%d len=%d", out.Total, len(out.Checks))
	}
}

func TestEventsEndpointWithoutPostgres(t *testing.T) {
	srv, c, _ := newTestServer(t)
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: got %d", r.StatusCode)
	}
	resp, err := c.Get(srv.URL + "/api/events")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("events without PG: got %d, want 503", resp.StatusCode)
	}
}

func TestLoginLockoutAfterRepeatedFailures(t *testing.T) {
	srv, c, a := newTestServer(t)
	for i := 1; i <= 5; i++ {
		if resp := doLogin(t, srv, c, "wrong-password-attempt"); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("failure %d: got %d, want 401", i, resp.StatusCode)
		}
	}
	resp := doLogin(t, srv, c, "wrong-password-attempt")
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("6th failure: got %d, want 429", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Fatal("429 must carry Retry-After")
	}
	// Even the correct password is refused while locked.
	if resp := doLogin(t, srv, c, testPassword); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("locked login with correct password: got %d, want 429", resp.StatusCode)
	}

	// The lockout must leave a security-severity audit event.
	a.store.mu.RLock()
	defer a.store.mu.RUnlock()
	found := false
	for _, e := range a.store.data.Audit {
		if e.Action == "login-lockout" && e.Severity == "security" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected a security-severity login-lockout audit event")
	}
}
