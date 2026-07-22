package main

import (
	"context"
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

	mailmod "saguaro.local/network-manager/internal/mail"
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
	mailKey, err := mailmod.LoadOrCreateKey(filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	users, err := openFileUsers(filepath.Join(dir, "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seedAdmin(users, "admin", phc); err != nil {
		t.Fatal(err)
	}
	// Most tests exercise features past the W1 forced password change.
	adminRec, _, err := users.Get("admin")
	if err != nil {
		t.Fatal(err)
	}
	adminRec.MustChangePassword = false
	if err := users.Upsert(adminRec); err != nil {
		t.Fatal(err)
	}
	a := &app{
		mailKey:       mailKey,
		runFirewall:   func(context.Context, string) ([]byte, error) { return nil, nil },
		runIDS:        func(context.Context, ...string) ([]byte, error) { return nil, nil },
		runRPZ:        func(context.Context, string) ([]byte, error) { return nil, nil },
		runProxy:      func(context.Context, string) ([]byte, error) { return nil, nil },
		probeUpstream: func(context.Context, string) error { return nil },
		runCert:       func(context.Context, ...string) ([]byte, error) { return nil, nil },
		runVPN:        func(context.Context, string) ([]byte, error) { return nil, nil },
		runBackupCfg:  func(context.Context, string) ([]byte, error) { return nil, nil },
		runWAN:        func(context.Context, string) ([]byte, error) { return nil, nil },
		runRoute:      func(context.Context, string) ([]byte, error) { return nil, nil },
		runS2S:        func(context.Context, string) ([]byte, error) { return nil, nil },
		runIPsec:      func(context.Context, string) ([]byte, error) { return nil, nil },
		runSvc:        func(context.Context, ...string) ([]byte, error) { return nil, nil },
		runLogs:       func(context.Context, ...string) ([]byte, error) { return nil, nil },
		runTools:      func(context.Context, ...string) ([]byte, error) { return nil, nil },
		runWebProxy:   func(context.Context, ...string) ([]byte, error) { return nil, nil },
		runNet:        func(context.Context, ...string) ([]byte, error) { return nil, nil },
		readInterfaces: func(context.Context) ([]nicInfo, error) {
			return []nicInfo{{Name: "enp1s0", MAC: "aa:bb:cc:dd:ee:01", State: "up", Carrier: true, SpeedMb: 1000, Driver: "igb", Addresses: []string{"192.168.50.61/24"}}}, nil
		},
		readDefaultRoutes: func(context.Context) ([]defaultRoute, error) { return nil, nil },
		log:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:             st,
		adminUser:         "admin",
		users:             users,
		dummyPHC:          phc,
		sessions:          sess,
		sessionTTL:        time.Hour,
		secure:            false,
		ipLimiter:         newLoginLimiter(),
		userLimiter:       newLoginLimiter(),
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

func TestMailConfigAPI(t *testing.T) {
	srv, c, a := newTestServer(t)
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: got %d", r.StatusCode)
	}
	csrf := csrfCookie(t, srv, c)
	putMail := func(body string) *http.Response {
		req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/mail", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// Defaults before configuration.
	resp, err := c.Get(srv.URL + "/api/mail")
	if err != nil {
		t.Fatal(err)
	}
	var view struct {
		TLSMode     string `json:"tlsMode"`
		HasPassword bool   `json:"hasPassword"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&view); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if view.TLSMode != "starttls" || view.HasPassword {
		t.Fatalf("defaults wrong: %+v", view)
	}

	// Invalid config is rejected.
	if r := putMail(`{"enabled":false,"host":"","port":587,"tlsMode":"starttls","from":"a@b","username":"","password":"","recipients":["c@d"],"minSeverity":"error"}`); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty host: got %d, want 400", r.StatusCode)
	} else {
		r.Body.Close()
	}

	// Valid config with a password.
	if r := putMail(`{"enabled":false,"host":"smtp.example.com","port":587,"tlsMode":"starttls","from":"sna@example.com","username":"sna","password":"topsecret","recipients":["ops@example.com"],"minSeverity":"error"}`); r.StatusCode != http.StatusOK {
		t.Fatalf("valid put: got %d", r.StatusCode)
	} else {
		r.Body.Close()
	}
	cfg, ok := a.getMail()
	if !ok || cfg.PasswordEnc == "" || strings.Contains(cfg.PasswordEnc, "topsecret") {
		t.Fatalf("password not stored encrypted: %+v", cfg)
	}

	// Saving again without a password keeps the stored one; the API never
	// returns the ciphertext.
	if r := putMail(`{"enabled":false,"host":"smtp.example.com","port":587,"tlsMode":"starttls","from":"sna@example.com","username":"sna","password":"","recipients":["ops@example.com"],"minSeverity":"security"}`); r.StatusCode != http.StatusOK {
		t.Fatalf("second put: got %d", r.StatusCode)
	} else {
		r.Body.Close()
	}
	cfg2, _ := a.getMail()
	if cfg2.PasswordEnc != cfg.PasswordEnc || cfg2.MinSeverity != "security" {
		t.Fatal("empty password must keep the stored ciphertext while other fields update")
	}
	resp, err = c.Get(srv.URL + "/api/mail")
	if err != nil {
		t.Fatal(err)
	}
	raw := new(strings.Builder)
	if _, err := io.Copy(raw, resp.Body); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if strings.Contains(raw.String(), "passwordEnc") || !strings.Contains(raw.String(), `"hasPassword":true`) {
		t.Fatalf("view must redact the password: %s", raw)
	}
}

func TestAdapterEndpointsUnconfigured(t *testing.T) {
	srv, c, _ := newTestServer(t)
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: got %d", r.StatusCode)
	}
	for _, path := range []string{"/api/dns/zones", "/api/dhcp/subnets", "/api/dhcp/leases", "/api/dhcp/status", "/api/dhcp/reservations"} {
		resp, err := c.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("%s unconfigured: got %d, want 503", path, resp.StatusCode)
		}
	}
}

func TestDNSAPIThroughFakePowerDNS(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "k" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/v1/servers/localhost/zones":
			w.Write([]byte(`[{"id":"z.internal.","name":"z.internal.","kind":"Native","serial":7}]`))
		case r.Method == "PATCH":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"nope"}`))
		}
	}))
	defer fake.Close()

	srv, c, a := newTestServer(t)
	a.pdnsURL, a.pdnsKey = fake.URL, "k"
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: got %d", r.StatusCode)
	}
	csrf := csrfCookie(t, srv, c)

	resp, err := c.Get(srv.URL + "/api/dns/zones")
	if err != nil {
		t.Fatal(err)
	}
	var zones []struct{ Name string }
	if err := json.NewDecoder(resp.Body).Decode(&zones); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(zones) != 1 || zones[0].Name != "z.internal." {
		t.Fatalf("zones through API: %+v", zones)
	}

	// Record upsert goes through, invalid type is rejected before PowerDNS.
	put := func(body string) int {
		req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/dns/zones/z.internal/records", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := put(`{"name":"h.z.internal","type":"A","ttl":300,"contents":["192.168.1.5"],"delete":false}`); code != http.StatusOK {
		t.Fatalf("record upsert: got %d", code)
	}
	if code := put(`{"name":"h.z.internal","type":"DNSKEY","ttl":300,"contents":["x"],"delete":false}`); code != http.StatusBadRequest {
		t.Fatalf("forbidden type: got %d, want 400", code)
	}
	if code := put(`{"name":"h.z.internal","type":"A","ttl":300,"contents":[],"delete":false}`); code != http.StatusBadRequest {
		t.Fatalf("empty contents: got %d, want 400", code)
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

func TestAssetsRevalidate(t *testing.T) {
	srv, c, _ := newTestServer(t)
	// Without a validator a browser may keep serving an old app.js forever, so
	// the GUI would run stale code against a freshly self-updated API.
	resp, err := c.Get(srv.URL + "/app.js")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	etag := resp.Header.Get("ETag")
	if etag == "" || resp.Header.Get("Cache-Control") != "no-cache" {
		t.Fatalf("assets served without revalidation headers: %+v", resp.Header)
	}
	// A browser holding the current version gets a cheap 304, not a re-download.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/app.js", nil)
	req.Header.Set("If-None-Match", etag)
	resp2, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotModified {
		t.Fatalf("conditional request: got %d, want 304", resp2.StatusCode)
	}
}
