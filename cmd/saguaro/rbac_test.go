package main

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
)

// reqJSON performs an authenticated JSON request with the client's CSRF token.
func reqJSON(t *testing.T, srv *httptest.Server, c *http.Client, method, path, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if method != http.MethodGet {
		req.Header.Set("X-CSRF-Token", csrfCookie(t, srv, c))
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func loginAs(t *testing.T, srv *httptest.Server, username, password string) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	body := `{"username":"` + username + `","password":"` + password + `"}`
	resp, err := c.Post(srv.URL+"/api/login", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login as %s: got %d", username, resp.StatusCode)
	}
	return c
}

const operatorPassword = "operator-pass-14chars"

func createUser(t *testing.T, srv *httptest.Server, adminClient *http.Client, username, role string) {
	t.Helper()
	body := `{"username":"` + username + `","password":"` + operatorPassword + `","role":"` + role + `"}`
	if resp := reqJSON(t, srv, adminClient, http.MethodPost, "/api/users", body); resp.StatusCode != http.StatusOK {
		t.Fatalf("create %s: got %d", username, resp.StatusCode)
	}
}

func TestRBACPermissionEnforcement(t *testing.T) {
	srv, admin, _ := newTestServer(t)
	if r := doLogin(t, srv, admin, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("admin login: %d", r.StatusCode)
	}
	createUser(t, srv, admin, "dnsop", roleDNSOperator)
	createUser(t, srv, admin, "netop", roleNetworkOperator)
	createUser(t, srv, admin, "audit", roleAuditor)

	dnsop := loginAs(t, srv, "dnsop", operatorPassword)
	netop := loginAs(t, srv, "netop", operatorPassword)
	auditor := loginAs(t, srv, "audit", operatorPassword)

	recBody := `{"name":"h.z","type":"A","ttl":300,"contents":["1.2.3.4"],"delete":false}`
	// dns-operator passes authz for DNS writes (503 = adapter unconfigured,
	// which proves the role check let the request through).
	if r := reqJSON(t, srv, dnsop, http.MethodPut, "/api/dns/zones/z/records", recBody); r.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("dnsop dns write: got %d, want 503", r.StatusCode)
	}
	// network-operator must NOT write DNS.
	if r := reqJSON(t, srv, netop, http.MethodPut, "/api/dns/zones/z/records", recBody); r.StatusCode != http.StatusForbidden {
		t.Fatalf("netop dns write: got %d, want 403", r.StatusCode)
	}
	resBody := `{"id":0,"mac":"aa:bb:cc:dd:ee:ff","ip":"192.168.1.5","hostname":"x","subnetId":1}`
	// network-operator passes authz for DHCP writes.
	if r := reqJSON(t, srv, netop, http.MethodPost, "/api/dhcp/reservations", resBody); r.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("netop dhcp write: got %d, want 503", r.StatusCode)
	}
	// dns-operator and auditor must not.
	if r := reqJSON(t, srv, dnsop, http.MethodPost, "/api/dhcp/reservations", resBody); r.StatusCode != http.StatusForbidden {
		t.Fatalf("dnsop dhcp write: got %d, want 403", r.StatusCode)
	}
	if r := reqJSON(t, srv, auditor, http.MethodPost, "/api/dhcp/reservations", resBody); r.StatusCode != http.StatusForbidden {
		t.Fatalf("auditor dhcp write: got %d, want 403", r.StatusCode)
	}
	// Reads stay open to every role.
	if r := reqJSON(t, srv, auditor, http.MethodGet, "/api/audit", ""); r.StatusCode != http.StatusOK {
		t.Fatalf("auditor audit read: got %d, want 200", r.StatusCode)
	}
	// User management is admin-only.
	if r := reqJSON(t, srv, netop, http.MethodGet, "/api/users", ""); r.StatusCode != http.StatusForbidden {
		t.Fatalf("netop users list: got %d, want 403", r.StatusCode)
	}
	if r := reqJSON(t, srv, admin, http.MethodGet, "/api/users", ""); r.StatusCode != http.StatusOK {
		t.Fatalf("admin users list: got %d, want 200", r.StatusCode)
	}
}

func TestLastAdminProtection(t *testing.T) {
	srv, admin, _ := newTestServer(t)
	if r := doLogin(t, srv, admin, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("admin login: %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, admin, http.MethodPatch, "/api/users/admin", `{"enabled":false}`); r.StatusCode != http.StatusConflict {
		t.Fatalf("disable last admin: got %d, want 409", r.StatusCode)
	}
	if r := reqJSON(t, srv, admin, http.MethodDelete, "/api/users/admin", ""); r.StatusCode != http.StatusConflict {
		t.Fatalf("delete last admin: got %d, want 409", r.StatusCode)
	}
	// With a second admin the first one may be disabled.
	createUser(t, srv, admin, "admin2", roleAdmin)
	if r := reqJSON(t, srv, admin, http.MethodPatch, "/api/users/admin", `{"enabled":false}`); r.StatusCode != http.StatusOK {
		t.Fatalf("disable admin with backup admin: got %d, want 200", r.StatusCode)
	}
	// The disabled admin's session dies immediately.
	if r := reqJSON(t, srv, admin, http.MethodGet, "/api/services", ""); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("disabled user session: got %d, want 401", r.StatusCode)
	}
}

func TestProfilePasswordChange(t *testing.T) {
	srv, admin, _ := newTestServer(t)
	if r := doLogin(t, srv, admin, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("admin login: %d", r.StatusCode)
	}
	createUser(t, srv, admin, "worker", roleReadOnly)
	worker := loginAs(t, srv, "worker", operatorPassword)

	if r := reqJSON(t, srv, worker, http.MethodPost, "/api/profile/password",
		`{"oldPassword":"wrong-old-password","newPassword":"a-new-password-14ch"}`); r.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong old password: got %d, want 403", r.StatusCode)
	}
	if r := reqJSON(t, srv, worker, http.MethodPost, "/api/profile/password",
		`{"oldPassword":"`+operatorPassword+`","newPassword":"a-new-password-14ch"}`); r.StatusCode != http.StatusOK {
		t.Fatalf("password change: got %d, want 200", r.StatusCode)
	}
	// New password works for a fresh login.
	loginAs(t, srv, "worker", "a-new-password-14ch")
}
