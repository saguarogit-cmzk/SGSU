package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestForcedPasswordChangeFlow(t *testing.T) {
	srv, c, a := newTestServer(t)
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	// Flip the flag on the live account — the very next request must hit the
	// W1 wall, because the middleware reads the user record per request.
	rec, _, err := a.users.Get("admin")
	if err != nil {
		t.Fatal(err)
	}
	rec.MustChangePassword = true
	if err := a.users.Upsert(rec); err != nil {
		t.Fatal(err)
	}

	if r := reqJSON(t, srv, c, http.MethodGet, "/api/services", ""); r.StatusCode != http.StatusForbidden {
		t.Fatalf("services during forced change: got %d, want 403", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodGet, "/api/profile", ""); r.StatusCode != http.StatusOK {
		t.Fatalf("profile during forced change: got %d, want 200", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/profile/password",
		`{"oldPassword":"`+testPassword+`","newPassword":"a-brand-new-pass-14"}`); r.StatusCode != http.StatusOK {
		t.Fatalf("password change during forced change: got %d, want 200", r.StatusCode)
	}
	// The wall lifts immediately after the change.
	if r := reqJSON(t, srv, c, http.MethodGet, "/api/services", ""); r.StatusCode != http.StatusOK {
		t.Fatalf("services after change: got %d, want 200", r.StatusCode)
	}
}

func TestLoginReportsMustChangeAndAdminCreatedUsersRequireIt(t *testing.T) {
	srv, admin, _ := newTestServer(t)
	if r := doLogin(t, srv, admin, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("admin login: %d", r.StatusCode)
	}
	// Create through the raw API so the W1 flag stays set.
	if r := reqJSON(t, srv, admin, http.MethodPost, "/api/users",
		`{"username":"fresh","password":"`+operatorPassword+`","role":"read-only"}`); r.StatusCode != http.StatusOK {
		t.Fatalf("create fresh: got %d", r.StatusCode)
	}

	fresh := loginAs(t, srv, "fresh", operatorPassword)
	resp, err := fresh.Post(srv.URL+"/api/login", "application/json",
		strings.NewReader(`{"username":"fresh","password":"`+operatorPassword+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		MustChangePassword bool `json:"mustChangePassword"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !out.MustChangePassword {
		t.Fatal("admin-created user must be flagged for a forced password change")
	}
	// And the wall is active until they change it.
	if r := reqJSON(t, srv, fresh, http.MethodGet, "/api/services", ""); r.StatusCode != http.StatusForbidden {
		t.Fatalf("fresh user services: got %d, want 403", r.StatusCode)
	}
	if r := reqJSON(t, srv, fresh, http.MethodPost, "/api/profile/password",
		`{"oldPassword":"`+operatorPassword+`","newPassword":"fresh-own-pass-14ch"}`); r.StatusCode != http.StatusOK {
		t.Fatalf("fresh password change: got %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, fresh, http.MethodGet, "/api/services", ""); r.StatusCode != http.StatusOK {
		t.Fatalf("fresh user after change: got %d, want 200", r.StatusCode)
	}
}
