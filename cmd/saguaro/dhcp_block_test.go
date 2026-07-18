package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeKea answers the control-agent commands used by keaSubnetTxn and records
// the last config-set payload so tests can inspect the pushed DROP class.
func fakeKea(t *testing.T, lastSet *map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Command   string         `json:"command"`
			Arguments map[string]any `json:"arguments"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Command {
		case "config-get":
			json.NewEncoder(w).Encode([]map[string]any{{"result": 0, "arguments": map[string]any{"Dhcp4": map[string]any{"subnet4": []any{}}}}})
		case "config-set":
			*lastSet = req.Arguments
			json.NewEncoder(w).Encode([]map[string]any{{"result": 0}})
		default: // config-test, status-get, config-write
			json.NewEncoder(w).Encode([]map[string]any{{"result": 0, "arguments": map[string]any{}}})
		}
	}))
}

func dropTest(set map[string]any) string {
	dhcp4, _ := set["Dhcp4"].(map[string]any)
	classes, _ := dhcp4["client-classes"].([]any)
	for _, c := range classes {
		if m, ok := c.(map[string]any); ok && m["name"] == "DROP" {
			s, _ := m["test"].(string)
			return s
		}
	}
	return ""
}

func TestDHCPBlockRoundTrip(t *testing.T) {
	srv, c, a := newTestServer(t)
	var lastSet map[string]any
	fake := fakeKea(t, &lastSet)
	defer fake.Close()
	a.keaURL, a.keaUser, a.keaPass = fake.URL, "u", "p"
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	// Block a MAC (mixed case + dashes normalises to colon-lowercase).
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/dhcp/blocklist", `{"mac":"AA-BB-CC-DD-EE-FF"}`); r.StatusCode != http.StatusOK {
		t.Fatalf("block add: got %d", r.StatusCode)
	}
	if got := a.getBlockedMACs(); len(got) != 1 || got[0] != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("blocklist not persisted normalised: %v", got)
	}
	if !strings.Contains(dropTest(lastSet), "aa:bb:cc:dd:ee:ff") {
		t.Fatalf("DROP class not pushed to Kea: %v", lastSet)
	}
	// Adding again is idempotent.
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/dhcp/blocklist", `{"mac":"aa:bb:cc:dd:ee:ff"}`); r.StatusCode != http.StatusOK {
		t.Fatalf("idempotent add: got %d", r.StatusCode)
	}
	if len(a.getBlockedMACs()) != 1 {
		t.Fatalf("duplicate stored")
	}
	// Unblock.
	if r := reqJSON(t, srv, c, http.MethodDelete, "/api/dhcp/blocklist/aa:bb:cc:dd:ee:ff", ""); r.StatusCode != http.StatusOK {
		t.Fatalf("unblock: got %d", r.StatusCode)
	}
	if len(a.getBlockedMACs()) != 0 {
		t.Fatalf("not unblocked")
	}
}

func TestDHCPBlockValidationAndRole(t *testing.T) {
	srv, admin, a := newTestServer(t)
	if r := doLogin(t, srv, admin, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("admin login: %d", r.StatusCode)
	}
	// invalid MAC rejected before Kea
	if r := reqJSON(t, srv, admin, http.MethodPost, "/api/dhcp/blocklist", `{"mac":"nope"}`); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad mac: got %d, want 400", r.StatusCode)
	}
	// unblocking a MAC that is not blocked
	if r := reqJSON(t, srv, admin, http.MethodDelete, "/api/dhcp/blocklist/aa:bb:cc:dd:ee:ff", ""); r.StatusCode != http.StatusNotFound {
		t.Fatalf("unblock missing: got %d, want 404", r.StatusCode)
	}
	// auditor may read the list but not modify it
	createUser(t, srv, admin, a, "auditor1", roleAuditor)
	aud := loginAs(t, srv, "auditor1", operatorPassword)
	if r := reqJSON(t, srv, aud, http.MethodGet, "/api/dhcp/blocklist", ""); r.StatusCode != http.StatusOK {
		t.Fatalf("auditor list: got %d, want 200", r.StatusCode)
	}
	if r := reqJSON(t, srv, aud, http.MethodPost, "/api/dhcp/blocklist", `{"mac":"aa:bb:cc:dd:ee:ff"}`); r.StatusCode != http.StatusForbidden {
		t.Fatalf("auditor block: got %d, want 403", r.StatusCode)
	}
}
