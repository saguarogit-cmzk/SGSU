package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"saguaro.local/network-manager/internal/adapters/nftgen"
)

func getSystem(t *testing.T, srv *httptest.Server, c *http.Client) map[string]any {
	t.Helper()
	resp, err := c.Get(srv.URL + "/api/system")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestSystemProfileDefault(t *testing.T) {
	srv, c, _ := newTestServer(t)
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	m := getSystem(t, srv, c)
	if m["profile"] != "gateway" || m["gateway"] != true || m["utm"] != true {
		t.Fatalf("default profile wrong: %+v", m)
	}
}

func TestSystemProfileSwitch(t *testing.T) {
	srv, c, a := newTestServer(t)
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/system/profile", `{"profile":"router"}`); r.StatusCode != http.StatusOK {
		t.Fatalf("switch to router: got %d", r.StatusCode)
	}
	if a.getProfile() != "router" {
		t.Fatalf("profile not persisted: %q", a.getProfile())
	}
	m := getSystem(t, srv, c)
	if m["profile"] != "router" || m["gateway"] != false || m["utm"] != false {
		t.Fatalf("router view wrong: %+v", m)
	}
	// invalid profile rejected
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/system/profile", `{"profile":"bogus"}`); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("bogus profile: got %d, want 400", r.StatusCode)
	}
}

func TestSwitchToRouterBlockedWhenGatewayActive(t *testing.T) {
	srv, c, a := newTestServer(t)
	if err := a.setGateway(nftgen.Config{AdminNetwork: "192.168.50.0/24", ClientNetwork: "10.10.10.0/24",
		GatewayEnabled: true, WANInterface: "enp1s0", LANInterface: "enp2s0", NATEnabled: true}); err != nil {
		t.Fatal(err)
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/system/profile", `{"profile":"router"}`); r.StatusCode != http.StatusConflict {
		t.Fatalf("switch with gateway active: got %d, want 409", r.StatusCode)
	}
}

func TestGatewayEnableBlockedInRouterMode(t *testing.T) {
	srv, c, a := newTestServer(t)
	if err := a.setProfile("router"); err != nil {
		t.Fatal(err)
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	body := `{"adminNetwork":"192.168.50.0/24","clientNetwork":"10.10.10.0/24","gatewayEnabled":true,"wanInterface":"enp1s0","lanInterface":"enp2s0","natEnabled":true}`
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/gateway", body); r.StatusCode != http.StatusConflict {
		t.Fatalf("enable gateway in router mode: got %d, want 409", r.StatusCode)
	}
	// a non-gateway (local) config is still allowed in router mode
	local := `{"adminNetwork":"192.168.50.0/24","clientNetwork":"10.10.10.0/24","gatewayEnabled":false}`
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/gateway", local); r.StatusCode != http.StatusOK {
		t.Fatalf("local config in router mode: got %d, want 200", r.StatusCode)
	}
}

func TestSystemProfileRequiresRole(t *testing.T) {
	srv, admin, a := newTestServer(t)
	if r := doLogin(t, srv, admin, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("admin login: %d", r.StatusCode)
	}
	createUser(t, srv, admin, a, "auditor1", roleAuditor)
	aud := loginAs(t, srv, "auditor1", operatorPassword)
	if r := reqJSON(t, srv, aud, http.MethodGet, "/api/system", ""); r.StatusCode != http.StatusOK {
		t.Fatalf("auditor get system: got %d, want 200", r.StatusCode)
	}
	if r := reqJSON(t, srv, aud, http.MethodPut, "/api/system/profile", `{"profile":"router"}`); r.StatusCode != http.StatusForbidden {
		t.Fatalf("auditor set profile: got %d, want 403", r.StatusCode)
	}
}
