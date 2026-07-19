package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"saguaro.local/network-manager/internal/adapters/nftgen"
)

func TestInterfacesList(t *testing.T) {
	srv, c, a := newTestServer(t)
	a.readInterfaces = func(context.Context) ([]nicInfo, error) {
		return []nicInfo{
			{Name: "enp1s0", MAC: "aa:bb:cc:dd:ee:01", State: "up", Carrier: true, SpeedMb: 1000, Driver: "igb", Addresses: []string{"192.168.50.61/24"}},
			{Name: "enp2s0", MAC: "aa:bb:cc:dd:ee:02", State: "down", Carrier: false, Driver: "igb", Addresses: []string{}},
		}, nil
	}
	// role annotation from an enabled gateway config (enp1s0 = WAN)
	if err := a.setGateway(nftgen.Config{AdminNetwork: "192.168.50.0/24", ClientNetwork: "10.10.10.0/24",
		GatewayEnabled: true, WANInterface: "enp1s0", LANInterface: "enp2s0", NATEnabled: true}); err != nil {
		t.Fatal(err)
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	resp, err := c.Get(srv.URL + "/api/interfaces")
	if err != nil {
		t.Fatal(err)
	}
	var nics []nicInfo
	if err := json.NewDecoder(resp.Body).Decode(&nics); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(nics) != 2 || nics[0].Name != "enp1s0" || !nics[0].Carrier {
		t.Fatalf("interface list wrong: %+v", nics)
	}
	// WAN role annotated (gwBody uses enp1s0 as WAN).
	if nics[0].Role != "WAN" {
		t.Fatalf("expected enp1s0 role WAN, got %q", nics[0].Role)
	}
}

func TestInterfaceIdentify(t *testing.T) {
	srv, c, a := newTestServer(t)
	var calls []string
	a.runNet = func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		return []byte("ok"), nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/interfaces/enp1s0/identify", `{"seconds":10}`); r.StatusCode != http.StatusOK {
		t.Fatalf("identify: got %d", r.StatusCode)
	}
	if len(calls) != 1 || calls[0] != "identify enp1s0 10" {
		t.Fatalf("adapter call wrong: %v", calls)
	}
	// invalid name rejected before the adapter runs
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/interfaces/bad%20name/identify", `{}`); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad name: got %d, want 400", r.StatusCode)
	}
	// out-of-range seconds clamped to 10
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/interfaces/enp1s0/identify", `{"seconds":999}`); r.StatusCode != http.StatusOK {
		t.Fatalf("clamp: got %d", r.StatusCode)
	}
	if calls[len(calls)-1] != "identify enp1s0 10" {
		t.Fatalf("seconds not clamped: %v", calls)
	}
}

func TestInterfaceLabel(t *testing.T) {
	srv, c, a := newTestServer(t)
	a.readInterfaces = func(context.Context) ([]nicInfo, error) {
		return []nicInfo{{Name: "enp1s0", MAC: "aa:bb:cc:dd:ee:01", State: "up"}}, nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/interfaces/enp1s0/label", `{"label":"WAN1"}`); r.StatusCode != http.StatusOK {
		t.Fatalf("set label: got %d", r.StatusCode)
	}
	if a.getNICLabels()["enp1s0"] != "WAN1" {
		t.Fatalf("label not stored: %v", a.getNICLabels())
	}
	// the label surfaces on the interfaces list
	resp, _ := c.Get(srv.URL + "/api/interfaces")
	var nics []nicInfo
	json.NewDecoder(resp.Body).Decode(&nics)
	resp.Body.Close()
	if len(nics) != 1 || nics[0].Label != "WAN1" {
		t.Fatalf("label not on interfaces list: %+v", nics)
	}
	// clearing removes it
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/interfaces/enp1s0/label", `{"label":""}`); r.StatusCode != http.StatusOK {
		t.Fatalf("clear label: got %d", r.StatusCode)
	}
	if _, ok := a.getNICLabels()["enp1s0"]; ok {
		t.Fatal("cleared label still present")
	}
	// invalid label rejected
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/interfaces/enp1s0/label", `{"label":"<script>alert(1)</script>"}`); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad label: got %d, want 400", r.StatusCode)
	}
}

func TestInterfaceIdentifyRequiresRole(t *testing.T) {
	srv, admin, a := newTestServer(t)
	a.runNet = func(context.Context, ...string) ([]byte, error) { return nil, nil }
	if r := doLogin(t, srv, admin, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("admin login: %d", r.StatusCode)
	}
	createUser(t, srv, admin, a, "auditor1", roleAuditor)
	aud := loginAs(t, srv, "auditor1", operatorPassword)
	// auditor can list (read) but not identify (firewall:write)
	if r := reqJSON(t, srv, aud, http.MethodGet, "/api/interfaces", ""); r.StatusCode != http.StatusOK {
		t.Fatalf("auditor list: got %d, want 200", r.StatusCode)
	}
	if r := reqJSON(t, srv, aud, http.MethodPost, "/api/interfaces/enp1s0/identify", `{}`); r.StatusCode != http.StatusForbidden {
		t.Fatalf("auditor identify: got %d, want 403", r.StatusCode)
	}
}
