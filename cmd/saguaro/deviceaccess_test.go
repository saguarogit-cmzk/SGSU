package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"saguaro.local/network-manager/internal/adapters/nftgen"
)

// The first time the page is opened there is no stored matrix, so the API must
// derive one from the settings in force — otherwise the operator would be shown
// an empty grid that does not describe the running appliance.
func TestDeviceAccessDerivesCurrentState(t *testing.T) {
	srv, c, _ := newTestServer(t)
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/gateway",
		`{"adminNetwork":"","clientNetwork":"10.10.10.0/24","gatewayEnabled":true,"wanInterface":"wan1","lanInterface":"lan0","natEnabled":true,"dhcpInterface":"lan0","mgmtOnLan":true,"mgmtOnWan":true}`); r.StatusCode != http.StatusOK {
		t.Fatalf("gateway put: got %d", r.StatusCode)
	}
	resp, err := c.Get(srv.URL + "/api/device-access")
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Zones   []accessZone        `json:"zones"`
		ACLs    []nftgen.ServiceACL `json:"acls"`
		Derived bool                `json:"derived"`
	}
	json.NewDecoder(resp.Body).Decode(&got)
	resp.Body.Close()
	if !got.Derived {
		t.Error("an empty matrix must be reported as derived")
	}
	byZone := map[string]nftgen.ServiceACL{}
	for _, r := range got.ACLs {
		byZone[r.Zone] = r
	}
	if !byZone["wan"].HTTPS || !byZone["wan"].SSH {
		t.Errorf("mgmtOnWan must show as WAN management: %+v", byZone["wan"])
	}
	if !byZone["lan"].DNS || !byZone["lan"].DHCP {
		t.Errorf("LAN row should carry DNS and DHCP: %+v", byZone["lan"])
	}
	var wanZone *accessZone
	for i := range got.Zones {
		if got.Zones[i].Zone == "wan" {
			wanZone = &got.Zones[i]
		}
	}
	if wanZone == nil || !wanZone.Untrusted {
		t.Errorf("the WAN row must be flagged untrusted: %+v", wanZone)
	}
}

// Saving a matrix must persist it, refuse unknown zones, and refuse one that
// would lock everyone out.
func TestDeviceAccessPut(t *testing.T) {
	srv, c, a := newTestServer(t)
	a.runFirewall = func(context.Context, string) ([]byte, error) { return []byte("ok"), nil }
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/gateway",
		`{"adminNetwork":"","clientNetwork":"10.10.10.0/24","gatewayEnabled":true,"wanInterface":"wan1","lanInterface":"lan0","natEnabled":true,"mgmtOnLan":true,"mgmtOnWan":true}`); r.StatusCode != http.StatusOK {
		t.Fatalf("gateway put: got %d", r.StatusCode)
	}
	// Management off the WAN, kept on the LAN.
	body := `{"acls":[{"zone":"lan","https":true,"ssh":true,"dns":true,"ping":true},{"zone":"wan","ping":false}]}`
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/device-access", body); r.StatusCode != http.StatusOK {
		t.Fatalf("device access put: got %d", r.StatusCode)
	}
	cfg, _ := a.getGateway()
	if len(cfg.ServiceACLs) != 2 {
		t.Fatalf("matrix not persisted: %+v", cfg.ServiceACLs)
	}
	if cfg.ServiceACLs[0].Zone != "lan" || !cfg.ServiceACLs[0].HTTPS {
		t.Fatalf("LAN row wrong: %+v", cfg.ServiceACLs[0])
	}
	// The generated ruleset must no longer open management on the WAN.
	text, err := cfg.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if containsStr(text, `iifname "wan1" tcp dport`) {
		t.Errorf("WAN management still present:\n%s", text)
	}

	// An unknown zone is rejected.
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/device-access",
		`{"acls":[{"zone":"ghost","https":true}]}`); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown zone: got %d, want 400", r.StatusCode)
	}
	// A matrix with no management path anywhere is rejected.
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/device-access",
		`{"acls":[{"zone":"lan","dns":true},{"zone":"wan"}]}`); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("lockout matrix: got %d, want 400", r.StatusCode)
	}
	// The earlier configuration must survive the rejected attempts.
	cfg, _ = a.getGateway()
	if len(cfg.ServiceACLs) != 2 || !cfg.ServiceACLs[0].HTTPS {
		t.Fatalf("rejected save must not change stored matrix: %+v", cfg.ServiceACLs)
	}
}

func containsStr(haystack, needle string) bool { return strings.Contains(haystack, needle) }
