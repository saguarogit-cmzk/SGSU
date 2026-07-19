package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"saguaro.local/network-manager/internal/adapters/nftgen"
)

const gwBody = `{"adminNetwork":"192.168.10.0/24","clientNetwork":"192.168.10.0/24","dhcpInterface":"","gatewayEnabled":true,"wanInterface":"enp1s0","lanInterface":"enp2s0","natEnabled":true,"portForwards":[{"proto":"tcp","extPort":8443,"destIp":"192.168.10.5","destPort":443}]}`

func TestGatewayConfigureAndApply(t *testing.T) {
	srv, c, a := newTestServer(t)
	var actions []string
	a.runFirewall = func(_ context.Context, action string) ([]byte, error) {
		actions = append(actions, action)
		return []byte("ok"), nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}

	// Invalid config rejected.
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/gateway", `{"adminNetwork":"","clientNetwork":"192.168.10.0/24","dhcpInterface":"","gatewayEnabled":false,"wanInterface":"","lanInterface":"","natEnabled":false,"portForwards":[]}`); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid gateway config: got %d, want 400", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/gateway", gwBody); r.StatusCode != http.StatusOK {
		t.Fatalf("valid gateway config: got %d", r.StatusCode)
	}

	// Preview shows the generated ruleset.
	resp, err := c.Get(srv.URL + "/api/gateway/preview")
	if err != nil {
		t.Fatal(err)
	}
	var prev struct {
		Ruleset string `json:"ruleset"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&prev); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !strings.Contains(prev.Ruleset, "table ip saguaro-nat") || !strings.Contains(prev.Ruleset, "dnat to 192.168.10.5:443") {
		t.Fatalf("preview incomplete:\n%s", prev.Ruleset)
	}

	// Apply stages the ruleset and calls the root adapter.
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/gateway/apply", "{}"); r.StatusCode != http.StatusOK {
		t.Fatalf("apply: got %d", r.StatusCode)
	}
	staged, err := os.ReadFile(filepath.Join(filepath.Dir(a.store.path), stagedRulesetName))
	if err != nil {
		t.Fatalf("staged ruleset missing: %v", err)
	}
	if !strings.Contains(string(staged), "masquerade") {
		t.Fatal("staged ruleset content wrong")
	}
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/gateway/confirm", "{}"); r.StatusCode != http.StatusOK {
		t.Fatalf("confirm: got %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/gateway/rollback", "{}"); r.StatusCode != http.StatusOK {
		t.Fatalf("rollback: got %d", r.StatusCode)
	}
	if strings.Join(actions, ",") != "apply,confirm,rollback" {
		t.Fatalf("adapter call sequence wrong: %v", actions)
	}
}

// TestGatewayPutPreservesIPS guards against the regression where saving the
// gateway form (which omits the IPS toggle) silently cleared IPSEnabled and
// dropped the inline-IPS NFQUEUE rule on the next apply.
func TestGatewayPutPreservesIPS(t *testing.T) {
	srv, c, a := newTestServer(t)
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	// Simulate IPS having been enabled by the IDS module.
	if err := a.setGateway(nftgen.Config{AdminNetwork: "192.168.10.0/24", ClientNetwork: "192.168.10.0/24",
		GatewayEnabled: true, WANInterface: "enp1s0", LANInterface: "enp2s0", NATEnabled: true, IPSEnabled: true}); err != nil {
		t.Fatal(err)
	}
	// Saving the gateway (whose form carries no ipsEnabled) must not disable IPS.
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/gateway", gwBody); r.StatusCode != http.StatusOK {
		t.Fatalf("put gateway: got %d", r.StatusCode)
	}
	if cfg, _ := a.getGateway(); !cfg.IPSEnabled {
		t.Fatal("gateway save cleared IPSEnabled (inline IPS would be silently disabled)")
	}
}

func TestGatewayApplyRequiresFirewallRole(t *testing.T) {
	srv, admin, a := newTestServer(t)
	a.runFirewall = func(_ context.Context, _ string) ([]byte, error) { return nil, nil }
	if r := doLogin(t, srv, admin, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("admin login: %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, admin, http.MethodPut, "/api/gateway", gwBody); r.StatusCode != http.StatusOK {
		t.Fatalf("admin gateway config: got %d", r.StatusCode)
	}
	createUser(t, srv, admin, a, "dnsonly", roleDNSOperator)
	dns := loginAs(t, srv, "dnsonly", operatorPassword)
	if r := reqJSON(t, srv, dns, http.MethodPost, "/api/gateway/apply", "{}"); r.StatusCode != http.StatusForbidden {
		t.Fatalf("dns-operator firewall apply: got %d, want 403", r.StatusCode)
	}
	createUser(t, srv, admin, a, "netops", roleNetworkOperator)
	net := loginAs(t, srv, "netops", operatorPassword)
	if r := reqJSON(t, srv, net, http.MethodPost, "/api/gateway/apply", "{}"); r.StatusCode != http.StatusOK {
		t.Fatalf("network-operator firewall apply: got %d, want 200", r.StatusCode)
	}
}
