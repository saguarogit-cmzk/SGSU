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

func TestFirewallAliasesAndRules(t *testing.T) {
	srv, c, _ := newTestServer(t)
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	// Add aliases.
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/firewall/aliases",
		`{"aliases":[{"name":"servers","type":"host","values":["192.168.10.5"]},{"name":"guests","type":"network","values":["192.168.30.0/24"]}]}`); r.StatusCode != http.StatusOK {
		t.Fatalf("put aliases: got %d", r.StatusCode)
	}
	// A rule referencing an existing alias is accepted.
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/firewall/rules",
		`{"rules":[{"name":"block","action":"drop","proto":"any","srcAlias":"guests","dstAlias":"servers","enabled":true}]}`); r.StatusCode != http.StatusOK {
		t.Fatalf("put rules: got %d", r.StatusCode)
	}
	// A rule referencing an unknown alias is rejected.
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/firewall/rules",
		`{"rules":[{"name":"bad","action":"drop","proto":"any","srcAlias":"nope","enabled":true}]}`); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown alias ref: got %d, want 400", r.StatusCode)
	}
	// GET reflects the persisted objects.
	resp, _ := c.Get(srv.URL + "/api/firewall")
	var view struct {
		Aliases []nftgen.Alias `json:"aliases"`
		Rules   []nftgen.Rule  `json:"rules"`
	}
	json.NewDecoder(resp.Body).Decode(&view)
	resp.Body.Close()
	if len(view.Aliases) != 2 || len(view.Rules) != 1 || view.Rules[0].Name != "block" {
		t.Fatalf("firewall view wrong: %+v", view)
	}
}

func TestFirewallApplyIncludesObjects(t *testing.T) {
	srv, c, a := newTestServer(t)
	var actions []string
	a.runFirewall = func(_ context.Context, action string) ([]byte, error) {
		actions = append(actions, action)
		return []byte("ok"), nil
	}
	// A configured gateway base so the ruleset is valid.
	if err := a.setGateway(nftgen.Config{AdminNetwork: "192.168.50.0/24", ClientNetwork: "10.10.10.0/24",
		GatewayEnabled: true, WANInterface: "enp1", LANInterface: "enp2", NATEnabled: true}); err != nil {
		t.Fatal(err)
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/firewall/aliases",
		`{"aliases":[{"name":"servers","type":"host","values":["192.168.10.5"]}]}`); r.StatusCode != http.StatusOK {
		t.Fatalf("put aliases: got %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/firewall/apply", `{}`); r.StatusCode != http.StatusOK {
		t.Fatalf("apply: got %d", r.StatusCode)
	}
	if len(actions) != 1 || actions[0] != "apply" {
		t.Fatalf("expected apply, got %v", actions)
	}
	staged, err := os.ReadFile(filepath.Join(filepath.Dir(a.store.path), stagedRulesetName))
	if err != nil || !strings.Contains(string(staged), "set alias_servers") {
		t.Fatalf("staged ruleset missing alias set: %v %s", err, staged)
	}
}

func TestGatewayPutPreservesAliases(t *testing.T) {
	srv, c, a := newTestServer(t)
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/firewall/aliases",
		`{"aliases":[{"name":"servers","type":"host","values":["192.168.10.5"]}]}`); r.StatusCode != http.StatusOK {
		t.Fatalf("put aliases: got %d", r.StatusCode)
	}
	// Saving the gateway (whose form omits aliases) must not wipe them.
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/gateway",
		`{"adminNetwork":"192.168.50.0/24","clientNetwork":"10.10.10.0/24","gatewayEnabled":false}`); r.StatusCode != http.StatusOK {
		t.Fatalf("put gateway: got %d", r.StatusCode)
	}
	if cfg, _ := a.getGateway(); len(cfg.Aliases) != 1 {
		t.Fatalf("gateway save wiped aliases: %+v", cfg.Aliases)
	}
}

func TestFirewallTestEndpoint(t *testing.T) {
	srv, c, a := newTestServer(t)
	if err := a.setGateway(nftgen.Config{AdminNetwork: "192.168.50.0/24", ClientNetwork: "192.168.10.0/24",
		Aliases: []nftgen.Alias{
			{Name: "guests", Type: "network", Values: []string{"192.168.30.0/24"}},
			{Name: "servers", Type: "host", Values: []string{"192.168.10.5"}},
		},
		Rules: []nftgen.Rule{{Name: "block", Action: "drop", Proto: "any", SrcAlias: "guests", DstAlias: "servers", Enabled: true}},
	}); err != nil {
		t.Fatal(err)
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	r := reqJSON(t, srv, c, http.MethodPost, "/api/firewall/test", `{"src":"192.168.30.10","dst":"192.168.10.5","proto":"tcp","dstPort":443}`)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("test: got %d", r.StatusCode)
	}
	var res nftgen.RuleEval
	json.NewDecoder(r.Body).Decode(&res)
	r.Body.Close()
	if !res.Matched || res.Action != "drop" || res.RuleName != "block" {
		t.Fatalf("evaluation wrong: %+v", res)
	}
}

func TestFirewallRequiresRole(t *testing.T) {
	srv, admin, a := newTestServer(t)
	if r := doLogin(t, srv, admin, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("admin login: %d", r.StatusCode)
	}
	createUser(t, srv, admin, a, "auditor1", roleAuditor)
	aud := loginAs(t, srv, "auditor1", operatorPassword)
	if r := reqJSON(t, srv, aud, http.MethodGet, "/api/firewall", ""); r.StatusCode != http.StatusOK {
		t.Fatalf("auditor get: got %d, want 200", r.StatusCode)
	}
	if r := reqJSON(t, srv, aud, http.MethodPut, "/api/firewall/aliases",
		`{"aliases":[]}`); r.StatusCode != http.StatusForbidden {
		t.Fatalf("auditor put: got %d, want 403", r.StatusCode)
	}
}
