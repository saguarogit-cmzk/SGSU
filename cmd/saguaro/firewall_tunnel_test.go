package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"saguaro.local/network-manager/internal/adapters/ipsec"
	"saguaro.local/network-manager/internal/adapters/nftgen"
	"saguaro.local/network-manager/internal/adapters/s2s"
)

func TestFirewallIncludesTunnelRules(t *testing.T) {
	srv, c, a := newTestServer(t)
	var actions []string
	a.runFirewall = func(_ context.Context, action string) ([]byte, error) {
		actions = append(actions, action)
		return []byte("ok"), nil
	}
	if err := a.setGateway(nftgen.Config{AdminNetwork: "192.168.50.0/24", ClientNetwork: "10.10.10.0/24",
		GatewayEnabled: true, WANInterface: "enp1", LANInterface: "enp2", NATEnabled: true}); err != nil {
		t.Fatal(err)
	}
	// Enabled WireGuard site-to-site and IPsec tunnels contribute forward rules.
	if err := a.setS2S(s2s.Config{Enabled: true, LocalNetworks: []string{"192.168.10.0/24"},
		Sites: []s2s.Site{{Name: "b", RemoteNetworks: []string{"192.168.20.0/24"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := a.setIPsec(ipsec.Config{Enabled: true,
		Connections: []ipsec.Connection{{Name: "c", LocalSubnets: []string{"10.0.0.0/24"}, RemoteSubnets: []string{"10.9.0.0/24"}}}}); err != nil {
		t.Fatal(err)
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/firewall/apply", `{}`); r.StatusCode != http.StatusOK {
		t.Fatalf("apply: got %d", r.StatusCode)
	}
	if len(actions) != 1 || actions[0] != "apply" {
		t.Fatalf("expected apply, got %v", actions)
	}
	staged, err := os.ReadFile(filepath.Join(filepath.Dir(a.store.path), stagedRulesetName))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`ip saddr 192.168.10.0/24 ip daddr 192.168.20.0/24 counter accept comment "tunnel"`, // WireGuard s2s
		`ip saddr 10.0.0.0/24 ip daddr 10.9.0.0/24 counter accept comment "tunnel"`,         // IPsec
	} {
		if !strings.Contains(string(staged), want) {
			t.Fatalf("staged ruleset missing tunnel rule %q:\n%s", want, staged)
		}
	}
	// Disabled tunnels contribute nothing.
	if err := a.setS2S(s2s.Config{Enabled: false, LocalNetworks: []string{"192.168.10.0/24"},
		Sites: []s2s.Site{{Name: "b", RemoteNetworks: []string{"192.168.20.0/24"}}}}); err != nil {
		t.Fatal(err)
	}
	if len(a.tunnelNets()) != 1 { // only the IPsec one remains
		t.Fatalf("disabled s2s still contributes: %d", len(a.tunnelNets()))
	}
}
