package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"saguaro.local/network-manager/internal/adapters/wireguard"
)

type testServerBundle struct {
	srv *httptest.Server
	c   *http.Client
	a   *app
}

func idsTestServer(t *testing.T) (*testServerBundle, *[]string, *[]string) {
	t.Helper()
	srv, c, a := newTestServer(t)
	var idsCalls, fwCalls []string
	a.runIDS = func(_ context.Context, args ...string) ([]byte, error) {
		idsCalls = append(idsCalls, strings.Join(args, " "))
		return []byte("ok"), nil
	}
	a.runFirewall = func(_ context.Context, action string) ([]byte, error) {
		fwCalls = append(fwCalls, action)
		return []byte("ok"), nil
	}
	a.hwMemMB, a.hwCores = 16384, 8
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	return &testServerBundle{srv: srv, c: c, a: a}, &idsCalls, &fwCalls
}

func TestIDSHardwareGate(t *testing.T) {
	b, _, _ := idsTestServer(t)
	b.a.hwMemMB = 2048
	body := `{"mode":"ids","interface":"enp1s0","homeNet":"","force":false}`
	if r := reqJSON(t, b.srv, b.c, http.MethodPost, "/api/ids/enable", body); r.StatusCode != http.StatusConflict {
		t.Fatalf("low-spec IDS enable: got %d, want 409", r.StatusCode)
	}
}

func TestIDSEnableAndEmergencyOff(t *testing.T) {
	b, idsCalls, _ := idsTestServer(t)
	body := `{"mode":"ids","interface":"enp1s0","homeNet":"192.168.10.0/24","force":false}`
	if r := reqJSON(t, b.srv, b.c, http.MethodPost, "/api/ids/enable", body); r.StatusCode != http.StatusOK {
		t.Fatalf("IDS enable: got %d", r.StatusCode)
	}
	staged, err := os.ReadFile(filepath.Join(filepath.Dir(b.a.store.path), stagedSuricataName))
	if err != nil || !strings.Contains(string(staged), "af-packet:") {
		t.Fatalf("staged suricata config wrong: %v %s", err, staged)
	}
	if len(*idsCalls) != 1 || (*idsCalls)[0] != "apply ids" {
		t.Fatalf("adapter calls wrong: %v", *idsCalls)
	}
	st := b.a.getIDS()
	if st.Mode != "ids" || st.IDSEnabledAt.IsZero() {
		t.Fatalf("state wrong: %+v", st)
	}
	if r := reqJSON(t, b.srv, b.c, http.MethodPost, "/api/ids/disable", "{}"); r.StatusCode != http.StatusOK {
		t.Fatalf("disable: got %d", r.StatusCode)
	}
	if b.a.getIDS().Mode != "off" {
		t.Fatal("disable must set mode off")
	}
}

func TestIPSPreconditionsAndQueueRule(t *testing.T) {
	b, idsCalls, fwCalls := idsTestServer(t)
	// IPS without gateway mode is refused.
	ipsBody := `{"mode":"ips","interface":"enp1s0","homeNet":"","force":true}`
	if r := reqJSON(t, b.srv, b.c, http.MethodPost, "/api/ids/enable", ipsBody); r.StatusCode != http.StatusConflict {
		t.Fatalf("IPS without gateway: got %d, want 409", r.StatusCode)
	}
	// Configure gateway, then enable IDS.
	if r := reqJSON(t, b.srv, b.c, http.MethodPut, "/api/gateway", gwBody); r.StatusCode != http.StatusOK {
		t.Fatalf("gateway config: got %d", r.StatusCode)
	}
	if r := reqJSON(t, b.srv, b.c, http.MethodPost, "/api/ids/enable", `{"mode":"ids","interface":"enp1s0","homeNet":"","force":false}`); r.StatusCode != http.StatusOK {
		t.Fatalf("IDS enable: got %d", r.StatusCode)
	}
	// IPS before the observation period without force is refused...
	if r := reqJSON(t, b.srv, b.c, http.MethodPost, "/api/ids/enable", `{"mode":"ips","interface":"","homeNet":"","force":false}`); r.StatusCode != http.StatusConflict {
		t.Fatalf("IPS before observation period: got %d, want 409", r.StatusCode)
	}
	// ...and allowed with force: suricata switches to ips and the firewall
	// transaction applies the queue rule.
	if r := reqJSON(t, b.srv, b.c, http.MethodPost, "/api/ids/enable", `{"mode":"ips","interface":"","homeNet":"","force":true}`); r.StatusCode != http.StatusOK {
		t.Fatalf("forced IPS enable: got %d", r.StatusCode)
	}
	if (*idsCalls)[len(*idsCalls)-1] != "apply ips" {
		t.Fatalf("expected apply ips, calls: %v", *idsCalls)
	}
	if len(*fwCalls) == 0 || (*fwCalls)[len(*fwCalls)-1] != "apply" {
		t.Fatalf("firewall apply missing: %v", *fwCalls)
	}
	gw, _ := b.a.getGateway()
	if !gw.IPSEnabled {
		t.Fatal("gateway config must record IPSEnabled")
	}
	stagedFW, err := os.ReadFile(filepath.Join(filepath.Dir(b.a.store.path), stagedRulesetName))
	if err != nil || !strings.Contains(string(stagedFW), "queue num 0 bypass") {
		t.Fatalf("staged firewall lacks queue rule: %v", err)
	}
	// Enabling IPS keeps the 120 s window (the operator confirms on the Gateway
	// page), so no confirm may follow the apply here.
	if last := (*fwCalls)[len(*fwCalls)-1]; last != "apply" {
		t.Fatalf("IPS enable must not auto-confirm, calls: %v", *fwCalls)
	}
	// Emergency off removes the queue rule again — and confirms it, because a
	// ruleset that auto-reverts after 120 s would restore the queue rule
	// against a Suricata that is no longer running.
	if r := reqJSON(t, b.srv, b.c, http.MethodPost, "/api/ids/disable", "{}"); r.StatusCode != http.StatusOK {
		t.Fatalf("emergency off: got %d", r.StatusCode)
	}
	gw, _ = b.a.getGateway()
	if gw.IPSEnabled {
		t.Fatal("emergency off must clear IPSEnabled")
	}
	n := len(*fwCalls)
	if n < 2 || (*fwCalls)[n-2] != "apply" || (*fwCalls)[n-1] != "confirm" {
		t.Fatalf("emergency off must apply then confirm, calls: %v", *fwCalls)
	}
	stagedFW, err = os.ReadFile(filepath.Join(filepath.Dir(b.a.store.path), stagedRulesetName))
	if err != nil || strings.Contains(string(stagedFW), "queue num 0 bypass") {
		t.Fatalf("emergency off must stage a ruleset without the queue rule: %v", err)
	}
}

// Toggling IPS regenerates the whole ruleset, so the runtime-injected rules
// (VPN tunnel accepts, geo-block CIDRs, VPN input ports) must survive it —
// rendering from the stored config alone used to drop them.
func TestIPSToggleKeepsRuntimeRules(t *testing.T) {
	b, _, _ := idsTestServer(t)
	if r := reqJSON(t, b.srv, b.c, http.MethodPut, "/api/gateway", gwBody); r.StatusCode != http.StatusOK {
		t.Fatalf("gateway config: got %d", r.StatusCode)
	}
	// A WireGuard listen port is one of the rules injected at generate time and
	// never stored in the gateway config.
	if err := b.a.setVPN(wireguard.Config{Enabled: true, ListenPort: 51820,
		Subnet: "10.8.0.0/24"}); err != nil {
		t.Fatalf("setVPN: %v", err)
	}
	if err := b.a.setGatewayIPS(context.Background(), true, false); err != nil {
		t.Fatalf("setGatewayIPS: %v", err)
	}
	staged, err := os.ReadFile(filepath.Join(filepath.Dir(b.a.store.path), stagedRulesetName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(staged), "queue num 0 bypass") {
		t.Fatalf("queue rule missing:\n%s", staged)
	}
	if !strings.Contains(string(staged), "udp dport 51820 accept") {
		t.Fatalf("VPN port rule dropped by the IPS toggle:\n%s", staged)
	}
}
