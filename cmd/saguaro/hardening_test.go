package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

const hardStatusWeak = `ssh_password_auth=yes
ssh_root_login=without-password
ssh_x11=yes
ssh_max_auth_tries=6
ssh_keys_installed=0
ssh_dropin=no
sysctl_send_redirects=1
sysctl_accept_redirects=1
sysctl_accept_source_route=0
sysctl_log_martians=0
sysctl_syncookies=1
sysctl_dropin=no
suricata_installed=no
journal_retention=30day
`

const hardStatusStrong = `ssh_password_auth=no
ssh_root_login=no
ssh_x11=no
ssh_max_auth_tries=3
ssh_keys_installed=2
ssh_dropin=yes
sysctl_send_redirects=0
sysctl_accept_redirects=0
sysctl_accept_source_route=0
sysctl_log_martians=1
sysctl_syncookies=1
sysctl_dropin=yes
suricata_installed=yes
journal_retention=90day
`

// A weak host must be reported as failing on the items the audit called
// critical, and the SSH item must warn that no key is installed.
func TestHardeningReportsWeakHost(t *testing.T) {
	srv, c, a := newTestServer(t)
	a.runHarden = func(context.Context, string) ([]byte, error) { return []byte(hardStatusWeak), nil }
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/gateway",
		`{"adminNetwork":"","clientNetwork":"10.10.10.0/24","gatewayEnabled":true,"wanInterface":"enp1s0","lanInterface":"enp2s0","natEnabled":true,"mgmtOnWan":true,"mgmtOnLan":true}`); r.StatusCode != http.StatusOK {
		t.Fatalf("gateway put: got %d", r.StatusCode)
	}
	resp, err := c.Get(srv.URL + "/api/hardening")
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Checks  []hardeningCheck `json:"checks"`
		Summary map[string]int   `json:"summary"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	byKey := map[string]hardeningCheck{}
	for _, c := range out.Checks {
		byKey[c.Key] = c
	}
	for _, k := range []string{"ssh_password", "ssh_root", "mgmt_wan", "backup_drill"} {
		if byKey[k].Status != "fail" {
			t.Errorf("%s: got %q, want fail (%+v)", k, byKey[k].Status, byKey[k])
		}
	}
	if !strings.Contains(byKey["ssh_password"].Detail, "ključ") {
		t.Errorf("SSH item must warn about the missing key: %q", byKey["ssh_password"].Detail)
	}
	if byKey["ssh_keys"].Status != "warn" {
		t.Errorf("missing key must warn, got %q", byKey["ssh_keys"].Status)
	}
	if byKey["sysctl"].Status != "warn" || byKey["sysctl"].Fix != "sysctl" {
		t.Errorf("kernel item wrong: %+v", byKey["sysctl"])
	}
	if out.Summary["fail"] < 3 {
		t.Errorf("summary should count the failures: %+v", out.Summary)
	}
}

// A hardened host reports the same items as satisfied.
func TestHardeningReportsStrongHost(t *testing.T) {
	srv, c, a := newTestServer(t)
	a.runHarden = func(context.Context, string) ([]byte, error) { return []byte(hardStatusStrong), nil }
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/gateway",
		`{"adminNetwork":"192.168.50.0/24","clientNetwork":"10.10.10.0/24","gatewayEnabled":true,"wanInterface":"enp1s0","lanInterface":"enp2s0","natEnabled":true,"mgmtOnLan":true,"bruteForceProtect":true}`); r.StatusCode != http.StatusOK {
		t.Fatalf("gateway put: got %d", r.StatusCode)
	}
	resp, _ := c.Get(srv.URL + "/api/hardening")
	var out struct {
		Checks []hardeningCheck `json:"checks"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	byKey := map[string]hardeningCheck{}
	for _, c := range out.Checks {
		byKey[c.Key] = c
	}
	for _, k := range []string{"ssh_password", "ssh_root", "ssh_keys", "mgmt_wan", "admin_net", "brute", "sysctl"} {
		if byKey[k].Status != "ok" {
			t.Errorf("%s: got %q, want ok (%+v)", k, byKey[k].Status, byKey[k])
		}
	}
}

// The adapter owns the anti-lockout rule; when it refuses, the API must pass
// that refusal through instead of reporting success.
func TestHardeningApplyRefusalSurfaces(t *testing.T) {
	srv, c, a := newTestServer(t)
	var called []string
	a.runHarden = func(_ context.Context, action string) ([]byte, error) {
		called = append(called, action)
		if action == "ssh-harden" {
			return []byte("refusing: no SSH key is installed for any account that can become root."), errors.New("exit 1")
		}
		return []byte("ok"), nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/hardening/apply", `{"target":"ssh"}`); r.StatusCode != http.StatusBadGateway {
		t.Fatalf("refused SSH hardening: got %d, want 502", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/hardening/apply", `{"target":"sysctl"}`); r.StatusCode != http.StatusOK {
		t.Fatalf("sysctl hardening: got %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/hardening/apply", `{"target":"ssh","revert":true}`); r.StatusCode != http.StatusOK {
		t.Fatalf("ssh revert: got %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/hardening/apply", `{"target":"nonsense"}`); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown target: got %d, want 400", r.StatusCode)
	}
	want := []string{"ssh-harden", "sysctl-harden", "ssh-revert"}
	if len(called) != len(want) {
		t.Fatalf("adapter actions wrong: %v", called)
	}
	for i, w := range want {
		if called[i] != w {
			t.Fatalf("action %d = %q, want %q", i, called[i], w)
		}
	}
}

// Off-site backup is a recommendation for small sites, not a hard failure —
// the operator may keep the encrypted archive and key on removable media.
func TestHardeningOffsiteBackupIsAdvisory(t *testing.T) {
	srv, c, a := newTestServer(t)
	a.runHarden = func(context.Context, string) ([]byte, error) { return []byte(hardStatusStrong), nil }
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	resp, _ := c.Get(srv.URL + "/api/hardening")
	var out struct {
		Checks []hardeningCheck `json:"checks"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	for _, ch := range out.Checks {
		if ch.Key == "backup_offsite" && ch.Status != "warn" {
			t.Fatalf("off-site backup must warn, not fail: %+v", ch)
		}
	}
}
