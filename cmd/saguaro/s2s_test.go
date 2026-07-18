package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"saguaro.local/network-manager/internal/adapters/wireguard"
)

func TestS2SApplyAndSite(t *testing.T) {
	srv, c, a := newTestServer(t)
	var actions []string
	a.runS2S = func(_ context.Context, action string) ([]byte, error) {
		actions = append(actions, action)
		return []byte("ok"), nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}

	// Enable the interface: generates + seals the keypair, stages wgs2s.conf.
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/s2s/apply",
		`{"enabled":true,"listenPort":51821,"tunnelAddress":"10.9.0.1/30","localNetworks":["192.168.10.0/24"]}`); r.StatusCode != http.StatusOK {
		t.Fatalf("s2s apply: got %d", r.StatusCode)
	}
	cfg := a.getS2S()
	if cfg.ServerPub == "" || cfg.ServerPrivEnc == "" {
		t.Fatalf("server keys not generated: %+v", cfg)
	}
	staged, err := os.ReadFile(filepath.Join(filepath.Dir(a.store.path), stagedS2SName))
	if err != nil || !strings.Contains(string(staged), "ListenPort = 51821") || !strings.Contains(string(staged), "PrivateKey = ") {
		t.Fatalf("staged wgs2s.conf wrong: %v %s", err, staged)
	}

	// Add a remote site with a preshared key.
	_, pub, _ := wireguard.GenerateKeypair()
	_, psk, _ := wireguard.GenerateKeypair()
	body := `{"name":"ured-zg","pubKey":"` + pub + `","endpoint":"203.0.113.5:51821","remoteNetworks":["192.168.20.0/24"],"keepalive":25,"psk":"` + psk + `"}`
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/s2s/sites", body); r.StatusCode != http.StatusOK {
		t.Fatalf("add site: got %d", r.StatusCode)
	}
	cfg = a.getS2S()
	if len(cfg.Sites) != 1 || cfg.Sites[0].Name != "ured-zg" {
		t.Fatalf("site not persisted: %+v", cfg.Sites)
	}
	if cfg.Sites[0].PSKEnc == "" || cfg.Sites[0].PSKEnc == psk {
		t.Fatalf("psk not sealed: %q", cfg.Sites[0].PSKEnc)
	}
	staged, _ = os.ReadFile(filepath.Join(filepath.Dir(a.store.path), stagedS2SName))
	for _, want := range []string{"PublicKey = " + pub, "AllowedIPs = 192.168.20.0/24", "PresharedKey = ", "Endpoint = 203.0.113.5:51821"} {
		if !strings.Contains(string(staged), want) {
			t.Fatalf("staged conf missing %q:\n%s", want, staged)
		}
	}
	// the view must not leak the sealed PSK, only report its presence
	resp, _ := c.Get(srv.URL + "/api/s2s")
	var view map[string]any
	json.NewDecoder(resp.Body).Decode(&view)
	resp.Body.Close()
	if b, _ := json.Marshal(view); strings.Contains(string(b), cfg.Sites[0].PSKEnc) {
		t.Fatal("view leaked the sealed PSK")
	}

	// Delete the site.
	if r := reqJSON(t, srv, c, http.MethodDelete, "/api/s2s/sites/ured-zg", ""); r.StatusCode != http.StatusOK {
		t.Fatalf("delete site: got %d", r.StatusCode)
	}
	if len(a.getS2S().Sites) != 0 {
		t.Fatalf("site not deleted")
	}
}

func TestS2SSiteRequiresEnabled(t *testing.T) {
	srv, c, a := newTestServer(t)
	a.runS2S = func(context.Context, string) ([]byte, error) { return nil, nil }
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	_, pub, _ := wireguard.GenerateKeypair()
	body := `{"name":"x","pubKey":"` + pub + `","remoteNetworks":["10.0.0.0/8"]}`
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/s2s/sites", body); r.StatusCode != http.StatusConflict {
		t.Fatalf("add site before enable: got %d, want 409", r.StatusCode)
	}
}

func TestS2SRequiresRole(t *testing.T) {
	srv, admin, a := newTestServer(t)
	a.runS2S = func(context.Context, string) ([]byte, error) { return nil, nil }
	if r := doLogin(t, srv, admin, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("admin login: %d", r.StatusCode)
	}
	createUser(t, srv, admin, a, "auditor1", roleAuditor)
	aud := loginAs(t, srv, "auditor1", operatorPassword)
	if r := reqJSON(t, srv, aud, http.MethodGet, "/api/s2s", ""); r.StatusCode != http.StatusOK {
		t.Fatalf("auditor get: got %d, want 200", r.StatusCode)
	}
	if r := reqJSON(t, srv, aud, http.MethodPost, "/api/s2s/apply", `{"enabled":true}`); r.StatusCode != http.StatusForbidden {
		t.Fatalf("auditor apply: got %d, want 403", r.StatusCode)
	}
}
