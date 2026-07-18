package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const vpnSettings = `{"enabled":true,"subnet":"10.8.0.0/24","listenPort":51820,"endpoint":"vpn.example.com:51820","dns":"192.168.10.1","splitNetworks":["192.168.10.0/24"]}`

func TestVPNApplyAndPeers(t *testing.T) {
	srv, c, a := newTestServer(t)
	var actions []string
	a.runVPN = func(_ context.Context, action string) ([]byte, error) {
		actions = append(actions, action)
		return []byte("ok"), nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}

	// Enable: generates and seals the server keypair, stages wg0.conf.
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/vpn/apply", vpnSettings); r.StatusCode != http.StatusOK {
		t.Fatalf("vpn apply: got %d", r.StatusCode)
	}
	cfg := a.getVPN()
	if cfg.ServerPub == "" || cfg.ServerPrivEnc == "" || strings.Contains(cfg.ServerPrivEnc, cfg.ServerPub) {
		t.Fatalf("server keys wrong: %+v", cfg)
	}
	staged, err := os.ReadFile(filepath.Join(filepath.Dir(a.store.path), stagedWGName))
	if err != nil || !strings.Contains(string(staged), "PrivateKey = ") || !strings.Contains(string(staged), "ListenPort = 51820") {
		t.Fatalf("staged wg0.conf wrong: %v %s", err, staged)
	}

	// Peer creation returns a one-time client config + QR and re-applies.
	addPeer := func(body string) (int, map[string]any) {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/vpn/peers", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrfCookie(t, srv, c))
		res, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(res.Body).Decode(&out)
		return res.StatusCode, out
	}
	code, out := addPeer(`{"name":"ana-laptop","fullTunnel":false,"expireDays":30}`)
	if code != http.StatusOK {
		t.Fatalf("peer add: got %d", code)
	}
	conf, _ := out["clientConf"].(string)
	if !strings.Contains(conf, "PrivateKey = ") || !strings.Contains(conf, "AllowedIPs = 10.8.0.0/24, 192.168.10.0/24") {
		t.Fatalf("client conf wrong:\n%s", conf)
	}
	if qr, _ := out["qrPng"].(string); qr == "" {
		t.Fatal("QR code missing")
	}
	// The client private key must not be persisted anywhere in state.
	priv := ""
	for _, line := range strings.Split(conf, "\n") {
		if strings.HasPrefix(line, "PrivateKey = ") {
			priv = strings.TrimPrefix(line, "PrivateKey = ")
		}
	}
	stateRaw, _ := os.ReadFile(a.store.path)
	if priv == "" || strings.Contains(string(stateRaw), priv) {
		t.Fatal("client private key leaked into state.json")
	}
	if cfg := a.getVPN(); len(cfg.Peers) != 1 || cfg.Peers[0].Address != "10.8.0.2" || cfg.Peers[0].ExpiresAt.IsZero() {
		t.Fatalf("peer state wrong: %+v", cfg.Peers)
	}

	// Duplicate name refused; second peer gets the next address.
	if code, _ := addPeer(`{"name":"ana-laptop","fullTunnel":true,"expireDays":0}`); code != http.StatusConflict {
		t.Fatalf("duplicate peer: got %d, want 409", code)
	}
	if code, _ := addPeer(`{"name":"marko-mobitel","fullTunnel":true,"expireDays":0}`); code != http.StatusOK {
		t.Fatalf("second peer: got %d", code)
	}
	if cfg := a.getVPN(); cfg.Peers[1].Address != "10.8.0.3" {
		t.Fatalf("address allocation wrong: %+v", cfg.Peers)
	}

	// Delete re-applies and removes state.
	if r := reqJSON(t, srv, c, http.MethodDelete, "/api/vpn/peers/ana-laptop", ""); r.StatusCode != http.StatusOK {
		t.Fatalf("peer delete: got %d", r.StatusCode)
	}
	if cfg := a.getVPN(); len(cfg.Peers) != 1 || cfg.Peers[0].Name != "marko-mobitel" {
		t.Fatalf("peer delete state wrong: %+v", cfg.Peers)
	}
	// apply sequence: settings + 3 successful mutations that re-apply.
	if strings.Join(actions, ",") != "apply,apply,apply,apply" {
		t.Fatalf("adapter sequence wrong: %v", actions)
	}
}

func TestVPNPeerRequiresEnabledConfig(t *testing.T) {
	srv, c, a := newTestServer(t)
	a.runVPN = func(_ context.Context, _ string) ([]byte, error) { return nil, nil }
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/vpn/peers", `{"name":"x","fullTunnel":false,"expireDays":0}`); r.StatusCode != http.StatusConflict {
		t.Fatalf("peer before enable: got %d, want 409", r.StatusCode)
	}
}

func TestVPNRequiresFirewallRole(t *testing.T) {
	srv, admin, a := newTestServer(t)
	a.runVPN = func(_ context.Context, _ string) ([]byte, error) { return nil, nil }
	if r := doLogin(t, srv, admin, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("admin login: %d", r.StatusCode)
	}
	createUser(t, srv, admin, a, "dnsv", roleDNSOperator)
	dns := loginAs(t, srv, "dnsv", operatorPassword)
	if r := reqJSON(t, srv, dns, http.MethodPost, "/api/vpn/apply", vpnSettings); r.StatusCode != http.StatusForbidden {
		t.Fatalf("dns-operator vpn apply: got %d, want 403", r.StatusCode)
	}
}
