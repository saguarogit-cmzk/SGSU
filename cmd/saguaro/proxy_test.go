package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const proxyAppsBody = `{"apps":[{"name":"wiki","hostname":"wiki.example.internal","upstreamIp":"192.168.10.5","upstreamPort":8080,"tls":"appliance","certPath":"","keyPath":"","allowCidrs":["192.168.10.0/24"],"webSocket":false}],"force":false}`

func TestProxyPublishFlow(t *testing.T) {
	srv, c, a := newTestServer(t)
	var actions []string
	probeOK := true
	a.runProxy = func(_ context.Context, action string) ([]byte, error) {
		actions = append(actions, action)
		return []byte("ok"), nil
	}
	a.probeUpstream = func(_ context.Context, addr string) error {
		if !probeOK {
			return fmt.Errorf("connection refused (%s)", addr)
		}
		return nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}

	// Unreachable upstream is refused without force...
	probeOK = false
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/proxy/apply", proxyAppsBody); r.StatusCode != http.StatusConflict {
		t.Fatalf("unreachable upstream: got %d, want 409", r.StatusCode)
	}
	if len(actions) != 0 {
		t.Fatal("adapter must not run when the probe fails")
	}
	// ...and allowed with force.
	forced := strings.Replace(proxyAppsBody, `"force":false`, `"force":true`, 1)
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/proxy/apply", forced); r.StatusCode != http.StatusOK {
		t.Fatalf("forced publish: got %d", r.StatusCode)
	}
	staged, err := os.ReadFile(filepath.Join(filepath.Dir(a.store.path), stagedProxyName))
	if err != nil || !strings.Contains(string(staged), "server_name wiki.example.internal;") {
		t.Fatalf("staged vhost wrong: %v %s", err, staged)
	}
	if apps := a.getProxyApps(); len(apps) != 1 || apps[0].Name != "wiki" {
		t.Fatalf("persisted apps wrong: %+v", apps)
	}

	// Reachable upstream publishes without force.
	probeOK = true
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/proxy/apply", proxyAppsBody); r.StatusCode != http.StatusOK {
		t.Fatalf("publish: got %d", r.StatusCode)
	}
	// Emptying the list calls disable.
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/proxy/apply", `{"apps":[],"force":false}`); r.StatusCode != http.StatusOK {
		t.Fatalf("unpublish all: got %d", r.StatusCode)
	}
	if strings.Join(actions, ",") != "apply,apply,disable" {
		t.Fatalf("adapter sequence wrong: %v", actions)
	}
	if len(a.getProxyApps()) != 0 {
		t.Fatal("apps must be cleared")
	}
}

func TestProxyRequiresRole(t *testing.T) {
	srv, admin, a := newTestServer(t)
	a.runProxy = func(_ context.Context, _ string) ([]byte, error) { return nil, nil }
	a.probeUpstream = func(_ context.Context, _ string) error { return nil }
	if r := doLogin(t, srv, admin, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("admin login: %d", r.StatusCode)
	}
	createUser(t, srv, admin, a, "dnsp", roleDNSOperator)
	dns := loginAs(t, srv, "dnsp", operatorPassword)
	if r := reqJSON(t, srv, dns, http.MethodPost, "/api/proxy/apply", proxyAppsBody); r.StatusCode != http.StatusForbidden {
		t.Fatalf("dns-operator proxy apply: got %d, want 403", r.StatusCode)
	}
	createUser(t, srv, admin, a, "netp", roleNetworkOperator)
	netop := loginAs(t, srv, "netp", operatorPassword)
	if r := reqJSON(t, srv, netop, http.MethodPost, "/api/proxy/apply", proxyAppsBody); r.StatusCode != http.StatusOK {
		t.Fatalf("network-operator proxy apply: got %d, want 200", r.StatusCode)
	}
}
