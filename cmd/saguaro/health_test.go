package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"testing"
)

func healthApp() *app { return &app{} }

func TestCheckPDNS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "good-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"version":"4.8.3"}`))
	}))
	defer srv.Close()

	a := healthApp()
	if r := a.checkPDNS(context.Background()); r.Status != "not-configured" {
		t.Fatalf("unconfigured: got %q", r.Status)
	}
	a.pdnsURL, a.pdnsKey = srv.URL, "good-key"
	if r := a.checkPDNS(context.Background()); r.Status != "healthy" {
		t.Fatalf("valid key: got %q (%s)", r.Status, r.Detail)
	}
	a.pdnsKey = "bad-key"
	if r := a.checkPDNS(context.Background()); r.Status != "error" || r.Detail != "API key rejected" {
		t.Fatalf("bad key: got %q (%s)", r.Status, r.Detail)
	}
}

func TestCheckKea(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "saguaro" || p != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`[{"result":0,"text":"running"}]`))
	}))
	defer srv.Close()

	a := healthApp()
	if r := a.checkKea(context.Background(), "kea", "dhcp4"); r.Status != "not-configured" {
		t.Fatalf("unconfigured: got %q", r.Status)
	}
	a.keaURL, a.keaUser, a.keaPass = srv.URL, "saguaro", "secret"
	if r := a.checkKea(context.Background(), "kea", "dhcp4"); r.Status != "healthy" {
		t.Fatalf("valid: got %q (%s)", r.Status, r.Detail)
	}
	a.keaPass = "wrong"
	if r := a.checkKea(context.Background(), "kea", "dhcp4"); r.Status != "error" {
		t.Fatalf("bad credentials: got %q", r.Status)
	}
}

func TestCheckKeaServiceFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`[{"result":1,"text":"dhcp4 not running"}]`))
	}))
	defer srv.Close()
	a := healthApp()
	a.keaURL, a.keaUser, a.keaPass = srv.URL, "u", "p"
	if r := a.checkKea(context.Background(), "kea", "dhcp4"); r.Status != "error" {
		t.Fatalf("result 1: got %q (%s)", r.Status, r.Detail)
	}
}

func TestCheckUnbound(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	a := healthApp()
	a.resolverAddr = ln.Addr().String()
	if r := a.checkUnbound(context.Background()); r.Status != "healthy" {
		t.Fatalf("listening: got %q (%s)", r.Status, r.Detail)
	}
	addr := ln.Addr().String()
	ln.Close()
	a.resolverAddr = addr
	if r := a.checkUnbound(context.Background()); r.Status != "error" {
		t.Fatalf("closed port: got %q", r.Status)
	}
}

func TestCheckSystemdUnitWithoutSystemctl(t *testing.T) {
	if _, err := exec.LookPath("systemctl"); err == nil {
		t.Skip("systemctl present; behaviour covered on real hosts")
	}
	if r := checkSystemdUnit(context.Background(), "nginx", "nginx"); r.Status != "unknown" {
		t.Fatalf("no systemctl: got %q", r.Status)
	}
}
