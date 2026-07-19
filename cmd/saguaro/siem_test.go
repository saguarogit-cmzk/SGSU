package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSIEMForwardUDP(t *testing.T) {
	srv, c, a := newTestServer(t)
	a.siem = newSIEMForwarder("gw", "test", a.log)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	port := pc.LocalAddr().(*net.UDPAddr).Port

	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	body := fmt.Sprintf(`{"enabled":true,"protocol":"udp","host":"127.0.0.1","port":%d,"format":"rfc5424","minSeverity":"info"}`, port)
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/siem", body); r.StatusCode != http.StatusOK {
		t.Fatalf("put siem: got %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/siem/test", `{}`); r.StatusCode != http.StatusOK {
		t.Fatalf("siem test: got %d", r.StatusCode)
	}
	// The PUT itself records a forwarded "siem-config" event, so read datagrams
	// until the test probe arrives (proving the whole pipeline transmits).
	buf := make([]byte, 4096)
	pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	seen := false
	for i := 0; i < 5 && !seen; i++ {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			break
		}
		if strings.Contains(string(buf[:n]), "siem-test") {
			seen = true
		}
	}
	if !seen {
		t.Fatal("did not receive the siem-test probe datagram")
	}
}

func TestSIEMValidationAndRole(t *testing.T) {
	srv, admin, a := newTestServer(t)
	a.siem = newSIEMForwarder("gw", "test", a.log)
	if r := doLogin(t, srv, admin, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("admin login: %d", r.StatusCode)
	}
	// enabling with a bad protocol is rejected
	if r := reqJSON(t, srv, admin, http.MethodPut, "/api/siem",
		`{"enabled":true,"protocol":"carrier-pigeon","host":"x","port":514,"format":"cef","minSeverity":"info"}`); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad protocol: got %d, want 400", r.StatusCode)
	}
	// network-operator lacks mail:write and cannot change SIEM
	createUser(t, srv, admin, a, "netop1", roleNetworkOperator)
	op := loginAs(t, srv, "netop1", operatorPassword)
	if r := reqJSON(t, srv, op, http.MethodGet, "/api/siem", ""); r.StatusCode != http.StatusOK {
		t.Fatalf("netop get: got %d, want 200", r.StatusCode)
	}
	if r := reqJSON(t, srv, op, http.MethodPut, "/api/siem",
		`{"enabled":false}`); r.StatusCode != http.StatusForbidden {
		t.Fatalf("netop put: got %d, want 403", r.StatusCode)
	}
}
