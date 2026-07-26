package openvpn

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func TestPKIAndConfig(t *testing.T) {
	caCert, caKey, err := GenerateCA()
	if err != nil {
		t.Fatal(err)
	}
	srvCert, srvKey, err := SignServer(caCert, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cliCert, cliKey, serial, err := SignClient(caCert, caKey, "alice", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if serial == "" || !strings.Contains(cliCert, "CERTIFICATE") || !strings.Contains(cliKey, "PRIVATE KEY") {
		t.Fatal("client cert/key/serial not produced")
	}

	// The client cert must verify against the CA with client-auth EKU.
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(caCert)) {
		t.Fatal("bad CA pem")
	}
	cb, _ := pem.Decode([]byte(cliCert))
	leaf, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("client cert did not verify: %v", err)
	}

	tc, err := GenerateTLSCrypt()
	if err != nil || !strings.Contains(tc, "OpenVPN Static key V1") {
		t.Fatalf("tls-crypt wrong: %v", err)
	}
	crl, err := GenerateCRL(caCert, caKey, []Client{{Serial: serial, Revoked: true}})
	if err != nil || !strings.Contains(crl, "X509 CRL") {
		t.Fatalf("crl wrong: %v", err)
	}

	cfg := Config{Enabled: true, Subnet: "10.9.0.0/24", Endpoint: "vpn.example.com", DNS: "10.10.10.1",
		SplitNetworks: []string{"10.10.10.0/24"}, CACertPEM: caCert, ServerCertPEM: srvCert}
	_ = srvKey
	sc, err := cfg.GenerateServerConf()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"server 10.9.0.0 255.255.255.0", "tls-crypt", "crl-verify",
		`push "route 10.10.10.0 255.255.255.0"`, `push "dhcp-option DNS 10.10.10.1"`} {
		if !strings.Contains(sc, want) {
			t.Fatalf("server conf missing %q:\n%s", want, sc)
		}
	}
	ovpn := cfg.GenerateClientOVPN(cliCert, cliKey, tc)
	for _, want := range []string{"remote vpn.example.com 1194", "<ca>", "<cert>", "<key>", "<tls-crypt>", "remote-cert-tls server"} {
		if !strings.Contains(ovpn, want) {
			t.Fatalf("ovpn missing %q", want)
		}
	}
	// Split-tunnel must NOT redirect the client's whole internet.
	if strings.Contains(sc, "redirect-gateway") {
		t.Fatal("split-tunnel server must not push redirect-gateway")
	}
}
