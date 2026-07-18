package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func genCertKeyPEM(t *testing.T, cn string) (certPEM, keyPEM string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDer, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	// Trim so the values match what the handler stores (it trims PEM input).
	certPEM = strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	keyPEM = strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDer})))
	return certPEM, keyPEM
}

func TestIPsecCertConnection(t *testing.T) {
	srv, c, a := newTestServer(t)
	var actions []string
	a.runIPsec = func(_ context.Context, action string) ([]byte, error) {
		actions = append(actions, action)
		return []byte("ok"), nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	cert, key := genCertKeyPEM(t, "vpn.local")
	ca, _ := genCertKeyPEM(t, "peer-ca")
	body, _ := json.Marshal(map[string]any{
		"name": "certconn", "remoteAddr": "203.0.113.9", "localId": "vpn.local", "remoteId": "peer.remote",
		"localSubnets": []string{"10.0.0.0/24"}, "remoteSubnets": []string{"10.9.0.0/24"},
		"auth": "cert", "localCert": cert, "localKey": key, "remoteCa": ca,
	})
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/ipsec/connections", string(body)); r.StatusCode != http.StatusOK {
		t.Fatalf("add cert conn: got %d", r.StatusCode)
	}
	conn := a.getIPsec().Connections[0]
	if conn.Auth != "cert" || conn.LocalKeyEnc == "" || conn.LocalKeyEnc == key || conn.LocalCert != cert {
		t.Fatalf("cert conn not stored/sealed correctly: auth=%s keyEnc empty? %v", conn.Auth, conn.LocalKeyEnc == "")
	}
	// Enable -> applyIPsec stages the swanctl.conf and the per-connection creds.
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/ipsec/apply", `{"enabled":true}`); r.StatusCode != http.StatusOK {
		t.Fatalf("enable: got %d", r.StatusCode)
	}
	credsDir := filepath.Join(filepath.Dir(a.store.path), "staged-swanctl-creds")
	keyFile, err := os.ReadFile(filepath.Join(credsDir, "certconn.key.pem"))
	if err != nil || string(keyFile) != key {
		t.Fatalf("staged key wrong: %v", err)
	}
	if _, err := os.Stat(filepath.Join(credsDir, "certconn.cert.pem")); err != nil {
		t.Fatalf("cert file not staged: %v", err)
	}
	if _, err := os.Stat(filepath.Join(credsDir, "certconn.ca.pem")); err != nil {
		t.Fatalf("ca file not staged: %v", err)
	}
	staged, _ := os.ReadFile(filepath.Join(filepath.Dir(a.store.path), stagedIPsecName))
	if !strings.Contains(string(staged), "certs = saguaro-certconn.pem") || !strings.Contains(string(staged), "auth = pubkey") {
		t.Fatalf("swanctl.conf missing cert refs:\n%s", staged)
	}
	// The view must not leak the sealed private key.
	resp, _ := c.Get(srv.URL + "/api/ipsec")
	var view map[string]any
	json.NewDecoder(resp.Body).Decode(&view)
	resp.Body.Close()
	if b, _ := json.Marshal(view); strings.Contains(string(b), conn.LocalKeyEnc) {
		t.Fatal("view leaked the sealed key")
	}

	// A cert connection missing IDs is rejected.
	bad, _ := json.Marshal(map[string]any{
		"name": "badcert", "remoteAddr": "203.0.113.9",
		"localSubnets": []string{"10.0.0.0/24"}, "remoteSubnets": []string{"10.9.0.0/24"},
		"auth": "cert", "localCert": cert, "localKey": key, "remoteCa": ca,
	})
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/ipsec/connections", string(bad)); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("cert without IDs: got %d, want 400", r.StatusCode)
	}
}
