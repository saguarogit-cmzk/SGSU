package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeCert drops a self-signed certificate with the given expiry where
// certExpiry() looks for it.
func writeCert(t *testing.T, dir, name string, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name+".crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
}

// Certificates are reported only once they enter the warning window, escalate
// as they get close, and an already-expired one is called out as expired.
func TestCertExpiryReport(t *testing.T) {
	dir := t.TempDir()
	old := certDir
	certDir = dir
	t.Cleanup(func() { certDir = old })

	_, _, a := newTestServer(t)
	now := time.Now()
	writeCert(t, dir, "healthy", now.AddDate(0, 6, 0))
	writeCert(t, dir, "soon", now.AddDate(0, 0, 14))
	writeCert(t, dir, "urgent", now.AddDate(0, 0, 3))
	writeCert(t, dir, "gone", now.AddDate(0, 0, -2))
	if err := a.setCerts([]certRecord{
		{Name: "healthy"}, {Name: "soon"}, {Name: "urgent"}, {Name: "gone"},
		{Name: "missing-file"},
	}); err != nil {
		t.Fatal(err)
	}

	items := a.certExpiryReport()
	if len(items) != 3 {
		t.Fatalf("expected 3 reported certificates, got %d: %+v", len(items), items)
	}
	// Most urgent first: the expired one has the fewest days left.
	if items[0].Name != "gone" || !items[0].Expired || items[0].Severity != "critical" {
		t.Errorf("expired certificate must lead and be critical: %+v", items[0])
	}
	if items[1].Name != "urgent" || items[1].Severity != "critical" {
		t.Errorf("3 days left must be critical: %+v", items[1])
	}
	if items[2].Name != "soon" || items[2].Severity != "warning" {
		t.Errorf("14 days left must warn: %+v", items[2])
	}
	for _, it := range items {
		if it.Name == "healthy" || it.Name == "missing-file" {
			t.Errorf("%s should not be reported: %+v", it.Name, it)
		}
	}
}

// The posture check surfaces the worst certificate and counts the rest.
func TestHardeningReportsCertExpiry(t *testing.T) {
	dir := t.TempDir()
	old := certDir
	certDir = dir
	t.Cleanup(func() { certDir = old })

	_, _, a := newTestServer(t)
	writeCert(t, dir, "expiring", time.Now().AddDate(0, 0, 2))
	if err := a.setCerts([]certRecord{{Name: "expiring"}}); err != nil {
		t.Fatal(err)
	}
	var found *hardeningCheck
	for _, c := range a.hardeningReport(context.Background()) {
		if c.Key == "certs" {
			cc := c
			found = &cc
		}
	}
	if found == nil || found.Status != "fail" {
		t.Fatalf("expiring certificate must fail the posture check: %+v", found)
	}
}
