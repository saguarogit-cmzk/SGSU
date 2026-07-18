package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	stagedCertRequestName = "staged-cert-request"
	certDir               = "/etc/saguaro/certs"
)

// certRecord is persisted in state.json; expiry is read live from the
// certificate file when available.
type certRecord struct {
	Name     string    `json:"name"`
	SANs     []string  `json:"sans"`
	IssuedAt time.Time `json:"issuedAt"`
}

var (
	certNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)
	sanHostRe  = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)
)

// validateSAN accepts hostnames (wildcard allowed), single-label internal
// names and IP addresses.
func validateSAN(s string) error {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return fmt.Errorf("empty SAN")
	}
	if net.ParseIP(s) != nil {
		return nil
	}
	if sanHostRe.MatchString(s) {
		return nil
	}
	// single-label internal hostnames like "saguaro"
	if regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`).MatchString(s) {
		return nil
	}
	return fmt.Errorf("invalid SAN %q", s)
}

func defaultRunCert(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	full := append([]string{"-n", "/usr/sbin/saguaro-cert"}, args...)
	return exec.CommandContext(ctx, "sudo", full...).CombinedOutput()
}

func (a *app) getCerts() []certRecord {
	a.store.mu.RLock()
	defer a.store.mu.RUnlock()
	return append([]certRecord(nil), a.store.data.Certs...)
}

func (a *app) setCerts(certs []certRecord) error {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	a.store.data.Certs = certs
	return a.store.saveLocked()
}

// certExpiry parses NotAfter from the issued certificate; zero when the file
// is unreadable (development host).
func certExpiry(name string) time.Time {
	b, err := os.ReadFile(filepath.Join(certDir, name+".crt"))
	if err != nil {
		return time.Time{}
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return time.Time{}
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}
	}
	return crt.NotAfter
}

func (a *app) apiCertsList(w http.ResponseWriter, _ *http.Request) {
	type view struct {
		certRecord
		NotAfter *time.Time `json:"notAfter,omitempty"`
	}
	out := []view{}
	for _, c := range a.getCerts() {
		v := view{certRecord: c}
		if exp := certExpiry(c.Name); !exp.IsZero() {
			v.NotAfter = &exp
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

// apiCertIssue issues an internal certificate from the appliance Step CA.
// Public (Let's Encrypt) certificates are a later iteration; the README
// policy already forbids public certificates for private names.
func (a *app) apiCertIssue(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Type      string   `json:"type"` // internal (public: planned)
		Name      string   `json:"name"`
		SANs      []string `json:"sans"`
		DeployGUI bool     `json:"deployGui"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	if in.Type == "" {
		in.Type = "internal"
	}
	if in.Type != "internal" {
		writeError(w, http.StatusNotImplemented, "public (ACME/Let's Encrypt) certificates arrive in a later version; internal step-ca certificates are available now")
		return
	}
	in.Name = strings.ToLower(strings.TrimSpace(in.Name))
	if !certNameRe.MatchString(in.Name) {
		writeError(w, http.StatusBadRequest, "invalid certificate name (lowercase, digits, dashes)")
		return
	}
	if len(in.SANs) == 0 {
		writeError(w, http.StatusBadRequest, "at least one SAN is required")
		return
	}
	sans := make([]string, 0, len(in.SANs))
	for _, s := range in.SANs {
		s = strings.ToLower(strings.TrimSpace(s))
		if err := validateSAN(s); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		sans = append(sans, s)
	}
	staged := filepath.Join(filepath.Dir(a.store.path), stagedCertRequestName)
	if err := os.WriteFile(staged, []byte(in.Name+"\n"+strings.Join(sans, "\n")+"\n"), 0644); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot write staged request")
		return
	}
	if out, err := a.runCert(r.Context(), "issue"); err != nil {
		a.record(r, a.actor(r), "cert-issue", in.Name, "failed", map[string]any{"error": err.Error(), "output": truncate(string(out), 300)})
		writeError(w, http.StatusBadGateway, "issue failed: "+truncate(string(out), 300))
		return
	}
	certs := a.getCerts()
	replaced := false
	for i := range certs {
		if certs[i].Name == in.Name {
			certs[i] = certRecord{Name: in.Name, SANs: sans, IssuedAt: time.Now().UTC()}
			replaced = true
		}
	}
	if !replaced {
		certs = append(certs, certRecord{Name: in.Name, SANs: sans, IssuedAt: time.Now().UTC()})
	}
	if err := a.setCerts(certs); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist certificate list")
		return
	}
	a.record(r, a.actor(r), "cert-issue", in.Name, "success", map[string]any{"sans": sans})
	note := ""
	if in.DeployGUI {
		if out, err := a.runCert(r.Context(), "deploy-gui", in.Name); err != nil {
			note = "certificate issued but GUI deploy failed: " + truncate(string(out), 200)
		} else {
			a.record(r, a.actor(r), "cert-deploy-gui", in.Name, "success", nil)
			note = "deployed to the GUI vhost"
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "name": in.Name, "note": note,
		"paths": map[string]string{"cert": certDir + "/" + in.Name + ".crt", "key": certDir + "/" + in.Name + ".key"}})
}

func (a *app) apiCertDeployGUI(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !certNameRe.MatchString(name) {
		writeError(w, http.StatusBadRequest, "invalid certificate name")
		return
	}
	if out, err := a.runCert(r.Context(), "deploy-gui", name); err != nil {
		writeError(w, http.StatusBadGateway, "deploy failed: "+truncate(string(out), 300))
		return
	}
	a.record(r, a.actor(r), "cert-deploy-gui", name, "success", nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *app) apiCertDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !certNameRe.MatchString(name) {
		writeError(w, http.StatusBadRequest, "invalid certificate name")
		return
	}
	// Refuse deleting a certificate still referenced by a published service.
	for _, app := range a.getProxyApps() {
		if app.TLS == "managed" && app.CertName == name {
			writeError(w, http.StatusConflict, fmt.Sprintf("certificate is used by published service %q", app.Name))
			return
		}
	}
	if out, err := a.runCert(r.Context(), "remove", name); err != nil {
		writeError(w, http.StatusBadGateway, "remove failed: "+truncate(string(out), 300))
		return
	}
	certs := a.getCerts()
	next := certs[:0]
	for _, c := range certs {
		if c.Name != name {
			next = append(next, c)
		}
	}
	if err := a.setCerts(append([]certRecord(nil), next...)); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist certificate list")
		return
	}
	a.recordSev(r, a.actor(r), "cert-remove", name, "success", "warning", nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
