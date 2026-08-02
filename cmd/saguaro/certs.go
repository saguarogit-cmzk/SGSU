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

const stagedCertRequestName = "staged-cert-request"

// certDir is a var, not a const, so tests can point the expiry reader at a
// temporary directory; nothing in production reassigns it.
var certDir = "/etc/saguaro/certs"

// certRecord is persisted in state.json; expiry is read live from the
// certificate file when available.
type certRecord struct {
	Name     string    `json:"name"`
	SANs     []string  `json:"sans"`
	IssuedAt time.Time `json:"issuedAt"`
	Public   bool      `json:"public,omitempty"` // Let's Encrypt (vs internal step-ca)
}

var (
	certNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)
	sanHostRe  = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)
	emailRe    = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
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
		Type      string   `json:"type"` // internal | public
		Name      string   `json:"name"`
		SANs      []string `json:"sans"`
		Domain    string   `json:"domain"`    // public: the FQDN to certify
		Email     string   `json:"email"`     // public: ACME contact
		Challenge string   `json:"challenge"` // public: http-01 (default) | dns-01
		DeployGUI bool     `json:"deployGui"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	if in.Type == "" {
		in.Type = "internal"
	}
	if in.Type != "internal" && in.Type != "public" {
		writeError(w, http.StatusBadRequest, "type must be internal or public")
		return
	}
	in.Name = strings.ToLower(strings.TrimSpace(in.Name))
	if !certNameRe.MatchString(in.Name) {
		writeError(w, http.StatusBadRequest, "invalid certificate name (lowercase, digits, dashes)")
		return
	}
	if in.Type == "public" {
		a.issuePublicCert(w, r, in.Name, in.Domain, in.Email, in.Challenge, in.DeployGUI)
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

// issuePublicCert obtains a Let's Encrypt certificate for a public domain. With
// challenge "http-01" (default) it uses certbot --standalone with a temporary
// firewall opening. With "dns-01" it uses certbot --manual against the local
// PowerDNS (via the saguaro-cert hooks), which also supports wildcard domains.
// Renewal is handled unattended by certbot.timer.
func (a *app) issuePublicCert(w http.ResponseWriter, r *http.Request, name, domain, email, challenge string, deployGUI bool) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if challenge == "" {
		challenge = "http-01"
	}
	if challenge != "http-01" && challenge != "dns-01" {
		writeError(w, http.StatusBadRequest, "challenge must be http-01 or dns-01")
		return
	}
	wildcard := strings.HasPrefix(domain, "*.")
	if wildcard && challenge != "dns-01" {
		writeError(w, http.StatusBadRequest, "wildcard certificates require the dns-01 challenge")
		return
	}
	// Validate the domain (strip a leading "*." before the host check).
	base := strings.TrimPrefix(domain, "*.")
	if !sanHostRe.MatchString(base) {
		writeError(w, http.StatusBadRequest, "public certificate needs a valid public domain")
		return
	}
	if !emailRe.MatchString(strings.TrimSpace(email)) {
		writeError(w, http.StatusBadRequest, "a contact email is required for Let's Encrypt")
		return
	}
	action := "acme"
	if challenge == "dns-01" {
		action = "acme-dns"
	}
	if out, err := a.runCert(r.Context(), action, name, domain, strings.TrimSpace(email)); err != nil {
		a.recordSev(r, a.actor(r), "cert-issue-public", domain, "failed", "warning", map[string]any{"output": truncate(string(out), 400)})
		writeError(w, http.StatusBadGateway, "Let's Encrypt issuance failed: "+truncate(string(out), 400))
		return
	}
	certs := a.getCerts()
	rec := certRecord{Name: name, SANs: []string{domain}, IssuedAt: time.Now().UTC(), Public: true}
	replaced := false
	for i := range certs {
		if certs[i].Name == name {
			certs[i] = rec
			replaced = true
		}
	}
	if !replaced {
		certs = append(certs, rec)
	}
	if err := a.setCerts(certs); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist certificate list")
		return
	}
	a.record(r, a.actor(r), "cert-issue-public", domain, "success", map[string]any{"name": name})
	note := "Let's Encrypt certifikat izdan; automatska obnova preko certbot.timer."
	if deployGUI {
		if out, err := a.runCert(r.Context(), "deploy-gui", name); err != nil {
			note = "certificate issued but GUI deploy failed: " + truncate(string(out), 200)
		} else {
			a.record(r, a.actor(r), "cert-deploy-gui", name, "success", nil)
			note = "deployed to the GUI vhost"
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "name": name, "domain": domain, "note": note})
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
