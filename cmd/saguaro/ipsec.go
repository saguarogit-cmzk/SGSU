package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"saguaro.local/network-manager/internal/adapters/ipsec"
	mailmod "saguaro.local/network-manager/internal/mail"
)

// validatePEMCert confirms s is a parseable PEM X.509 certificate.
func validatePEMCert(s string) error {
	block, _ := pem.Decode([]byte(strings.TrimSpace(s)))
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("expected a PEM certificate")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return fmt.Errorf("unparseable certificate")
	}
	return nil
}

// validatePEMKey confirms s is a parseable PEM private key (PKCS#1/#8 or EC).
func validatePEMKey(s string) error {
	block, _ := pem.Decode([]byte(strings.TrimSpace(s)))
	if block == nil {
		return fmt.Errorf("expected a PEM private key")
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return nil
	}
	if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return nil
	}
	if _, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return nil
	}
	return fmt.Errorf("unparseable private key")
}

const stagedIPsecName = "staged-swanctl.conf"

// A preshared key is a free-form secret written into swanctl.conf inside double
// quotes; restrict it to a safe charset (no quotes, backslash, spaces or
// control characters) so it cannot break out of the generated file.
var ipsecPSKRe = regexp.MustCompile(`^[A-Za-z0-9._~!@#$%^&*()+=:;,/?|-]{8,64}$`)

func defaultRunIPsec(ctx context.Context, action string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "sudo", "-n", "/usr/sbin/saguaro-ipsec", action).CombinedOutput()
}

func (a *app) getIPsec() ipsec.Config {
	a.store.mu.RLock()
	defer a.store.mu.RUnlock()
	if a.store.data.IPsec == nil {
		return ipsec.Config{Connections: []ipsec.Connection{}}
	}
	cfg := *a.store.data.IPsec
	cfg.Connections = append([]ipsec.Connection(nil), cfg.Connections...)
	return cfg
}

func (a *app) setIPsec(cfg ipsec.Config) error {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	a.store.data.IPsec = &cfg
	return a.store.saveLocked()
}

// ipsecView never exposes the sealed preshared keys, only whether one is set.
func ipsecView(cfg ipsec.Config) map[string]any {
	conns := make([]map[string]any, 0, len(cfg.Connections))
	for _, c := range cfg.Connections {
		ike, esp := c.IKEProposal, c.ESPProposal
		if ike == "" {
			ike = ipsec.DefaultIKEProposal
		}
		if esp == "" {
			esp = ipsec.DefaultESPProposal
		}
		auth := c.Auth
		if auth == "" {
			auth = "psk"
		}
		conns = append(conns, map[string]any{
			"name": c.Name, "remoteAddr": c.RemoteAddr, "localId": c.LocalID, "remoteId": c.RemoteID,
			"localSubnets": c.LocalSubnets, "remoteSubnets": c.RemoteSubnets,
			"ikeProposal": ike, "espProposal": esp, "initiate": c.Initiate,
			"auth": auth, "hasPsk": c.PSKEnc != "", "hasCert": c.LocalCert != "", "hasKey": c.LocalKeyEnc != "", "hasCa": c.RemoteCA != "",
		})
	}
	return map[string]any{"enabled": cfg.Enabled, "connections": conns,
		"defaultIke": ipsec.DefaultIKEProposal, "defaultEsp": ipsec.DefaultESPProposal}
}

func (a *app) apiIPsecGet(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, ipsecView(a.getIPsec()))
}

// applyIPsec unseals each connection's preshared key, renders swanctl.conf and
// runs the root adapter. Disable path when off.
func (a *app) applyIPsec(ctx context.Context, cfg ipsec.Config) error {
	if !cfg.Enabled {
		if out, err := a.runIPsec(ctx, "disable"); err != nil {
			return fmt.Errorf("disable failed: %s", truncate(string(out), 300))
		}
		return nil
	}
	if a.mailKey == nil {
		return fmt.Errorf("secret key unavailable; cannot unseal preshared keys")
	}
	psks := map[string]string{}
	for _, c := range cfg.Connections {
		if c.IsCert() {
			continue // certificate connections carry no PSK
		}
		if c.PSKEnc == "" {
			return fmt.Errorf("connection %s has no preshared key", c.Name)
		}
		p, err := mailmod.Decrypt(a.mailKey, c.PSKEnc)
		if err != nil {
			return fmt.Errorf("cannot unseal preshared key for %s: %w", c.Name, err)
		}
		psks[c.Name] = p
	}
	text, err := cfg.GenerateConf(psks)
	if err != nil {
		return err
	}
	staged := filepath.Join(filepath.Dir(a.store.path), stagedIPsecName)
	if err := os.WriteFile(staged, []byte(text), 0600); err != nil {
		return fmt.Errorf("cannot write staged config: %w", err)
	}
	// Stage per-connection certificate material for cert-auth connections.
	credsDir := filepath.Join(filepath.Dir(a.store.path), "staged-swanctl-creds")
	if err := os.RemoveAll(credsDir); err != nil {
		return fmt.Errorf("cannot reset staged creds: %w", err)
	}
	if err := os.MkdirAll(credsDir, 0700); err != nil {
		return fmt.Errorf("cannot create staged creds: %w", err)
	}
	for _, c := range cfg.Connections {
		if !c.IsCert() {
			continue
		}
		key, err := mailmod.Decrypt(a.mailKey, c.LocalKeyEnc)
		if err != nil {
			return fmt.Errorf("cannot unseal private key for %s: %w", c.Name, err)
		}
		writeCred := func(suffix, data string) error {
			return os.WriteFile(filepath.Join(credsDir, c.Name+suffix), []byte(data), 0600)
		}
		if err := writeCred(".cert.pem", c.LocalCert); err != nil {
			return err
		}
		if err := writeCred(".key.pem", key); err != nil {
			return err
		}
		if err := writeCred(".ca.pem", c.RemoteCA); err != nil {
			return err
		}
	}
	if out, err := a.runIPsec(ctx, "apply"); err != nil {
		return fmt.Errorf("apply failed: %s", truncate(string(out), 300))
	}
	return nil
}

func (a *app) apiIPsecApply(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	cfg := a.getIPsec()
	if in.Enabled && len(cfg.Connections) == 0 {
		writeError(w, http.StatusConflict, "add at least one connection before enabling IPsec")
		return
	}
	cfg.Enabled = in.Enabled
	if err := a.applyIPsec(r.Context(), cfg); err != nil {
		a.recordSev(r, a.actor(r), "ipsec-apply", "strongswan", "failed", "security", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadGateway, friendlyError(err, "IPsec"))
		return
	}
	if err := a.setIPsec(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist IPsec configuration")
		return
	}
	a.recordSev(r, a.actor(r), "ipsec-apply", "strongswan", "success", "security",
		map[string]any{"enabled": cfg.Enabled, "connections": len(cfg.Connections)})
	writeJSON(w, http.StatusOK, ipsecView(cfg))
}

// apiIPsecConnAdd adds or replaces a connection. When IPsec is enabled the new
// configuration is applied immediately; otherwise it is only persisted.
func (a *app) apiIPsecConnAdd(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name          string   `json:"name"`
		RemoteAddr    string   `json:"remoteAddr"`
		LocalID       string   `json:"localId"`
		RemoteID      string   `json:"remoteId"`
		LocalSubnets  []string `json:"localSubnets"`
		RemoteSubnets []string `json:"remoteSubnets"`
		IKEProposal   string   `json:"ikeProposal"`
		ESPProposal   string   `json:"espProposal"`
		Initiate      bool     `json:"initiate"`
		Auth          string   `json:"auth"`
		PSK           string   `json:"psk"`
		LocalCert     string   `json:"localCert"`
		LocalKey      string   `json:"localKey"`
		RemoteCA      string   `json:"remoteCa"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	auth := in.Auth
	if auth == "" {
		auth = "psk"
	}
	conn := ipsec.Connection{
		Name: strings.ToLower(strings.TrimSpace(in.Name)), RemoteAddr: strings.TrimSpace(in.RemoteAddr),
		LocalID: strings.TrimSpace(in.LocalID), RemoteID: strings.TrimSpace(in.RemoteID),
		LocalSubnets: in.LocalSubnets, RemoteSubnets: in.RemoteSubnets,
		IKEProposal: strings.TrimSpace(in.IKEProposal), ESPProposal: strings.TrimSpace(in.ESPProposal),
		Initiate: in.Initiate, Auth: auth,
	}
	cfg := a.getIPsec()
	// Reuse existing sealed secrets when the caller edits a connection without
	// re-entering them; require them for brand-new connections.
	var existing *ipsec.Connection
	for i := range cfg.Connections {
		if cfg.Connections[i].Name == conn.Name {
			existing = &cfg.Connections[i]
		}
	}
	if auth == "cert" {
		conn.LocalCert = strings.TrimSpace(in.LocalCert)
		conn.RemoteCA = strings.TrimSpace(in.RemoteCA)
		if conn.LocalCert == "" && existing != nil {
			conn.LocalCert = existing.LocalCert
		}
		if conn.RemoteCA == "" && existing != nil {
			conn.RemoteCA = existing.RemoteCA
		}
		if err := validatePEMCert(conn.LocalCert); err != nil {
			writeError(w, http.StatusBadRequest, "localCert: "+err.Error())
			return
		}
		if err := validatePEMCert(conn.RemoteCA); err != nil {
			writeError(w, http.StatusBadRequest, "remoteCa: "+err.Error())
			return
		}
		if key := strings.TrimSpace(in.LocalKey); key != "" {
			if err := validatePEMKey(key); err != nil {
				writeError(w, http.StatusBadRequest, "localKey: "+err.Error())
				return
			}
			if a.mailKey == nil {
				writeError(w, http.StatusInternalServerError, "secret key unavailable; cannot store the private key")
				return
			}
			enc, err := mailmod.Encrypt(a.mailKey, key)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "cannot seal private key")
				return
			}
			conn.LocalKeyEnc = enc
		} else if existing != nil && existing.LocalKeyEnc != "" {
			conn.LocalKeyEnc = existing.LocalKeyEnc
		} else {
			writeError(w, http.StatusBadRequest, "a private key is required for certificate auth")
			return
		}
	} else if psk := strings.TrimSpace(in.PSK); psk != "" {
		if !ipsecPSKRe.MatchString(psk) {
			writeError(w, http.StatusBadRequest, "preshared key must be 8-64 characters without quotes, backslashes or spaces")
			return
		}
		if a.mailKey == nil {
			writeError(w, http.StatusInternalServerError, "secret key unavailable; cannot store the preshared key")
			return
		}
		enc, err := mailmod.Encrypt(a.mailKey, psk)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "cannot seal preshared key")
			return
		}
		conn.PSKEnc = enc
	} else if existing != nil && existing.PSKEnc != "" {
		conn.PSKEnc = existing.PSKEnc
	} else {
		writeError(w, http.StatusBadRequest, "a preshared key is required")
		return
	}
	next := cfg
	next.Connections = nil
	replaced := false
	for _, c := range cfg.Connections {
		if c.Name == conn.Name {
			next.Connections = append(next.Connections, conn)
			replaced = true
			continue
		}
		next.Connections = append(next.Connections, c)
	}
	if !replaced {
		next.Connections = append(next.Connections, conn)
	}
	if err := next.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if cfg.Enabled {
		if err := a.applyIPsec(r.Context(), next); err != nil {
			writeError(w, http.StatusBadGateway, friendlyError(err, "IPsec"))
			return
		}
	}
	if err := a.setIPsec(next); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist IPsec configuration")
		return
	}
	a.record(r, a.actor(r), "ipsec-conn-add", conn.Name, "success",
		map[string]any{"remote": conn.RemoteAddr, "initiate": conn.Initiate})
	writeJSON(w, http.StatusOK, ipsecView(next))
}

func (a *app) apiIPsecConnDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	cfg := a.getIPsec()
	next := cfg
	next.Connections = nil
	found := false
	for _, c := range cfg.Connections {
		if c.Name == name {
			found = true
			continue
		}
		next.Connections = append(next.Connections, c)
	}
	if !found {
		writeError(w, http.StatusNotFound, "connection not found")
		return
	}
	if len(next.Connections) == 0 {
		next.Enabled = false
	}
	if cfg.Enabled {
		if err := a.applyIPsec(r.Context(), next); err != nil {
			writeError(w, http.StatusBadGateway, friendlyError(err, "IPsec"))
			return
		}
	}
	if err := a.setIPsec(next); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist IPsec configuration")
		return
	}
	a.recordSev(r, a.actor(r), "ipsec-conn-delete", name, "success", "warning", nil)
	writeJSON(w, http.StatusOK, ipsecView(next))
}
