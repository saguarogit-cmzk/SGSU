package main

import (
	"context"
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
		conns = append(conns, map[string]any{
			"name": c.Name, "remoteAddr": c.RemoteAddr, "localId": c.LocalID, "remoteId": c.RemoteID,
			"localSubnets": c.LocalSubnets, "remoteSubnets": c.RemoteSubnets,
			"ikeProposal": ike, "espProposal": esp, "initiate": c.Initiate, "hasPsk": c.PSKEnc != "",
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
		writeError(w, http.StatusBadGateway, err.Error())
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
		PSK           string   `json:"psk"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	conn := ipsec.Connection{
		Name: strings.ToLower(strings.TrimSpace(in.Name)), RemoteAddr: strings.TrimSpace(in.RemoteAddr),
		LocalID: strings.TrimSpace(in.LocalID), RemoteID: strings.TrimSpace(in.RemoteID),
		LocalSubnets: in.LocalSubnets, RemoteSubnets: in.RemoteSubnets,
		IKEProposal: strings.TrimSpace(in.IKEProposal), ESPProposal: strings.TrimSpace(in.ESPProposal),
		Initiate: in.Initiate,
	}
	cfg := a.getIPsec()
	// Reuse the existing sealed PSK when the caller edits a connection without
	// re-entering the key; require one for brand-new connections.
	var existing *ipsec.Connection
	for i := range cfg.Connections {
		if cfg.Connections[i].Name == conn.Name {
			existing = &cfg.Connections[i]
		}
	}
	if psk := strings.TrimSpace(in.PSK); psk != "" {
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
	} else if existing != nil {
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
			writeError(w, http.StatusBadGateway, err.Error())
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
			writeError(w, http.StatusBadGateway, err.Error())
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
