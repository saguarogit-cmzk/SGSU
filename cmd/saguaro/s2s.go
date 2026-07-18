package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"saguaro.local/network-manager/internal/adapters/s2s"
	"saguaro.local/network-manager/internal/adapters/wireguard"
	mailmod "saguaro.local/network-manager/internal/mail"
)

const stagedS2SName = "staged-wgs2s.conf"

func defaultRunS2S(ctx context.Context, action string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "sudo", "-n", "/usr/sbin/saguaro-s2s", action).CombinedOutput()
}

func (a *app) getS2S() s2s.Config {
	a.store.mu.RLock()
	defer a.store.mu.RUnlock()
	if a.store.data.S2S == nil {
		return s2s.Config{ListenPort: 51821, Sites: []s2s.Site{}, LocalNetworks: []string{}}
	}
	cfg := *a.store.data.S2S
	cfg.Sites = append([]s2s.Site(nil), cfg.Sites...)
	cfg.LocalNetworks = append([]string(nil), cfg.LocalNetworks...)
	return cfg
}

func (a *app) setS2S(cfg s2s.Config) error {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	a.store.data.S2S = &cfg
	return a.store.saveLocked()
}

// s2sView never exposes the sealed server key or per-site preshared keys. It
// strips the sealed PSK but reports whether each site has one.
func s2sView(cfg s2s.Config) map[string]any {
	sites := make([]map[string]any, 0, len(cfg.Sites))
	for _, s := range cfg.Sites {
		sites = append(sites, map[string]any{
			"name": s.Name, "pubKey": s.PubKey, "endpoint": s.Endpoint,
			"remoteNetworks": s.RemoteNetworks, "keepalive": s.Keepalive,
			"hasPsk": s.PSKEnc != "",
		})
	}
	local := cfg.LocalNetworks
	if local == nil {
		local = []string{}
	}
	return map[string]any{
		"enabled": cfg.Enabled, "listenPort": cfg.ListenPort, "tunnelAddress": cfg.TunnelAddress,
		"localNetworks": local, "serverPub": cfg.ServerPub, "sites": sites,
		"remotePeerSnippet": cfg.RemotePeerSnippet(""),
	}
}

func (a *app) apiS2SGet(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s2sView(a.getS2S()))
}

// applyS2S unseals the interface private key and per-site preshared keys,
// renders the config and runs the root adapter. Disable path when off.
func (a *app) applyS2S(ctx context.Context, cfg s2s.Config) error {
	if !cfg.Enabled {
		if out, err := a.runS2S(ctx, "disable"); err != nil {
			return fmt.Errorf("disable failed: %s", truncate(string(out), 300))
		}
		return nil
	}
	if a.mailKey == nil {
		return fmt.Errorf("secret key unavailable; cannot unseal the server private key")
	}
	priv, err := mailmod.Decrypt(a.mailKey, cfg.ServerPrivEnc)
	if err != nil {
		return fmt.Errorf("cannot unseal server private key: %w", err)
	}
	psks := map[string]string{}
	for _, s := range cfg.Sites {
		if s.PSKEnc == "" {
			continue
		}
		p, err := mailmod.Decrypt(a.mailKey, s.PSKEnc)
		if err != nil {
			return fmt.Errorf("cannot unseal preshared key for site %s: %w", s.Name, err)
		}
		psks[s.Name] = p
	}
	text, err := cfg.GenerateConf(priv, psks)
	if err != nil {
		return err
	}
	staged := filepath.Join(filepath.Dir(a.store.path), stagedS2SName)
	if err := os.WriteFile(staged, []byte(text), 0600); err != nil {
		return fmt.Errorf("cannot write staged config: %w", err)
	}
	if out, err := a.runS2S(ctx, "apply"); err != nil {
		return fmt.Errorf("apply failed: %s", truncate(string(out), 300))
	}
	return nil
}

// apiS2SApply saves interface settings and applies them; the interface keypair
// is generated on first save and the private key is sealed.
func (a *app) apiS2SApply(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled       bool     `json:"enabled"`
		ListenPort    int      `json:"listenPort"`
		TunnelAddress string   `json:"tunnelAddress"`
		LocalNetworks []string `json:"localNetworks"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	cfg := a.getS2S()
	cfg.Enabled, cfg.TunnelAddress, cfg.LocalNetworks = in.Enabled, strings.TrimSpace(in.TunnelAddress), in.LocalNetworks
	cfg.ListenPort = in.ListenPort
	if cfg.ListenPort == 0 {
		cfg.ListenPort = 51821
	}
	if err := cfg.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if cfg.ServerPub == "" {
		if a.mailKey == nil {
			writeError(w, http.StatusInternalServerError, "secret key unavailable; cannot store the server private key")
			return
		}
		priv, pub, err := wireguard.GenerateKeypair()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "key generation failed")
			return
		}
		enc, err := mailmod.Encrypt(a.mailKey, priv)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "cannot seal server private key")
			return
		}
		cfg.ServerPrivEnc, cfg.ServerPub = enc, pub
	}
	if err := a.applyS2S(r.Context(), cfg); err != nil {
		a.recordSev(r, a.actor(r), "s2s-apply", "wireguard", "failed", "security", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if err := a.setS2S(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist site-to-site configuration")
		return
	}
	a.recordSev(r, a.actor(r), "s2s-apply", "wireguard", "success", "security",
		map[string]any{"enabled": cfg.Enabled, "sites": len(cfg.Sites), "port": cfg.ListenPort})
	writeJSON(w, http.StatusOK, s2sView(cfg))
}

// apiS2SSiteAdd adds (or replaces) a remote site and re-applies.
func (a *app) apiS2SSiteAdd(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name           string   `json:"name"`
		PubKey         string   `json:"pubKey"`
		Endpoint       string   `json:"endpoint"`
		RemoteNetworks []string `json:"remoteNetworks"`
		Keepalive      int      `json:"keepalive"`
		PSK            string   `json:"psk"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	cfg := a.getS2S()
	if !cfg.Enabled || cfg.ServerPub == "" {
		writeError(w, http.StatusConflict, "enable and apply the site-to-site interface first")
		return
	}
	site := s2s.Site{
		Name: strings.ToLower(strings.TrimSpace(in.Name)), PubKey: strings.TrimSpace(in.PubKey),
		Endpoint: strings.TrimSpace(in.Endpoint), RemoteNetworks: in.RemoteNetworks, Keepalive: in.Keepalive,
	}
	if site.Endpoint != "" && site.Keepalive == 0 {
		site.Keepalive = 25 // initiating side needs keepalive to keep the tunnel warm
	}
	if psk := strings.TrimSpace(in.PSK); psk != "" {
		if a.mailKey == nil {
			writeError(w, http.StatusInternalServerError, "secret key unavailable; cannot store the preshared key")
			return
		}
		if !wireguard.ValidKey(psk) {
			writeError(w, http.StatusBadRequest, "preshared key must be a base64 WireGuard key (wg genpsk)")
			return
		}
		enc, err := mailmod.Encrypt(a.mailKey, psk)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "cannot seal preshared key")
			return
		}
		site.PSKEnc = enc
	}
	next := cfg
	next.Sites = nil
	replaced := false
	for _, s := range cfg.Sites {
		if s.Name == site.Name {
			next.Sites = append(next.Sites, site)
			replaced = true
			continue
		}
		next.Sites = append(next.Sites, s)
	}
	if !replaced {
		next.Sites = append(next.Sites, site)
	}
	if err := next.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.applyS2S(r.Context(), next); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if err := a.setS2S(next); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist site-to-site configuration")
		return
	}
	a.record(r, a.actor(r), "s2s-site-add", site.Name, "success",
		map[string]any{"endpoint": site.Endpoint, "networks": site.RemoteNetworks, "psk": site.PSKEnc != ""})
	writeJSON(w, http.StatusOK, s2sView(next))
}

func (a *app) apiS2SSiteDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	cfg := a.getS2S()
	next := cfg
	next.Sites = nil
	found := false
	for _, s := range cfg.Sites {
		if s.Name == name {
			found = true
			continue
		}
		next.Sites = append(next.Sites, s)
	}
	if !found {
		writeError(w, http.StatusNotFound, "site not found")
		return
	}
	if cfg.Enabled {
		if err := a.applyS2S(r.Context(), next); err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
	}
	if err := a.setS2S(next); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist site-to-site configuration")
		return
	}
	a.recordSev(r, a.actor(r), "s2s-site-delete", name, "success", "warning", nil)
	writeJSON(w, http.StatusOK, s2sView(next))
}
