package main

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"saguaro.local/network-manager/internal/adapters/openvpn"
	mailmod "saguaro.local/network-manager/internal/mail"
)

func defaultRunOpenVPN(ctx context.Context, action string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "sudo", "-n", "/usr/sbin/saguaro-openvpn", action).CombinedOutput()
}

func (a *app) getOpenVPN() openvpn.Config {
	a.store.mu.RLock()
	defer a.store.mu.RUnlock()
	if a.store.data.OpenVPN == nil {
		return openvpn.Config{Subnet: "10.9.0.0/24", Port: openvpn.DefaultPort, Clients: []openvpn.Client{}, SplitNetworks: []string{}}
	}
	cfg := *a.store.data.OpenVPN
	cfg.Clients = append([]openvpn.Client(nil), cfg.Clients...)
	cfg.SplitNetworks = append([]string(nil), cfg.SplitNetworks...)
	return cfg
}

func (a *app) setOpenVPN(cfg openvpn.Config) error {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	a.store.data.OpenVPN = &cfg
	return a.store.saveLocked()
}

func openvpnPending() bool {
	_, err := os.Stat("/run/saguaro/openvpn-pending")
	return err == nil
}

// apiOpenVPNGet returns the config without secret material, plus the client list.
func (a *app) apiOpenVPNGet(w http.ResponseWriter, _ *http.Request) {
	cfg := a.getOpenVPN()
	clients := make([]map[string]any, 0, len(cfg.Clients))
	for _, c := range cfg.Clients {
		if c.Revoked {
			continue
		}
		clients = append(clients, map[string]any{"name": c.Name, "createdAt": c.CreatedAt, "expiresAt": c.ExpiresAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": cfg.Enabled, "subnet": cfg.Subnet, "port": cfg.PortOrDefault(),
		"endpoint": cfg.Endpoint, "dns": cfg.DNS, "splitNetworks": cfg.SplitNetworks,
		"clients": clients, "provisioned": cfg.CACertPEM != "",
	})
}

// stageAndApply decrypts the sealed keys, writes the server config + PKI to the
// staged directory and calls the adapter to install and (re)start the server.
func (a *app) stageAndApplyOpenVPN(ctx context.Context, cfg openvpn.Config) error {
	caKey, err := mailmod.Decrypt(a.mailKey, cfg.CAKeyEnc)
	if err != nil {
		return err
	}
	srvKey, err := mailmod.Decrypt(a.mailKey, cfg.ServerKeyEnc)
	if err != nil {
		return err
	}
	tlsCrypt, err := mailmod.Decrypt(a.mailKey, cfg.TLSCryptEnc)
	if err != nil {
		return err
	}
	conf, err := cfg.GenerateServerConf()
	if err != nil {
		return err
	}
	var revoked []openvpn.Client
	for _, c := range cfg.Clients {
		if c.Revoked {
			revoked = append(revoked, c)
		}
	}
	crl, err := openvpn.GenerateCRL(cfg.CACertPEM, caKey, revoked)
	if err != nil {
		return err
	}
	dir := filepath.Join(filepath.Dir(a.store.path), "staged-openvpn")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	files := map[string]string{
		"saguaro.conf":         conf,
		"saguaro-ca.crt":       cfg.CACertPEM,
		"saguaro-server.crt":   cfg.ServerCertPEM,
		"saguaro-server.key":   srvKey,
		"saguaro-tlscrypt.key": tlsCrypt,
		"saguaro-crl.pem":      crl,
		"saguaro-auth":         openvpn.GenerateAuthFile(cfg.Clients),
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			return err
		}
	}
	_, err = a.runOpenVPN(ctx, "apply")
	return err
}

func (a *app) apiOpenVPNApply(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled       bool     `json:"enabled"`
		Subnet        string   `json:"subnet"`
		Port          int      `json:"port"`
		Endpoint      string   `json:"endpoint"`
		DNS           string   `json:"dns"`
		SplitNetworks []string `json:"splitNetworks"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	a.mutateMu.Lock()
	defer a.mutateMu.Unlock()
	cfg := a.getOpenVPN()
	if len(cfg.Clients) > 0 && cfg.Subnet != "" && in.Subnet != "" && in.Subnet != cfg.Subnet {
		writeError(w, http.StatusConflict, "subnet cannot change while clients exist; remove clients first")
		return
	}
	cfg.Enabled, cfg.Subnet, cfg.Port = in.Enabled, in.Subnet, in.Port
	cfg.Endpoint, cfg.DNS, cfg.SplitNetworks = in.Endpoint, in.DNS, in.SplitNetworks
	// Split-brain by default: fall back to the LAN so clients reach internal
	// resources while their own internet is untouched.
	if len(cfg.SplitNetworks) == 0 {
		if gw, ok := a.getGateway(); ok && gw.ClientNetwork != "" {
			cfg.SplitNetworks = []string{gw.ClientNetwork}
		}
	}
	if err := cfg.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !in.Enabled {
		if out, err := a.runOpenVPN(r.Context(), "disable"); err != nil {
			writeError(w, http.StatusBadGateway, "disable failed: "+truncate(string(out), 200))
			return
		}
		_ = a.setOpenVPN(cfg)
		// Close the VPN port again.
		if _, ok := a.firewallConfig(); ok {
			_ = a.applyAndConfirm(r)
		}
		a.recordSev(r, a.actor(r), "openvpn-config", "openvpn", "success", "warning", map[string]any{"enabled": false})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	if a.mailKey == nil {
		writeError(w, http.StatusInternalServerError, "secret key unavailable; cannot store the VPN private keys")
		return
	}
	// First enable: mint the PKI (its own CA, server cert, tls-crypt key).
	if cfg.CACertPEM == "" {
		caCert, caKey, err := openvpn.GenerateCA()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "cannot generate CA")
			return
		}
		srvCert, srvKey, err := openvpn.SignServer(caCert, caKey)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "cannot generate server certificate")
			return
		}
		tlsCrypt, err := openvpn.GenerateTLSCrypt()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "cannot generate tls-crypt key")
			return
		}
		if cfg.CAKeyEnc, err = mailmod.Encrypt(a.mailKey, caKey); err != nil {
			writeError(w, http.StatusInternalServerError, "cannot seal CA key")
			return
		}
		if cfg.ServerKeyEnc, err = mailmod.Encrypt(a.mailKey, srvKey); err != nil {
			writeError(w, http.StatusInternalServerError, "cannot seal server key")
			return
		}
		if cfg.TLSCryptEnc, err = mailmod.Encrypt(a.mailKey, tlsCrypt); err != nil {
			writeError(w, http.StatusInternalServerError, "cannot seal tls-crypt key")
			return
		}
		cfg.CACertPEM, cfg.ServerCertPEM = caCert, srvCert
	}
	if err := a.stageAndApplyOpenVPN(r.Context(), cfg); err != nil {
		a.recordSev(r, a.actor(r), "openvpn-config", "openvpn", "failed", "security", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadGateway, "apply failed: "+truncate(err.Error(), 200))
		return
	}
	if err := a.setOpenVPN(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist OpenVPN configuration")
		return
	}
	// Open the VPN UDP port in the firewall so remote clients can connect.
	if _, ok := a.firewallConfig(); ok {
		if err := a.applyAndConfirm(r); err != nil {
			a.recordSev(r, a.actor(r), "openvpn-fwsync", "nftables", "failed", "warning", map[string]any{"error": err.Error()})
		}
	}
	a.recordSev(r, a.actor(r), "openvpn-config", "openvpn", "success", "security", map[string]any{"clients": len(cfg.Clients)})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *app) apiOpenVPNAddClient(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name       string `json:"name"`
		Password   string `json:"password"`
		ExpiryDays int    `json:"expiryDays"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	if len(in.Password) < 8 {
		writeError(w, http.StatusBadRequest, "a password of at least 8 characters is required")
		return
	}
	a.mutateMu.Lock()
	defer a.mutateMu.Unlock()
	cfg := a.getOpenVPN()
	if cfg.CACertPEM == "" {
		writeError(w, http.StatusConflict, "enable OpenVPN first")
		return
	}
	for _, c := range cfg.Clients {
		if c.Name == in.Name && !c.Revoked {
			writeError(w, http.StatusConflict, "a client with that name already exists")
			return
		}
	}
	caKey, err := mailmod.Decrypt(a.mailKey, cfg.CAKeyEnc)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot open CA key")
		return
	}
	// A real, displayable expiry: default two years when none is given.
	notAfter := time.Now().AddDate(2, 0, 0)
	if in.ExpiryDays > 0 {
		notAfter = time.Now().AddDate(0, 0, in.ExpiryDays)
	}
	certPEM, keyPEM, serial, err := openvpn.SignClient(cfg.CACertPEM, caKey, in.Name, notAfter)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	phc, err := hashPassword(in.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot hash password")
		return
	}
	cfg.Clients = append(cfg.Clients, openvpn.Client{Name: in.Name, Serial: serial, CertPEM: certPEM,
		PassHash: phc, CreatedAt: time.Now(), ExpiresAt: notAfter})
	if err := a.setOpenVPN(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist client")
		return
	}
	// Reload the server so its auth file knows the new user's password.
	if cfg.Enabled {
		if err := a.stageAndApplyOpenVPN(r.Context(), cfg); err != nil {
			writeError(w, http.StatusBadGateway, "reload failed: "+truncate(err.Error(), 200))
			return
		}
	}
	tlsCrypt, err := mailmod.Decrypt(a.mailKey, cfg.TLSCryptEnc)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot open tls-crypt key")
		return
	}
	a.recordSev(r, a.actor(r), "openvpn-client-add", "openvpn", "success", "security", map[string]any{"name": in.Name})
	ovpn := cfg.GenerateClientOVPN(certPEM, keyPEM, tlsCrypt)
	w.Header().Set("Content-Type", "application/x-openvpn-profile")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+in.Name+".ovpn\"")
	_, _ = w.Write([]byte(ovpn))
}

func (a *app) apiOpenVPNDelClient(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	a.mutateMu.Lock()
	defer a.mutateMu.Unlock()
	cfg := a.getOpenVPN()
	found := false
	for i := range cfg.Clients {
		if cfg.Clients[i].Name == name && !cfg.Clients[i].Revoked {
			cfg.Clients[i].Revoked = true
			found = true
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "client not found")
		return
	}
	// Revocation must reach the running server: regenerate the CRL and reload.
	if cfg.Enabled {
		if err := a.stageAndApplyOpenVPN(r.Context(), cfg); err != nil {
			writeError(w, http.StatusBadGateway, "reload failed: "+truncate(err.Error(), 200))
			return
		}
	}
	if err := a.setOpenVPN(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist revocation")
		return
	}
	a.recordSev(r, a.actor(r), "openvpn-client-revoke", "openvpn", "success", "security", map[string]any{"name": name})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
