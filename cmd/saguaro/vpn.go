package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"saguaro.local/network-manager/internal/adapters/wireguard"
	mailmod "saguaro.local/network-manager/internal/mail"
)

const stagedWGName = "staged-wg0.conf"

func defaultRunVPN(ctx context.Context, action string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "sudo", "-n", "/usr/sbin/saguaro-vpn", action).CombinedOutput()
}

func (a *app) getVPN() wireguard.Config {
	a.store.mu.RLock()
	defer a.store.mu.RUnlock()
	if a.store.data.VPN == nil {
		return wireguard.Config{Subnet: "10.8.0.0/24", ListenPort: 51820, Peers: []wireguard.Peer{}, SplitNetworks: []string{}}
	}
	cfg := *a.store.data.VPN
	cfg.Peers = append([]wireguard.Peer(nil), cfg.Peers...)
	cfg.SplitNetworks = append([]string(nil), cfg.SplitNetworks...)
	return cfg
}

func (a *app) setVPN(cfg wireguard.Config) error {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	a.store.data.VPN = &cfg
	return a.store.saveLocked()
}

// vpnView never exposes the sealed server private key.
func vpnView(cfg wireguard.Config) map[string]any {
	peers := cfg.Peers
	if peers == nil {
		peers = []wireguard.Peer{}
	}
	return map[string]any{
		"enabled": cfg.Enabled, "subnet": cfg.Subnet, "listenPort": cfg.ListenPort,
		"endpoint": cfg.Endpoint, "dns": cfg.DNS, "splitNetworks": cfg.SplitNetworks,
		"serverPub": cfg.ServerPub, "peers": peers,
	}
}

func (a *app) apiVPNGet(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, vpnView(a.getVPN()))
}

// applyVPN stages the server config (with the decrypted private key) and
// runs the root adapter; disable path when the config is off.
func (a *app) applyVPN(ctx context.Context, cfg wireguard.Config) error {
	if !cfg.Enabled {
		if out, err := a.runVPN(ctx, "disable"); err != nil {
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
	text, err := cfg.GenerateServerConf(priv, time.Now().UTC())
	if err != nil {
		return err
	}
	staged := filepath.Join(filepath.Dir(a.store.path), stagedWGName)
	if err := os.WriteFile(staged, []byte(text), 0600); err != nil {
		return fmt.Errorf("cannot write staged config: %w", err)
	}
	if out, err := a.runVPN(ctx, "apply"); err != nil {
		return fmt.Errorf("apply failed: %s", truncate(string(out), 300))
	}
	return nil
}

// apiVPNApply saves settings and applies them; the server keypair is
// generated on first save and the private key is sealed with the appliance
// secret key.
func (a *app) apiVPNApply(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled       bool     `json:"enabled"`
		Subnet        string   `json:"subnet"`
		ListenPort    int      `json:"listenPort"`
		Endpoint      string   `json:"endpoint"`
		DNS           string   `json:"dns"`
		SplitNetworks []string `json:"splitNetworks"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	cfg := a.getVPN()
	// Changing the subnet with existing peers would orphan their addresses.
	if len(cfg.Peers) > 0 && cfg.Subnet != "" && in.Subnet != cfg.Subnet {
		writeError(w, http.StatusConflict, "subnet cannot change while peers exist; delete peers first")
		return
	}
	cfg.Enabled, cfg.Subnet, cfg.ListenPort = in.Enabled, in.Subnet, in.ListenPort
	cfg.Endpoint, cfg.DNS, cfg.SplitNetworks = in.Endpoint, in.DNS, in.SplitNetworks
	if cfg.ListenPort == 0 {
		cfg.ListenPort = 51820
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
	if err := a.applyVPN(r.Context(), cfg); err != nil {
		a.recordSev(r, a.actor(r), "vpn-apply", "wireguard", "failed", "security", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadGateway, friendlyError(err, "WireGuard VPN"))
		return
	}
	if err := a.setVPN(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist VPN configuration")
		return
	}
	a.recordSev(r, a.actor(r), "vpn-apply", "wireguard", "success", "security",
		map[string]any{"enabled": cfg.Enabled, "peers": len(cfg.Peers), "port": cfg.ListenPort})
	writeJSON(w, http.StatusOK, vpnView(cfg))
}

// apiVPNPeerAdd creates a peer with a unique address, re-applies the server
// config and returns the one-time client configuration with a QR code. The
// client private key is never stored.
func (a *app) apiVPNPeerAdd(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name       string `json:"name"`
		FullTunnel bool   `json:"fullTunnel"`
		ExpireDays int    `json:"expireDays"` // 0 = no expiry
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	cfg := a.getVPN()
	if !cfg.Enabled || cfg.ServerPub == "" {
		writeError(w, http.StatusConflict, "enable and apply the VPN configuration first")
		return
	}
	in.Name = strings.ToLower(strings.TrimSpace(in.Name))
	for _, p := range cfg.Peers {
		if p.Name == in.Name {
			writeError(w, http.StatusConflict, "peer name already exists")
			return
		}
	}
	addr, err := cfg.AllocateAddress()
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	priv, pub, err := wireguard.GenerateKeypair()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key generation failed")
		return
	}
	peer := wireguard.Peer{Name: in.Name, PubKey: pub, Address: addr,
		FullTunnel: in.FullTunnel, CreatedAt: time.Now().UTC()}
	if in.ExpireDays > 0 {
		peer.ExpiresAt = time.Now().UTC().AddDate(0, 0, in.ExpireDays)
	}
	next := cfg
	next.Peers = append(append([]wireguard.Peer(nil), cfg.Peers...), peer)
	if err := next.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.applyVPN(r.Context(), next); err != nil {
		writeError(w, http.StatusBadGateway, friendlyError(err, "WireGuard VPN"))
		return
	}
	if err := a.setVPN(next); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist VPN configuration")
		return
	}
	conf, err := next.GenerateClientConf(priv, peer)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var qrB64 string
	if png, err := qrcode.Encode(conf, qrcode.Medium, 320); err == nil {
		qrB64 = base64.StdEncoding.EncodeToString(png)
	}
	a.record(r, a.actor(r), "vpn-peer-add", in.Name, "success",
		map[string]any{"address": addr, "fullTunnel": in.FullTunnel, "expireDays": in.ExpireDays})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "peer": peer, "clientConf": conf, "qrPng": qrB64})
}

func (a *app) apiVPNPeerDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	cfg := a.getVPN()
	next := cfg
	next.Peers = nil
	found := false
	for _, p := range cfg.Peers {
		if p.Name == name {
			found = true
			continue
		}
		next.Peers = append(next.Peers, p)
	}
	if !found {
		writeError(w, http.StatusNotFound, "peer not found")
		return
	}
	if cfg.Enabled {
		if err := a.applyVPN(r.Context(), next); err != nil {
			writeError(w, http.StatusBadGateway, friendlyError(err, "WireGuard VPN"))
			return
		}
	}
	if err := a.setVPN(next); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist VPN configuration")
		return
	}
	a.recordSev(r, a.actor(r), "vpn-peer-delete", name, "success", "warning", nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
