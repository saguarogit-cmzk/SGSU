package main

import (
	"context"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"saguaro.local/network-manager/internal/pkgstat"
)

// packageKeys is the allow-list of appliance package keys the GUI may query and
// upgrade. It mirrors the key->package map in /usr/sbin/saguaro-pkg; the control
// plane only ever passes a key so an arbitrary apt package can never be named.
var packageKeys = []struct{ Key, Name string }{
	{"control-plane", "Saguaro control plane"},
	{"postgresql", "PostgreSQL"},
	{"unbound", "Unbound (resolver)"},
	{"pdns", "PowerDNS (authoritative)"},
	{"kea", "Kea DHCP"},
	{"nginx", "Nginx (GUI / proxy)"},
	{"nftables", "nftables (firewall)"},
	{"suricata", "Suricata IDS/IPS"},
	{"strongswan", "IPsec (strongSwan)"},
	{"wireguard", "WireGuard"},
	{"step-ca", "Step CA"},
	{"squid", "Squid (web proxy)"},
	{"e2guardian", "e2guardian (content filter)"},
	{"certbot", "certbot (ACME)"},
}

var packageKeySet = func() map[string]bool {
	m := map[string]bool{}
	for _, p := range packageKeys {
		m[p.Key] = true
	}
	return m
}()

var packageNames = func() map[string]string {
	m := map[string]string{}
	for _, p := range packageKeys {
		m[p.Key] = p.Name
	}
	return m
}()

// defaultRunPkg invokes the root adapter. apt operations (refresh/upgrade) can
// run for minutes, so callers pass a generous timeout via the context.
func defaultRunPkg(ctx context.Context, args ...string) ([]byte, error) {
	full := append([]string{"-n", "/usr/sbin/saguaro-pkg"}, args...)
	return exec.CommandContext(ctx, "sudo", full...).CombinedOutput()
}

func defaultRunSelfUpdate(ctx context.Context, args ...string) ([]byte, error) {
	full := append([]string{"-n", "/usr/sbin/saguaro-selfupdate"}, args...)
	return exec.CommandContext(ctx, "sudo", full...).CombinedOutput()
}

// apiSelfUpdateStatus reports the control plane's own version and, for a git
// source install, how far behind the git remote it is.
func (a *app) apiSelfUpdateStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	res := map[string]any{"version": appVersion, "gitRepo": false}
	out, err := a.runSelfUpdate(ctx, "check")
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(line), " ")
			if !ok {
				continue
			}
			switch k {
			case "gitrepo":
				res["gitRepo"] = v == "yes"
			case "current":
				res["current"] = v
			case "remote":
				res["remote"] = v
			case "behind":
				if n, e := strconv.Atoi(v); e == nil {
					res["behind"] = n
				}
			case "buildable":
				res["buildable"] = v == "yes"
			}
		}
	}
	writeJSON(w, http.StatusOK, res)
}

// apiSelfUpdateApply rebuilds and redeploys the control plane from git, then the
// service restarts out-of-band. Admin-only; audited as a security event before
// the adapter runs because the restart may cut the response short.
func (a *app) apiSelfUpdateApply(w http.ResponseWriter, r *http.Request) {
	extendDeadline(w, 6*time.Minute)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	a.recordSev(r, a.actor(r), "self-update", "control-plane", "started", "security", nil)
	out, err := a.runSelfUpdate(ctx, "apply")
	if err != nil {
		a.recordSev(r, a.actor(r), "self-update", "control-plane", "failed", "security",
			map[string]any{"output": truncate(string(out), 400)})
		writeError(w, http.StatusBadGateway, "update failed: "+truncate(string(out), 400))
		return
	}
	a.recordSev(r, a.actor(r), "self-update", "control-plane", "success", "security",
		map[string]any{"output": truncate(string(out), 200)})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": truncate(string(out), 200)})
}

// extendDeadline lifts the 30 s server WriteTimeout for a single slow handler so
// a long apt upgrade can still return its result to the browser.
func extendDeadline(w http.ResponseWriter, d time.Duration) {
	if rc := http.NewResponseController(w); rc != nil {
		_ = rc.SetWriteDeadline(time.Now().Add(d))
	}
}

// pkgInventory runs `list` + `unattended-status` and assembles the view. Adapter
// keys are joined to friendly names here.
func (a *app) pkgInventory(ctx context.Context) (map[string]any, error) {
	lctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	out, err := a.runPkg(lctx, "list")
	if err != nil {
		return nil, err
	}
	pkgs := pkgstat.ParseList(out)
	view := make([]map[string]any, 0, len(pkgs))
	for _, p := range pkgs {
		view = append(view, map[string]any{
			"key": p.Key, "name": packageNames[p.Key], "package": p.Name,
			"installed": p.Installed, "candidate": p.Candidate, "upgradable": p.Upgradable,
		})
	}
	res := map[string]any{"packages": view, "upgradable": pkgstat.UpgradableCount(pkgs)}
	if uout, uerr := a.runPkg(lctx, "unattended-status"); uerr == nil {
		res["unattended"] = pkgstat.ParseUnattended(uout)
	}
	return res, nil
}

func (a *app) apiPkgList(w http.ResponseWriter, r *http.Request) {
	res, err := a.pkgInventory(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "cannot read package inventory: "+truncate(err.Error(), 200))
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// apiPkgRefresh re-reads apt package lists (apt-get update) and returns the
// refreshed inventory so the GUI shows newly available versions.
func (a *app) apiPkgRefresh(w http.ResponseWriter, r *http.Request) {
	extendDeadline(w, 3*time.Minute)
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if out, err := a.runPkg(ctx, "refresh"); err != nil {
		a.recordSev(r, a.actor(r), "package-refresh", "apt", "failed", "warning",
			map[string]any{"output": truncate(string(out), 300)})
		writeError(w, http.StatusBadGateway, "refresh failed: "+truncate(string(out), 300))
		return
	}
	a.record(r, a.actor(r), "package-refresh", "apt", "success", nil)
	res, err := a.pkgInventory(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "refreshed, but inventory read failed: "+truncate(err.Error(), 200))
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// apiPkgUpgrade upgrades a single allow-listed package (never a blanket upgrade,
// never a new install). It is admin-only and audited as a security event.
func (a *app) apiPkgUpgrade(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if !packageKeySet[key] {
		writeError(w, http.StatusNotFound, "unknown package")
		return
	}
	extendDeadline(w, 6*time.Minute)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	out, err := a.runPkg(ctx, "upgrade", key)
	if err != nil {
		a.recordSev(r, a.actor(r), "package-upgrade", key, "failed", "security",
			map[string]any{"output": truncate(string(out), 400)})
		writeError(w, http.StatusBadGateway, "upgrade failed: "+truncate(string(out), 400))
		return
	}
	a.recordSev(r, a.actor(r), "package-upgrade", key, "success", "security",
		map[string]any{"output": truncate(string(out), 400)})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "key": key, "output": truncate(string(out), 2000)})
}

// apiPkgUnattended enables or disables Ubuntu's unattended security upgrades.
func (a *app) apiPkgUnattended(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	action := "unattended-disable"
	if in.Enabled {
		action = "unattended-enable"
	}
	extendDeadline(w, 3*time.Minute)
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if out, err := a.runPkg(ctx, action); err != nil {
		a.recordSev(r, a.actor(r), "package-unattended", "apt", "failed", "security",
			map[string]any{"enabled": in.Enabled, "output": truncate(string(out), 300)})
		writeError(w, http.StatusBadGateway, "change failed: "+truncate(string(out), 300))
		return
	}
	a.recordSev(r, a.actor(r), "package-unattended", "apt", "success", "security",
		map[string]any{"enabled": in.Enabled})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "enabled": in.Enabled})
}
