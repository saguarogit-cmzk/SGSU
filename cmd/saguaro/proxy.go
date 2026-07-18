package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"saguaro.local/network-manager/internal/adapters/nginxgen"
)

const stagedProxyName = "staged-nginx-apps.conf"

func defaultRunProxy(ctx context.Context, action string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "sudo", "-n", "/usr/sbin/saguaro-proxy", action).CombinedOutput()
}

// defaultProbeUpstream is the W5 reachability probe: a plain TCP dial.
func defaultProbeUpstream(ctx context.Context, addr string) error {
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

func (a *app) getProxyApps() []nginxgen.App {
	a.store.mu.RLock()
	defer a.store.mu.RUnlock()
	return append([]nginxgen.App(nil), a.store.data.ProxyApps...)
}

func (a *app) setProxyApps(apps []nginxgen.App) error {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	a.store.data.ProxyApps = apps
	return a.store.saveLocked()
}

func (a *app) apiProxyGet(w http.ResponseWriter, _ *http.Request) {
	apps := a.getProxyApps()
	if apps == nil {
		apps = []nginxgen.App{}
	}
	writeJSON(w, http.StatusOK, apps)
}

// apiProxyApply replaces the whole published-services list transactionally:
// validate → upstream probes → stage → root adapter (nginx -t with revert).
func (a *app) apiProxyApply(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Apps  []nginxgen.App `json:"apps"`
		Force bool           `json:"force"` // skip failed upstream probes
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	if in.Apps == nil {
		in.Apps = []nginxgen.App{}
	}
	text, err := nginxgen.Generate(in.Apps)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !in.Force {
		for _, app := range in.Apps {
			addr := net.JoinHostPort(app.UpstreamIP, fmt.Sprintf("%d", app.UpstreamPort))
			if err := a.probeUpstream(r.Context(), addr); err != nil {
				writeError(w, http.StatusConflict,
					fmt.Sprintf("upstream %s (%s) is unreachable: %v — repeat with force=true to publish anyway", app.Name, addr, err))
				return
			}
		}
	}
	if len(in.Apps) == 0 {
		if out, err := a.runProxy(r.Context(), "disable"); err != nil {
			writeError(w, http.StatusBadGateway, "disable failed: "+truncate(string(out), 300))
			return
		}
	} else {
		staged := filepath.Join(filepath.Dir(a.store.path), stagedProxyName)
		if err := os.WriteFile(staged, []byte(text), 0644); err != nil {
			writeError(w, http.StatusInternalServerError, "cannot write staged vhost file")
			return
		}
		if out, err := a.runProxy(r.Context(), "apply"); err != nil {
			a.record(r, a.actor(r), "proxy-apply", "nginx", "failed", map[string]any{"error": err.Error(), "output": truncate(string(out), 300)})
			writeError(w, http.StatusBadGateway, "apply failed: "+truncate(string(out), 300))
			return
		}
	}
	if err := a.setProxyApps(in.Apps); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist published services")
		return
	}
	a.record(r, a.actor(r), "proxy-apply", "nginx", "success", map[string]any{"services": len(in.Apps), "force": in.Force})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "services": len(in.Apps)})
}
