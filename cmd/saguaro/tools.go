package main

import (
	"context"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

var toolNames = map[string]bool{"ping": true, "dns": true, "trace": true, "mtr": true, "http": true}

func defaultRunTools(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	full := append([]string{"-n", "/usr/sbin/saguaro-tools"}, args...)
	return exec.CommandContext(ctx, "sudo", full...).CombinedOutput()
}

// apiToolRun runs a diagnostic (ping/dns/trace/mtr/http) optionally bound to an
// interface (or against a DNS server) and returns the raw output.
func (a *app) apiToolRun(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Tool   string `json:"tool"`
		Host   string `json:"host"`
		Iface  string `json:"iface"`
		Server string `json:"server"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	if !toolNames[in.Tool] {
		writeError(w, http.StatusBadRequest, "tool must be ping, dns, trace, mtr or http")
		return
	}
	host := strings.TrimSpace(in.Host)
	if host == "" {
		writeError(w, http.StatusBadRequest, "host/target is required")
		return
	}
	args := []string{in.Tool, host}
	if in.Tool == "dns" {
		if s := strings.TrimSpace(in.Server); s != "" {
			args = append(args, s)
		}
	} else if f := strings.TrimSpace(in.Iface); f != "" {
		args = append(args, f)
	}
	out, err := a.runTools(r.Context(), args...)
	result := "success"
	if err != nil {
		result = "failed"
	}
	a.record(r, a.actor(r), "tool-"+in.Tool, host, result, map[string]any{"iface": in.Iface, "server": in.Server})
	writeJSON(w, http.StatusOK, map[string]any{"ok": err == nil, "output": string(out)})
}
