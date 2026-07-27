package main

import (
	"context"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var toolNames = map[string]bool{"ping": true, "dns": true, "trace": true, "mtr": true, "http": true}

var diagIfaceRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,15}$`)
var captureProtos = map[string]bool{"any": true, "tcp": true, "udp": true, "icmp": true}

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

// apiDiagCapture runs a bounded, header-only tcpdump on a chosen interface via
// the saguaro-tools adapter. Every field is validated here (defense in depth on
// top of the adapter's own re-validation); the filter is passed to the adapter
// as discrete positional tokens (proto/host/port), never a raw expression, so
// no user input reaches a shell or a tcpdump command-execution option.
func (a *app) apiDiagCapture(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Interface string `json:"interface"`
		Proto     string `json:"proto"`
		Host      string `json:"host"`
		Port      int    `json:"port"`
		Count     int    `json:"count"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	iface := strings.TrimSpace(in.Interface)
	if !diagIfaceRe.MatchString(iface) {
		writeError(w, http.StatusBadRequest, "invalid interface")
		return
	}
	proto := strings.TrimSpace(in.Proto)
	if proto == "" {
		proto = "any"
	}
	if !captureProtos[proto] {
		writeError(w, http.StatusBadRequest, "proto must be any, tcp, udp or icmp")
		return
	}
	count := in.Count
	if count <= 0 {
		count = 50
	}
	if count > 500 {
		count = 500
	}
	// Empty host/port are sent as the sentinel "-" so positions stay fixed and no
	// empty argv words are passed through sudo.
	host := strings.TrimSpace(in.Host)
	hostArg := "-"
	if host != "" {
		if ip := net.ParseIP(host); ip == nil || ip.To4() == nil {
			writeError(w, http.StatusBadRequest, "host must be an IPv4 address")
			return
		}
		hostArg = host
	}
	portArg := "-"
	if in.Port != 0 {
		if in.Port < 1 || in.Port > 65535 {
			writeError(w, http.StatusBadRequest, "port out of range")
			return
		}
		portArg = strconv.Itoa(in.Port)
	}
	out, err := a.runTools(r.Context(), "capture", iface, strconv.Itoa(count), proto, hostArg, portArg)
	result := "success"
	if err != nil {
		result = "failed"
	}
	a.record(r, a.actor(r), "diag-capture", iface, result, map[string]any{"proto": proto, "host": host, "port": in.Port, "count": count})
	writeJSON(w, http.StatusOK, map[string]any{"ok": err == nil, "output": string(out)})
}
