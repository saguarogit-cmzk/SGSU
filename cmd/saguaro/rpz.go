package main

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	rpzmod "saguaro.local/network-manager/internal/adapters/rpz"
)

// rpzHit is one parsed RPZ block from the unbound log.
type rpzHit struct {
	Time    string `json:"time"`
	Client  string `json:"client"`
	Domain  string `json:"domain"`  // the queried name that was blocked
	Trigger string `json:"trigger"` // the blocklist entry that matched it
	Action  string `json:"action"`
}

// parseRPZHits turns unbound rpz-log lines into a top-domains ranking and a
// recent-blocks list. A line reads:
//
//	... info: rpz: applied [saguaro-rpz] <trigger>. <action> <client>@<port> <qname>. <qtype> <qclass>
func parseRPZHits(out []byte) ([]map[string]any, []rpzHit) {
	counts := map[string]int{}
	var recent []rpzHit
	for _, ln := range strings.Split(string(out), "\n") {
		i := strings.Index(ln, "rpz: applied [")
		if i < 0 {
			continue
		}
		rest := ln[i+len("rpz: applied ["):]
		j := strings.Index(rest, "] ")
		if j < 0 {
			continue
		}
		f := strings.Fields(rest[j+2:])
		if len(f) < 4 {
			continue
		}
		client := f[2]
		if at := strings.Index(client, "@"); at >= 0 {
			client = client[:at]
		}
		qname := strings.TrimSuffix(f[3], ".")
		t := ""
		if lf := strings.Fields(ln); len(lf) > 0 {
			t = lf[0]
		}
		counts[qname]++
		recent = append(recent, rpzHit{Time: t, Client: client, Domain: qname,
			Trigger: strings.TrimSuffix(f[0], "."), Action: f[1]})
	}
	top := make([]map[string]any, 0, len(counts))
	for d, c := range counts {
		top = append(top, map[string]any{"domain": d, "count": c})
	}
	sort.Slice(top, func(i, j int) bool {
		if top[i]["count"].(int) != top[j]["count"].(int) {
			return top[i]["count"].(int) > top[j]["count"].(int)
		}
		return top[i]["domain"].(string) < top[j]["domain"].(string)
	})
	if len(top) > 15 {
		top = top[:15]
	}
	// journalctl returns oldest-first; show newest-first, capped.
	for a, b := 0, len(recent)-1; a < b; a, b = a+1, b-1 {
		recent[a], recent[b] = recent[b], recent[a]
	}
	if len(recent) > 100 {
		recent = recent[:100]
	}
	return top, recent
}

func (a *app) apiRPZHits(w http.ResponseWriter, r *http.Request) {
	out, err := a.runRPZ(r.Context(), "hits")
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"top": []any{}, "recent": []any{}})
		return
	}
	top, recent := parseRPZHits(out)
	writeJSON(w, http.StatusOK, map[string]any{"top": top, "recent": recent})
}

const (
	stagedRPZZoneName = "staged-rpz.zone"
	stagedRPZConfName = "staged-rpz.conf"
	rpzZonePath       = "/var/lib/unbound/saguaro-rpz.zone"
)

func defaultRunRPZ(ctx context.Context, action string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "sudo", "-n", "/usr/sbin/saguaro-rpz", action).CombinedOutput()
}

func (a *app) getRPZ() rpzmod.Config {
	a.store.mu.RLock()
	defer a.store.mu.RUnlock()
	if a.store.data.RPZ == nil {
		return rpzmod.Config{Domains: []string{}, Feeds: []string{}}
	}
	cfg := *a.store.data.RPZ
	cfg.Domains = append([]string(nil), cfg.Domains...)
	cfg.Feeds = append([]string(nil), cfg.Feeds...)
	return cfg
}

func (a *app) setRPZ(cfg rpzmod.Config) error {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	a.store.data.RPZ = &cfg
	return a.store.saveLocked()
}

func (a *app) apiRPZGet(w http.ResponseWriter, _ *http.Request) {
	cfg := a.getRPZ()
	if cfg.Domains == nil {
		cfg.Domains = []string{}
	}
	if cfg.Feeds == nil {
		cfg.Feeds = []string{}
	}
	writeJSON(w, http.StatusOK, cfg)
}

// apiRPZApply saves the configuration, stages zone + Unbound drop-in and
// applies through the root adapter. RPZ has no hardware gate — it is the
// security tier for low-spec devices.
func (a *app) apiRPZApply(w http.ResponseWriter, r *http.Request) {
	var in rpzmod.Config
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	normalized := make([]string, 0, len(in.Domains))
	for _, d := range in.Domains {
		nd, err := rpzmod.NormalizeDomain(d)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		normalized = append(normalized, nd)
	}
	in.Domains = normalized
	if err := in.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !in.Enabled {
		if out, err := a.runRPZ(r.Context(), "disable"); err != nil {
			writeError(w, http.StatusBadGateway, "disable failed: "+truncate(string(out), 300))
			return
		}
		if err := a.setRPZ(in); err != nil {
			writeError(w, http.StatusInternalServerError, "cannot persist RPZ configuration")
			return
		}
		a.recordSev(r, a.actor(r), "rpz-disable", "unbound", "success", "warning", nil)
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	zone, err := in.GenerateZone(time.Now().Unix())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	conf, err := in.GenerateConf(rpzZonePath)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	dir := filepath.Dir(a.store.path)
	if err := os.WriteFile(filepath.Join(dir, stagedRPZZoneName), []byte(zone), 0644); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot write staged zone")
		return
	}
	if err := os.WriteFile(filepath.Join(dir, stagedRPZConfName), []byte(conf), 0644); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot write staged config")
		return
	}
	if out, err := a.runRPZ(r.Context(), "apply"); err != nil {
		a.recordSev(r, a.actor(r), "rpz-apply", "unbound", "failed", "security",
			map[string]any{"error": err.Error(), "output": truncate(string(out), 300)})
		writeError(w, http.StatusBadGateway, "apply failed: "+truncate(string(out), 300))
		return
	}
	if err := a.setRPZ(in); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist RPZ configuration")
		return
	}
	a.recordSev(r, a.actor(r), "rpz-apply", "unbound", "success", "security",
		map[string]any{"domains": len(in.Domains), "feeds": len(in.Feeds)})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "domains": len(in.Domains), "feeds": len(in.Feeds)})
}
