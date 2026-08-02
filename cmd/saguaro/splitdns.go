package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"saguaro.local/network-manager/internal/adapters/dnszones"
	"saguaro.local/network-manager/internal/adapters/nftgen"
)

// getSplitDNS returns the configured split-horizon records (never nil-mutating
// the caller's slice).
func (a *app) getSplitDNS() []dnszones.SplitRecord {
	a.store.mu.RLock()
	defer a.store.mu.RUnlock()
	out := make([]dnszones.SplitRecord, len(a.store.data.SplitDNS))
	copy(out, a.store.data.SplitDNS)
	return out
}

// setSplitDNS persists the split-horizon records.
func (a *app) setSplitDNS(recs []dnszones.SplitRecord) error {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	a.store.data.SplitDNS = recs
	return a.store.saveLocked()
}

// applyDNSDropin regenerates the Unbound zone-access + split-horizon drop-in
// from current state and applies it, or removes it when there is nothing to
// serve. It returns the eligible-zone and valid-split counts plus the adapter
// output for error reporting.
func (a *app) applyDNSDropin(ctx context.Context) (zones, splits int, out []byte, err error) {
	return a.applyDNSDropinWith(ctx, a.getSplitDNS())
}

// applyDNSDropinWith is applyDNSDropin over an explicit record set, so a
// handler can apply records before persisting them (apply-then-persist).
func (a *app) applyDNSDropinWith(ctx context.Context, split []dnszones.SplitRecord) (zones, splits int, out []byte, err error) {
	cfg, _ := a.getGateway()
	// Eligibility comes from the same helper that feeds the firewall's
	// internal4 set and the generated access-control lines.
	zones = len(nftgen.ZoneNetworks(cfg.Zones))
	for _, s := range split {
		if s.Valid() {
			splits++
		}
	}
	if zones == 0 && splits == 0 {
		out, err = a.runDNSZones(ctx, "zone-access-disable")
		return
	}
	conf := dnszones.GenerateAccessConf(cfg.Zones, split, cfg.ClientNetwork)
	staged := filepath.Join(filepath.Dir(a.store.path), stagedDNSZonesName)
	if werr := os.WriteFile(staged, []byte(conf), 0600); werr != nil {
		err = werr
		return
	}
	out, err = a.runDNSZones(ctx, "zone-access-apply")
	return
}

// apiDNSSplitGet returns the split-horizon records.
func (a *app) apiDNSSplitGet(w http.ResponseWriter, r *http.Request) {
	recs := a.getSplitDNS()
	if recs == nil {
		recs = []dnszones.SplitRecord{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": recs})
}

// apiDNSSplitPut replaces the split-horizon records and re-applies the Unbound
// drop-in. Every record is validated (host name, A/AAAA, matching address
// family) before it is stored, so nothing unsafe reaches the config file.
func (a *app) apiDNSSplitPut(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Records []dnszones.SplitRecord `json:"records"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	clean := make([]dnszones.SplitRecord, 0, len(in.Records))
	for _, s := range in.Records {
		s.Name = strings.ToLower(strings.TrimSpace(s.Name))
		s.Type = strings.ToUpper(strings.TrimSpace(s.Type))
		s.Internal = strings.TrimSpace(s.Internal)
		s.External = strings.TrimSpace(s.External)
		if !s.Valid() {
			writeError(w, http.StatusBadRequest, "neispravan split-horizon zapis: "+s.Name+" (provjeri ime, tip A/AAAA i IP adrese)")
			return
		}
		clean = append(clean, s)
	}
	// Apply first, persist second (house pattern): a failed Unbound apply must
	// not leave state.json claiming records that were never installed.
	_, splits, out, err := a.applyDNSDropinWith(r.Context(), clean)
	if err != nil {
		a.recordSev(r, a.actor(r), "dns-split", "unbound", "failed", "warning",
			map[string]any{"error": err.Error(), "output": truncate(string(out), 300)})
		writeError(w, http.StatusBadGateway, "apply failed: "+truncate(string(out), 300))
		return
	}
	if err := a.setSplitDNS(clean); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot save split-horizon records")
		return
	}
	a.record(r, a.actor(r), "dns-split", "unbound", "success", map[string]any{"records": splits})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "records": splits})
}
