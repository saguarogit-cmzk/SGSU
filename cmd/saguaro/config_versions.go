package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// maxConfigVersions caps how many config snapshots are retained on disk.
const maxConfigVersions = 40

var versionIDRe = regexp.MustCompile(`^[0-9]{1,19}$`)

// configVersion is one on-disk config snapshot: the full state plus a small
// header describing when it was taken and which config sections changed.
type configVersion struct {
	Time       int64           `json:"time"` // UnixNano; also the file name / id
	Changed    []string        `json:"changed"`
	LastAction string          `json:"lastAction,omitempty"`
	State      json.RawMessage `json:"state"`
}

func sectionHash(v any) string {
	b, _ := json.Marshal(v)
	// Treat "absent" encodings as no section so toggling a feature off and on is a
	// real change but an unset pointer never registers as content.
	s := string(b)
	if s == "null" || s == "[]" || s == "{}" || s == "" {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// sectionFingerprints returns a per-section content hash of the config-relevant
// parts of the state -- everything except the volatile audit log and the runtime
// service list -- keyed by an operator-friendly section name.
func (d state) sectionFingerprints() map[string]string {
	raw := map[string]any{
		"Pošta (mail)":           d.Mail,
		"Vatrozid/Gateway":       d.Gateway,
		"IDS/IPS":                d.IDS,
		"DNS filtriranje":        d.RPZ,
		"Reverse proxy":          d.ProxyApps,
		"Certifikati":            d.Certs,
		"WireGuard VPN":          d.VPN,
		"OpenVPN":                d.OpenVPN,
		"Backup":                 d.Backup,
		"Multi-WAN":              d.MultiWAN,
		"Rute":                   d.Routes,
		"Site-to-site VPN":       d.S2S,
		"IPsec":                  d.IPsec,
		"Profil sustava":         d.SystemProfile,
		"Blokirani MAC-ovi":      d.BlockedMACs,
		"WAN adresiranje":        d.WANConfigs,
		"SIEM":                   d.SIEM,
		"Web proxy":              d.WebProxy,
		"Oznake sučelja":         d.NICLabels,
		"Split-horizon DNS":      d.SplitDNS,
		"Šifrirani DNS upstream": d.DNSForward,
	}
	out := map[string]string{}
	for name, v := range raw {
		if h := sectionHash(v); h != "" {
			out[name] = h
		}
	}
	return out
}

// changedSections lists sections whose content differs between two fingerprints
// (added, removed or modified), sorted for stable display.
func changedSections(prev, cur map[string]string) []string {
	seen := map[string]bool{}
	var out []string
	for name, h := range cur {
		if prev[name] != h {
			out = append(out, name)
			seen[name] = true
		}
	}
	for name := range prev {
		if _, ok := cur[name]; !ok && !seen[name] {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// initVersions wires the versions directory, records the current config
// fingerprint and writes a baseline snapshot on first run. Called once from
// openStore before the store is shared, so no lock is held or needed.
func (s *store) initVersions() {
	s.verDir = filepath.Join(filepath.Dir(s.path), "versions")
	if err := os.MkdirAll(s.verDir, 0700); err != nil {
		s.verDir = "" // versioning disabled if we cannot create the directory
		return
	}
	s.lastSections = s.data.sectionFingerprints()
	// Baseline snapshot if none exist yet, so there is always a restore target.
	if entries, _ := filepath.Glob(filepath.Join(s.verDir, "*.json")); len(entries) == 0 {
		if b, err := json.MarshalIndent(s.data, "", "  "); err == nil {
			s.snapshotLocked(b, []string{"početno stanje"})
		}
	}
}

// maybeSnapshotLocked writes a new config version iff the config sections changed
// since the last snapshot. No-op for audit-only saves and before initVersions.
// The caller holds s.mu.
func (s *store) maybeSnapshotLocked(stateBytes []byte) {
	if s.verDir == "" {
		return
	}
	cur := s.data.sectionFingerprints()
	changed := changedSections(s.lastSections, cur)
	if s.lastSections != nil && len(changed) == 0 {
		return
	}
	s.snapshotLocked(stateBytes, changed)
	s.lastSections = cur
}

// snapshotLocked writes one version file and prunes old ones. Caller holds s.mu
// (or is single-threaded startup). Best-effort: snapshot failures never block the
// primary state save.
func (s *store) snapshotLocked(stateBytes []byte, changed []string) {
	if s.verDir == "" {
		return
	}
	ver := configVersion{Time: time.Now().UnixNano(), Changed: changed, State: json.RawMessage(stateBytes)}
	if len(s.data.Audit) > 0 {
		a := s.data.Audit[0]
		ver.LastAction = strings.TrimSpace(a.Actor + " · " + a.Action)
		if a.Target != "" {
			ver.LastAction += " (" + a.Target + ")"
		}
	}
	b, err := json.MarshalIndent(ver, "", "  ")
	if err != nil {
		return
	}
	name := filepath.Join(s.verDir, strconv.FormatInt(ver.Time, 10)+".json")
	if os.WriteFile(name, b, 0600) != nil {
		return
	}
	s.pruneVersionsLocked()
}

func (s *store) pruneVersionsLocked() {
	entries, _ := filepath.Glob(filepath.Join(s.verDir, "*.json"))
	if len(entries) <= maxConfigVersions {
		return
	}
	sort.Strings(entries) // filenames are zero-free unixnano; lexical == chronological
	for _, old := range entries[:len(entries)-maxConfigVersions] {
		_ = os.Remove(old)
	}
}

// listVersions returns snapshot headers (without the bulky state), newest first.
func (s *store) listVersions() []map[string]any {
	s.mu.RLock()
	dir := s.verDir
	s.mu.RUnlock()
	if dir == "" {
		return []map[string]any{}
	}
	entries, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	out := []map[string]any{}
	for _, f := range entries {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var v configVersion
		if json.Unmarshal(b, &v) != nil {
			continue
		}
		id := strings.TrimSuffix(filepath.Base(f), ".json")
		out = append(out, map[string]any{
			"id": id, "time": time.Unix(0, v.Time).UTC().Format(time.RFC3339),
			"changed": v.Changed, "lastAction": v.LastAction,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["id"].(string) > out[j]["id"].(string) })
	return out
}

func (s *store) readVersion(id string) (*configVersion, error) {
	s.mu.RLock()
	dir := s.verDir
	s.mu.RUnlock()
	b, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		return nil, err
	}
	var v configVersion
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (a *app) apiConfigVersions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"versions": a.store.listVersions(), "max": maxConfigVersions})
}

func (a *app) apiConfigVersionGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !versionIDRe.MatchString(id) {
		writeError(w, http.StatusBadRequest, "invalid version id")
		return
	}
	v, err := a.store.readVersion(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "version not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "time": time.Unix(0, v.Time).UTC().Format(time.RFC3339),
		"changed": v.Changed, "lastAction": v.LastAction, "state": v.State})
}

// apiConfigCheckpoint takes a manual config snapshot (a named restore point).
func (a *app) apiConfigCheckpoint(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Label string `json:"label"`
	}
	_ = decodeJSON(w, r, &in)
	label := strings.TrimSpace(in.Label)
	if label == "" {
		label = "ručna kontrolna točka"
	} else {
		label = "kontrolna točka: " + truncate(label, 60)
	}
	a.store.mu.Lock()
	b, err := json.MarshalIndent(a.store.data, "", "  ")
	if err == nil {
		a.store.snapshotLocked(b, []string{label})
		a.store.lastSections = a.store.data.sectionFingerprints()
	}
	a.store.mu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot serialize state")
		return
	}
	a.record(r, a.actor(r), "config-checkpoint", label, "success", nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// apiConfigVersionRestore replaces the current config with a snapshot's config,
// preserving the live audit trail and runtime service list. It does NOT re-apply
// to running services -- the response lists the changed sections so the operator
// re-applies (firewall, DHCP, WAN, ...) deliberately.
func (a *app) apiConfigVersionRestore(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !versionIDRe.MatchString(id) {
		writeError(w, http.StatusBadRequest, "invalid version id")
		return
	}
	v, err := a.store.readVersion(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "version not found")
		return
	}
	var restored state
	if err := json.Unmarshal(v.State, &restored); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "snapshot is unreadable")
		return
	}
	a.store.mu.Lock()
	changed := changedSections(a.store.data.sectionFingerprints(), restored.sectionFingerprints())
	// Keep the live audit history and current runtime service list; roll back only
	// the config surface.
	restored.Audit = a.store.data.Audit
	restored.Services = a.store.data.Services
	if restored.Version == 0 {
		restored.Version = a.store.data.Version
	}
	a.store.data = restored
	saveErr := a.store.saveLocked()
	a.store.mu.Unlock()
	if saveErr != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist restored config")
		return
	}
	a.recordSev(r, a.actor(r), "config-restore", id, "success", "security", map[string]any{"changed": changed})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "changed": changed,
		"message": "Konfiguracija vraćena. Ponovno primijeni pogođene module (Vatrozid, DHCP, WAN…) da promjene stupe na snagu."})
}
