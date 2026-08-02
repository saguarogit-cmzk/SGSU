package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"saguaro.local/network-manager/internal/adapters/suricata"
)

const stagedSuricataName = "staged-suricata.yaml"

// Hardware profile rule (§2.1): the security module is gated on
// >= 8 GB RAM and >= 4 cores; low-spec devices use RPZ filtering instead.
const (
	idsMinMemMB = 7500
	idsMinCores = 4
)

// idsState is persisted in state.json.
type idsState struct {
	Mode         string    `json:"mode"` // off | ids | ips
	Interface    string    `json:"interface"`
	HomeNet      string    `json:"homeNet"`
	IDSEnabledAt time.Time `json:"idsEnabledAt,omitempty"`
	IPSEnabledAt time.Time `json:"ipsEnabledAt,omitempty"`
}

func defaultRunIDS(ctx context.Context, args ...string) ([]byte, error) {
	// The apply/disable actions are quick, but a first `suricata-update` fetches
	// and compiles tens of thousands of rules — it needs minutes, not the 60 s
	// that used to apply to every action and made a fresh install report a
	// refresh failure that was really a timeout.
	timeout := 60 * time.Second
	if len(args) > 0 && args[0] == "update-rules" {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	full := append([]string{"-n", "/usr/sbin/saguaro-ids"}, args...)
	return exec.CommandContext(ctx, "sudo", full...).CombinedOutput()
}

// readMemTotalMB returns total RAM in MB, 0 when unknown (development).
func readMemTotalMB() int {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if kb, err := strconv.Atoi(fields[1]); err == nil {
					return kb / 1024
				}
			}
		}
	}
	return 0
}

func (a *app) idsHardwareOK() (bool, string) {
	if a.hwMemMB < idsMinMemMB || a.hwCores < idsMinCores {
		return false, fmt.Sprintf("security module requires >= 8 GB RAM and >= 4 cores (detected: %d MB, %d cores); use RPZ filtering on low-spec devices",
			a.hwMemMB, a.hwCores)
	}
	return true, ""
}

func (a *app) getIDS() idsState {
	a.store.mu.RLock()
	defer a.store.mu.RUnlock()
	if a.store.data.IDS == nil {
		return idsState{Mode: "off"}
	}
	return *a.store.data.IDS
}

func (a *app) setIDS(st idsState) error {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	a.store.data.IDS = &st
	return a.store.saveLocked()
}

func (a *app) ipsMinIDSDays() int { return atoi(env("SAGUARO_IPS_MIN_IDS_DAYS", "7"), 7) }

// ipsAllowed applies the W9 precondition: IDS must have been observing for
// the configured minimum period.
func (a *app) ipsAllowed(st idsState) (bool, string) {
	if st.Mode == "off" || st.IDSEnabledAt.IsZero() {
		return false, "enable IDS mode first; IPS requires an observation period"
	}
	days := int(time.Since(st.IDSEnabledAt).Hours() / 24)
	min := a.ipsMinIDSDays()
	if days < min {
		return false, fmt.Sprintf("IDS has been observing for %d days; %d required before IPS (repeat with force=true to override)", days, min)
	}
	return true, ""
}

func (a *app) apiIDSGet(w http.ResponseWriter, r *http.Request) {
	st := a.getIDS()
	hwOK, hwReason := a.idsHardwareOK()
	ipsOK, ipsReason := a.ipsAllowed(st)
	var stats map[string]int64
	if a.events != nil {
		if s, err := a.events.ModuleStats(r.Context(), "ids", time.Now().AddDate(0, 0, -14)); err == nil {
			stats = s
		}
	}
	if stats == nil {
		stats = map[string]int64{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"config":    st,
		"hw":        map[string]any{"memMB": a.hwMemMB, "cores": a.hwCores, "ok": hwOK, "reason": hwReason},
		"ips":       map[string]any{"allowed": ipsOK, "reason": ipsReason, "minIdsDays": a.ipsMinIDSDays()},
		"stats14d":  stats,
		"installed": a.suricataInstalled(r.Context()),
	})
}

// suricataInstalled reports whether the engine is present. The installer can
// skip it on small hardware, and until now that meant reinstalling the whole
// appliance to gain IDS — so the GUI needs to know, and to be able to fix it.
func (a *app) suricataInstalled(ctx context.Context) bool {
	out, err := a.runHarden(ctx, "status")
	if err != nil {
		return false
	}
	return parseKV(out)["suricata_installed"] == "yes"
}

// apiIDSInstall installs Suricata (and suricata-update) through the package
// adapter's tiny install allow-list, so an appliance that shipped without the
// IDS can gain it in place.
func (a *app) apiIDSInstall(w http.ResponseWriter, r *http.Request) {
	if ok, reason := a.idsHardwareOK(); !ok {
		writeError(w, http.StatusConflict, "hardver ne zadovoljava minimum za IDS: "+reason)
		return
	}
	if a.suricataInstalled(r.Context()) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "note": "Suricata je već instalirana."})
		return
	}
	// apt install pulls tens of megabytes; lift the 30 s write deadline the same
	// way the package-upgrade handler does, or the browser sees a truncated
	// failure while the install is still running.
	extendDeadline(w, 15*time.Minute)
	ctx, cancel := context.WithTimeout(r.Context(), 14*time.Minute)
	defer cancel()
	out, err := a.runPkg(ctx, "install", "suricata")
	if err != nil {
		a.recordSev(r, a.actor(r), "ids-install", "suricata", "failed", "warning",
			map[string]any{"output": truncate(string(out), 300)})
		writeError(w, http.StatusBadGateway, "instalacija nije uspjela: "+truncate(string(out), 300))
		return
	}
	// A freshly installed Suricata ships no rule files, and `suricata -T` fails
	// without them — so the engine would be installed but impossible to enable,
	// with only an opaque validation error to show for it. Fetch the ruleset as
	// part of the install so it leaves behind something that actually starts.
	note := "Suricata je instalirana i baza pravila je preuzeta. Sada je uključi u načinu IDS (promatranje)."
	if rulesOut, rulesErr := a.runIDS(ctx, "update-rules"); rulesErr != nil {
		note = "Suricata je instalirana, ali baza pravila nije preuzeta (" +
			truncate(strings.TrimSpace(string(rulesOut)), 200) +
			"). Pokreni \"Ažuriraj pravila\" prije uključivanja."
		a.recordSev(r, a.actor(r), "ids-install", "suricata-update", "failed", "warning",
			map[string]any{"output": truncate(string(rulesOut), 300)})
	}
	a.recordSev(r, a.actor(r), "ids-install", "suricata", "success", "security", nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true,
		"note": note, "output": truncate(string(out), 300)})
}

// apiIDSEnable turns on IDS (af-packet) or IPS (NFQUEUE + nftables queue
// rule through the existing 120 s firewall transaction).
func (a *app) apiIDSEnable(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Mode      string `json:"mode"`
		Interface string `json:"interface"`
		HomeNet   string `json:"homeNet"`
		Force     bool   `json:"force"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	if in.Mode != "ids" && in.Mode != "ips" {
		writeError(w, http.StatusBadRequest, "mode must be ids or ips")
		return
	}
	if ok, reason := a.idsHardwareOK(); !ok {
		writeError(w, http.StatusConflict, reason)
		return
	}
	st := a.getIDS()
	if in.Interface == "" {
		in.Interface = st.Interface
	}
	if in.HomeNet == "" {
		in.HomeNet = st.HomeNet
	}
	scfg := suricata.Config{Mode: suricata.Mode(in.Mode), Interface: in.Interface, HomeNet: in.HomeNet}
	if in.Mode == "ips" {
		gw, gwConfigured := a.getGateway()
		if !gwConfigured || !gw.GatewayEnabled {
			writeError(w, http.StatusConflict, "IPS inspects forwarded traffic and requires gateway mode (W8) first")
			return
		}
		if ok, reason := a.ipsAllowed(st); !ok && !in.Force {
			writeError(w, http.StatusConflict, reason)
			return
		}
	}
	text, err := scfg.Generate()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	staged := filepath.Join(filepath.Dir(a.store.path), stagedSuricataName)
	if err := os.WriteFile(staged, []byte(text), 0644); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot write staged suricata config")
		return
	}
	if out, err := a.runIDS(r.Context(), "apply", in.Mode); err != nil {
		a.recordSev(r, a.actor(r), "ids-enable", in.Mode, "failed", "security",
			map[string]any{"error": err.Error(), "output": truncate(string(out), 300)})
		writeError(w, http.StatusBadGateway, "suricata apply failed: "+truncate(string(out), 300))
		return
	}
	now := time.Now().UTC()
	if st.Mode == "off" || st.IDSEnabledAt.IsZero() {
		st.IDSEnabledAt = now
	}
	st.Interface, st.HomeNet = in.Interface, in.HomeNet
	st.Mode = in.Mode
	firewallNote := ""
	if in.Mode == "ips" {
		st.IPSEnabledAt = now
		if err := a.setGatewayIPS(r.Context(), true, false); err != nil {
			writeError(w, http.StatusBadGateway, "suricata started but the firewall queue rule failed: "+err.Error())
			return
		}
		firewallNote = "nftables queue rule applied with a 120 s confirm window — confirm on the Gateway page"
	}
	if err := a.setIDS(st); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist IDS state")
		return
	}
	a.recordSev(r, a.actor(r), "ids-enable", in.Mode, "success", "security",
		map[string]any{"interface": in.Interface, "force": in.Force})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mode": in.Mode, "note": firewallNote})
}

// apiIDSDisable is the always-available Emergency IPS off (W9): stops
// Suricata and removes the queue rule so traffic flows uninspected.
func (a *app) apiIDSDisable(w http.ResponseWriter, r *http.Request) {
	st := a.getIDS()
	if out, err := a.runIDS(r.Context(), "disable"); err != nil {
		writeError(w, http.StatusBadGateway, "disable failed: "+truncate(string(out), 300))
		return
	}
	// The queue rule is removed and confirmed in one step: an emergency stop
	// that silently reverts two minutes later is worse than none.
	queueNote := ""
	if st.Mode == "ips" {
		if err := a.setGatewayIPS(r.Context(), false, true); err != nil {
			a.log.Error("cannot remove IPS queue rule", "error", err)
			// Suricata is already stopped, so report honestly rather than
			// implying the firewall is clean.
			queueNote = "Suricata je zaustavljen, ali nftables queue pravilo nije uklonjeno: " + err.Error()
			a.recordSev(r, a.actor(r), "ids-disable", "nftables", "failed", "security",
				map[string]any{"error": err.Error()})
		}
	}
	st.Mode = "off"
	st.IPSEnabledAt = time.Time{}
	if err := a.setIDS(st); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist IDS state")
		return
	}
	a.recordSev(r, a.actor(r), "ids-disable", "suricata", "success", "security", nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "note": queueNote})
}

// apiIDSUpdateRules refreshes the Suricata ruleset (suricata-update) and reloads
// Suricata if it is running. Long-running (network fetch), so it is intentionally
// not wrapped in serialized().
func (a *app) apiIDSUpdateRules(w http.ResponseWriter, r *http.Request) {
	extendDeadline(w, 11*time.Minute)
	if out, err := a.runIDS(r.Context(), "update-rules"); err != nil {
		a.recordSev(r, a.actor(r), "ids-update-rules", "suricata", "failed", "warning",
			map[string]any{"error": truncate(string(out), 300)})
		writeError(w, http.StatusBadGateway, "update failed: "+truncate(string(out), 300))
		return
	}
	a.record(r, a.actor(r), "ids-update-rules", "suricata", "success", nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// setGatewayIPS toggles the NFQUEUE rule through the normal firewall
// transaction (stage + root adapter apply). When confirm is set the ruleset is
// also confirmed immediately, so it cannot auto-revert: turning IPS *off* must
// stick, otherwise the 120 s timer restores the queue rule against a Suricata
// that is no longer running. Turning it *on* deliberately keeps the window —
// inline inspection is exactly the change an operator may need undone.
func (a *app) setGatewayIPS(ctx context.Context, enabled, confirm bool) error {
	stored, ok := a.getGateway()
	if !ok {
		return fmt.Errorf("gateway is not configured")
	}
	stored.IPSEnabled = enabled
	// Render from the runtime view: generating from the stored config alone
	// would drop the VPN tunnel accepts, geo-block CIDRs, VPN input ports and
	// OpenVPN per-client policy from the live ruleset every time IPS toggles.
	gen, _ := a.firewallConfig()
	gen.IPSEnabled = enabled
	text, err := gen.Generate()
	if err != nil {
		return err
	}
	staged := filepath.Join(filepath.Dir(a.store.path), stagedRulesetName)
	if err := os.WriteFile(staged, []byte(text), 0644); err != nil {
		return err
	}
	if out, err := a.runFirewall(ctx, "apply"); err != nil {
		return fmt.Errorf("%s", truncate(string(out), 300))
	}
	if confirm {
		if out, err := a.runFirewall(ctx, "confirm"); err != nil {
			return fmt.Errorf("%s", truncate(string(out), 300))
		}
	}
	return a.setGateway(stored)
}
