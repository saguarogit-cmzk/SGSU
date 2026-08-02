package main

import (
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// defaultRunHarden invokes the root hardening adapter through the sudoers
// allow-list, argv-only like every other adapter call.
func defaultRunHarden(ctx context.Context, action string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "sudo", "-n", "/usr/sbin/saguaro-harden", action).CombinedOutput()
}

// The hardening module answers one question the audit kept asking: is this
// appliance actually configured the way its own documentation says it should
// be? Every check below corresponds to a finding that a real deployment can
// (and did) get wrong silently — SSH left on passwords, management reachable
// from the WAN, backups with no off-site copy, logs that never leave the box.
// Checks are read-only; the two fixes that need root go through saguaro-harden.

// hardeningCheck is one posture item shown in the GUI.
type hardeningCheck struct {
	Key      string `json:"key"`
	Title    string `json:"title"`
	Status   string `json:"status"` // ok | warn | fail | unknown
	Detail   string `json:"detail"`
	Severity string `json:"severity"` // critical | high | medium | low
	// Fix names the API action that resolves it, empty when the operator must
	// act elsewhere (another module, or physically).
	Fix string `json:"fix,omitempty"`
}

// parseKV turns the adapter's key=value output into a map.
func parseKV(out []byte) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			m[k] = v
		}
	}
	return m
}

// hardeningReport builds the full posture. Host facts come from the adapter;
// the rest is read from the stored configuration.
func (a *app) hardeningReport(ctx context.Context) []hardeningCheck {
	host := map[string]string{}
	if out, err := a.runHarden(ctx, "status"); err == nil {
		host = parseKV(out)
	}
	get := func(k string) string {
		if v, ok := host[k]; ok && v != "" {
			return v
		}
		return "unknown"
	}
	var checks []hardeningCheck
	add := func(c hardeningCheck) { checks = append(checks, c) }

	// --- SSH ---------------------------------------------------------------
	keys, _ := strconv.Atoi(get("ssh_keys_installed"))
	switch pw := get("ssh_password_auth"); {
	case pw == "no":
		add(hardeningCheck{Key: "ssh_password", Title: "SSH prijava lozinkom", Status: "ok",
			Detail: "Isključena — dopušteni su samo ključevi.", Severity: "critical"})
	case pw == "yes":
		detail := "Uključena. Lozinke se mogu pogađati; preporuka je pristup samo ključem."
		if keys < 1 {
			detail += " Prije isključivanja instaliraj SSH ključ (ssh-copy-id), inače gubiš pristup."
		}
		add(hardeningCheck{Key: "ssh_password", Title: "SSH prijava lozinkom", Status: "fail",
			Detail: detail, Severity: "critical", Fix: "ssh"})
	default:
		add(hardeningCheck{Key: "ssh_password", Title: "SSH prijava lozinkom", Status: "unknown",
			Detail: "Stanje nije moguće očitati.", Severity: "critical"})
	}
	if root := get("ssh_root_login"); root == "no" {
		add(hardeningCheck{Key: "ssh_root", Title: "SSH prijava kao root", Status: "ok",
			Detail: "Zabranjena.", Severity: "high"})
	} else if root != "unknown" {
		add(hardeningCheck{Key: "ssh_root", Title: "SSH prijava kao root", Status: "fail",
			Detail:   "Dopuštena (" + root + "). Administratori se trebaju prijavljivati imenom pa koristiti sudo.",
			Severity: "high", Fix: "ssh"})
	}
	if keys < 1 {
		add(hardeningCheck{Key: "ssh_keys", Title: "SSH ključ za administratora", Status: "warn",
			Detail:   "Nije pronađen nijedan ključ za račun koji može postati root. Bez ključa se pristup samo lozinkom ne smije isključiti.",
			Severity: "high"})
	} else {
		add(hardeningCheck{Key: "ssh_keys", Title: "SSH ključ za administratora", Status: "ok",
			Detail: strconv.Itoa(keys) + " instaliran(ih) ključ(ev)a.", Severity: "high"})
	}

	// --- Upravljački pristup ----------------------------------------------
	cfg, configured := a.getGateway()
	if configured {
		switch {
		case cfg.MgmtOnWAN:
			add(hardeningCheck{Key: "mgmt_wan", Title: "Upravljanje s WAN strane", Status: "fail",
				Detail:   "SSH i GUI su dostupni s WAN sučelja. Za produkciju isključi u modulu Gateway ili ograniči administrativnu mrežu.",
				Severity: "critical"})
		default:
			add(hardeningCheck{Key: "mgmt_wan", Title: "Upravljanje s WAN strane", Status: "ok",
				Detail: "Isključeno.", Severity: "critical"})
		}
		if strings.TrimSpace(cfg.AdminNetwork) == "" {
			add(hardeningCheck{Key: "admin_net", Title: "Administrativna mreža", Status: "warn",
				Detail: "Nije postavljena — upravljanje nema ograničenje izvorišne mreže.", Severity: "high"})
		} else {
			add(hardeningCheck{Key: "admin_net", Title: "Administrativna mreža", Status: "ok",
				Detail: "Ograničeno na " + cfg.AdminNetwork + ".", Severity: "high"})
		}
		if cfg.BruteForceProtect {
			add(hardeningCheck{Key: "brute", Title: "Zaštita od pogađanja lozinki (firewall)", Status: "ok",
				Detail: "Ograničenje broja novih veza prema upravljačkim portovima je uključeno.", Severity: "high"})
		} else {
			add(hardeningCheck{Key: "brute", Title: "Zaštita od pogađanja lozinki (firewall)", Status: "warn",
				Detail:   "Isključena. Uključi je u modulu Gateway; ograničava broj pokušaja po izvorišnoj adresi.",
				Severity: "high"})
		}
	}

	// --- Jezgra ------------------------------------------------------------
	kernelBad := []string{}
	if get("sysctl_send_redirects") == "1" {
		kernelBad = append(kernelBad, "šalje ICMP redirect")
	}
	if get("sysctl_accept_redirects") == "1" {
		kernelBad = append(kernelBad, "prihvaća ICMP redirect")
	}
	if get("sysctl_accept_source_route") == "1" {
		kernelBad = append(kernelBad, "prihvaća source routing")
	}
	if get("sysctl_log_martians") == "0" {
		kernelBad = append(kernelBad, "ne logira nemoguće adrese")
	}
	if len(kernelBad) == 0 && get("sysctl_send_redirects") != "unknown" {
		add(hardeningCheck{Key: "sysctl", Title: "Otvrdnjavanje mrežne jezgre", Status: "ok",
			Detail: "Redirecti i source routing isključeni, sumnjivi paketi se logiraju.", Severity: "medium"})
	} else if get("sysctl_send_redirects") == "unknown" {
		add(hardeningCheck{Key: "sysctl", Title: "Otvrdnjavanje mrežne jezgre", Status: "unknown",
			Detail: "Stanje nije moguće očitati.", Severity: "medium"})
	} else {
		add(hardeningCheck{Key: "sysctl", Title: "Otvrdnjavanje mrežne jezgre", Status: "warn",
			Detail: "Jezgra " + strings.Join(kernelBad, ", ") + ".", Severity: "medium", Fix: "sysctl"})
	}

	// --- Detekcija i dokazi ------------------------------------------------
	ids := a.getIDS()
	switch {
	case get("suricata_installed") == "no":
		add(hardeningCheck{Key: "ids", Title: "Detekcija upada (IDS)", Status: "warn",
			Detail: "Suricata nije instalirana — sadržaj prometa se ne pregledava.", Severity: "high"})
	case ids.Mode == "off":
		add(hardeningCheck{Key: "ids", Title: "Detekcija upada (IDS)", Status: "warn",
			Detail: "Suricata je instalirana, ali isključena. Uključi je u modulu IDS/IPS.", Severity: "high"})
	default:
		add(hardeningCheck{Key: "ids", Title: "Detekcija upada (IDS)", Status: "ok",
			Detail: "Aktivna u načinu " + ids.Mode + ".", Severity: "high"})
	}
	if s := a.getSIEM(); s.Enabled {
		add(hardeningCheck{Key: "siem", Title: "Prosljeđivanje logova izvan uređaja", Status: "ok",
			Detail: "Uključeno prema " + s.Host + ".", Severity: "high"})
	} else {
		add(hardeningCheck{Key: "siem", Title: "Prosljeđivanje logova izvan uređaja", Status: "warn",
			Detail:   "Isključeno — ako uređaj otkaže ili bude kompromitiran, dokazi nestaju s njim.",
			Severity: "high"})
	}

	// --- Certifikati -------------------------------------------------------
	if exp := a.certExpiryReport(); len(exp) > 0 {
		worst := exp[0]
		detail := fmt.Sprintf("Certifikat %q istječe za %d dana (%s).", worst.Name, worst.DaysLeft,
			worst.NotAfter.Format("2006-01-02"))
		if worst.Expired {
			detail = fmt.Sprintf("Certifikat %q je istekao %s.", worst.Name, worst.NotAfter.Format("2006-01-02"))
		}
		if len(exp) > 1 {
			detail += fmt.Sprintf(" Ukupno %d certifikata traži pažnju.", len(exp))
		}
		status := "warn"
		if worst.Severity == "critical" {
			status = "fail"
		}
		add(hardeningCheck{Key: "certs", Title: "Istek certifikata", Status: status,
			Detail: detail, Severity: "high"})
	} else {
		add(hardeningCheck{Key: "certs", Title: "Istek certifikata", Status: "ok",
			Detail: "Nijedan upravljani certifikat ne istječe u sljedeća 3 tjedna.", Severity: "high"})
	}

	// --- Oporavak ----------------------------------------------------------
	b := a.getBackup()
	offsite := strings.TrimSpace(b.SFTPHost) != "" || strings.TrimSpace(b.S3Bucket) != ""
	// Off-site copies are a recommendation, not a hard requirement: on a small
	// site the operator may deliberately keep the encrypted archive and the key
	// on removable media. It stays a warning so the risk is visible without
	// pretending the appliance is broken.
	if offsite {
		add(hardeningCheck{Key: "backup_offsite", Title: "Kopija izvan uređaja", Status: "ok",
			Detail: "Konfigurirano udaljeno odredište (SFTP ili S3).", Severity: "high"})
	} else {
		add(hardeningCheck{Key: "backup_offsite", Title: "Kopija izvan uređaja", Status: "warn",
			Detail:   "Kopije postoje samo lokalno. Za manju instalaciju dovoljno je povremeno preuzeti arhivu i ključ na vanjski medij; inače kvar diska uništava i sustav i kopije.",
			Severity: "high"})
	}
	if b.LastDrill.IsZero() {
		add(hardeningCheck{Key: "backup_drill", Title: "Testirano vraćanje iz kopije", Status: "fail",
			Detail: "Nikad provedeno. Netestirana kopija nije kopija.", Severity: "high"})
	} else {
		add(hardeningCheck{Key: "backup_drill", Title: "Testirano vraćanje iz kopije", Status: "ok",
			Detail: "Zadnji put " + b.LastDrill.Format("2006-01-02") + ".", Severity: "high"})
	}

	return checks
}

// apiHardeningGet returns the posture plus a summary count per status.
func (a *app) apiHardeningGet(w http.ResponseWriter, r *http.Request) {
	checks := a.hardeningReport(r.Context())
	summary := map[string]int{"ok": 0, "warn": 0, "fail": 0, "unknown": 0}
	for _, c := range checks {
		summary[c.Status]++
	}
	writeJSON(w, http.StatusOK, map[string]any{"checks": checks, "summary": summary})
}

// apiHardeningApply runs one of the two root fixes. The adapter refuses SSH
// hardening when no key is installed, so the lockout case is handled at the
// privilege boundary rather than trusted to the caller.
func (a *app) apiHardeningApply(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Target string `json:"target"` // ssh | sysctl
		Revert bool   `json:"revert"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	if in.Target != "ssh" && in.Target != "sysctl" {
		writeError(w, http.StatusBadRequest, "nepoznata meta otvrdnjavanja (ssh ili sysctl)")
		return
	}
	action := in.Target + "-harden"
	if in.Revert {
		action = in.Target + "-revert"
	}
	out, err := a.runHarden(r.Context(), action)
	if err != nil {
		a.recordSev(r, a.actor(r), "hardening", in.Target, "failed", "security",
			map[string]any{"action": action, "output": truncate(string(out), 300)})
		writeError(w, http.StatusBadGateway, truncate(strings.TrimSpace(string(out)), 300))
		return
	}
	a.recordSev(r, a.actor(r), "hardening", in.Target, "success", "security",
		map[string]any{"action": action})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "output": strings.TrimSpace(string(out))})
}
