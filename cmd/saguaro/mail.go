package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	evstore "saguaro.local/network-manager/internal/events"
	mailmod "saguaro.local/network-manager/internal/mail"
)

func (a *app) getMail() (mailmod.Config, bool) {
	a.store.mu.RLock()
	defer a.store.mu.RUnlock()
	if a.store.data.Mail == nil {
		return mailmod.Config{}, false
	}
	cfg := *a.store.data.Mail
	cfg.Recipients = append([]string(nil), cfg.Recipients...)
	return cfg, true
}

func (a *app) setMail(cfg mailmod.Config) error {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	a.store.data.Mail = &cfg
	return a.store.saveLocked()
}

// mailView is the API representation: the encrypted password is never
// exposed, only whether one is stored.
type mailView struct {
	Enabled     bool     `json:"enabled"`
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	TLSMode     string   `json:"tlsMode"`
	From        string   `json:"from"`
	Username    string   `json:"username"`
	HasPassword bool     `json:"hasPassword"`
	Recipients  []string `json:"recipients"`
	MinSeverity string   `json:"minSeverity"`
}

func toView(cfg mailmod.Config) mailView {
	if cfg.Recipients == nil {
		cfg.Recipients = []string{}
	}
	return mailView{Enabled: cfg.Enabled, Host: cfg.Host, Port: cfg.Port, TLSMode: cfg.TLSMode,
		From: cfg.From, Username: cfg.Username, HasPassword: cfg.PasswordEnc != "",
		Recipients: cfg.Recipients, MinSeverity: cfg.MinSeverity}
}

func (a *app) apiMailGet(w http.ResponseWriter, _ *http.Request) {
	cfg, ok := a.getMail()
	if !ok {
		cfg = mailmod.Config{Port: 587, TLSMode: "starttls", MinSeverity: "error", Recipients: []string{}}
	}
	writeJSON(w, http.StatusOK, toView(cfg))
}

func (a *app) apiMailPut(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled     bool     `json:"enabled"`
		Host        string   `json:"host"`
		Port        int      `json:"port"`
		TLSMode     string   `json:"tlsMode"`
		From        string   `json:"from"`
		Username    string   `json:"username"`
		Password    string   `json:"password"` // empty = keep the stored one
		Recipients  []string `json:"recipients"`
		MinSeverity string   `json:"minSeverity"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	if in.MinSeverity == "" {
		in.MinSeverity = "error"
	}
	if !evstore.ValidSeverity(in.MinSeverity) {
		writeError(w, http.StatusBadRequest, "invalid minSeverity")
		return
	}
	cfg := mailmod.Config{Enabled: in.Enabled, Host: in.Host, Port: in.Port, TLSMode: in.TLSMode,
		From: in.From, Username: in.Username, Recipients: in.Recipients, MinSeverity: in.MinSeverity}
	if in.Password != "" {
		if a.mailKey == nil {
			writeError(w, http.StatusInternalServerError, "secret key unavailable; cannot store SMTP password")
			return
		}
		enc, err := mailmod.Encrypt(a.mailKey, in.Password)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "cannot encrypt SMTP password")
			return
		}
		cfg.PasswordEnc = enc
	} else if old, ok := a.getMail(); ok {
		cfg.PasswordEnc = old.PasswordEnc
	}
	if err := cfg.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.setMail(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist mail configuration")
		return
	}
	a.record(r, a.adminUser, "mail-config", "mail", "success", map[string]any{
		"host": cfg.Host, "port": cfg.Port, "tlsMode": cfg.TLSMode,
		"recipients": len(cfg.Recipients), "minSeverity": cfg.MinSeverity, "enabled": cfg.Enabled})
	writeJSON(w, http.StatusOK, toView(cfg))
}

func (a *app) apiMailTest(w http.ResponseWriter, r *http.Request) {
	cfg, ok := a.getMail()
	if !ok {
		writeError(w, http.StatusBadRequest, "mail is not configured yet")
		return
	}
	err := mailmod.Send(cfg, a.mailKey, "[SNA] Test message",
		"This is a Saguaro Network Appliance test message. If you can read this, SMTP settings work.")
	if err != nil {
		a.record(r, a.adminUser, "mail-test", "mail", "failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadGateway, "test mail failed: "+err.Error())
		return
	}
	a.record(r, a.adminUser, "mail-test", "mail", "success", nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// alertLoop is the mail-alert dispatcher: every 30 s it reads events newer
// than its cursor at or above the configured severity, sends first
// occurrences immediately (batched per tick into one message) and, after the
// 10-minute window, a summary of suppressed duplicates.
func (a *app) alertLoop() {
	if a.events == nil {
		return
	}
	ctx := context.Background()
	cursor, err := a.events.MaxID(ctx)
	if err != nil {
		a.log.Error("alert loop: cannot read event cursor", "error", err)
	}
	agg := mailmod.NewAggregator(10 * time.Minute)
	for range time.Tick(30 * time.Second) {
		cfg, ok := a.getMail()
		if !ok || !cfg.Enabled {
			continue
		}
		sevs := evstore.SeveritiesAtLeast(cfg.MinSeverity)
		if sevs == nil {
			sevs = evstore.SeveritiesAtLeast("error")
		}
		evs, err := a.events.QueryAfter(ctx, cursor, sevs, 500)
		if err != nil {
			a.log.Error("alert loop: event query failed", "error", err)
			continue
		}
		now := time.Now()
		var fresh []evstore.Event
		for _, e := range evs {
			cursor = e.ID
			key := e.Module + "|" + e.Severity + "|" + e.Action + "|" + truncate(e.Message, 120)
			if agg.Offer(key, e.Message, now) {
				fresh = append(fresh, e)
			}
		}
		if len(fresh) > 0 {
			subject := fmt.Sprintf("[SNA][%s] %s: %s", strings.ToUpper(fresh[0].Severity), fresh[0].Module, truncate(fresh[0].Message, 80))
			if len(fresh) > 1 {
				subject = fmt.Sprintf("[SNA] %d new alerts (%s and above)", len(fresh), cfg.MinSeverity)
			}
			var b strings.Builder
			for _, e := range fresh {
				fmt.Fprintf(&b, "%s  [%s] %s: %s\n", e.TS.Format(time.RFC3339), e.Severity, e.Module, e.Message)
			}
			b.WriteString("\nDuplicates of these events are aggregated for 10 minutes.\n")
			if err := mailmod.Send(cfg, a.mailKey, subject, b.String()); err != nil {
				a.log.Error("alert mail failed", "error", err, "count", len(fresh))
			}
		}
		if sums := agg.Flush(now); len(sums) > 0 {
			var b strings.Builder
			total := 0
			for _, s := range sums {
				total += s.Count
				fmt.Fprintf(&b, "%dx  %s\n     last: %s\n", s.Count, s.Key, truncate(s.Last, 200))
			}
			subject := fmt.Sprintf("[SNA] summary: %d suppressed duplicate events", total)
			if err := mailmod.Send(cfg, a.mailKey, subject, b.String()); err != nil {
				a.log.Error("summary mail failed", "error", err)
			}
		}
	}
}
