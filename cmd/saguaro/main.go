package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web/*
var webFS embed.FS

type service struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      string `json:"status"`
	Enabled     bool   `json:"enabled"`
}

type auditEvent struct {
	ID        string         `json:"id"`
	Time      time.Time      `json:"time"`
	Severity  string         `json:"severity"`
	Actor     string         `json:"actor"`
	Action    string         `json:"action"`
	Target    string         `json:"target"`
	Result    string         `json:"result"`
	RemoteIP  string         `json:"remoteIp"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

type state struct {
	Version  int          `json:"version"`
	Services []service    `json:"services"`
	Audit    []auditEvent `json:"audit"`
}

type store struct {
	mu   sync.RWMutex
	path string
	data state
}

type app struct {
	log         *slog.Logger
	store       *store
	adminUser   string
	passPHC     string
	sessions    sessionStore
	sessionTTL  time.Duration
	secure      bool
	ipLimiter   *loginLimiter
	userLimiter *loginLimiter

	// component endpoints used by health checks
	resolverAddr string
	pdnsURL      string
	pdnsKey      string
	keaURL       string
	keaUser      string
	keaPass      string
}

const appVersion = "0.4.1"

// ctxKeySession carries the authenticated session's token hash through a request.
type ctxKeySession struct{}

func main() {
	dataDir := env("SAGUARO_DATA_DIR", "/var/lib/saguaro")
	listen := env("SAGUARO_LISTEN", "127.0.0.1:9080")
	adminUser := env("SAGUARO_ADMIN_USER", "admin")
	adminPass := loadAdminPassword()
	if len(adminPass) < 14 {
		fmt.Fprintln(os.Stderr, "administrator password must contain at least 14 characters; provide it via systemd LoadCredential=admin-password, SAGUARO_ADMIN_PASSWORD_FILE or SAGUARO_ADMIN_PASSWORD")
		os.Exit(2)
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		panic(err)
	}
	s, err := openStore(filepath.Join(dataDir, "state.json"))
	if err != nil {
		panic(err)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	passPHC, err := hashPassword(adminPass)
	if err != nil {
		panic(err)
	}
	var sessions sessionStore
	if dsn := os.Getenv("SAGUARO_DB_DSN"); dsn != "" {
		sessions, err = openPGSessions(dsn)
		if err != nil {
			logger.Error("cannot open PostgreSQL session store", "error", err)
			os.Exit(1)
		}
		logger.Info("session store: postgresql")
	} else {
		sessions, err = openFileSessions(filepath.Join(dataDir, "sessions.json"))
		if err != nil {
			panic(err)
		}
		logger.Info("session store: file", "path", filepath.Join(dataDir, "sessions.json"))
	}
	a := &app{
		log:        logger,
		store:      s,
		adminUser:  adminUser,
		passPHC:    passPHC,
		sessions:   sessions,
		sessionTTL: time.Duration(atoi(env("SAGUARO_SESSION_HOURS", "8"), 8)) * time.Hour,
		secure:     env("SAGUARO_SECURE_COOKIE", "true") == "true",

		ipLimiter:   newLoginLimiter(),
		userLimiter: newLoginLimiter(),

		resolverAddr: env("SAGUARO_RESOLVER_ADDR", "127.0.0.1:53"),
		pdnsURL:      os.Getenv("SAGUARO_PDNS_API_URL"),
		pdnsKey:      os.Getenv("SAGUARO_PDNS_API_KEY"),
		keaURL:       os.Getenv("SAGUARO_KEA_API_URL"),
		keaUser:      os.Getenv("SAGUARO_KEA_API_USER"),
		keaPass:      os.Getenv("SAGUARO_KEA_API_PASSWORD"),
	}
	if err := a.sessions.PruneExpired(time.Now()); err != nil {
		a.log.Error("session prune failed", "error", err)
	}
	go func() {
		for range time.Tick(time.Hour) {
			if err := a.sessions.PruneExpired(time.Now()); err != nil {
				a.log.Error("session prune failed", "error", err)
			}
			a.ipLimiter.prune(time.Now())
			a.userLimiter.prune(time.Now())
		}
	}()
	go func() {
		// One early sweep so the dashboard shows real statuses shortly after
		// boot, then a periodic refresh.
		time.Sleep(5 * time.Second)
		a.runHealthChecks(context.Background())
		interval := time.Duration(atoi(env("SAGUARO_HEALTH_INTERVAL_MIN", "5"), 5)) * time.Minute
		for range time.Tick(interval) {
			a.runHealthChecks(context.Background())
		}
	}()
	srv := &http.Server{Addr: listen, Handler: a.handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	a.log.Info("saguaro starting", "listen", listen, "dataDir", dataDir)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		a.log.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func (a *app) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", a.login)
	mux.HandleFunc("POST /api/logout", a.auth(a.logout))
	mux.HandleFunc("GET /api/health", a.health)
	mux.HandleFunc("GET /api/health/deep", a.auth(a.healthDeep))
	mux.HandleFunc("GET /api/dashboard", a.auth(a.dashboard))
	mux.HandleFunc("GET /api/services", a.auth(a.services))
	mux.HandleFunc("POST /api/services/{id}/actions/{action}", a.auth(a.serviceAction))
	mux.HandleFunc("GET /api/audit", a.auth(a.audit))
	mux.HandleFunc("GET /api/sessions", a.auth(a.listSessions))
	mux.HandleFunc("POST /api/sessions/{id}/revoke", a.auth(a.revokeSession))
	assets, err := fs.Sub(webFS, "web")
	if err != nil { panic(err) }
	mux.Handle("/", http.FileServer(http.FS(assets)))
	return securityHeaders(a.requestLog(mux))
}

func openStore(path string) (*store, error) {
	s := &store{path: path, data: state{Version: 1, Services: defaultServices()}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, s.saveLocked()
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.data); err != nil {
		return nil, fmt.Errorf("invalid state file: %w", err)
	}
	return s, nil
}

func defaultServices() []service {
	return []service{
		{ID: "postgresql", Name: "PostgreSQL", Description: "Configuration, events, Kea and PowerDNS database", Status: "not-configured"},
		{ID: "unbound", Name: "Unbound", Description: "Recursive DNS resolver for clients", Status: "not-configured"},
		{ID: "pdns", Name: "PowerDNS Authoritative", Description: "Local authoritative zones with HTTP API", Status: "not-configured"},
		{ID: "kea", Name: "Kea DHCP", Description: "DHCPv4/v6, reservations and client classes", Status: "not-configured"},
		{ID: "kea-ddns", Name: "Kea DDNS", Description: "Automatic A/PTR updates from DHCP leases", Status: "not-configured"},
		{ID: "step-ca", Name: "Step CA", Description: "Internal certificate authority", Status: "not-configured"},
		{ID: "nginx", Name: "Nginx", Description: "TLS reverse proxy", Status: "not-configured"},
		{ID: "nftables", Name: "nftables", Description: "Host and gateway firewall", Status: "not-configured"},
	}
}

func (s *store) saveLocked() error {
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil { return err }
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil { return err }
	return os.Rename(tmp, s.path)
}

func (s *store) addAudit(e auditEvent) error {
	s.mu.Lock(); defer s.mu.Unlock()
	s.data.Audit = append([]auditEvent{e}, s.data.Audit...)
	if len(s.data.Audit) > 5000 { s.data.Audit = s.data.Audit[:5000] }
	return s.saveLocked()
}

func (a *app) login(w http.ResponseWriter, r *http.Request) {
	var in struct { Username string `json:"username"`; Password string `json:"password"` }
	if err := decodeJSON(w, r, &in); err != nil { return }
	ip := remoteIP(r)
	now := time.Now().UTC()
	if locked, retry := a.ipLimiter.check("ip:"+ip, now); locked {
		writeLocked(w, retry)
		return
	}
	if locked, retry := a.userLimiter.check("user:"+in.Username, now); locked {
		writeLocked(w, retry)
		return
	}
	userOK := subtle.ConstantTimeCompare([]byte(in.Username), []byte(a.adminUser)) == 1
	if !verifyPassword(in.Password, a.passPHC) || !userOK {
		time.Sleep(350 * time.Millisecond)
		lockIP := a.ipLimiter.fail("ip:"+ip, now)
		lockUser := a.userLimiter.fail("user:"+in.Username, now)
		a.record(r, in.Username, "login", "control-plane", "denied", nil)
		if lock := maxDuration(lockIP, lockUser); lock > 0 {
			a.recordSev(r, in.Username, "login-lockout", "control-plane", "locked", "security",
				map[string]any{"lockSeconds": int(lock.Seconds())})
			writeLocked(w, lock)
			return
		}
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	a.ipLimiter.success("ip:" + ip)
	a.userLimiter.success("user:" + in.Username)
	token := randomToken()
	csrf := randomToken()
	tokenHash := hashToken(token)
	rec := sessionRecord{TokenHash: tokenHash, ID: sessionID(tokenHash), Username: in.Username, CreatedAt: now, ExpiresAt: now.Add(a.sessionTTL), RemoteIP: ip, CSRFHash: hashToken(csrf)}
	if err := a.sessions.Create(rec); err != nil {
		a.log.Error("session create failed", "error", err)
		writeError(w, http.StatusInternalServerError, "session store unavailable")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "saguaro_session", Value: token, Path: "/", HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteStrictMode, MaxAge: int(a.sessionTTL.Seconds())})
	// Deliberately not HttpOnly: the SPA reads this cookie and echoes it in the
	// X-CSRF-Token header, which the auth middleware checks against the session.
	http.SetCookie(w, &http.Cookie{Name: "saguaro_csrf", Value: csrf, Path: "/", HttpOnly: false, Secure: a.secure, SameSite: http.SameSiteStrictMode, MaxAge: int(a.sessionTTL.Seconds())})
	a.record(r, in.Username, "login", "control-plane", "success", map[string]any{"sessionId": rec.ID})
	writeJSON(w, http.StatusOK, map[string]any{"user": in.Username})
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func writeLocked(w http.ResponseWriter, retry time.Duration) {
	secs := int(retry.Seconds()) + 1
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeError(w, http.StatusTooManyRequests, fmt.Sprintf("too many failed logins; retry in %ds", secs))
}

func maxDuration(a, b time.Duration) time.Duration { if a > b { return a }; return b }

func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("saguaro_session"); err == nil {
		if err := a.sessions.Delete(hashToken(c.Value)); err != nil { a.log.Error("session delete failed", "error", err) }
	}
	http.SetCookie(w, &http.Cookie{Name: "saguaro_session", Path: "/", MaxAge: -1, HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteStrictMode})
	http.SetCookie(w, &http.Cookie{Name: "saguaro_csrf", Path: "/", MaxAge: -1, Secure: a.secure, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *app) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("saguaro_session")
		if err != nil { writeError(w, http.StatusUnauthorized, "authentication required"); return }
		tokenHash := hashToken(c.Value)
		rec, ok, err := a.sessions.Get(tokenHash)
		if err != nil {
			a.log.Error("session lookup failed", "error", err)
			writeError(w, http.StatusInternalServerError, "session store unavailable")
			return
		}
		if ok && time.Now().After(rec.ExpiresAt) {
			if err := a.sessions.Delete(tokenHash); err != nil { a.log.Error("session delete failed", "error", err) }
			ok = false
		}
		if !ok { writeError(w, http.StatusUnauthorized, "authentication required"); return }
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			header := r.Header.Get("X-CSRF-Token")
			if header == "" || rec.CSRFHash == "" ||
				subtle.ConstantTimeCompare([]byte(hashToken(header)), []byte(rec.CSRFHash)) != 1 {
				a.recordSev(r, rec.Username, "csrf-reject", r.URL.Path, "denied", "security", nil)
				writeError(w, http.StatusForbidden, "missing or invalid CSRF token")
				return
			}
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKeySession{}, tokenHash)))
	}
}

func (a *app) listSessions(w http.ResponseWriter, r *http.Request) {
	recs, err := a.sessions.List()
	if err != nil { writeError(w, http.StatusInternalServerError, "session store unavailable"); return }
	current, _ := r.Context().Value(ctxKeySession{}).(string)
	type view struct {
		ID        string    `json:"id"`
		Username  string    `json:"username"`
		CreatedAt time.Time `json:"createdAt"`
		ExpiresAt time.Time `json:"expiresAt"`
		RemoteIP  string    `json:"remoteIp"`
		Current   bool      `json:"current"`
	}
	out := make([]view, 0, len(recs))
	for _, rec := range recs {
		out = append(out, view{ID: rec.ID, Username: rec.Username, CreatedAt: rec.CreatedAt, ExpiresAt: rec.ExpiresAt, RemoteIP: rec.RemoteIP, Current: rec.TokenHash == current})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *app) revokeSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	removed, err := a.sessions.DeleteByID(id)
	if err != nil { writeError(w, http.StatusInternalServerError, "session store unavailable"); return }
	if !removed { writeError(w, http.StatusNotFound, "session not found"); return }
	a.record(r, a.adminUser, "session-revoke", id, "success", nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// health is the unauthenticated liveness probe: it confirms only that the
// control plane answers. Component details require an authenticated session.
func (a *app) health(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": appVersion}) }

func (a *app) healthDeep(w http.ResponseWriter, r *http.Request) {
	results := a.runHealthChecks(r.Context())
	healthy := 0
	for _, res := range results { if res.Status == "healthy" { healthy++ } }
	writeJSON(w, http.StatusOK, map[string]any{"healthy": healthy, "total": len(results), "checks": results})
}

func (a *app) dashboard(w http.ResponseWriter, _ *http.Request) {
	a.store.mu.RLock(); defer a.store.mu.RUnlock()
	configured, healthy := 0, 0
	for _, s := range a.store.data.Services { if s.Enabled { configured++ }; if s.Status == "healthy" { healthy++ } }
	writeJSON(w, http.StatusOK, map[string]any{"services": len(a.store.data.Services), "configured": configured, "healthy": healthy, "alerts": 0, "recentAudit": first(a.store.data.Audit, 8)})
}

func (a *app) services(w http.ResponseWriter, _ *http.Request) { a.store.mu.RLock(); defer a.store.mu.RUnlock(); writeJSON(w, http.StatusOK, a.store.data.Services) }

func (a *app) serviceAction(w http.ResponseWriter, r *http.Request) {
	id, action := r.PathValue("id"), r.PathValue("action")
	if action != "check" { writeError(w, http.StatusNotImplemented, "only safe health checks are enabled in this milestone"); return }
	res, ok := a.runHealthCheck(r.Context(), id)
	if !ok { writeError(w, http.StatusNotFound, "service not found"); return }
	a.record(r, a.adminUser, "health-check", id, res.Status, map[string]any{"detail": res.Detail, "latencyMs": res.LatencyMs})
	writeJSON(w, http.StatusOK, map[string]any{"result": res})
}

func (a *app) audit(w http.ResponseWriter, _ *http.Request) { a.store.mu.RLock(); defer a.store.mu.RUnlock(); writeJSON(w, http.StatusOK, first(a.store.data.Audit, 200)) }

func (a *app) record(r *http.Request, actor, action, target, result string, meta map[string]any) {
	a.recordSev(r, actor, action, target, result, "info", meta)
}

func (a *app) recordSev(r *http.Request, actor, action, target, result, severity string, meta map[string]any) {
	e := auditEvent{ID: newID(), Time: time.Now().UTC(), Severity: severity, Actor: actor, Action: action, Target: target, Result: result, RemoteIP: remoteIP(r), Metadata: meta}
	if err := a.store.addAudit(e); err != nil { a.log.Error("audit persistence failed", "error", err) }
	if severity == "security" {
		a.log.Warn("security event", "action", action, "actor", actor, "target", target, "remote", remoteIP(r))
	}
}

// loadAdminPassword prefers file-based sources so the secret never has to live in
// an environment file: systemd LoadCredential first, then an explicit file path,
// then the plain environment variable for development runs.
func loadAdminPassword() string {
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		if b, err := os.ReadFile(filepath.Join(dir, "admin-password")); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	if path := os.Getenv("SAGUARO_ADMIN_PASSWORD_FILE"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot read SAGUARO_ADMIN_PASSWORD_FILE: %v\n", err)
			os.Exit(2)
		}
		return strings.TrimSpace(string(b))
	}
	return os.Getenv("SAGUARO_ADMIN_PASSWORD")
}

func securityHeaders(next http.Handler) http.Handler { return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("X-Content-Type-Options", "nosniff"); w.Header().Set("X-Frame-Options", "DENY"); w.Header().Set("Referrer-Policy", "no-referrer"); w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'"); next.ServeHTTP(w, r) }) }
func (a *app) requestLog(next http.Handler) http.Handler { return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { start := time.Now(); next.ServeHTTP(w, r); a.log.Info("http request", "method", r.Method, "path", r.URL.Path, "durationMs", time.Since(start).Milliseconds(), "remote", remoteIP(r)) }) }
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error { r.Body = http.MaxBytesReader(w, r.Body, 1<<20); d := json.NewDecoder(r.Body); d.DisallowUnknownFields(); if err := d.Decode(dst); err != nil { writeError(w, 400, "invalid JSON"); return err }; if err := d.Decode(&struct{}{}); !errors.Is(err, io.EOF) { writeError(w, 400, "request must contain one JSON object"); return errors.New("trailing JSON") }; return nil }
func writeJSON(w http.ResponseWriter, status int, v any) { w.Header().Set("Content-Type", "application/json"); w.WriteHeader(status); _ = json.NewEncoder(w).Encode(v) }
func writeError(w http.ResponseWriter, status int, message string) { writeJSON(w, status, map[string]string{"error": message}) }
func env(k, fallback string) string { if v := os.Getenv(k); v != "" { return v }; return fallback }
func newID() string { b := make([]byte, 12); _, _ = rand.Read(b); return hex.EncodeToString(b) }
func remoteIP(r *http.Request) string { host := r.RemoteAddr; if i := strings.LastIndex(host, ":"); i > 0 { host = host[:i] }; return strings.Trim(host, "[]") }
func first[T any](items []T, n int) []T { if len(items) < n { n = len(items) }; return items[:n] }
func atoi(s string, fallback int) int { v, err := strconv.Atoi(s); if err != nil { return fallback }; return v }
