package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// API tokens exist so automation (Ansible, monitoring, a backup script) can
// call the API without pretending to be a browser. Until now the only way in
// was a session cookie plus a CSRF header, which meant every script had to log
// in with an administrator's password and juggle two cookies — so in practice
// the admin password ended up in scripts.
//
// A token carries a role, so a monitoring job can be read-only while a
// deployment job gets what it needs. Tokens are shown once and stored hashed.

// tokenNameRe keeps names to something safe to show in an audit line.
var tokenNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,40}$`)

const (
	apiTokenPrefix = "sgs_"
	// apiTokenBytes is the entropy of the secret part. 32 bytes is far beyond
	// guessing range, which is also why a fast hash is the right choice below.
	apiTokenBytes = 32
)

// apiToken is the stored half of a token. The secret itself is never persisted.
type apiToken struct {
	ID string `json:"id"`
	// Name is operator-chosen ("ansible", "zabbix") so a revocation is obvious.
	Name string `json:"name"`
	Role string `json:"role"`
	// Hash is SHA-256 of the presented secret. Passwords need a slow KDF
	// because humans pick guessable ones; a 256-bit random token does not, and
	// a slow hash here would tax every single API request.
	Hash string `json:"hash"`
	// Preview is the leading characters of the secret, so the list can identify
	// a token without being able to reconstruct it.
	Preview   string    `json:"preview"`
	CreatedAt time.Time `json:"createdAt"`
	CreatedBy string    `json:"createdBy"`
	// ExpiresAt zero means no expiry.
	ExpiresAt time.Time `json:"expiresAt,omitempty"`
	LastUsed  time.Time `json:"lastUsed,omitempty"`
}

// expired reports whether the token is past its expiry.
func (t apiToken) expired(now time.Time) bool {
	return !t.ExpiresAt.IsZero() && now.After(t.ExpiresAt)
}

// view is the token without its hash, safe to return to the GUI.
func (t apiToken) view() map[string]any {
	m := map[string]any{
		"id": t.ID, "name": t.Name, "role": t.Role, "preview": t.Preview,
		"createdAt": t.CreatedAt, "createdBy": t.CreatedBy,
		"expired": t.expired(time.Now()),
	}
	if !t.ExpiresAt.IsZero() {
		m["expiresAt"] = t.ExpiresAt
	}
	if !t.LastUsed.IsZero() {
		m["lastUsed"] = t.LastUsed
	}
	return m
}

func (a *app) getAPITokens() []apiToken {
	a.store.mu.RLock()
	defer a.store.mu.RUnlock()
	out := make([]apiToken, len(a.store.data.APITokens))
	copy(out, a.store.data.APITokens)
	return out
}

func (a *app) setAPITokens(toks []apiToken) error {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	a.store.data.APITokens = toks
	return a.store.saveLocked()
}

// newAPIToken mints a secret and returns it with its stored half. The secret is
// returned to the caller exactly once and never written down anywhere else.
func newAPIToken(name, role, createdBy string, ttl time.Duration) (secret string, rec apiToken, err error) {
	buf := make([]byte, apiTokenBytes)
	if _, err = rand.Read(buf); err != nil {
		return "", apiToken{}, err
	}
	secret = apiTokenPrefix + base64.RawURLEncoding.EncodeToString(buf)
	rec = apiToken{
		ID:        newID(),
		Name:      name,
		Role:      role,
		Hash:      hashToken(secret),
		Preview:   secret[:len(apiTokenPrefix)+6],
		CreatedAt: time.Now().UTC(),
		CreatedBy: createdBy,
	}
	if ttl > 0 {
		rec.ExpiresAt = rec.CreatedAt.Add(ttl)
	}
	return secret, rec, nil
}

// authenticateToken resolves a bearer token to a synthetic user carrying the
// token's role. Comparison is constant-time against every stored hash so a
// timing signal cannot reveal which token exists.
func (a *app) authenticateToken(secret string) (userRecord, bool) {
	if !strings.HasPrefix(secret, apiTokenPrefix) {
		return userRecord{}, false
	}
	want := hashToken(secret)
	now := time.Now()
	toks := a.getAPITokens()
	idx := -1
	for i, t := range toks {
		if subtle.ConstantTimeCompare([]byte(t.Hash), []byte(want)) == 1 && !t.expired(now) {
			idx = i
		}
	}
	if idx < 0 {
		return userRecord{}, false
	}
	// Record use, but only when it moves by more than a minute: every API call
	// would otherwise rewrite state.json.
	if time.Since(toks[idx].LastUsed) > time.Minute {
		toks[idx].LastUsed = now.UTC()
		if err := a.setAPITokens(toks); err != nil {
			a.log.Error("cannot record token use", "error", err)
		}
	}
	return userRecord{
		Username: "token:" + toks[idx].Name,
		Role:     toks[idx].Role,
		Enabled:  true,
	}, true
}

// ctxKeyTokenAuth marks a request that authenticated with a bearer token.
type ctxKeyTokenAuth struct{}

func isTokenAuth(r *http.Request) bool {
	v, _ := r.Context().Value(ctxKeyTokenAuth{}).(bool)
	return v
}

// requireInteractive refuses token-authenticated access to token management
// itself. A leaked automation token must not be able to quietly mint a second,
// permanent one — recovering from a leak has to mean revoking it, not chasing
// whatever it created in the meantime.
func requireInteractive(w http.ResponseWriter, r *http.Request) bool {
	if isTokenAuth(r) {
		writeError(w, http.StatusForbidden,
			"upravljanje tokenima traži prijavu korisnika; API token ne može stvarati ni brisati tokene")
		return false
	}
	return true
}

// bearerToken extracts the secret from an Authorization header.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// --- API ---------------------------------------------------------------

func (a *app) apiTokensList(w http.ResponseWriter, r *http.Request) {
	toks := a.getAPITokens()
	out := make([]map[string]any, 0, len(toks))
	for _, t := range toks {
		out = append(out, t.view())
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": out})
}

// apiTokensCreate mints a token. The secret appears in this one response and
// nowhere else — not in the audit log, not in state.json.
func (a *app) apiTokensCreate(w http.ResponseWriter, r *http.Request) {
	if !requireInteractive(w, r) {
		return
	}
	var in struct {
		Name string `json:"name"`
		Role string `json:"role"`
		Days int    `json:"days,omitempty"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if !tokenNameRe.MatchString(in.Name) {
		writeError(w, http.StatusBadRequest, "ime tokena: 1-40 znakova (slova, brojke, . _ -)")
		return
	}
	if _, ok := rolePermissions[in.Role]; !ok {
		writeError(w, http.StatusBadRequest, "nepoznata uloga")
		return
	}
	if in.Days < 0 || in.Days > 3650 {
		writeError(w, http.StatusBadRequest, "trajanje mora biti između 0 (bez isteka) i 3650 dana")
		return
	}
	toks := a.getAPITokens()
	for _, t := range toks {
		if strings.EqualFold(t.Name, in.Name) {
			writeError(w, http.StatusConflict, "token s tim imenom već postoji")
			return
		}
	}
	secret, rec, err := newAPIToken(in.Name, in.Role, a.actor(r), time.Duration(in.Days)*24*time.Hour)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot generate token")
		return
	}
	if err := a.setAPITokens(append(toks, rec)); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist token")
		return
	}
	a.recordSev(r, a.actor(r), "api-token-create", rec.Name, "success", "security",
		map[string]any{"role": rec.Role, "expires": rec.ExpiresAt})
	writeJSON(w, http.StatusCreated, map[string]any{
		"token": rec.view(),
		// Shown once; there is no way to retrieve it later.
		"secret": secret,
		"note":   "Zapiši token sada — više se ne može prikazati. Koristi ga kao zaglavlje: Authorization: Bearer <token>",
	})
}

func (a *app) apiTokensRevoke(w http.ResponseWriter, r *http.Request) {
	if !requireInteractive(w, r) {
		return
	}
	id := r.PathValue("id")
	toks := a.getAPITokens()
	out := make([]apiToken, 0, len(toks))
	var revoked string
	for _, t := range toks {
		if t.ID == id {
			revoked = t.Name
			continue
		}
		out = append(out, t)
	}
	if revoked == "" {
		writeError(w, http.StatusNotFound, "nepoznat token")
		return
	}
	if err := a.setAPITokens(out); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist tokens")
		return
	}
	a.recordSev(r, a.actor(r), "api-token-revoke", revoked, "success", "security", nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
