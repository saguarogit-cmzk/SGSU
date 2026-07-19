package main

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// Permission keys gate mutations; every authenticated user may read.
const (
	permDNSWrite       = "dns:write"
	permDHCPWrite      = "dhcp:write"
	permServiceCheck   = "service:check"
	permServiceControl = "service:control"
	permMailWrite      = "mail:write"
	permUsersWrite     = "users:write"
	permSessions       = "sessions:revoke"
	permFirewall       = "firewall:write"
	permProxy          = "proxy:write"
	permCerts          = "certs:write"
	permBackup         = "backup:write"
	permPackages       = "packages:write"
)

var rolePermissions = map[string]map[string]bool{
	roleAdmin: {permDNSWrite: true, permDHCPWrite: true, permServiceCheck: true, permServiceControl: true,
		permMailWrite: true, permUsersWrite: true, permSessions: true, permFirewall: true, permProxy: true, permCerts: true, permBackup: true, permPackages: true},
	roleNetworkOperator: {permDHCPWrite: true, permServiceCheck: true, permServiceControl: true, permFirewall: true, permProxy: true},
	roleDNSOperator:     {permDNSWrite: true, permServiceCheck: true},
	roleAuditor:         {},
	roleReadOnly:        {},
}

func roleAllows(role, perm string) bool { return rolePermissions[role][perm] }

// ctxKeyUser carries the authenticated user (with live role) through a request.
type ctxKeyUser struct{}

func currentUser(r *http.Request) (userRecord, bool) {
	u, ok := r.Context().Value(ctxKeyUser{}).(userRecord)
	return u, ok
}

// actor returns the audit actor for the request.
func (a *app) actor(r *http.Request) string {
	if u, ok := currentUser(r); ok {
		return u.Username
	}
	return a.adminUser
}

// authz wraps auth with a permission check; the role is read live from the
// user store, so role changes and disables apply to existing sessions.
func (a *app) authz(perm string, next http.HandlerFunc) http.HandlerFunc {
	return a.auth(func(w http.ResponseWriter, r *http.Request) {
		u, ok := currentUser(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if !roleAllows(u.Role, perm) {
			a.recordSev(r, u.Username, "authz-deny", perm+" "+r.URL.Path, "denied", "security", nil)
			writeError(w, http.StatusForbidden, "your role does not permit this action")
			return
		}
		next(w, r)
	})
}

// --- user management API (admin only) ---

type userView struct {
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"createdAt"`
}

func (a *app) apiUsersList(w http.ResponseWriter, _ *http.Request) {
	recs, err := a.users.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "user store unavailable")
		return
	}
	out := make([]userView, 0, len(recs))
	for _, u := range recs {
		out = append(out, userView{Username: u.Username, Role: u.Role, Enabled: u.Enabled, CreatedAt: u.CreatedAt})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *app) apiUserCreate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	in.Username = strings.ToLower(strings.TrimSpace(in.Username))
	if !usernameRe.MatchString(in.Username) {
		writeError(w, http.StatusBadRequest, "invalid username (lowercase, 2-32 chars, a-z 0-9 . _ -)")
		return
	}
	if !validRoles[in.Role] {
		writeError(w, http.StatusBadRequest, "invalid role")
		return
	}
	if len(in.Password) < 14 {
		writeError(w, http.StatusBadRequest, "password must contain at least 14 characters")
		return
	}
	if _, exists, err := a.users.Get(in.Username); err != nil {
		writeError(w, http.StatusInternalServerError, "user store unavailable")
		return
	} else if exists {
		writeError(w, http.StatusConflict, "user already exists")
		return
	}
	phc, err := hashPassword(in.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot hash password")
		return
	}
	rec := userRecord{Username: in.Username, PHC: phc, Role: in.Role, Enabled: true, CreatedAt: time.Now().UTC(), MustChangePassword: true}
	if err := a.users.Upsert(rec); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist user")
		return
	}
	a.record(r, a.actor(r), "user-create", in.Username, "success", map[string]any{"role": in.Role})
	writeJSON(w, http.StatusOK, userView{Username: rec.Username, Role: rec.Role, Enabled: rec.Enabled, CreatedAt: rec.CreatedAt})
}

// apiUserUpdate changes role, enabled state and/or resets the password.
func (a *app) apiUserUpdate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	rec, ok, err := a.users.Get(name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "user store unavailable")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	var in struct {
		Role     *string `json:"role"`
		Enabled  *bool   `json:"enabled"`
		Password *string `json:"password"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	meta := map[string]any{}
	if in.Role != nil {
		if !validRoles[*in.Role] {
			writeError(w, http.StatusBadRequest, "invalid role")
			return
		}
		rec.Role = *in.Role
		meta["role"] = *in.Role
	}
	if in.Enabled != nil {
		rec.Enabled = *in.Enabled
		meta["enabled"] = *in.Enabled
	}
	if in.Password != nil {
		if len(*in.Password) < 14 {
			writeError(w, http.StatusBadRequest, "password must contain at least 14 characters")
			return
		}
		phc, err := hashPassword(*in.Password)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "cannot hash password")
			return
		}
		rec.PHC = phc
		rec.MustChangePassword = true
		meta["passwordReset"] = true
	}
	// The appliance must never lose its last enabled administrator.
	if rec.Role != roleAdmin || !rec.Enabled {
		if last, err := a.isLastEnabledAdmin(name); err != nil {
			writeError(w, http.StatusInternalServerError, "user store unavailable")
			return
		} else if last {
			writeError(w, http.StatusConflict, "cannot demote or disable the last enabled administrator")
			return
		}
	}
	if err := a.users.Upsert(rec); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist user")
		return
	}
	a.record(r, a.actor(r), "user-update", name, "success", meta)
	writeJSON(w, http.StatusOK, userView{Username: rec.Username, Role: rec.Role, Enabled: rec.Enabled, CreatedAt: rec.CreatedAt})
}

func (a *app) apiUserDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if last, err := a.isLastEnabledAdmin(name); err != nil {
		writeError(w, http.StatusInternalServerError, "user store unavailable")
		return
	} else if last {
		writeError(w, http.StatusConflict, "cannot delete the last enabled administrator")
		return
	}
	removed, err := a.users.Delete(name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "user store unavailable")
		return
	}
	if !removed {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	a.recordSev(r, a.actor(r), "user-delete", name, "success", "warning", nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// isLastEnabledAdmin reports whether username is the only enabled admin left.
func (a *app) isLastEnabledAdmin(username string) (bool, error) {
	recs, err := a.users.List()
	if err != nil {
		return false, err
	}
	others := 0
	target := false
	for _, u := range recs {
		if u.Role == roleAdmin && u.Enabled {
			if u.Username == username {
				target = true
			} else {
				others++
			}
		}
	}
	return target && others == 0, nil
}

// apiProfilePassword lets any authenticated user change their own password
// after proving the current one.
func (a *app) apiProfilePassword(w http.ResponseWriter, r *http.Request) {
	u, ok := currentUser(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var in struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	if !verifyPassword(in.OldPassword, u.PHC) {
		a.recordSev(r, u.Username, "password-change", "profile", "denied", "security", nil)
		writeError(w, http.StatusForbidden, "current password is incorrect")
		return
	}
	if len(in.NewPassword) < 14 {
		writeError(w, http.StatusBadRequest, "password must contain at least 14 characters")
		return
	}
	phc, err := hashPassword(in.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot hash password")
		return
	}
	u.PHC = phc
	u.MustChangePassword = false
	if err := a.users.Upsert(u); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist user")
		return
	}
	a.record(r, u.Username, "password-change", "profile", "success", nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// apiProfile returns the caller's identity for the GUI.
func (a *app) apiProfile(w http.ResponseWriter, r *http.Request) {
	u, ok := currentUser(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"username": u.Username, "role": u.Role, "mustChangePassword": u.MustChangePassword})
}

// requireUser injects the live user record after session validation; used by
// the auth middleware.
func (a *app) resolveUser(ctx context.Context, username string) (userRecord, bool) {
	rec, ok, err := a.users.Get(username)
	if err != nil {
		a.log.Error("user lookup failed", "error", err)
		return userRecord{}, false
	}
	if !ok || !rec.Enabled {
		return userRecord{}, false
	}
	return rec, true
}
