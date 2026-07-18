package main

import (
	"net/http"
	"os"
	"strings"
)

// Deployment modes. "gateway" is the full firewall/gateway/VPN (UTM) appliance;
// "router" is a local DHCP/DNS/router that sits behind another gateway and does
// not do WAN NAT or perimeter firewalling.
const (
	profileGateway = "gateway"
	profileRouter  = "router"
)

func validProfile(p string) bool {
	return p == profileGateway || p == profileRouter
}

// profileSeedFile lets the installer preselect the deployment mode. It is read
// once, only when the stored state has no profile yet.
const profileSeedFile = "/etc/saguaro/profile"

// seedProfile picks the initial deployment mode when state has none: the
// installer's /etc/saguaro/profile if valid, otherwise "gateway" (preserves
// the behaviour of installs that predate this setting).
func seedProfile(s *store) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if validProfile(s.data.SystemProfile) {
		return
	}
	p := profileGateway
	if b, err := os.ReadFile(profileSeedFile); err == nil {
		if v := strings.TrimSpace(string(b)); validProfile(v) {
			p = v
		}
	}
	s.data.SystemProfile = p
	_ = s.saveLocked()
}

func (a *app) getProfile() string {
	a.store.mu.RLock()
	defer a.store.mu.RUnlock()
	if validProfile(a.store.data.SystemProfile) {
		return a.store.data.SystemProfile
	}
	return profileGateway
}

func (a *app) setProfile(p string) error {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	a.store.data.SystemProfile = p
	return a.store.saveLocked()
}

// profileView describes the mode and which capability groups it enables, so the
// GUI can hide UTM modules and show the right guidance in router mode.
func profileView(p string) map[string]any {
	gateway := p == profileGateway
	return map[string]any{
		"profile": p,
		"gateway": gateway, // WAN routing, NAT, perimeter firewall
		"utm":     gateway, // IDS/IPS, VPN, multi-WAN
	}
}

func (a *app) apiSystemGet(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, profileView(a.getProfile()))
}

func (a *app) apiSystemProfilePut(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Profile string `json:"profile"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	if !validProfile(in.Profile) {
		writeError(w, http.StatusBadRequest, `profile must be "gateway" or "router"`)
		return
	}
	// Switching to router mode while the WAN gateway is live is contradictory:
	// require the operator to turn the gateway off first so they see the change.
	if in.Profile == profileRouter {
		if gw, ok := a.getGateway(); ok && gw.GatewayEnabled {
			writeError(w, http.StatusConflict,
				"gateway mode is active; disable Gateway (WAN/NAT) before switching to router profile")
			return
		}
	}
	if err := a.setProfile(in.Profile); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist deployment mode")
		return
	}
	a.recordSev(r, a.actor(r), "system-profile", in.Profile, "success", "warning", map[string]any{"profile": in.Profile})
	writeJSON(w, http.StatusOK, profileView(in.Profile))
}
