package main

import (
	"net/http"
	"strconv"

	"saguaro.local/network-manager/internal/adapters/kea"
)

func (a *app) keaClient() *kea.Client {
	if a.keaURL == "" || a.keaUser == "" || a.keaPass == "" {
		return nil
	}
	return kea.New(a.keaURL, a.keaUser, a.keaPass)
}

const keaUnavailable = "Kea control agent is not configured (SAGUARO_KEA_API_URL/USER/PASSWORD)"

func (a *app) apiDHCPStatus(w http.ResponseWriter, r *http.Request) {
	c := a.keaClient()
	if c == nil {
		writeError(w, http.StatusServiceUnavailable, keaUnavailable)
		return
	}
	raw, err := c.Status(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (a *app) apiDHCPSubnets(w http.ResponseWriter, r *http.Request) {
	c := a.keaClient()
	if c == nil {
		writeError(w, http.StatusServiceUnavailable, keaUnavailable)
		return
	}
	subnets, err := c.Subnets(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if subnets == nil {
		subnets = []kea.Subnet{}
	}
	writeJSON(w, http.StatusOK, subnets)
}

func (a *app) apiDHCPLeases(w http.ResponseWriter, r *http.Request) {
	c := a.keaClient()
	if c == nil {
		writeError(w, http.StatusServiceUnavailable, keaUnavailable)
		return
	}
	leases, err := c.Leases(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if leases == nil {
		leases = []kea.Lease{}
	}
	writeJSON(w, http.StatusOK, leases)
}

const keaDBUnavailable = "Kea host database is not configured (SAGUARO_KEA_DB_DSN)"

func (a *app) apiDHCPReservations(w http.ResponseWriter, r *http.Request) {
	if a.keaHosts == nil {
		writeError(w, http.StatusServiceUnavailable, keaDBUnavailable)
		return
	}
	subnetID, _ := strconv.ParseInt(r.URL.Query().Get("subnetId"), 10, 64)
	out, err := a.keaHosts.List(r.Context(), subnetID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if out == nil {
		out = []kea.Reservation{}
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *app) apiDHCPReservationAdd(w http.ResponseWriter, r *http.Request) {
	if a.keaHosts == nil {
		writeError(w, http.StatusServiceUnavailable, keaDBUnavailable)
		return
	}
	var in kea.Reservation
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	id, err := a.keaHosts.Add(r.Context(), in)
	if err != nil {
		a.record(r, a.adminUser, "dhcp-reservation-add", in.IP, "failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.record(r, a.adminUser, "dhcp-reservation-add", in.IP, "success",
		map[string]any{"mac": in.MAC, "hostname": in.Hostname, "subnetId": in.SubnetID, "hostId": id})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}

func (a *app) apiDHCPReservationDelete(w http.ResponseWriter, r *http.Request) {
	if a.keaHosts == nil {
		writeError(w, http.StatusServiceUnavailable, keaDBUnavailable)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid reservation id")
		return
	}
	removed, err := a.keaHosts.Delete(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !removed {
		writeError(w, http.StatusNotFound, "reservation not found")
		return
	}
	a.record(r, a.adminUser, "dhcp-reservation-delete", strconv.FormatInt(id, 10), "success", nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
