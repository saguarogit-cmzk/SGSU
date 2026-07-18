package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

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

// keaSubnetTxn implements the spec's configuration transaction entirely via
// Kea core API commands: config-get (inspect) → mutate → config-test
// (validate) → config-set (apply) → status-get (verify, with config-set
// rollback on failure) → config-write (persist) + JSON backup on disk.
func (a *app) keaSubnetTxn(ctx context.Context, mutate func(dhcp4 map[string]any) error) error {
	c := a.keaClient()
	if c == nil {
		return fmt.Errorf("%s", keaUnavailable)
	}
	cfg, err := c.ConfigGetRaw(ctx)
	if err != nil {
		return fmt.Errorf("config-get: %w", err)
	}
	backup, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	dhcp4 := cfg["Dhcp4"].(map[string]any)
	if err := mutate(dhcp4); err != nil {
		return err
	}
	if err := c.ConfigTest(ctx, cfg); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}
	if err := c.ConfigSet(ctx, cfg); err != nil {
		return fmt.Errorf("apply failed: %w", err)
	}
	if _, err := c.Status(ctx); err != nil {
		var prev map[string]any
		if uerr := json.Unmarshal(backup, &prev); uerr == nil {
			if rbErr := c.ConfigSet(ctx, prev); rbErr != nil {
				a.log.Error("ROLLBACK FAILED after verify failure", "error", rbErr)
				return fmt.Errorf("verify failed AND rollback failed: %v / %v", err, rbErr)
			}
		}
		return fmt.Errorf("verify failed, previous configuration restored: %w", err)
	}
	if err := c.ConfigWrite(ctx); err != nil {
		a.log.Warn("config-write failed; the running config is applied but not persisted to disk", "error", err)
	}
	backupPath := filepath.Join(filepath.Dir(a.store.path), fmt.Sprintf("kea-config-backup-%d.json", time.Now().Unix()))
	if err := os.WriteFile(backupPath, backup, 0600); err != nil {
		a.log.Warn("cannot store kea config backup", "error", err)
	}
	return nil
}

func (a *app) apiDHCPSubnetAdd(w http.ResponseWriter, r *http.Request) {
	var in kea.SubnetSpec
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	var newID int64
	err := a.keaSubnetTxn(r.Context(), func(dhcp4 map[string]any) error {
		id, err := kea.AddSubnet(dhcp4, in)
		newID = id
		return err
	})
	if err != nil {
		a.record(r, a.actor(r), "dhcp-subnet-add", in.Subnet, "failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.record(r, a.actor(r), "dhcp-subnet-add", in.Subnet, "success", map[string]any{"id": newID, "pool": in.PoolStart + " - " + in.PoolEnd})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": newID})
}

func (a *app) apiDHCPSubnetUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid subnet id")
		return
	}
	var in kea.SubnetSpec
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	err = a.keaSubnetTxn(r.Context(), func(dhcp4 map[string]any) error {
		return kea.UpdateSubnet(dhcp4, id, in)
	})
	if err != nil {
		a.record(r, a.actor(r), "dhcp-subnet-update", in.Subnet, "failed", map[string]any{"error": err.Error(), "id": id})
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.record(r, a.actor(r), "dhcp-subnet-update", in.Subnet, "success", map[string]any{"id": id, "pool": in.PoolStart + " - " + in.PoolEnd})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *app) apiDHCPSubnetDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid subnet id")
		return
	}
	// Refuse deleting a subnet that still carries reservations unless the
	// caller explicitly forces it.
	if a.keaHosts != nil && r.URL.Query().Get("force") != "true" {
		if resv, err := a.keaHosts.List(r.Context(), id); err == nil && len(resv) > 0 {
			writeError(w, http.StatusConflict, fmt.Sprintf("subnet has %d reservations; delete them first or repeat with ?force=true", len(resv)))
			return
		}
	}
	err = a.keaSubnetTxn(r.Context(), func(dhcp4 map[string]any) error {
		if !kea.DeleteSubnet(dhcp4, id) {
			return fmt.Errorf("subnet id %d not found", id)
		}
		return nil
	})
	if err != nil {
		a.record(r, a.actor(r), "dhcp-subnet-delete", strconv.FormatInt(id, 10), "failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.recordSev(r, a.actor(r), "dhcp-subnet-delete", strconv.FormatInt(id, 10), "success", "warning", nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

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
		a.record(r, a.actor(r), "dhcp-reservation-add", in.IP, "failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.record(r, a.actor(r), "dhcp-reservation-add", in.IP, "success",
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
	a.record(r, a.actor(r), "dhcp-reservation-delete", strconv.FormatInt(id, 10), "success", nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
