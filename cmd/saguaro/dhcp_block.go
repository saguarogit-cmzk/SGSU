package main

import (
	"context"
	"net/http"

	"saguaro.local/network-manager/internal/adapters/kea"
)

func (a *app) getBlockedMACs() []string {
	a.store.mu.RLock()
	defer a.store.mu.RUnlock()
	return append([]string(nil), a.store.data.BlockedMACs...)
}

func (a *app) setBlockedMACs(macs []string) error {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	a.store.data.BlockedMACs = macs
	return a.store.saveLocked()
}

// applyDropClass rebuilds Kea's DROP client class from the MAC list through the
// same validated config transaction used for subnets.
func (a *app) applyDropClass(ctx context.Context, macs []string) error {
	return a.keaSubnetTxn(ctx, func(dhcp4 map[string]any) error {
		kea.SetDropClass(dhcp4, macs)
		return nil
	})
}

func (a *app) apiDHCPBlockList(w http.ResponseWriter, _ *http.Request) {
	macs := a.getBlockedMACs()
	if macs == nil {
		macs = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"blocked": macs})
}

func (a *app) apiDHCPBlockAdd(w http.ResponseWriter, r *http.Request) {
	var in struct {
		MAC string `json:"mac"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	hex, err := kea.NormalizeMAC(in.MAC)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	mac := kea.FormatMACHex(hex)
	macs := a.getBlockedMACs()
	for _, m := range macs {
		if m == mac {
			writeJSON(w, http.StatusOK, map[string]any{"blocked": macs}) // idempotent
			return
		}
	}
	next := append(append([]string(nil), macs...), mac)
	if err := a.applyDropClass(r.Context(), next); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if err := a.setBlockedMACs(next); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist blocklist")
		return
	}
	a.recordSev(r, a.actor(r), "dhcp-block-add", mac, "success", "warning", nil)
	writeJSON(w, http.StatusOK, map[string]any{"blocked": next})
}

func (a *app) apiDHCPBlockDelete(w http.ResponseWriter, r *http.Request) {
	hex, err := kea.NormalizeMAC(r.PathValue("mac"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	mac := kea.FormatMACHex(hex)
	macs := a.getBlockedMACs()
	next := make([]string, 0, len(macs))
	found := false
	for _, m := range macs {
		if m == mac {
			found = true
			continue
		}
		next = append(next, m)
	}
	if !found {
		writeError(w, http.StatusNotFound, "MAC is not blocked")
		return
	}
	if err := a.applyDropClass(r.Context(), next); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if err := a.setBlockedMACs(next); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist blocklist")
		return
	}
	a.record(r, a.actor(r), "dhcp-block-remove", mac, "success", nil)
	writeJSON(w, http.StatusOK, map[string]any{"blocked": next})
}
