package main

import (
	"net/http"
	"regexp"
	"strings"

	"saguaro.local/network-manager/internal/adapters/pdns"
)

func (a *app) pdnsClient() *pdns.Client {
	if a.pdnsURL == "" || a.pdnsKey == "" {
		return nil
	}
	return pdns.New(a.pdnsURL, a.pdnsKey)
}

var zoneNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.?$`)

// recordTypes is the allowlist the GUI can manage; DNSSEC and zone-plumbing
// types stay under PowerDNS control.
var recordTypes = map[string]bool{"A": true, "AAAA": true, "CNAME": true, "TXT": true,
	"MX": true, "SRV": true, "NS": true, "PTR": true, "CAA": true}

func (a *app) apiDNSZones(w http.ResponseWriter, r *http.Request) {
	c := a.pdnsClient()
	if c == nil {
		writeError(w, http.StatusServiceUnavailable, "PowerDNS API is not configured (SAGUARO_PDNS_API_URL/KEY)")
		return
	}
	zones, err := c.ListZones(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if zones == nil {
		zones = []pdns.Zone{}
	}
	writeJSON(w, http.StatusOK, zones)
}

func (a *app) apiDNSZoneCreate(w http.ResponseWriter, r *http.Request) {
	c := a.pdnsClient()
	if c == nil {
		writeError(w, http.StatusServiceUnavailable, "PowerDNS API is not configured (SAGUARO_PDNS_API_URL/KEY)")
		return
	}
	var in struct {
		Name        string   `json:"name"`
		Nameservers []string `json:"nameservers"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	name := strings.ToLower(strings.TrimSpace(in.Name))
	if !zoneNameRe.MatchString(name) {
		writeError(w, http.StatusBadRequest, "invalid zone name")
		return
	}
	if len(in.Nameservers) == 0 {
		writeError(w, http.StatusBadRequest, "at least one nameserver is required")
		return
	}
	if err := c.CreateZone(r.Context(), name, in.Nameservers); err != nil {
		a.record(r, a.adminUser, "dns-zone-create", name, "failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	a.record(r, a.adminUser, "dns-zone-create", name, "success", nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *app) apiDNSZoneGet(w http.ResponseWriter, r *http.Request) {
	c := a.pdnsClient()
	if c == nil {
		writeError(w, http.StatusServiceUnavailable, "PowerDNS API is not configured (SAGUARO_PDNS_API_URL/KEY)")
		return
	}
	detail, err := c.GetZone(r.Context(), r.PathValue("zone"))
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func (a *app) apiDNSZoneDelete(w http.ResponseWriter, r *http.Request) {
	c := a.pdnsClient()
	if c == nil {
		writeError(w, http.StatusServiceUnavailable, "PowerDNS API is not configured (SAGUARO_PDNS_API_URL/KEY)")
		return
	}
	zone := r.PathValue("zone")
	if err := c.DeleteZone(r.Context(), zone); err != nil {
		a.record(r, a.adminUser, "dns-zone-delete", zone, "failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	a.recordSev(r, a.adminUser, "dns-zone-delete", zone, "success", "warning", nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// apiDNSRecordPut upserts (or with delete=true removes) one rrset.
func (a *app) apiDNSRecordPut(w http.ResponseWriter, r *http.Request) {
	c := a.pdnsClient()
	if c == nil {
		writeError(w, http.StatusServiceUnavailable, "PowerDNS API is not configured (SAGUARO_PDNS_API_URL/KEY)")
		return
	}
	zone := r.PathValue("zone")
	var in struct {
		Name     string   `json:"name"`
		Type     string   `json:"type"`
		TTL      int      `json:"ttl"`
		Contents []string `json:"contents"`
		Delete   bool     `json:"delete"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	typ := strings.ToUpper(strings.TrimSpace(in.Type))
	if !recordTypes[typ] {
		writeError(w, http.StatusBadRequest, "unsupported record type")
		return
	}
	if in.TTL <= 0 {
		in.TTL = 3600
	}
	rr := pdns.RRSet{Name: in.Name, Type: typ, TTL: in.TTL}
	if !in.Delete {
		if len(in.Contents) == 0 {
			writeError(w, http.StatusBadRequest, "at least one record value is required")
			return
		}
		for _, content := range in.Contents {
			if strings.TrimSpace(content) == "" {
				writeError(w, http.StatusBadRequest, "empty record value")
				return
			}
			rr.Records = append(rr.Records, pdns.Record{Content: content})
		}
	}
	action := "dns-record-upsert"
	if in.Delete {
		action = "dns-record-delete"
	}
	target := pdns.Canonical(in.Name) + "/" + typ
	if err := c.PatchRRSet(r.Context(), zone, rr, in.Delete); err != nil {
		a.record(r, a.adminUser, action, target, "failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	a.record(r, a.adminUser, action, target, "success", map[string]any{"zone": zone, "ttl": rr.TTL, "values": len(rr.Records)})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
