package main

import (
	"fmt"
	"net"
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
		writeError(w, http.StatusBadGateway, friendlyError(err, "PowerDNS"))
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
		a.record(r, a.actor(r), "dns-zone-create", name, "failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadGateway, friendlyError(err, "PowerDNS"))
		return
	}
	a.record(r, a.actor(r), "dns-zone-create", name, "success", nil)
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
		writeError(w, http.StatusBadGateway, friendlyError(err, "PowerDNS"))
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
		a.record(r, a.actor(r), "dns-zone-delete", zone, "failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadGateway, friendlyError(err, "PowerDNS"))
		return
	}
	a.recordSev(r, a.actor(r), "dns-zone-delete", zone, "success", "warning", nil)
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
		a.record(r, a.actor(r), action, target, "failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadGateway, friendlyError(err, "PowerDNS"))
		return
	}
	a.record(r, a.actor(r), action, target, "success", map[string]any{"zone": zone, "ttl": rr.TTL, "values": len(rr.Records)})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// reverseZoneForCIDR returns the in-addr.arpa zone name for a /8, /16 or /24 IPv4
// prefix -- the classful reverse boundaries. Longer/other prefixes need RFC2317
// delegation, which is out of scope; the caller gets a clear error instead.
func reverseZoneForCIDR(cidr string) (string, error) {
	_, ipnet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return "", fmt.Errorf("invalid CIDR")
	}
	b := ipnet.IP.To4()
	if b == nil {
		return "", fmt.Errorf("only IPv4 reverse zones are supported")
	}
	ones, _ := ipnet.Mask.Size()
	switch ones {
	case 8:
		return fmt.Sprintf("%d.in-addr.arpa.", b[0]), nil
	case 16:
		return fmt.Sprintf("%d.%d.in-addr.arpa.", b[1], b[0]), nil
	case 24:
		return fmt.Sprintf("%d.%d.%d.in-addr.arpa.", b[2], b[1], b[0]), nil
	default:
		return "", fmt.Errorf("prefix must be /8, /16 or /24 for a reverse zone")
	}
}

// ptrNameForIP returns the fully-qualified PTR owner name for an IPv4 address,
// e.g. 192.168.50.10 -> 10.50.168.192.in-addr.arpa.
func ptrNameForIP(ipStr string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil || ip.To4() == nil {
		return "", fmt.Errorf("invalid IPv4 address")
	}
	b := ip.To4()
	return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", b[3], b[2], b[1], b[0]), nil
}

// apiDNSReverseCreate creates the in-addr.arpa reverse zone for a subnet CIDR;
// the arpa name is computed server-side so the GUI only sends the CIDR.
func (a *app) apiDNSReverseCreate(w http.ResponseWriter, r *http.Request) {
	c := a.pdnsClient()
	if c == nil {
		writeError(w, http.StatusServiceUnavailable, "PowerDNS API is not configured (SAGUARO_PDNS_API_URL/KEY)")
		return
	}
	var in struct {
		CIDR        string   `json:"cidr"`
		Nameservers []string `json:"nameservers"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	name, err := reverseZoneForCIDR(in.CIDR)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(in.Nameservers) == 0 {
		writeError(w, http.StatusBadRequest, "at least one nameserver is required")
		return
	}
	if err := c.CreateZone(r.Context(), name, in.Nameservers); err != nil {
		a.record(r, a.actor(r), "dns-reverse-create", name, "failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadGateway, friendlyError(err, "PowerDNS"))
		return
	}
	a.record(r, a.actor(r), "dns-reverse-create", name, "success", map[string]any{"cidr": in.CIDR})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "zone": name})
}

// apiDNSPTRUpsert creates/updates a single PTR record for an IP, routing it into
// whichever existing reverse zone is authoritative for that address (the longest
// in-addr.arpa zone that is a label-boundary suffix of the PTR name). Returns a
// clear error if no reverse zone covers the IP yet.
func (a *app) apiDNSPTRUpsert(w http.ResponseWriter, r *http.Request) {
	c := a.pdnsClient()
	if c == nil {
		writeError(w, http.StatusServiceUnavailable, "PowerDNS API is not configured (SAGUARO_PDNS_API_URL/KEY)")
		return
	}
	var in struct {
		IP       string `json:"ip"`
		Hostname string `json:"hostname"`
		TTL      int    `json:"ttl"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	ptr, err := ptrNameForIP(in.IP)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	host := pdns.Canonical(in.Hostname)
	if host == "" {
		writeError(w, http.StatusBadRequest, "hostname is required")
		return
	}
	zones, err := c.ListZones(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, friendlyError(err, "PowerDNS"))
		return
	}
	target := ""
	for _, z := range zones {
		zn := pdns.Canonical(z.Name)
		if !strings.HasSuffix(zn, ".in-addr.arpa.") {
			continue
		}
		if ptr == zn || strings.HasSuffix(ptr, "."+zn) {
			if len(zn) > len(target) {
				target = zn
			}
		}
	}
	if target == "" {
		writeError(w, http.StatusBadRequest, "no reverse zone covers this IP -- create a reverse (PTR) zone for its subnet first")
		return
	}
	if in.TTL <= 0 {
		in.TTL = 3600
	}
	rr := pdns.RRSet{Name: ptr, Type: "PTR", TTL: in.TTL, Records: []pdns.Record{{Content: host}}}
	if err := c.PatchRRSet(r.Context(), target, rr, false); err != nil {
		a.record(r, a.actor(r), "dns-ptr-upsert", ptr, "failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadGateway, friendlyError(err, "PowerDNS"))
		return
	}
	a.record(r, a.actor(r), "dns-ptr-upsert", ptr, "success", map[string]any{"zone": target, "host": host})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "zone": target, "ptr": ptr})
}
