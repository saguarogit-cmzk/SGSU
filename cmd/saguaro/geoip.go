package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const geoDir = "/var/lib/saguaro/geoip"
const geoBaseURL = "https://www.ipdeny.com/ipblocks/data/aggregated/%s-aggregated.zone"

var geoCode = regexp.MustCompile(`^[a-z]{2}$`)

// geoCIDRsForCodes reads the cached, per-country CIDR lists for the given codes
// and returns every valid IPv4 CIDR. Missing/invalid entries are skipped.
func geoCIDRsForCodes(codes []string) []string {
	var out []string
	for _, cc := range codes {
		data, err := os.ReadFile(filepath.Join(geoDir, cc+".zone"))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			if _, _, err := net.ParseCIDR(line); err == nil {
				out = append(out, line)
			}
		}
	}
	return out
}

// downloadGeo fetches a country's aggregated CIDR list and caches it. Every line
// is validated as an IPv4 CIDR so nothing but clean network data reaches the
// ruleset. Returns the number of CIDRs cached.
func downloadGeo(ctx context.Context, cc string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf(geoBaseURL, cc), nil)
	if err != nil {
		return 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("download for %q returned HTTP %d", cc, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return 0, err
	}
	var kept []string
	sc := bufio.NewScanner(bytes.NewReader(body))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(line); err != nil {
			return 0, fmt.Errorf("country %q returned a non-CIDR line", cc)
		}
		kept = append(kept, line)
	}
	if len(kept) == 0 {
		return 0, fmt.Errorf("country %q returned no networks", cc)
	}
	if err := os.MkdirAll(geoDir, 0755); err != nil {
		return 0, err
	}
	if err := os.WriteFile(filepath.Join(geoDir, cc+".zone"), []byte(strings.Join(kept, "\n")+"\n"), 0644); err != nil {
		return 0, err
	}
	return len(kept), nil
}

func (a *app) apiGeoGet(w http.ResponseWriter, _ *http.Request) {
	cfg, _ := a.getGateway()
	counts := map[string]int{}
	for _, cc := range cfg.GeoCountries {
		counts[cc] = len(geoCIDRsForCodes([]string{cc}))
	}
	if cfg.GeoCountries == nil {
		cfg.GeoCountries = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"countries": cfg.GeoCountries, "counts": counts})
}

func (a *app) apiGeoApply(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Countries []string `json:"countries"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	seen := map[string]bool{}
	var codes []string
	for _, cc := range in.Countries {
		cc = strings.ToLower(strings.TrimSpace(cc))
		if cc == "" || seen[cc] {
			continue
		}
		if !geoCode.MatchString(cc) {
			writeError(w, http.StatusBadRequest, "country code "+cc+" must be two letters (ISO-3166 alpha-2)")
			return
		}
		seen[cc] = true
		codes = append(codes, cc)
	}
	cfg, ok := a.getGateway()
	if !ok || cfg.ClientNetwork == "" {
		writeError(w, http.StatusConflict, "configure the Gateway before geo-blocking")
		return
	}
	// Refresh each country's list; tolerate a failed refresh if a cache exists.
	for _, cc := range codes {
		if _, err := downloadGeo(r.Context(), cc); err != nil {
			if _, e2 := os.Stat(filepath.Join(geoDir, cc+".zone")); e2 != nil {
				writeError(w, http.StatusBadGateway, err.Error())
				return
			}
		}
	}
	cfg.GeoCountries = codes
	if err := a.setGateway(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist geo configuration")
		return
	}
	if err := a.applyAndConfirm(r); err != nil {
		a.recordSev(r, a.actor(r), "geo-block", "nftables", "failed", "security",
			map[string]any{"countries": codes, "error": err.Error()})
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	a.recordSev(r, a.actor(r), "geo-block", "nftables", "success", "security",
		map[string]any{"countries": codes})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "countries": codes,
		"cidrs": len(geoCIDRsForCodes(codes))})
}
