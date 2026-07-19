// Package logstats parses Unbound resolver counters and Suricata EVE alerts
// into compact structures for the dashboard. Parsing is pure and tested; the
// privileged reads happen in the root adapter /usr/sbin/saguaro-logs.
package logstats

import (
	"encoding/json"
	"strconv"
	"strings"
)

// UnboundStats holds the resolver counters shown on the dashboard.
type UnboundStats struct {
	Available   bool    `json:"available"`
	Queries     float64 `json:"queries"`
	CacheHits   float64 `json:"cacheHits"`
	CacheMiss   float64 `json:"cacheMiss"`
	CacheHitPct float64 `json:"cacheHitPct"`
	NXDOMAIN    float64 `json:"nxdomain"`
	SERVFAIL    float64 `json:"servfail"`
}

// ParseUnboundStats parses `unbound-control stats` output (key=value lines).
func ParseUnboundStats(out []byte) UnboundStats {
	m := map[string]float64{}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
			m[strings.TrimSpace(k)] = f
		}
	}
	s := UnboundStats{
		Available: len(m) > 0,
		Queries:   m["total.num.queries"],
		CacheHits: m["total.num.cachehits"],
		CacheMiss: m["total.num.cachemiss"],
		NXDOMAIN:  m["num.answer.rcode.NXDOMAIN"],
		SERVFAIL:  m["num.answer.rcode.SERVFAIL"],
	}
	if tot := s.CacheHits + s.CacheMiss; tot > 0 {
		s.CacheHitPct = float64(int64(1000*s.CacheHits/tot+0.5)) / 10
	}
	return s
}

// Alert is one Suricata EVE alert, flattened for display.
type Alert struct {
	Time      string `json:"time"`
	Signature string `json:"signature"`
	Severity  int    `json:"severity"`
	Src       string `json:"src"`
	Dst       string `json:"dst"`
	Proto     string `json:"proto"`
}

// ParseSuricataAlerts parses EVE JSON lines (already filtered to alerts),
// newest last; limit caps the returned count (0 = all).
func ParseSuricataAlerts(out []byte, limit int) []Alert {
	var alerts []Alert
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e struct {
			Timestamp string `json:"timestamp"`
			SrcIP     string `json:"src_ip"`
			DestIP    string `json:"dest_ip"`
			Proto     string `json:"proto"`
			EventType string `json:"event_type"`
			Alert     struct {
				Signature string `json:"signature"`
				Severity  int    `json:"severity"`
			} `json:"alert"`
		}
		if err := json.Unmarshal([]byte(line), &e); err != nil || e.EventType != "alert" {
			continue
		}
		alerts = append(alerts, Alert{
			Time: e.Timestamp, Signature: e.Alert.Signature, Severity: e.Alert.Severity,
			Src: e.SrcIP, Dst: e.DestIP, Proto: e.Proto,
		})
	}
	if limit > 0 && len(alerts) > limit {
		alerts = alerts[len(alerts)-limit:]
	}
	return alerts
}
