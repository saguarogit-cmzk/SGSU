package main

import (
	"net/http"
	"strings"
)

// fwLogEntry is one parsed netfilter LOG line emitted by the SNA rules.
type fwLogEntry struct {
	Time  string `json:"time"`
	Rule  string `json:"rule"` // prefix: SNA-INPUT-DROP, SNA-FWD-DROP, or SNA:<rule>
	In    string `json:"in"`
	Out   string `json:"out"`
	Src   string `json:"src"`
	Dst   string `json:"dst"`
	Proto string `json:"proto"`
	SPort string `json:"sport"`
	DPort string `json:"dport"`
}

// parseFwLog turns raw `journalctl -k` lines (netfilter LOG format) into records,
// most-recent first. A line looks like:
//
//	2026-... sbsu kernel: SNA-FWD-DROP IN=wan1 OUT=lan0 ... SRC=x DST=y PROTO=TCP SPT=1 DPT=2
func parseFwLog(out []byte) []fwLogEntry {
	lines := strings.Split(string(out), "\n")
	entries := make([]fwLogEntry, 0, len(lines))
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		idx := strings.Index(ln, "kernel: ")
		if idx < 0 {
			continue
		}
		head := strings.Fields(ln[:idx])
		body := ln[idx+len("kernel: "):]
		e := fwLogEntry{}
		if len(head) > 0 {
			e.Time = head[0]
		}
		if p := strings.Index(body, " IN="); p >= 0 {
			e.Rule = strings.TrimSpace(body[:p])
		}
		for _, tok := range strings.Fields(body) {
			kv := strings.SplitN(tok, "=", 2)
			if len(kv) != 2 {
				continue
			}
			switch kv[0] {
			case "IN":
				e.In = kv[1]
			case "OUT":
				e.Out = kv[1]
			case "SRC":
				e.Src = kv[1]
			case "DST":
				e.Dst = kv[1]
			case "PROTO":
				e.Proto = kv[1]
			case "SPT":
				e.SPort = kv[1]
			case "DPT":
				e.DPort = kv[1]
			}
		}
		if e.Src == "" {
			continue
		}
		entries = append(entries, e)
	}
	// journalctl returns oldest-first; show newest-first.
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
	return entries
}

func (a *app) apiFirewallLog(w http.ResponseWriter, r *http.Request) {
	out, err := a.runFirewall(r.Context(), "log")
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"entries": []fwLogEntry{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": parseFwLog(out)})
}
