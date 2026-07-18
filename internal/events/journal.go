package events

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// DefaultUnits are the systemd units the collector follows out of the box.
var DefaultUnits = []string{
	"saguaro.service", "saguaro-eventd.service",
	"kea-dhcp4-server.service", "kea-dhcp-ddns-server.service", "kea-ctrl-agent.service",
	"unbound.service", "pdns.service",
	"nginx.service", "step-ca-saguaro.service",
	"nftables.service", "ssh.service", "suricata.service",
}

// unitModule maps a systemd unit (prefix) to an SNA module name.
var unitModule = []struct{ prefix, module string }{
	{"kea-dhcp4", "dhcp"},
	{"kea-dhcp-ddns", "dhcp"},
	{"kea-ctrl-agent", "dhcp"},
	{"unbound", "dns"},
	{"pdns", "dns"},
	{"nginx", "proxy"},
	{"step-ca", "certificates"},
	{"nftables", "firewall"},
	{"suricata", "ids"},
	{"ssh", "system"},
	{"saguaro-eventd", "control-plane"},
	{"saguaro-backup", "backup"},
	{"saguaro", "control-plane"},
}

// ModuleForUnit derives the SNA module from a systemd unit name.
func ModuleForUnit(unit string) string {
	unit = strings.TrimSuffix(unit, ".service")
	for _, m := range unitModule {
		if strings.HasPrefix(unit, m.prefix) {
			return m.module
		}
	}
	return "system"
}

// JournalEntry is the subset of `journalctl -o json` fields the collector
// uses. MESSAGE can be a string or a byte array (binary payloads); only
// string messages are ingested.
type JournalEntry struct {
	Cursor     string          `json:"__CURSOR"`
	Realtime   string          `json:"__REALTIME_TIMESTAMP"`
	Message    json.RawMessage `json:"MESSAGE"`
	Priority   string          `json:"PRIORITY"`
	Unit       string          `json:"_SYSTEMD_UNIT"`
	Hostname   string          `json:"_HOSTNAME"`
	Identifier string          `json:"SYSLOG_IDENTIFIER"`
}

// ParseJournalLine turns one journalctl JSON line into an Event. ok is false
// for lines that should be skipped (unparseable, binary payload, no unit).
func ParseJournalLine(line []byte) (Event, string, bool) {
	var je JournalEntry
	if err := json.Unmarshal(line, &je); err != nil {
		return Event{}, "", false
	}
	var msg string
	if err := json.Unmarshal(je.Message, &msg); err != nil || strings.TrimSpace(msg) == "" {
		return Event{}, je.Cursor, false
	}
	prio := 6
	if p, err := strconv.Atoi(je.Priority); err == nil {
		prio = p
	}
	ts := time.Now().UTC()
	if us, err := strconv.ParseInt(je.Realtime, 10, 64); err == nil {
		ts = time.UnixMicro(us).UTC()
	}
	unit := je.Unit
	if unit == "" {
		unit = je.Identifier
	}
	if unit == "" {
		return Event{}, je.Cursor, false
	}
	rawUnit, _ := json.Marshal(map[string]string{"unit": unit})
	e := Event{
		TS:       ts,
		Module:   ModuleForUnit(unit),
		Severity: FromJournalPriority(prio),
		Host:     je.Hostname,
		Action:   "log",
		Message:  msg,
		Raw:      rawUnit,
	}
	// Unbound logs RPZ hits at info priority; promote them so the DNS
	// filtering tier is visible in the event store (and can alert).
	if e.Module == "dns" && strings.Contains(msg, "saguaro-rpz") {
		e.Module = "dns-filter"
		e.Action = "rpz-block"
		if Rank(e.Severity) < Rank("notice") {
			e.Severity = "notice"
		}
	}
	return e, je.Cursor, true
}
