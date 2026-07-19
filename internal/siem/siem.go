// Package siem formats Saguaro events for forwarding to an external SIEM as
// RFC 5424 syslog, ArcSight CEF or JSON. Formatting is pure and dependency-free
// so it can be unit-tested; the network transport lives in the control plane.
package siem

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Event is the normalised record forwarded to the SIEM.
type Event struct {
	Time     time.Time
	Host     string
	Severity string // info|notice|warning|error|critical|security
	Actor    string
	Action   string
	Target   string
	Result   string
	Message  string
}

// severityRank orders our severities; higher is more severe. Used to apply the
// minimum-severity threshold.
var severityRank = map[string]int{
	"info": 0, "notice": 1, "warning": 2, "error": 3, "critical": 4, "security": 5,
}

// AtLeast reports whether sev meets the min threshold.
func AtLeast(sev, min string) bool {
	return severityRank[sev] >= severityRank[min]
}

// syslogSeverity maps to RFC 5424 numeric severity (0 emerg .. 7 debug).
func syslogSeverity(sev string) int {
	switch sev {
	case "security", "critical":
		return 2 // critical
	case "error":
		return 3
	case "warning":
		return 4
	case "notice":
		return 5
	default:
		return 6 // informational
	}
}

// cefSeverity maps to CEF 0..10.
func cefSeverity(sev string) int {
	switch sev {
	case "security":
		return 10
	case "critical":
		return 9
	case "error":
		return 7
	case "warning":
		return 5
	case "notice":
		return 3
	default:
		return 2
	}
}

func nonEmpty(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

// FormatRFC5424 renders one syslog line (no trailing newline). facility is a
// syslog facility number (e.g. 16 = local0).
func FormatRFC5424(e Event, app, version string, facility int) string {
	pri := facility*8 + syslogSeverity(e.Severity)
	ts := e.Time.UTC().Format(time.RFC3339)
	host := nonEmpty(e.Host, "-")
	msg := fmt.Sprintf("actor=%s action=%s target=%s result=%s severity=%s msg=%q",
		nonEmpty(e.Actor, "-"), nonEmpty(e.Action, "-"), nonEmpty(e.Target, "-"),
		nonEmpty(e.Result, "-"), e.Severity, e.Message)
	return fmt.Sprintf("<%d>1 %s %s %s - %s - %s", pri, ts, host, app, "audit", msg)
}

// cefEscapeHeader escapes CEF header fields (\ and | are special).
func cefEscapeHeader(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, "|", `\|`)
}

// cefEscapeExt escapes CEF extension values (\, = and newlines).
func cefEscapeExt(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "=", `\=`)
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// FormatCEF renders one CEF line (no trailing newline).
func FormatCEF(e Event, version string) string {
	name := nonEmpty(e.Message, e.Action)
	ext := fmt.Sprintf("rt=%d suser=%s act=%s outcome=%s cs1Label=target cs1=%s msg=%s",
		e.Time.UnixMilli(), cefEscapeExt(nonEmpty(e.Actor, "-")), cefEscapeExt(nonEmpty(e.Action, "-")),
		cefEscapeExt(nonEmpty(e.Result, "-")), cefEscapeExt(nonEmpty(e.Target, "-")), cefEscapeExt(e.Message))
	return fmt.Sprintf("CEF:0|Saguaro|SNA|%s|%s|%s|%d|%s",
		cefEscapeHeader(version), cefEscapeHeader(nonEmpty(e.Action, "event")),
		cefEscapeHeader(name), cefSeverity(e.Severity), ext)
}

// FormatJSON renders a compact JSON object (no trailing newline).
func FormatJSON(e Event) string {
	b, _ := json.Marshal(map[string]any{
		"time": e.Time.UTC().Format(time.RFC3339), "host": e.Host, "severity": e.Severity,
		"actor": e.Actor, "action": e.Action, "target": e.Target, "result": e.Result, "message": e.Message,
	})
	return string(b)
}

// Format renders an event in the requested format (rfc5424|cef|json).
func Format(format string, e Event, app, version string) string {
	switch format {
	case "cef":
		return FormatCEF(e, version)
	case "json":
		return FormatJSON(e)
	default:
		return FormatRFC5424(e, app, version, 16)
	}
}
