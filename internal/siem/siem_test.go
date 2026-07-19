package siem

import (
	"strings"
	"testing"
	"time"
)

func sampleEvent() Event {
	return Event{Time: time.Unix(1700000000, 0).UTC(), Host: "gw", Severity: "security",
		Actor: "admin", Action: "login", Target: "session", Result: "success", Message: "admin logged in"}
}

func TestFormatRFC5424(t *testing.T) {
	got := FormatRFC5424(sampleEvent(), "saguaro", "1.0", 16)
	// facility 16 * 8 + severity 2 (security->critical) = 130
	for _, w := range []string{"<130>1 ", "saguaro", "actor=admin", "action=login", "result=success"} {
		if !strings.Contains(got, w) {
			t.Errorf("rfc5424 missing %q: %s", w, got)
		}
	}
}

func TestFormatCEF(t *testing.T) {
	got := FormatCEF(sampleEvent(), "1.0")
	for _, w := range []string{"CEF:0|Saguaro|SNA|1.0|login|", "|10|", "suser=admin", "outcome=success"} {
		if !strings.Contains(got, w) {
			t.Errorf("cef missing %q: %s", w, got)
		}
	}
	// pipes in header fields are escaped
	e := sampleEvent()
	e.Action = "a|b"
	if !strings.Contains(FormatCEF(e, "1.0"), `a\|b`) {
		t.Error("cef header pipe not escaped")
	}
}

func TestFormatJSONAndThreshold(t *testing.T) {
	if !strings.Contains(FormatJSON(sampleEvent()), `"severity":"security"`) {
		t.Error("json missing severity")
	}
	if !AtLeast("error", "warning") || AtLeast("info", "warning") {
		t.Error("severity threshold wrong")
	}
	if Format("cef", sampleEvent(), "saguaro", "1.0")[:4] != "CEF:" {
		t.Error("Format did not dispatch to cef")
	}
}
