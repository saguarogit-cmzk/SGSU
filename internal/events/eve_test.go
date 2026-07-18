package events

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const alertLine = `{"timestamp":"2026-07-18T12:00:00.123456+0200","event_type":"alert","src_ip":"203.0.113.7","dest_ip":"192.168.10.5","proto":"TCP","in_iface":"enp1s0","alert":{"action":"allowed","signature_id":2100498,"signature":"GPL ATTACK_RESPONSE id check returned root","category":"Potentially Bad Traffic","severity":1}}`

func TestParseEveLine(t *testing.T) {
	e, ok := ParseEveLine([]byte(alertLine))
	if !ok {
		t.Fatal("alert line must parse")
	}
	if e.Module != "ids" || e.Severity != "security" || e.SrcIP != "203.0.113.7" || e.DstIP != "192.168.10.5" {
		t.Fatalf("mapping wrong: %+v", e)
	}
	if e.Message != "GPL ATTACK_RESPONSE id check returned root" || e.Iface != "enp1s0" {
		t.Fatalf("fields wrong: %+v", e)
	}
	if e.TS.Year() != 2026 || e.TS.Hour() != 10 {
		t.Fatalf("timestamp not normalized to UTC: %v", e.TS)
	}
}

func TestParseEveLineSeverities(t *testing.T) {
	if SeverityFromSuricata(1) != "security" || SeverityFromSuricata(2) != "warning" || SeverityFromSuricata(3) != "notice" {
		t.Fatal("suricata severity mapping wrong")
	}
}

func TestParseEveLineSkipsNonAlerts(t *testing.T) {
	if _, ok := ParseEveLine([]byte(`{"event_type":"stats","uptime":5}`)); ok {
		t.Fatal("stats records must be skipped")
	}
	if _, ok := ParseEveLine([]byte(`not json at all`)); ok {
		t.Fatal("garbage must be skipped")
	}
}

func TestTailEveFollowsAppendsAndTruncation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	if err := os.WriteFile(path, []byte("{\"event_type\":\"stats\"}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got := make(chan Event, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go TailEve(ctx, path, 20*time.Millisecond, func(e Event) { got <- e })
	time.Sleep(100 * time.Millisecond) // tailer is at EOF now

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(alertLine + "\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	select {
	case e := <-got:
		if e.Severity != "security" {
			t.Fatalf("unexpected event: %+v", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("appended alert was not emitted")
	}

	// Rotation: truncate and write a fresh line; the tailer must reopen.
	if err := os.WriteFile(path, []byte(alertLine+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-got:
		if e.Module != "ids" {
			t.Fatalf("unexpected event after rotation: %+v", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("alert after truncation was not emitted")
	}
}
