package events

import (
	"testing"
	"time"
)

func TestSeverityRankAndValidity(t *testing.T) {
	if Rank("info") != 0 || Rank("security") != 5 {
		t.Fatalf("unexpected ranks: info=%d security=%d", Rank("info"), Rank("security"))
	}
	if Rank("warning") >= Rank("error") {
		t.Fatal("warning must rank below error")
	}
	if ValidSeverity("bogus") || !ValidSeverity("notice") {
		t.Fatal("severity validity broken")
	}
}

func TestFromJournalPriority(t *testing.T) {
	cases := map[int]string{0: "critical", 2: "critical", 3: "error", 4: "warning", 5: "notice", 6: "info", 7: "info"}
	for p, want := range cases {
		if got := FromJournalPriority(p); got != want {
			t.Fatalf("priority %d: got %q want %q", p, got, want)
		}
	}
}

func TestPartitionNameAndBounds(t *testing.T) {
	ts := time.Date(2026, 7, 18, 13, 45, 0, 0, time.UTC)
	if got := PartitionName(ts); got != "events_202607" {
		t.Fatalf("name: got %q", got)
	}
	from, to := PartitionBounds(ts)
	if !from.Equal(time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)) || !to.Equal(time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("bounds: got %v..%v", from, to)
	}
	// December rollover
	from, to = PartitionBounds(time.Date(2026, 12, 31, 23, 59, 0, 0, time.UTC))
	if to.Month() != time.January || to.Year() != 2027 {
		t.Fatalf("december rollover: to=%v", to)
	}
	_ = from
}

func TestModuleForUnit(t *testing.T) {
	cases := map[string]string{
		"kea-dhcp4-server.service":     "dhcp",
		"kea-dhcp-ddns-server.service": "dhcp",
		"unbound.service":              "dns",
		"pdns.service":                 "dns",
		"nginx.service":                "proxy",
		"nftables.service":             "firewall",
		"suricata.service":             "ids",
		"saguaro.service":              "control-plane",
		"saguaro-eventd.service":       "control-plane",
		"saguaro-backup.service":       "backup",
		"cron.service":                 "system",
	}
	for unit, want := range cases {
		if got := ModuleForUnit(unit); got != want {
			t.Fatalf("%s: got %q want %q", unit, got, want)
		}
	}
}

func TestParseJournalLine(t *testing.T) {
	line := []byte(`{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"1784800000000000","MESSAGE":"DHCPACK on 192.168.10.50","PRIORITY":"5","_SYSTEMD_UNIT":"kea-dhcp4-server.service","_HOSTNAME":"sna1"}`)
	e, cursor, ok := ParseJournalLine(line)
	if !ok {
		t.Fatal("expected parseable entry")
	}
	if cursor != "c1" || e.Module != "dhcp" || e.Severity != "notice" || e.Host != "sna1" {
		t.Fatalf("got %+v cursor=%q", e, cursor)
	}
	if e.TS.Year() < 2026 {
		t.Fatalf("timestamp not parsed: %v", e.TS)
	}
	if string(e.Raw) != `{"unit":"kea-dhcp4-server.service"}` {
		t.Fatalf("raw unit: %s", e.Raw)
	}
}

func TestParseJournalLinePromotesRPZHits(t *testing.T) {
	line := []byte(`{"__CURSOR":"c9","__REALTIME_TIMESTAMP":"1784800000000000","MESSAGE":"info: saguaro-rpz applied to ads.example.com. A IN","PRIORITY":"6","_SYSTEMD_UNIT":"unbound.service"}`)
	e, _, ok := ParseJournalLine(line)
	if !ok {
		t.Fatal("rpz line must parse")
	}
	if e.Module != "dns-filter" || e.Action != "rpz-block" || e.Severity != "notice" {
		t.Fatalf("rpz promotion wrong: %+v", e)
	}
	// Ordinary unbound info lines keep module dns and info severity.
	plain := []byte(`{"__CURSOR":"c10","MESSAGE":"info: start of service","PRIORITY":"6","_SYSTEMD_UNIT":"unbound.service"}`)
	e2, _, _ := ParseJournalLine(plain)
	if e2.Module != "dns" || e2.Severity != "info" {
		t.Fatalf("plain unbound line changed: %+v", e2)
	}
}

func TestParseJournalLineSkipsBinaryAndUnitless(t *testing.T) {
	if _, _, ok := ParseJournalLine([]byte(`not json`)); ok {
		t.Fatal("invalid JSON must not parse")
	}
	// Binary payloads arrive as byte arrays.
	if _, cursor, ok := ParseJournalLine([]byte(`{"__CURSOR":"c2","MESSAGE":[1,2,3],"PRIORITY":"6","_SYSTEMD_UNIT":"x.service"}`)); ok || cursor != "c2" {
		t.Fatalf("binary payload: ok=%v cursor=%q", ok, cursor)
	}
	if _, _, ok := ParseJournalLine([]byte(`{"__CURSOR":"c3","MESSAGE":"hi","PRIORITY":"6"}`)); ok {
		t.Fatal("entry without unit or identifier must be skipped")
	}
	// SYSLOG_IDENTIFIER is an acceptable fallback for unit.
	if e, _, ok := ParseJournalLine([]byte(`{"__CURSOR":"c4","MESSAGE":"hi","PRIORITY":"3","SYSLOG_IDENTIFIER":"unbound"}`)); !ok || e.Module != "dns" || e.Severity != "error" {
		t.Fatalf("identifier fallback: ok=%v %+v", ok, e)
	}
}
