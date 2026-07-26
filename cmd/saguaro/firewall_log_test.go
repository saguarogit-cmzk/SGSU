package main

import "testing"

func TestParseFwLog(t *testing.T) {
	raw := []byte(`2026-07-26T12:13:44+00:00 sbsu kernel: SNA-INPUT-DROP IN=wan1 OUT= MAC=aa SRC=192.168.50.75 DST=192.168.50.255 LEN=78 PROTO=UDP SPT=137 DPT=137 LEN=58
2026-07-26T12:14:01+00:00 sbsu kernel: SNA:Auto-blokada IN=wan1 OUT=lan0 SRC=203.0.113.5 DST=10.10.10.20 PROTO=TCP SPT=44000 DPT=3389
garbage line without kernel marker`)
	got := parseFwLog(raw)
	if len(got) != 2 {
		t.Fatalf("expected 2 parsed entries, got %d", len(got))
	}
	// Newest-first ordering.
	if got[0].Src != "203.0.113.5" || got[0].Rule != "SNA:Auto-blokada" || got[0].DPort != "3389" || got[0].Dst != "10.10.10.20" {
		t.Fatalf("first entry parsed wrong: %+v", got[0])
	}
	if got[1].Rule != "SNA-INPUT-DROP" || got[1].Proto != "UDP" || got[1].Src != "192.168.50.75" {
		t.Fatalf("second entry parsed wrong: %+v", got[1])
	}
}
