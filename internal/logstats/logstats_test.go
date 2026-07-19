package logstats

import "testing"

func TestParseUnboundStats(t *testing.T) {
	out := "total.num.queries=1000\ntotal.num.cachehits=800\ntotal.num.cachemiss=200\n" +
		"num.answer.rcode.NXDOMAIN=50\nnum.answer.rcode.SERVFAIL=5\n"
	s := ParseUnboundStats([]byte(out))
	if !s.Available || s.Queries != 1000 || s.NXDOMAIN != 50 || s.SERVFAIL != 5 {
		t.Fatalf("stats wrong: %+v", s)
	}
	if s.CacheHitPct != 80 {
		t.Fatalf("cache hit pct: got %v want 80", s.CacheHitPct)
	}
	if ParseUnboundStats([]byte("")).Available {
		t.Fatal("empty output should be unavailable")
	}
}

func TestParseSuricataAlerts(t *testing.T) {
	lines := `{"timestamp":"2026-07-19T10:00:00","event_type":"alert","src_ip":"1.2.3.4","dest_ip":"5.6.7.8","proto":"TCP","alert":{"signature":"ET SCAN","severity":2}}
{"event_type":"flow"}
{"timestamp":"2026-07-19T10:01:00","event_type":"alert","src_ip":"9.9.9.9","dest_ip":"8.8.8.8","proto":"UDP","alert":{"signature":"ET MALWARE","severity":1}}`
	a := ParseSuricataAlerts([]byte(lines), 50)
	if len(a) != 2 {
		t.Fatalf("expected 2 alerts, got %d", len(a))
	}
	if a[0].Signature != "ET SCAN" || a[1].Severity != 1 || a[1].Src != "9.9.9.9" || a[1].Proto != "UDP" {
		t.Fatalf("parsed alerts wrong: %+v", a)
	}
	// limit keeps the newest
	last := ParseSuricataAlerts([]byte(lines), 1)
	if len(last) != 1 || last[0].Signature != "ET MALWARE" {
		t.Fatalf("limit wrong: %+v", last)
	}
}
