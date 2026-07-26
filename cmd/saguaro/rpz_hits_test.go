package main

import "testing"

func TestParseRPZHits(t *testing.T) {
	raw := []byte(`2026-07-26T12:31:39+0000 sbsu unbound[5613]: [5613:0] info: rpz: applied [saguaro-rpz] doubleclick.net. rpz-nxdomain 127.0.0.1@37122 doubleclick.net. A IN
2026-07-26T12:31:39+0000 sbsu unbound[5613]: [5613:0] info: rpz: applied [saguaro-rpz] *.doubleclick.net. rpz-nxdomain 10.10.10.20@40308 foo.doubleclick.net. A IN
2026-07-26T12:31:40+0000 sbsu unbound[5613]: [5613:0] info: rpz: applied [saguaro-rpz] doubleclick.net. rpz-nxdomain 10.10.10.20@1 doubleclick.net. A IN
unrelated log line`)
	top, recent := parseRPZHits(raw)
	if len(recent) != 3 {
		t.Fatalf("expected 3 recent hits, got %d", len(recent))
	}
	// doubleclick.net was queried twice -> it ranks first.
	if len(top) < 2 || top[0]["domain"].(string) != "doubleclick.net" || top[0]["count"].(int) != 2 {
		t.Fatalf("top ranking wrong: %+v", top)
	}
	// recent is newest-first, with client IP stripped of its port.
	if recent[0].Domain != "doubleclick.net" || recent[0].Client != "10.10.10.20" {
		t.Fatalf("recent[0] wrong: %+v", recent[0])
	}
}
