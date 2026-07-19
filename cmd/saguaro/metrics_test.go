package main

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestCpuPercents(t *testing.T) {
	prev := &cpuStat{total: []uint64{100, 100}, idle: []uint64{80, 50}}
	cur := &cpuStat{total: []uint64{200, 200}, idle: []uint64{130, 100}}
	got := cpuPercents(prev, cur)
	if len(got) != 2 || got[0] != 50 || got[1] != 50 {
		t.Fatalf("expected [50 50], got %v", got)
	}
	if len(cpuPercents(nil, cur)) != 0 {
		t.Fatal("nil prev should yield no percentages")
	}
	// a fully idle core reports 0
	idle := cpuPercents(&cpuStat{total: []uint64{0}, idle: []uint64{0}}, &cpuStat{total: []uint64{100}, idle: []uint64{100}})
	if idle[0] != 0 {
		t.Fatalf("idle core should be 0, got %v", idle)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	srv, c, _ := newTestServer(t)
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	resp, err := c.Get(srv.URL + "/api/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics: got %d", resp.StatusCode)
	}
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"cpu", "mem", "conntrack", "interfaces", "ts"} {
		if _, ok := m[k]; !ok {
			t.Errorf("metrics missing %q", k)
		}
	}
}
