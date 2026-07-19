package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

func TestLogsEndpoints(t *testing.T) {
	srv, c, a := newTestServer(t)
	a.runLogs = func(_ context.Context, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "unbound-stats" {
			return []byte("total.num.queries=10\ntotal.num.cachehits=8\ntotal.num.cachemiss=2\n"), nil
		}
		return []byte(`{"timestamp":"t","event_type":"alert","src_ip":"1.1.1.1","dest_ip":"2.2.2.2","proto":"TCP","alert":{"signature":"SIG","severity":1}}`), nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	resp, _ := c.Get(srv.URL + "/api/logs/unbound")
	var u map[string]any
	json.NewDecoder(resp.Body).Decode(&u)
	resp.Body.Close()
	if u["available"] != true || u["queries"].(float64) != 10 || u["cacheHitPct"].(float64) != 80 {
		t.Fatalf("unbound view wrong: %v", u)
	}
	resp, _ = c.Get(srv.URL + "/api/logs/suricata")
	var s struct {
		Alerts []map[string]any `json:"alerts"`
	}
	json.NewDecoder(resp.Body).Decode(&s)
	resp.Body.Close()
	if len(s.Alerts) != 1 || s.Alerts[0]["signature"] != "SIG" {
		t.Fatalf("suricata view wrong: %+v", s.Alerts)
	}
	// adapter failure -> unbound reported unavailable (not an error to the GUI)
	a.runLogs = func(context.Context, ...string) ([]byte, error) { return nil, errors.New("no control") }
	resp, _ = c.Get(srv.URL + "/api/logs/unbound")
	json.NewDecoder(resp.Body).Decode(&u)
	resp.Body.Close()
	if u["available"] != false {
		t.Fatalf("expected available=false on error, got %v", u["available"])
	}
}
