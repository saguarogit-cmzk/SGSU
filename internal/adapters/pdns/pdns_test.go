package pdns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCanonical(t *testing.T) {
	for in, want := range map[string]string{"Example.COM": "example.com.", "a.b.": "a.b.", "": ""} {
		if got := Canonical(in); got != want {
			t.Fatalf("Canonical(%q) = %q, want %q", in, got, want)
		}
	}
}

func fakePDNS(t *testing.T) (*Client, *[]string) {
	t.Helper()
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"Unauthorized"}`))
			return
		}
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/v1/servers/localhost/zones":
			_, _ = w.Write([]byte(`[{"id":"example.internal.","name":"example.internal.","kind":"Native","serial":2026071801}]`))
		case r.Method == "POST" && r.URL.Path == "/api/v1/servers/localhost/zones":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["name"] != "new.internal." || body["kind"] != "Native" {
				w.WriteHeader(http.StatusUnprocessableEntity)
				_, _ = w.Write([]byte(`{"error":"bad zone body"}`))
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == "GET" && r.URL.Path == "/api/v1/servers/localhost/zones/example.internal.":
			_, _ = w.Write([]byte(`{"id":"example.internal.","name":"example.internal.","kind":"Native","serial":1,"rrsets":[{"name":"host.example.internal.","type":"A","ttl":3600,"records":[{"content":"192.168.10.20","disabled":false}]}]}`))
		case r.Method == "PATCH" && r.URL.Path == "/api/v1/servers/localhost/zones/example.internal.":
			var body struct {
				RRSets []map[string]any `json:"rrsets"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if len(body.RRSets) != 1 || body.RRSets[0]["changetype"] == "" {
				w.WriteHeader(http.StatusUnprocessableEntity)
				return
			}
			calls = append(calls, "changetype="+body.RRSets[0]["changetype"].(string))
			w.WriteHeader(http.StatusNoContent)
		case r.Method == "DELETE" && r.URL.Path == "/api/v1/servers/localhost/zones/example.internal.":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not found"}`))
		}
	}))
	t.Cleanup(srv.Close)
	return New(srv.URL, "test-key"), &calls
}

func TestZoneLifecycle(t *testing.T) {
	c, calls := fakePDNS(t)
	ctx := context.Background()

	zones, err := c.ListZones(ctx)
	if err != nil || len(zones) != 1 || zones[0].Name != "example.internal." {
		t.Fatalf("list: %v %+v", err, zones)
	}
	if err := c.CreateZone(ctx, "new.internal", []string{"ns1.new.internal"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	detail, err := c.GetZone(ctx, "example.internal")
	if err != nil || len(detail.RRSets) != 1 || detail.RRSets[0].Records[0].Content != "192.168.10.20" {
		t.Fatalf("get: %v %+v", err, detail)
	}
	rr := RRSet{Name: "host.example.internal", Type: "a", TTL: 300, Records: []Record{{Content: "192.168.10.21"}}}
	if err := c.PatchRRSet(ctx, "example.internal", rr, false); err != nil {
		t.Fatalf("patch replace: %v", err)
	}
	if err := c.PatchRRSet(ctx, "example.internal", RRSet{Name: "host.example.internal", Type: "A"}, true); err != nil {
		t.Fatalf("patch delete: %v", err)
	}
	if err := c.DeleteZone(ctx, "example.internal"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	sawReplace, sawDelete := false, false
	for _, call := range *calls {
		if call == "changetype=REPLACE" {
			sawReplace = true
		}
		if call == "changetype=DELETE" {
			sawDelete = true
		}
	}
	if !sawReplace || !sawDelete {
		t.Fatalf("expected REPLACE and DELETE changetypes, calls: %v", *calls)
	}
}

func TestAPIErrorSurface(t *testing.T) {
	c, _ := fakePDNS(t)
	c.APIKey = "wrong"
	if _, err := c.ListZones(context.Background()); err == nil {
		t.Fatal("expected auth error")
	}
}
