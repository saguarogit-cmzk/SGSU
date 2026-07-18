package kea

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func fakeAgent(t *testing.T) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "saguaro" || p != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var req struct {
			Command string `json:"command"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		switch req.Command {
		case "status-get":
			_, _ = w.Write([]byte(`[{"result":0,"arguments":{"pid":123,"uptime":42}}]`))
		case "config-get":
			_, _ = w.Write([]byte(`[{"result":0,"arguments":{"Dhcp4":{"subnet4":[{"id":1,"subnet":"192.168.10.0/24","pools":[{"pool":"192.168.10.100-192.168.10.200"}]}]}}}]`))
		case "lease4-get-all":
			_, _ = w.Write([]byte(`[{"result":0,"arguments":{"leases":[{"ip-address":"192.168.10.101","hw-address":"aa:bb:cc:dd:ee:ff","hostname":"laptop","subnet-id":1,"state":0,"cltt":1784800000,"valid-lft":3600}]}}]`))
		case "boom":
			_, _ = w.Write([]byte(`[{"result":1,"text":"command failed"}]`))
		default:
			_, _ = w.Write([]byte(`[{"result":2,"text":"unknown command"}]`))
		}
	}))
	t.Cleanup(srv.Close)
	return New(srv.URL, "saguaro", "secret")
}

func TestSubnetsAndLeases(t *testing.T) {
	c := fakeAgent(t)
	ctx := context.Background()
	subnets, err := c.Subnets(ctx)
	if err != nil || len(subnets) != 1 || subnets[0].Subnet != "192.168.10.0/24" || subnets[0].Pools[0] != "192.168.10.100-192.168.10.200" {
		t.Fatalf("subnets: %v %+v", err, subnets)
	}
	leases, err := c.Leases(ctx)
	if err != nil || len(leases) != 1 {
		t.Fatalf("leases: %v %+v", err, leases)
	}
	if leases[0].MAC != "aa:bb:cc:dd:ee:ff" || leases[0].Expires != 1784803600 {
		t.Fatalf("lease mapping wrong: %+v", leases[0])
	}
	if _, err := c.Status(ctx); err != nil {
		t.Fatalf("status: %v", err)
	}
}

func TestAgentErrors(t *testing.T) {
	c := fakeAgent(t)
	if _, err := c.Call(context.Background(), "boom", nil); err == nil {
		t.Fatal("result 1 must surface as error")
	}
	c.Password = "wrong"
	if _, err := c.Status(context.Background()); err == nil {
		t.Fatal("bad credentials must surface as error")
	}
}

func TestMACHelpers(t *testing.T) {
	hexMAC, err := NormalizeMAC("AA:BB:cc:dd:ee:ff")
	if err != nil || hexMAC != "aabbccddeeff" {
		t.Fatalf("normalize: %q %v", hexMAC, err)
	}
	if _, err := NormalizeMAC("not-a-mac"); err == nil {
		t.Fatal("invalid MAC must be rejected")
	}
	if got := FormatMACHex("aabbccddeeff"); got != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("format: %q", got)
	}
}

func TestIPConversion(t *testing.T) {
	v, err := IP4ToInt("192.168.10.50")
	if err != nil {
		t.Fatal(err)
	}
	if IntToIP4(v) != "192.168.10.50" {
		t.Fatalf("roundtrip: %d -> %s", v, IntToIP4(v))
	}
	if v != 0xC0A80A32 {
		t.Fatalf("byte order wrong: %x", v)
	}
	for _, bad := range []string{"", "999.1.1.1", "fe80::1", "abc"} {
		if _, err := IP4ToInt(bad); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}
