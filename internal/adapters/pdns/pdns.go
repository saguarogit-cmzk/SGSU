// Package pdns is the DNS adapter: a thin client for the PowerDNS
// authoritative HTTP API (zones and rrsets). All mutations happen through
// the API on 127.0.0.1 — the control plane never edits zone data on disk.
package pdns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
}

func New(baseURL, apiKey string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), APIKey: apiKey,
		HTTP: &http.Client{Timeout: 10 * time.Second}}
}

// Canonical returns the FQDN form PowerDNS expects (trailing dot).
func Canonical(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	if name != "" && !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

type Zone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Serial int64  `json:"serial"`
}

type Record struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

type RRSet struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	TTL     int      `json:"ttl"`
	Records []Record `json:"records"`
}

type ZoneDetail struct {
	Zone
	RRSets []RRSet `json:"rrsets"`
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var rdr *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+"/api/v1/servers/localhost"+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var apiErr struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&apiErr)
		if apiErr.Error != "" {
			return fmt.Errorf("powerdns: %s (HTTP %d)", apiErr.Error, resp.StatusCode)
		}
		return fmt.Errorf("powerdns: HTTP %d", resp.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *Client) ListZones(ctx context.Context) ([]Zone, error) {
	var zones []Zone
	if err := c.do(ctx, http.MethodGet, "/zones", nil, &zones); err != nil {
		return nil, err
	}
	return zones, nil
}

func (c *Client) GetZone(ctx context.Context, name string) (ZoneDetail, error) {
	var z ZoneDetail
	err := c.do(ctx, http.MethodGet, "/zones/"+url.PathEscape(Canonical(name)), nil, &z)
	return z, err
}

// CreateZone makes a Native zone; PowerDNS synthesizes SOA and NS from the
// nameserver list.
func (c *Client) CreateZone(ctx context.Context, name string, nameservers []string) error {
	for i := range nameservers {
		nameservers[i] = Canonical(nameservers[i])
	}
	body := map[string]any{"name": Canonical(name), "kind": "Native", "nameservers": nameservers}
	return c.do(ctx, http.MethodPost, "/zones", body, nil)
}

func (c *Client) DeleteZone(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, "/zones/"+url.PathEscape(Canonical(name)), nil, nil)
}

// PatchRRSet replaces (or deletes) one rrset in the zone.
func (c *Client) PatchRRSet(ctx context.Context, zone string, rr RRSet, del bool) error {
	change := "REPLACE"
	if del {
		change = "DELETE"
	}
	set := map[string]any{
		"name":       Canonical(rr.Name),
		"type":       strings.ToUpper(rr.Type),
		"ttl":        rr.TTL,
		"changetype": change,
		"records":    rr.Records,
	}
	if del {
		set["records"] = []Record{}
	}
	body := map[string]any{"rrsets": []any{set}}
	return c.do(ctx, http.MethodPatch, "/zones/"+url.PathEscape(Canonical(zone)), body, nil)
}
