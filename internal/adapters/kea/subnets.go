package kea

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

// Subnet CRUD uses Kea's core config commands — no root agent and no premium
// hooks: config-get → mutate → config-test → config-set → verify →
// config-write (persist). Rollback is a config-set of the previous config.

func (c *Client) ConfigGetRaw(ctx context.Context) (map[string]any, error) {
	raw, err := c.Call(ctx, "config-get", nil)
	if err != nil {
		return nil, err
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	if _, ok := cfg["Dhcp4"].(map[string]any); !ok {
		return nil, fmt.Errorf("config-get returned no Dhcp4 object")
	}
	return cfg, nil
}

func (c *Client) ConfigTest(ctx context.Context, cfg map[string]any) error {
	_, err := c.Call(ctx, "config-test", cfg)
	return err
}

func (c *Client) ConfigSet(ctx context.Context, cfg map[string]any) error {
	_, err := c.Call(ctx, "config-set", cfg)
	return err
}

// ConfigWrite persists the running configuration to the config file (the
// kea process user must own the file).
func (c *Client) ConfigWrite(ctx context.Context) error {
	_, err := c.Call(ctx, "config-write", nil)
	return err
}

// SubnetSpec is the GUI-facing shape of one IPv4 subnet.
type SubnetSpec struct {
	Subnet     string   `json:"subnet"`
	PoolStart  string   `json:"poolStart"`
	PoolEnd    string   `json:"poolEnd"`
	Router     string   `json:"router"`
	Domain     string   `json:"domain"`
	DNSServers []string `json:"dnsServers"`
}

// Validate checks CIDR syntax, pool membership and ordering, and that the
// optional router lives inside the subnet.
func (s SubnetSpec) Validate() error {
	_, ipnet, err := net.ParseCIDR(strings.TrimSpace(s.Subnet))
	if err != nil || ipnet.IP.To4() == nil {
		return fmt.Errorf("invalid IPv4 subnet CIDR %q", s.Subnet)
	}
	start, err := IP4ToInt(s.PoolStart)
	if err != nil {
		return fmt.Errorf("pool start: %w", err)
	}
	end, err := IP4ToInt(s.PoolEnd)
	if err != nil {
		return fmt.Errorf("pool end: %w", err)
	}
	if start > end {
		return fmt.Errorf("pool start must not be above pool end")
	}
	if !ipnet.Contains(net.ParseIP(s.PoolStart)) || !ipnet.Contains(net.ParseIP(s.PoolEnd)) {
		return fmt.Errorf("pool must lie inside %s", s.Subnet)
	}
	if s.Router != "" {
		if ip := net.ParseIP(s.Router); ip == nil || !ipnet.Contains(ip) {
			return fmt.Errorf("router %q must lie inside %s", s.Router, s.Subnet)
		}
	}
	for _, d := range s.DNSServers {
		if net.ParseIP(strings.TrimSpace(d)) == nil {
			return fmt.Errorf("invalid DNS server address %q", d)
		}
	}
	return nil
}

func subnetSlice(dhcp4 map[string]any) []any {
	list, _ := dhcp4["subnet4"].([]any)
	return list
}

func subnetID(entry any) int64 {
	m, ok := entry.(map[string]any)
	if !ok {
		return 0
	}
	id, _ := m["id"].(float64)
	return int64(id)
}

func (s SubnetSpec) optionData() []any {
	var opts []any
	if s.Router != "" {
		opts = append(opts, map[string]any{"name": "routers", "data": s.Router})
	}
	if len(s.DNSServers) > 0 {
		opts = append(opts, map[string]any{"name": "domain-name-servers", "data": strings.Join(s.DNSServers, ", ")})
	}
	if s.Domain != "" {
		opts = append(opts, map[string]any{"name": "domain-name", "data": s.Domain})
	}
	if opts == nil {
		return []any{}
	}
	return opts
}

func (s SubnetSpec) pools() []any {
	return []any{map[string]any{"pool": s.PoolStart + " - " + s.PoolEnd}}
}

// CIDRsOverlap reports whether two IPv4 CIDRs share any addresses.
func CIDRsOverlap(a, b string) bool {
	_, an, errA := net.ParseCIDR(a)
	_, bn, errB := net.ParseCIDR(b)
	if errA != nil || errB != nil {
		return false
	}
	return an.Contains(bn.IP) || bn.Contains(an.IP)
}

// AddSubnet appends a new subnet with the next free id and returns that id.
// Overlapping CIDRs are refused (wizard W2 validation).
func AddSubnet(dhcp4 map[string]any, s SubnetSpec) (int64, error) {
	if err := s.Validate(); err != nil {
		return 0, err
	}
	list := subnetSlice(dhcp4)
	var maxID int64
	for _, entry := range list {
		if m, ok := entry.(map[string]any); ok {
			existing, _ := m["subnet"].(string)
			if existing == s.Subnet {
				return 0, fmt.Errorf("subnet %s already exists", s.Subnet)
			}
			if CIDRsOverlap(existing, s.Subnet) {
				return 0, fmt.Errorf("subnet %s overlaps existing subnet %s", s.Subnet, existing)
			}
		}
		if id := subnetID(entry); id > maxID {
			maxID = id
		}
	}
	id := maxID + 1
	entry := map[string]any{
		"id":          id,
		"subnet":      s.Subnet,
		"pools":       s.pools(),
		"option-data": s.optionData(),
	}
	dhcp4["subnet4"] = append(list, entry)
	return id, nil
}

// UpdateSubnet rewrites pools and options of an existing subnet, preserving
// any other per-subnet settings Kea has (reservations, classes, timers).
func UpdateSubnet(dhcp4 map[string]any, id int64, s SubnetSpec) error {
	if err := s.Validate(); err != nil {
		return err
	}
	for _, entry := range subnetSlice(dhcp4) {
		if subnetID(entry) != id {
			continue
		}
		m := entry.(map[string]any)
		if existing, _ := m["subnet"].(string); existing != s.Subnet {
			return fmt.Errorf("subnet CIDR cannot change (delete and recreate instead)")
		}
		m["pools"] = s.pools()
		m["option-data"] = s.optionData()
		return nil
	}
	return fmt.Errorf("subnet id %d not found", id)
}

// DeleteSubnet removes the subnet with the given id.
func DeleteSubnet(dhcp4 map[string]any, id int64) bool {
	list := subnetSlice(dhcp4)
	out := make([]any, 0, len(list))
	found := false
	for _, entry := range list {
		if subnetID(entry) == id {
			found = true
			continue
		}
		out = append(out, entry)
	}
	if found {
		dhcp4["subnet4"] = out
	}
	return found
}
