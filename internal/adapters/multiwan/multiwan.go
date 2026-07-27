// Package multiwan generates the policy-routing commands for the Multi-WAN
// module (wizard W12): a weighted multipath default route across two or more
// WAN uplinks, plus per-uplink health-check targets. Applying and the
// failover loop live in the root adapter /usr/sbin/saguaro-wan.
package multiwan

import (
	"fmt"
	"net"
	"strings"
)

type Uplink struct {
	Name        string `json:"name"`
	Interface   string `json:"interface"`
	Gateway     string `json:"gateway"`
	Weight      int    `json:"weight"`
	HealthCheck string `json:"healthCheck"` // IP pinged to decide up/down
}

type Config struct {
	Enabled bool `json:"enabled"`
	// Mode is "loadbalance" (weighted multipath across all healthy uplinks, the
	// default) or "failover" (exactly one active uplink at a time — the first
	// healthy uplink in list order, list[0] = primary).
	Mode    string   `json:"mode"`
	Uplinks []Uplink `json:"uplinks"`
}

// mode returns the normalized mode ("loadbalance" when unset/unknown).
func (c Config) mode() string {
	if c.Mode == "failover" {
		return "failover"
	}
	return "loadbalance"
}

// GenerateMode returns the single word written to /etc/saguaro/wan.mode so the
// root adapter's failover loop knows which routing strategy to build.
func (c Config) GenerateMode() string { return c.mode() }

func validIface(name string) bool {
	if name == "" || len(name) > 15 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func (c Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	switch c.Mode {
	case "", "loadbalance", "failover":
	default:
		return fmt.Errorf("mode must be loadbalance or failover")
	}
	if len(c.Uplinks) < 2 {
		return fmt.Errorf("multi-WAN requires at least two uplinks")
	}
	seen := map[string]bool{}
	for _, u := range c.Uplinks {
		if u.Name == "" || seen[u.Name] {
			return fmt.Errorf("uplink names must be unique and non-empty")
		}
		seen[u.Name] = true
		if !validIface(u.Interface) {
			return fmt.Errorf("invalid interface for uplink %q", u.Name)
		}
		if net.ParseIP(u.Gateway) == nil {
			return fmt.Errorf("invalid gateway for uplink %q", u.Name)
		}
		if u.Weight < 1 || u.Weight > 256 {
			return fmt.Errorf("weight for uplink %q must be 1-256", u.Name)
		}
		if u.HealthCheck != "" && net.ParseIP(u.HealthCheck) == nil {
			return fmt.Errorf("invalid health-check target for uplink %q", u.Name)
		}
	}
	return nil
}

// DefaultRouteArgs returns the `ip route replace default` nexthop arguments
// for the currently-healthy uplinks (those in healthy). When healthy is nil
// all uplinks are considered up (initial apply).
func (c Config) DefaultRouteArgs(healthy map[string]bool) ([]string, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	// Failover: exactly one active uplink — the first healthy one in list order
	// (list[0] is the primary). Single-nexthop route, no weight.
	if c.mode() == "failover" {
		for _, u := range c.Uplinks {
			if healthy != nil && !healthy[u.Name] {
				continue
			}
			return []string{"route", "replace", "default", "via", u.Gateway, "dev", u.Interface}, nil
		}
		return nil, fmt.Errorf("no healthy uplinks")
	}
	args := []string{"route", "replace", "default"}
	count := 0
	for _, u := range c.Uplinks {
		if healthy != nil && !healthy[u.Name] {
			continue
		}
		args = append(args, "nexthop", "via", u.Gateway, "dev", u.Interface, "weight", fmt.Sprintf("%d", u.Weight))
		count++
	}
	if count == 0 {
		return nil, fmt.Errorf("no healthy uplinks")
	}
	return args, nil
}

// GenerateSpec renders the plain-text spec file the root adapter's failover
// loop reads: one line per uplink "name iface gateway weight healthcheck".
func (c Config) GenerateSpec() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("# Managed by Saguaro (generated). name iface gateway weight healthcheck\n")
	for _, u := range c.Uplinks {
		hc := u.HealthCheck
		if hc == "" {
			hc = "-"
		}
		fmt.Fprintf(&b, "%s %s %s %d %s\n", u.Name, u.Interface, u.Gateway, u.Weight, hc)
	}
	return b.String(), nil
}
