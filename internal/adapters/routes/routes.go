// Package routes models static routes and renders the spec the root adapter
// (/usr/sbin/saguaro-route) applies with `ip route`. Generation is pure.
package routes

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

type Route struct {
	Destination string `json:"destination"` // IPv4 CIDR or "default"
	Gateway     string `json:"gateway"`     // via IPv4 gateway
	Interface   string `json:"interface,omitempty"`
	Metric      int    `json:"metric,omitempty"`
}

type Config struct {
	Routes []Route `json:"routes"`
}

func validIface(name string) bool {
	if name == "" {
		return true // optional
	}
	if len(name) > 15 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func (r Route) Validate() error {
	if r.Destination != "default" {
		ip, _, err := net.ParseCIDR(strings.TrimSpace(r.Destination))
		if err != nil || ip.To4() == nil {
			return fmt.Errorf("destination %q must be an IPv4 CIDR or \"default\"", r.Destination)
		}
	}
	if gw := net.ParseIP(strings.TrimSpace(r.Gateway)); gw == nil || gw.To4() == nil {
		return fmt.Errorf("gateway %q must be an IPv4 address", r.Gateway)
	}
	if !validIface(r.Interface) {
		return fmt.Errorf("invalid interface %q", r.Interface)
	}
	if r.Metric < 0 || r.Metric > 4294967295 {
		return fmt.Errorf("metric out of range")
	}
	return nil
}

func (c Config) Validate() error {
	seen := map[string]bool{}
	for _, r := range c.Routes {
		if err := r.Validate(); err != nil {
			return err
		}
		if seen[r.Destination] {
			return fmt.Errorf("duplicate route for %s", r.Destination)
		}
		seen[r.Destination] = true
	}
	return nil
}

// GenerateSpec renders one line per route: "dest gateway iface metric".
// The root adapter reads this and applies each with `ip route replace`.
func (c Config) GenerateSpec() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("# Managed by Saguaro (generated). dest gateway iface metric\n")
	for _, r := range c.Routes {
		iface := r.Interface
		if iface == "" {
			iface = "-"
		}
		fmt.Fprintf(&b, "%s %s %s %d\n", r.Destination, r.Gateway, iface, r.Metric)
	}
	return b.String(), nil
}

// IPRouteArgs returns the `ip route replace ...` arguments for a route.
func (r Route) IPRouteArgs() []string {
	args := []string{"route", "replace", r.Destination, "via", r.Gateway}
	if r.Interface != "" {
		args = append(args, "dev", r.Interface)
	}
	if r.Metric > 0 {
		args = append(args, "metric", strconv.Itoa(r.Metric))
	}
	return args
}
