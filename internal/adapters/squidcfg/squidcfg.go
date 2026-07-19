// Package squidcfg renders the Squid drop-in (LAN access ACL) and the
// e2guardian banned/exception domain lists for the web-proxy module. Squid
// caches and proxies; e2guardian (chained in front of Squid) filters URLs.
// Generation is pure; the root adapter /usr/sbin/saguaro-webproxy applies it.
package squidcfg

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// Default ports: clients point at e2guardian (FilterPort); e2guardian forwards
// to Squid on 3128 (localhost).
const (
	DefaultFilterPort = 8080
	SquidPort         = 3128
)

var domainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,253}[a-z0-9])?$`)

type Config struct {
	Enabled        bool     `json:"enabled"`
	FilterPort     int      `json:"filterPort"`     // e2guardian client port (default 8080)
	AllowedNetwork string   `json:"allowedNetwork"` // CIDR permitted to use the proxy
	Filtering      bool     `json:"filtering"`      // route through e2guardian for URL filtering
	BannedSites    []string `json:"bannedSites"`
	ExceptionSites []string `json:"exceptionSites"`
}

func validCIDR4(s string) bool {
	ip, _, err := net.ParseCIDR(strings.TrimSpace(s))
	return err == nil && ip.To4() != nil
}

func normDomains(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if !domainRe.MatchString(d) {
			return nil, fmt.Errorf("invalid domain %q", d)
		}
		out = append(out, d)
	}
	return out, nil
}

func (c Config) FilterPortOrDefault() int {
	if c.FilterPort <= 0 {
		return DefaultFilterPort
	}
	return c.FilterPort
}

func (c Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if p := c.FilterPortOrDefault(); p < 1 || p > 65535 {
		return fmt.Errorf("filter port must be 1-65535")
	}
	if !validCIDR4(c.AllowedNetwork) {
		return fmt.Errorf("allowed network must be an IPv4 CIDR (e.g. 192.168.10.0/24)")
	}
	if _, err := normDomains(c.BannedSites); err != nil {
		return err
	}
	if _, err := normDomains(c.ExceptionSites); err != nil {
		return err
	}
	return nil
}

// GenerateSquidDropIn renders /etc/squid/conf.d/saguaro.conf: allow the LAN to
// use the proxy (evaluated before Squid's default "http_access deny all").
func (c Config) GenerateSquidDropIn() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("# Managed by Saguaro (generated).\n")
	fmt.Fprintf(&b, "acl saguaro_lan src %s\n", strings.TrimSpace(c.AllowedNetwork))
	b.WriteString("http_access allow saguaro_lan\n")
	return b.String(), nil
}

// GenerateBanned / GenerateExceptions render the e2guardian domain lists.
func (c Config) GenerateBanned() (string, error) {
	d, err := normDomains(c.BannedSites)
	if err != nil {
		return "", err
	}
	return listFile(d), nil
}

func (c Config) GenerateExceptions() (string, error) {
	d, err := normDomains(c.ExceptionSites)
	if err != nil {
		return "", err
	}
	return listFile(d), nil
}

func listFile(domains []string) string {
	var b strings.Builder
	b.WriteString("# Managed by Saguaro (generated).\n")
	for _, d := range domains {
		b.WriteString(d + "\n")
	}
	return b.String()
}
