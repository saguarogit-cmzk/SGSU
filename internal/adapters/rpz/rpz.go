// Package rpz generates the Unbound Response Policy Zone configuration —
// the SNA security tier that runs on any hardware (unlike Suricata, which is
// gated on 8 GB RAM). Blocked domains answer NXDOMAIN and every hit is
// logged, which the event collector turns into dns-filter events.
package rpz

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

type Config struct {
	Enabled bool     `json:"enabled"`
	Domains []string `json:"domains"` // locally blocked domains
	Feeds   []string `json:"feeds"`   // optional external RPZ feed URLs (http/https)
}

var domainRe = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)

// NormalizeDomain lowercases and strips a trailing dot; returns an error for
// anything that is not a plausible domain name.
func NormalizeDomain(d string) (string, error) {
	d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
	if !domainRe.MatchString(d) {
		return "", fmt.Errorf("invalid domain %q", d)
	}
	return d, nil
}

func (c Config) Validate() error {
	if len(c.Domains) == 0 && len(c.Feeds) == 0 && c.Enabled {
		return fmt.Errorf("enable RPZ with at least one blocked domain or feed")
	}
	for _, d := range c.Domains {
		if _, err := NormalizeDomain(d); err != nil {
			return err
		}
	}
	for _, f := range c.Feeds {
		u, err := url.Parse(strings.TrimSpace(f))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("invalid feed URL %q (http/https required)", f)
		}
	}
	return nil
}

// GenerateZone renders the local RPZ zone file: each domain and its
// subdomains answer NXDOMAIN (CNAME .).
func (c Config) GenerateZone(serial int64) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	seen := map[string]bool{}
	var domains []string
	for _, d := range c.Domains {
		nd, err := NormalizeDomain(d)
		if err != nil {
			return "", err
		}
		nd = strings.TrimPrefix(nd, "*.")
		if !seen[nd] {
			seen[nd] = true
			domains = append(domains, nd)
		}
	}
	sort.Strings(domains)
	var b strings.Builder
	b.WriteString("; Managed by Saguaro (generated). Manual edits are overwritten on apply.\n")
	b.WriteString("$TTL 300\n")
	fmt.Fprintf(&b, "@ IN SOA localhost. root.localhost. %d 3600 900 604800 300\n", serial)
	b.WriteString("@ IN NS localhost.\n")
	for _, d := range domains {
		fmt.Fprintf(&b, "%s CNAME .\n", d)
		fmt.Fprintf(&b, "*.%s CNAME .\n", d)
	}
	return b.String(), nil
}

// GenerateConf renders the Unbound drop-in enabling the respip module and
// the local zone plus any feeds.
func (c Config) GenerateConf(zonePath string) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("# Managed by Saguaro (generated). Manual edits are overwritten on apply.\n")
	b.WriteString("server:\n")
	b.WriteString("  module-config: \"respip validator iterator\"\n\n")
	b.WriteString("rpz:\n")
	b.WriteString("  name: saguaro-rpz.\n")
	fmt.Fprintf(&b, "  zonefile: %s\n", zonePath)
	b.WriteString("  rpz-action-override: nxdomain\n")
	b.WriteString("  rpz-log: yes\n")
	b.WriteString("  rpz-log-name: saguaro-rpz\n")
	for i, f := range c.Feeds {
		b.WriteString("\nrpz:\n")
		fmt.Fprintf(&b, "  name: saguaro-rpz-feed-%d.\n", i+1)
		fmt.Fprintf(&b, "  url: %s\n", strings.TrimSpace(f))
		fmt.Fprintf(&b, "  zonefile: /var/lib/unbound/saguaro-rpz-feed-%d.zone\n", i+1)
		b.WriteString("  rpz-action-override: nxdomain\n")
		b.WriteString("  rpz-log: yes\n")
		fmt.Fprintf(&b, "  rpz-log-name: saguaro-rpz-feed-%d\n", i+1)
	}
	return b.String(), nil
}
