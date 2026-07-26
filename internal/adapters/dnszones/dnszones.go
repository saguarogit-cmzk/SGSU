// Package dnszones renders an Unbound drop-in that grants each internal firewall
// zone access to the resolver and, optionally, split-horizon answers. Unbound
// already listens on all interfaces (interface: 0.0.0.0), so a zone's clients
// only need an access-control allow for their network to use the appliance as
// their DNS server. Split-horizon is served by an Unbound view (view-first) so
// internal clients get the internal answer while everyone else gets the external
// (public) one. Generation is pure and tested; the privileged unbound-checkconf
// + reload happen in the /usr/sbin/saguaro-dns adapter.
package dnszones

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"

	"saguaro.local/network-manager/internal/adapters/nftgen"
)

// internalView is the Unbound view name assigned to internal (non-WAN) client
// networks. Kept to a plain identifier so it is safe inside the config file.
const internalView = "saguaro-internal"

// hostRe matches a DNS host name (FQDN, trailing dot optional). Split-horizon
// names come from operators and are embedded verbatim in the Unbound config, so
// they must be strictly validated before generation.
var hostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.?$`)

// SplitRecord is one split-horizon override. Name is an FQDN; Type is A or AAAA.
// Internal is the address served to internal clients (required). External is the
// address served to everyone else (optional — when empty, external clients
// resolve the name normally through recursion).
type SplitRecord struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Internal string `json:"internal"`
	External string `json:"external"`
}

// Valid reports whether the record is well-formed and safe to render: a valid
// host name, an A/AAAA type, an internal address of the matching family, and (if
// present) an external address of the matching family.
func (s SplitRecord) Valid() bool {
	name := strings.ToLower(strings.TrimSpace(s.Name))
	if !hostRe.MatchString(name) {
		return false
	}
	typ := strings.ToUpper(strings.TrimSpace(s.Type))
	if typ != "A" && typ != "AAAA" {
		return false
	}
	if !addrOfType(s.Internal, typ) {
		return false
	}
	if strings.TrimSpace(s.External) != "" && !addrOfType(s.External, typ) {
		return false
	}
	return true
}

// addrOfType checks that addr parses and matches the A (IPv4) / AAAA (IPv6) type.
func addrOfType(addr, typ string) bool {
	ip := net.ParseIP(strings.TrimSpace(addr))
	if ip == nil {
		return false
	}
	if typ == "A" {
		return ip.To4() != nil
	}
	return ip.To4() == nil // AAAA: any parsed IP that is not IPv4
}

// canonName lower-cases and ensures a single trailing dot for Unbound.
func canonName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if !strings.HasSuffix(n, ".") {
		n += "."
	}
	return n
}

// GenerateAccessConf returns an unbound.conf.d drop-in with an access-control
// allow line for every non-WAN zone that has a valid IPv4 network, plus any
// split-horizon views. clientNet is the appliance's LAN network (already allowed
// by the base Unbound config); it is added to the internal view so split-horizon
// works even when no firewall zones are defined. Networks are deduplicated and
// sorted for stable output. With no eligible zones and no split records it
// returns an empty (server-only) drop-in so applying it removes prior state.
func GenerateAccessConf(zones []nftgen.Zone, split []SplitRecord, clientNet string) string {
	seen := map[string]bool{}
	var nets []string
	for _, z := range zones {
		if z.Kind == "wan" || z.Network == "" {
			continue
		}
		ip, _, err := net.ParseCIDR(strings.TrimSpace(z.Network))
		if err != nil || ip.To4() == nil {
			continue
		}
		n := strings.TrimSpace(z.Network)
		if !seen[n] {
			seen[n] = true
			nets = append(nets, n)
		}
	}
	sort.Strings(nets)

	// The internal view covers the firewall zones plus the LAN (client) network,
	// so LAN clients get split-horizon answers even without explicit zones. The
	// LAN is already allowed by the base config, so it needs no allow line here.
	viewNets := append([]string{}, nets...)
	if cn := strings.TrimSpace(clientNet); cn != "" {
		if ip, _, err := net.ParseCIDR(cn); err == nil && ip.To4() != nil && !seen[cn] {
			viewNets = append(viewNets, cn)
			seen[cn] = true
		}
	}
	sort.Strings(viewNets)

	var valid []SplitRecord
	for _, s := range split {
		if s.Valid() {
			valid = append(valid, s)
		}
	}

	var b strings.Builder
	b.WriteString("# Managed by Saguaro (generated). Per-zone resolver access")
	if len(valid) > 0 {
		b.WriteString(" + split-horizon views")
	}
	b.WriteString(".\n")
	b.WriteString("server:\n")
	for _, n := range nets {
		fmt.Fprintf(&b, "  access-control: %s allow\n", n)
	}
	// The external/default answers live in the global server clause: any allowed
	// client not assigned to the internal view (and the box's own recursion) sees
	// these. A record with no external address is simply left to recurse.
	for _, s := range valid {
		if strings.TrimSpace(s.External) == "" {
			continue
		}
		name := canonName(s.Name)
		typ := strings.ToUpper(strings.TrimSpace(s.Type))
		fmt.Fprintf(&b, "  local-zone: \"%s\" redirect\n", name)
		fmt.Fprintf(&b, "  local-data: \"%s %s %s\"\n", name, typ, strings.TrimSpace(s.External))
	}
	if len(valid) > 0 && len(viewNets) > 0 {
		// Assign every internal network to the internal view so it gets the
		// internal answers below.
		for _, n := range viewNets {
			fmt.Fprintf(&b, "  access-control-view: %s %s\n", n, internalView)
		}
	}

	// The internal view holds the internal answers, checked before the global
	// data (view-first) so overridden names differ only for internal clients;
	// everything else falls through to normal resolution.
	if len(valid) > 0 && len(viewNets) > 0 {
		b.WriteString("\nview:\n")
		fmt.Fprintf(&b, "  name: \"%s\"\n", internalView)
		b.WriteString("  view-first: yes\n")
		for _, s := range valid {
			name := canonName(s.Name)
			typ := strings.ToUpper(strings.TrimSpace(s.Type))
			fmt.Fprintf(&b, "  local-zone: \"%s\" redirect\n", name)
			fmt.Fprintf(&b, "  local-data: \"%s %s %s\"\n", name, typ, strings.TrimSpace(s.Internal))
		}
	}
	return b.String()
}
