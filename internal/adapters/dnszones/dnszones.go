// Package dnszones renders an Unbound drop-in that grants each internal firewall
// zone access to the resolver. Unbound already listens on all interfaces
// (interface: 0.0.0.0), so a zone's clients only need an access-control allow
// for their network to use the appliance as their DNS server. Generation is
// pure and tested; the privileged unbound-checkconf + reload happen in the
// /usr/sbin/saguaro-dns adapter.
package dnszones

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"saguaro.local/network-manager/internal/adapters/nftgen"
)

// GenerateAccessConf returns an unbound.conf.d drop-in with an access-control
// allow line for every non-WAN zone that has a valid IPv4 network. Networks are
// deduplicated and sorted for stable output. With no eligible zones it returns
// an empty (server-only) drop-in so applying it removes previously granted zones.
func GenerateAccessConf(zones []nftgen.Zone) string {
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

	var b strings.Builder
	b.WriteString("# Managed by Saguaro (generated). Per-zone resolver access.\n")
	b.WriteString("server:\n")
	for _, n := range nets {
		fmt.Fprintf(&b, "  access-control: %s allow\n", n)
	}
	return b.String()
}
