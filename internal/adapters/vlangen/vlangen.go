// Package vlangen renders a netplan file that creates the 802.1Q VLAN
// sub-interfaces backing tagged firewall zones. Generation is pure and tested;
// the privileged `netplan apply` happens in the /usr/sbin/saguaro-net adapter.
package vlangen

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"saguaro.local/network-manager/internal/adapters/nftgen"
)

// Generate returns a netplan document defining a VLAN sub-interface for every
// zone that carries a VLAN id, each with the appliance's own address on that
// VLAN. Zones without a VLAN id are ignored (their interfaces are configured
// elsewhere). With no VLAN zones the document is an empty, valid netplan so
// applying it removes any previously-created Saguaro VLANs.
func Generate(zones []nftgen.Zone) (string, error) {
	type vlan struct {
		name, link, addr string
		id               int
	}
	var vlans []vlan
	seen := map[string]bool{}
	for _, z := range zones {
		if z.VLANID <= 0 {
			continue
		}
		if z.VLANID > 4094 {
			return "", fmt.Errorf("zone %q has an out-of-range VLAN id %d", z.Name, z.VLANID)
		}
		if !ifaceOK(z.Interface) {
			return "", fmt.Errorf("zone %q has an invalid parent interface %q", z.Name, z.Interface)
		}
		if ip, _, err := net.ParseCIDR(z.Address); err != nil || ip.To4() == nil {
			return "", fmt.Errorf("zone %q needs an IPv4 CIDR address on its VLAN", z.Name)
		}
		name := z.IfaceName()
		if seen[name] {
			return "", fmt.Errorf("duplicate VLAN sub-interface %q", name)
		}
		seen[name] = true
		vlans = append(vlans, vlan{name: name, link: z.Interface, addr: strings.TrimSpace(z.Address), id: z.VLANID})
	}
	sort.Slice(vlans, func(i, j int) bool { return vlans[i].name < vlans[j].name })

	var b strings.Builder
	b.WriteString("# Managed by Saguaro (generated). Manual edits are overwritten on apply.\n")
	b.WriteString("network:\n  version: 2\n")
	if len(vlans) > 0 {
		b.WriteString("  vlans:\n")
		for _, v := range vlans {
			fmt.Fprintf(&b, "    %s:\n", v.name)
			fmt.Fprintf(&b, "      id: %d\n", v.id)
			fmt.Fprintf(&b, "      link: %s\n", v.link)
			b.WriteString("      addresses:\n")
			fmt.Fprintf(&b, "        - %s\n", v.addr)
		}
	}
	return b.String(), nil
}

func ifaceOK(name string) bool {
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
