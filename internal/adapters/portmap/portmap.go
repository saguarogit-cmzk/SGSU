// Package portmap gives every Ethernet port a stable logical name (lan0, wan1,
// net1...) by matching its MAC address in netplan and renaming it with
// set-name. Generation is pure; every value is charset-validated before it
// reaches YAML.
//
// Why: kernel names like enp2s0 encode a PCI path, so they change when a card
// moves slot and differ between machines. Every Saguaro module records the port
// it uses by name -- firewall zones, DHCP subnets, WAN addressing, multi-WAN
// uplinks, static routes, the IDS interface -- and a configuration backup
// carries all of those references with it. Restoring onto different hardware
// therefore points all of them at ports that do not exist. Renaming the ports
// themselves fixes this for every module at once, without any of them having to
// know that logical names exist: the only device-specific artifact left is this
// MAC-to-name map, which is regenerated per machine.
package portmap

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// nameRe is deliberately narrower than the kernel allows: lowercase, starts
// with a letter, no dots (a dot would collide with VLAN naming like lan0.20).
var nameRe = regexp.MustCompile(`^[a-z][a-z0-9]{1,13}$`)

var macRe = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)

// Port is one physical Ethernet port as the system currently sees it.
type Port struct {
	Kernel string `json:"kernel"` // current kernel name, e.g. enp2s0
	MAC    string `json:"mac"`
}

// Assignment binds a permanent MAC address to a logical port name.
type Assignment struct {
	MAC    string `json:"mac"`
	Name   string `json:"name"`
	Kernel string `json:"kernel"` // what it was called when assigned (audit aid)
}

func normalizeMAC(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// Auto derives the map with no operator input: the port serving DHCP becomes
// lan0, the port holding the default route becomes wan1, and every remaining
// port gets net1..netN in kernel-name order so a spare socket already has a
// stable name before anyone plugs anything into it.
func Auto(ports []Port, lanKernel, wanKernel string) ([]Assignment, error) {
	if lanKernel != "" && lanKernel == wanKernel {
		return nil, fmt.Errorf("LAN and WAN cannot be the same port (%s)", lanKernel)
	}
	sorted := append([]Port(nil), ports...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Kernel < sorted[j].Kernel })

	seenMAC := map[string]bool{}
	var usable []Port
	for _, p := range sorted {
		mac := normalizeMAC(p.MAC)
		// A port with no usable permanent MAC cannot be matched, so renaming it
		// would be unreliable; leave it on its kernel name rather than guess.
		if !macRe.MatchString(mac) || mac == "00:00:00:00:00:00" {
			continue
		}
		if seenMAC[mac] {
			return nil, fmt.Errorf("duplicate MAC address %s", mac)
		}
		seenMAC[mac] = true
		usable = append(usable, Port{Kernel: p.Kernel, MAC: mac})
	}
	for _, want := range []struct{ role, kernel string }{{"LAN", lanKernel}, {"WAN", wanKernel}} {
		if want.kernel == "" {
			continue
		}
		found := false
		for _, p := range usable {
			if p.Kernel == want.kernel {
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("%s port %q has no usable MAC address", want.role, want.kernel)
		}
	}

	// A port already carrying one of the names we hand out would collide once
	// another port is renamed to it, so refuse rather than produce a map that
	// only fails at boot.
	spare := 0
	out := make([]Assignment, 0, len(usable))
	for _, p := range usable {
		var name string
		switch p.Kernel {
		case lanKernel:
			name = "lan0"
		case wanKernel:
			name = "wan1"
		default:
			spare++
			name = fmt.Sprintf("net%d", spare)
		}
		out = append(out, Assignment{MAC: p.MAC, Name: name, Kernel: p.Kernel})
	}
	if err := Validate(out); err != nil {
		return nil, err
	}
	return out, nil
}

// Validate rejects anything that would produce a broken or ambiguous netplan.
func Validate(as []Assignment) error {
	if len(as) == 0 {
		return fmt.Errorf("no ports to map")
	}
	names, macs := map[string]bool{}, map[string]bool{}
	for _, a := range as {
		if !nameRe.MatchString(a.Name) {
			return fmt.Errorf("invalid port name %q (lowercase letter followed by 1-13 letters/digits)", a.Name)
		}
		if !macRe.MatchString(normalizeMAC(a.MAC)) {
			return fmt.Errorf("invalid MAC address %q for port %q", a.MAC, a.Name)
		}
		if names[a.Name] {
			return fmt.Errorf("duplicate port name %q", a.Name)
		}
		if macs[normalizeMAC(a.MAC)] {
			return fmt.Errorf("duplicate MAC address %q", a.MAC)
		}
		names[a.Name], macs[normalizeMAC(a.MAC)] = true, true
	}
	// A name that is another mapped port's current kernel name would be taken
	// at rename time by whichever port udev happens to reach first.
	for _, a := range as {
		for _, b := range as {
			if a.Name == b.Kernel && a.MAC != b.MAC {
				return fmt.Errorf("port name %q is already the kernel name of another mapped port", a.Name)
			}
		}
	}
	return nil
}

// GenerateNetplan renders the match/set-name netplan. It carries no addressing:
// the WAN and LAN files own that, keyed on the logical names this file creates.
func GenerateNetplan(as []Assignment) (string, error) {
	if err := Validate(as); err != nil {
		return "", err
	}
	sorted := append([]Assignment(nil), as...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	var b strings.Builder
	b.WriteString("# Managed by Saguaro (generated). Manual edits are overwritten on apply.\n")
	// Keep this header inside the charset the saguaro-net adapter accepts (no
	// apostrophes) or it will refuse to install the file it just generated.
	b.WriteString("# Stable port names: renaming the ports keeps every stored interface\n")
	b.WriteString("# reference valid across hardware changes and configuration restores.\n")
	b.WriteString("network:\n  version: 2\n  ethernets:\n")
	for _, a := range sorted {
		fmt.Fprintf(&b, "    %s:\n      match:\n        macaddress: %s\n      set-name: %s\n",
			a.Name, normalizeMAC(a.MAC), a.Name)
	}
	return b.String(), nil
}

// RenamePlan returns the ports whose kernel name does not yet match their
// logical name. netplan's set-name only takes effect through udev at boot, so
// the caller renames these live to avoid a mandatory reboot.
func RenamePlan(as []Assignment) []Assignment {
	var out []Assignment
	for _, a := range as {
		if a.Kernel != a.Name {
			out = append(out, a)
		}
	}
	return out
}
