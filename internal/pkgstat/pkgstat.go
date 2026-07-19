// Package pkgstat parses the output of the /usr/sbin/saguaro-pkg root adapter
// (appliance package inventory and unattended-upgrade status) into structures
// for the GUI. Parsing is pure and tested; the privileged apt/dpkg reads and
// upgrades happen in the adapter.
package pkgstat

import "strings"

// Package is one appliance package's version state.
type Package struct {
	Key        string `json:"key"`        // stable adapter key (e.g. "unbound")
	Name       string `json:"name"`       // apt package name (e.g. "unbound")
	Installed  string `json:"installed"`  // installed version, "" if not installed
	Candidate  string `json:"candidate"`  // apt candidate version
	Upgradable bool   `json:"upgradable"` // candidate newer than installed
}

// ParseList parses `saguaro-pkg list` output. Each line is
//
//	<key> <package> <installed|-> <candidate|-> <yes|no|na>
//
// where "-" marks a not-installed package and the last field is the adapter's
// dpkg --compare-versions verdict (so version math stays out of Go).
func ParseList(out []byte) []Package {
	var pkgs []Package
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) != 5 {
			continue
		}
		p := Package{Key: f[0], Name: f[1]}
		if f[2] != "-" {
			p.Installed = f[2]
		}
		if f[3] != "-" {
			p.Candidate = f[3]
		}
		p.Upgradable = f[4] == "yes"
		pkgs = append(pkgs, p)
	}
	return pkgs
}

// UpgradableCount returns how many packages have a newer candidate.
func UpgradableCount(pkgs []Package) int {
	n := 0
	for _, p := range pkgs {
		if p.Upgradable {
			n++
		}
	}
	return n
}

// Unattended holds the state of automatic security upgrades.
type Unattended struct {
	Installed bool `json:"installed"` // unattended-upgrades package present
	Enabled   bool `json:"enabled"`   // periodic Unattended-Upgrade "1"
}

// ParseUnattended parses `saguaro-pkg unattended-status` output — two lines
// "installed <yes|no>" and "enabled <yes|no>".
func ParseUnattended(out []byte) Unattended {
	var u Unattended
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) != 2 {
			continue
		}
		switch f[0] {
		case "installed":
			u.Installed = f[1] == "yes"
		case "enabled":
			u.Enabled = f[1] == "yes"
		}
	}
	return u
}
