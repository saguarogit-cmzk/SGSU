package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"saguaro.local/network-manager/internal/adapters/kea"
)

type conflict struct {
	Severity string `json:"severity"` // critical | warning | info
	Kind     string `json:"kind"`
	Message  string `json:"message"`
}

// parsePool parses a Kea pool string ("a.b.c.d - e.f.g.h") into an inclusive
// integer range.
func parsePool(pool string) (lo, hi int64, ok bool) {
	parts := strings.SplitN(strings.ReplaceAll(pool, " ", ""), "-", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	l, err1 := kea.IP4ToInt(parts[0])
	h, err2 := kea.IP4ToInt(parts[1])
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return l, h, true
}

func cidrsOverlap(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}

// detectConflicts reports overlapping subnets/pools and duplicate or misplaced
// reservations. It is pure so it can be unit-tested without Kea.
func detectConflicts(subnets []kea.Subnet, resv []kea.Reservation, blocked []string) []conflict {
	var out []conflict
	nets := map[int64]*net.IPNet{}
	for _, s := range subnets {
		_, ipnet, err := net.ParseCIDR(s.Subnet)
		if err != nil {
			out = append(out, conflict{"warning", "subnet", fmt.Sprintf("subnet %d has an invalid CIDR %q", s.ID, s.Subnet)})
			continue
		}
		nets[s.ID] = ipnet
	}
	// Subnet CIDR overlaps (pairwise).
	for i := 0; i < len(subnets); i++ {
		for j := i + 1; j < len(subnets); j++ {
			a, b := nets[subnets[i].ID], nets[subnets[j].ID]
			if a != nil && b != nil && cidrsOverlap(a, b) {
				out = append(out, conflict{"critical", "subnet-overlap",
					fmt.Sprintf("subnets %s and %s overlap", subnets[i].Subnet, subnets[j].Subnet)})
			}
		}
	}
	// Pool sanity within each subnet.
	for _, s := range subnets {
		ipnet := nets[s.ID]
		type rng struct{ lo, hi int64 }
		var ranges []rng
		for _, p := range s.Pools {
			lo, hi, ok := parsePool(p)
			if !ok {
				out = append(out, conflict{"warning", "pool", fmt.Sprintf("subnet %s has a malformed pool %q", s.Subnet, p)})
				continue
			}
			if lo > hi {
				out = append(out, conflict{"warning", "pool", fmt.Sprintf("subnet %s pool %q start is after its end", s.Subnet, p)})
			}
			if ipnet != nil {
				if loIP := kea.IntToIP4(lo); !ipnet.Contains(net.ParseIP(loIP)) {
					out = append(out, conflict{"warning", "pool-outside", fmt.Sprintf("subnet %s pool %q starts outside the subnet", s.Subnet, p)})
				} else if hiIP := kea.IntToIP4(hi); !ipnet.Contains(net.ParseIP(hiIP)) {
					out = append(out, conflict{"warning", "pool-outside", fmt.Sprintf("subnet %s pool %q ends outside the subnet", s.Subnet, p)})
				}
			}
			for _, r := range ranges {
				if lo <= r.hi && r.lo <= hi {
					out = append(out, conflict{"warning", "pool-overlap", fmt.Sprintf("subnet %s has overlapping pools", s.Subnet)})
					break
				}
			}
			ranges = append(ranges, rng{lo, hi})
		}
	}
	// Reservation duplicates and placement.
	ipSeen := map[string]bool{}
	ipDup := map[string]bool{}
	macSeen := map[string]bool{}
	for _, r := range resv {
		if ipSeen[r.IP] && !ipDup[r.IP] {
			out = append(out, conflict{"critical", "dup-ip", fmt.Sprintf("IP %s is reserved more than once", r.IP)})
			ipDup[r.IP] = true
		}
		ipSeen[r.IP] = true
		key := fmt.Sprintf("%d/%s", r.SubnetID, r.MAC)
		if macSeen[key] {
			out = append(out, conflict{"critical", "dup-mac", fmt.Sprintf("MAC %s has more than one reservation in subnet %d", r.MAC, r.SubnetID)})
		}
		macSeen[key] = true
		if ipnet := nets[r.SubnetID]; ipnet != nil && !ipnet.Contains(net.ParseIP(r.IP)) {
			out = append(out, conflict{"warning", "reservation-outside", fmt.Sprintf("reservation %s (%s) is outside its subnet %d", r.IP, r.MAC, r.SubnetID)})
		}
	}
	// Reservation IPs that fall inside a dynamic pool (Kea handles it but it is
	// worth surfacing).
	for _, r := range resv {
		ipInt, err := kea.IP4ToInt(r.IP)
		if err != nil {
			continue
		}
		for _, s := range subnets {
			if s.ID != r.SubnetID {
				continue
			}
			for _, p := range s.Pools {
				if lo, hi, ok := parsePool(p); ok && ipInt >= lo && ipInt <= hi {
					out = append(out, conflict{"info", "reservation-in-pool", fmt.Sprintf("reservation %s sits inside dynamic pool %q; consider moving it outside", r.IP, p)})
				}
			}
		}
	}
	// A blocked MAC that also has a reservation is contradictory.
	blockedSet := map[string]bool{}
	for _, m := range blocked {
		blockedSet[strings.ToLower(m)] = true
	}
	for _, r := range resv {
		if blockedSet[strings.ToLower(r.MAC)] {
			out = append(out, conflict{"warning", "blocked-reserved", fmt.Sprintf("MAC %s is both blocked and reserved (%s)", r.MAC, r.IP)})
		}
	}
	return out
}

func (a *app) apiConflicts(w http.ResponseWriter, r *http.Request) {
	var subnets []kea.Subnet
	if c := a.keaClient(); c != nil {
		if s, err := c.Subnets(r.Context()); err == nil {
			subnets = s
		}
	}
	var resv []kea.Reservation
	if a.keaHosts != nil {
		if rs, err := a.keaHosts.List(r.Context(), 0); err == nil {
			resv = rs
		}
	}
	conflicts := detectConflicts(subnets, resv, a.getBlockedMACs())
	if conflicts == nil {
		conflicts = []conflict{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"conflicts": conflicts,
		"checked":   map[string]int{"subnets": len(subnets), "reservations": len(resv)},
	})
}
