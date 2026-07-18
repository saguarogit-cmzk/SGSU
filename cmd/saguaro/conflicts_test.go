package main

import (
	"strings"
	"testing"

	"saguaro.local/network-manager/internal/adapters/kea"
)

func kinds(cs []conflict) map[string]int {
	m := map[string]int{}
	for _, c := range cs {
		m[c.Kind]++
	}
	return m
}

func TestDetectConflicts(t *testing.T) {
	subnets := []kea.Subnet{
		{ID: 1, Subnet: "192.168.10.0/24", Pools: []string{"192.168.10.100 - 192.168.10.200"}},
		{ID: 2, Subnet: "192.168.10.128/25", Pools: []string{"192.168.10.130 - 192.168.10.140"}}, // overlaps subnet 1
		{ID: 3, Subnet: "10.0.0.0/24", Pools: []string{"10.0.1.5 - 10.0.1.9", "10.0.0.50 - 10.0.0.40"}},
	}
	resv := []kea.Reservation{
		{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.10.5", SubnetID: 1},   // fine (outside pool, in subnet)
		{MAC: "aa:bb:cc:dd:ee:02", IP: "192.168.10.5", SubnetID: 1},   // dup IP with above
		{MAC: "aa:bb:cc:dd:ee:03", IP: "192.168.10.150", SubnetID: 1}, // inside dynamic pool -> info
		{MAC: "aa:bb:cc:dd:ee:04", IP: "172.16.0.9", SubnetID: 1},     // outside its subnet
		{MAC: "aa:bb:cc:dd:ee:05", IP: "10.0.0.60", SubnetID: 3},
		{MAC: "aa:bb:cc:dd:ee:05", IP: "10.0.0.61", SubnetID: 3}, // dup MAC in same subnet
	}
	blocked := []string{"aa:bb:cc:dd:ee:01"} // also reserved -> warning

	got := detectConflicts(subnets, resv, blocked)
	k := kinds(got)
	for _, want := range []string{"subnet-overlap", "pool-outside", "dup-ip", "dup-mac", "reservation-outside", "reservation-in-pool", "blocked-reserved"} {
		if k[want] == 0 {
			t.Errorf("expected a %q conflict; got %v", want, k)
		}
	}
	// the malformed/reversed pool "10.0.0.50 - 10.0.0.40" is flagged
	found := false
	for _, c := range got {
		if strings.Contains(c.Message, "start is after its end") {
			found = true
		}
	}
	if !found {
		t.Error("reversed pool not flagged")
	}
}

func TestDetectConflictsClean(t *testing.T) {
	subnets := []kea.Subnet{{ID: 1, Subnet: "192.168.10.0/24", Pools: []string{"192.168.10.100 - 192.168.10.200"}}}
	resv := []kea.Reservation{{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.10.5", SubnetID: 1}}
	if got := detectConflicts(subnets, resv, nil); len(got) != 0 {
		t.Fatalf("expected no conflicts, got %v", got)
	}
}
