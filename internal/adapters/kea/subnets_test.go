package kea

import (
	"encoding/json"
	"testing"
)

func specOK() SubnetSpec {
	return SubnetSpec{Subnet: "192.168.20.0/24", PoolStart: "192.168.20.100",
		PoolEnd: "192.168.20.200", Router: "192.168.20.1", Domain: "lan.internal",
		DNSServers: []string{"192.168.20.1"}}
}

func TestSubnetSpecValidate(t *testing.T) {
	if err := specOK().Validate(); err != nil {
		t.Fatalf("valid spec rejected: %v", err)
	}
	cases := map[string]func(*SubnetSpec){
		"bad cidr":         func(s *SubnetSpec) { s.Subnet = "not-a-cidr" },
		"pool outside":     func(s *SubnetSpec) { s.PoolEnd = "192.168.21.10" },
		"pool reversed":    func(s *SubnetSpec) { s.PoolStart = "192.168.20.201" },
		"router outside":   func(s *SubnetSpec) { s.Router = "10.0.0.1" },
		"bad dns":          func(s *SubnetSpec) { s.DNSServers = []string{"nope"} },
		"ipv6 subnet":      func(s *SubnetSpec) { s.Subnet = "fd00::/64" },
		"bad pool address": func(s *SubnetSpec) { s.PoolStart = "abc" },
	}
	for name, mutate := range cases {
		s := specOK()
		mutate(&s)
		if err := s.Validate(); err == nil {
			t.Fatalf("%s: expected validation error", name)
		}
	}
}

func dhcp4Fixture() map[string]any {
	raw := `{"subnet4":[{"id":1,"subnet":"192.168.10.0/24","pools":[{"pool":"192.168.10.100 - 192.168.10.200"}],"reservations":[{"hw-address":"aa:bb:cc:dd:ee:ff"}]}],"valid-lifetime":3600}`
	var m map[string]any
	_ = json.Unmarshal([]byte(raw), &m)
	return m
}

func TestAddSubnetAssignsNextID(t *testing.T) {
	d := dhcp4Fixture()
	id, err := AddSubnet(d, specOK())
	if err != nil || id != 2 {
		t.Fatalf("add: id=%d err=%v", id, err)
	}
	if len(subnetSlice(d)) != 2 {
		t.Fatalf("expected 2 subnets, got %d", len(subnetSlice(d)))
	}
	// Duplicate CIDR is refused.
	if _, err := AddSubnet(d, specOK()); err == nil {
		t.Fatal("duplicate subnet must be refused")
	}
}

func TestUpdateSubnetPreservesOtherFields(t *testing.T) {
	d := dhcp4Fixture()
	s := SubnetSpec{Subnet: "192.168.10.0/24", PoolStart: "192.168.10.50", PoolEnd: "192.168.10.99", Router: "192.168.10.1"}
	if err := UpdateSubnet(d, 1, s); err != nil {
		t.Fatalf("update: %v", err)
	}
	entry := subnetSlice(d)[0].(map[string]any)
	if _, ok := entry["reservations"]; !ok {
		t.Fatal("update must preserve unrelated per-subnet fields")
	}
	pools := entry["pools"].([]any)
	if pools[0].(map[string]any)["pool"] != "192.168.10.50 - 192.168.10.99" {
		t.Fatalf("pool not updated: %+v", pools)
	}
	// CIDR change is refused.
	s.Subnet = "192.168.99.0/24"
	s.PoolStart, s.PoolEnd, s.Router = "192.168.99.5", "192.168.99.9", ""
	if err := UpdateSubnet(d, 1, s); err == nil {
		t.Fatal("CIDR change must be refused")
	}
	if err := UpdateSubnet(d, 42, SubnetSpec{Subnet: "192.168.10.0/24", PoolStart: "192.168.10.50", PoolEnd: "192.168.10.99"}); err == nil {
		t.Fatal("unknown id must be refused")
	}
}

func TestDeleteSubnet(t *testing.T) {
	d := dhcp4Fixture()
	if !DeleteSubnet(d, 1) {
		t.Fatal("delete existing must succeed")
	}
	if len(subnetSlice(d)) != 0 {
		t.Fatal("subnet not removed")
	}
	if DeleteSubnet(d, 1) {
		t.Fatal("deleting a missing id must report false")
	}
}
