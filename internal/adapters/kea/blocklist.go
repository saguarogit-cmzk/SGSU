package kea

import (
	"fmt"
	"strings"
)

// DropClassTest builds the Kea client-classification expression that matches
// any of the given MACs (each already "aa:bb:cc:dd:ee:ff"). Returns "" for an
// empty list.
func DropClassTest(macs []string) string {
	parts := make([]string, 0, len(macs))
	for _, m := range macs {
		parts = append(parts, fmt.Sprintf("hexstring(pkt4.mac, ':') == '%s'", m))
	}
	return strings.Join(parts, " or ")
}

// SetDropClass installs, updates or removes the special "DROP" client class in
// a Dhcp4 config map. A packet matching the DROP class is silently dropped by
// Kea, so listed MACs never receive a lease. Other client classes are kept.
func SetDropClass(dhcp4 map[string]any, macs []string) {
	var classes []any
	if v, ok := dhcp4["client-classes"].([]any); ok {
		for _, c := range v {
			if m, ok := c.(map[string]any); ok {
				if name, _ := m["name"].(string); name == "DROP" {
					continue // drop the existing managed entry; rebuilt below
				}
			}
			classes = append(classes, c)
		}
	}
	if len(macs) > 0 {
		classes = append(classes, map[string]any{
			"name": "DROP",
			"test": DropClassTest(macs),
		})
	}
	if len(classes) == 0 {
		delete(dhcp4, "client-classes")
		return
	}
	dhcp4["client-classes"] = classes
}
