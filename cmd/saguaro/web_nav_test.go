package main

import (
	"regexp"
	"strings"
	"testing"
)

// The sidebar is not built from the module list but from NAV_GROUPS, so a
// module registered in `modules` and in the router is still invisible unless a
// group names it. That happened to two modules that shipped fully working and
// completely unreachable, which no Go test could catch — this one does.
func TestEveryModuleAppearsInNavigation(t *testing.T) {
	b, err := webFS.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	// The checkout may carry CRLF endings on Windows, which would leave a \r
	// before every line anchor and make the patterns below silently miss.
	src := strings.ReplaceAll(string(b), "\r\n", "\n")

	modLine := regexp.MustCompile(`(?m)^const modules=\[(.*)\];$`).FindStringSubmatch(src)
	if modLine == nil {
		t.Fatal("cannot find the modules list in app.js")
	}
	idRe := regexp.MustCompile(`\['([a-z]+)'`)
	var moduleIDs []string
	for _, m := range idRe.FindAllStringSubmatch(modLine[1], -1) {
		moduleIDs = append(moduleIDs, m[1])
	}
	if len(moduleIDs) < 20 {
		t.Fatalf("suspiciously few modules parsed (%d) — has the format changed?", len(moduleIDs))
	}

	groups := regexp.MustCompile(`const NAV_GROUPS=\[([\s\S]*?)\n\];`).FindStringSubmatch(src)
	if groups == nil {
		t.Fatal("cannot find NAV_GROUPS in app.js")
	}
	grouped := map[string]bool{}
	for _, m := range regexp.MustCompile(`'([a-z]+)'`).FindAllStringSubmatch(groups[1], -1) {
		grouped[m[1]] = true
	}

	var missing []string
	for _, id := range moduleIDs {
		if !grouped[id] {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("these modules are registered but reachable from no navigation group: %s",
			strings.Join(missing, ", "))
	}

	// And the reverse: a group naming a module that no longer exists would
	// leave a dead tab.
	known := map[string]bool{}
	for _, id := range moduleIDs {
		known[id] = true
	}
	for id := range grouped {
		// Group icons reuse module ids, so only flag entries that look like a
		// module reference but match nothing.
		if !known[id] && id != "monitoring" && id != "interfaces" && id != "dns" &&
			id != "fwrules" && id != "vpn" && id != "services" && id != "system" {
			t.Errorf("navigation references unknown module %q", id)
		}
	}
}

// Each module id must also have a route in openModule, or clicking its tab
// renders "Nepoznat modul".
func TestEveryModuleHasARoute(t *testing.T) {
	b, err := webFS.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	// The checkout may carry CRLF endings on Windows, which would leave a \r
	// before every line anchor and make the patterns below silently miss.
	src := strings.ReplaceAll(string(b), "\r\n", "\n")
	modLine := regexp.MustCompile(`(?m)^const modules=\[(.*)\];$`).FindStringSubmatch(src)
	if modLine == nil {
		t.Fatal("cannot find the modules list in app.js")
	}
	for _, m := range regexp.MustCompile(`\['([a-z]+)'`).FindAllStringSubmatch(modLine[1], -1) {
		id := m[1]
		if !strings.Contains(src, "id==='"+id+"'?") {
			t.Errorf("module %q has no route in openModule", id)
		}
	}
}
