package kea

import (
	"strings"
	"testing"
)

func TestDropClassTest(t *testing.T) {
	got := DropClassTest([]string{"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"})
	want := "hexstring(pkt4.mac, ':') == 'aa:bb:cc:dd:ee:ff' or hexstring(pkt4.mac, ':') == '11:22:33:44:55:66'"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if DropClassTest(nil) != "" {
		t.Fatal("empty list must produce empty test")
	}
}

func findClass(classes []any, name string) map[string]any {
	for _, c := range classes {
		if m, ok := c.(map[string]any); ok && m["name"] == name {
			return m
		}
	}
	return nil
}

func TestSetDropClass(t *testing.T) {
	dhcp4 := map[string]any{"client-classes": []any{map[string]any{"name": "OTHER", "test": "x"}}}
	// Add DROP, keep the unrelated class.
	SetDropClass(dhcp4, []string{"aa:bb:cc:dd:ee:ff"})
	classes := dhcp4["client-classes"].([]any)
	if len(classes) != 2 || findClass(classes, "OTHER") == nil {
		t.Fatalf("unrelated class not preserved: %v", classes)
	}
	drop := findClass(classes, "DROP")
	if drop == nil || !strings.Contains(drop["test"].(string), "aa:bb:cc:dd:ee:ff") {
		t.Fatalf("DROP class wrong: %v", drop)
	}
	// Replacing rebuilds rather than duplicating.
	SetDropClass(dhcp4, []string{"11:22:33:44:55:66"})
	classes = dhcp4["client-classes"].([]any)
	if len(classes) != 2 || strings.Contains(findClass(classes, "DROP")["test"].(string), "aa:bb") {
		t.Fatalf("DROP not rebuilt: %v", classes)
	}
	// Clearing removes DROP but keeps OTHER.
	SetDropClass(dhcp4, nil)
	classes = dhcp4["client-classes"].([]any)
	if len(classes) != 1 || findClass(classes, "DROP") != nil {
		t.Fatalf("DROP not removed: %v", classes)
	}
	// When only DROP existed, clearing removes the key entirely.
	only := map[string]any{"client-classes": []any{map[string]any{"name": "DROP", "test": "y"}}}
	SetDropClass(only, nil)
	if _, ok := only["client-classes"]; ok {
		t.Fatal("client-classes should be removed when empty")
	}
}
