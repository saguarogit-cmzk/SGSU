package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every root adapter must reach a fresh appliance through both install paths
// (install-ubuntu.sh and the .deb), and must be allowed in sudoers — otherwise
// a GUI module ships with its privileged half missing and only fails at the
// customer. Both install scripts once carried hand-written lists and both had
// silently fallen behind by two adapters.
func TestEveryAdapterIsInstalledAndAllowed(t *testing.T) {
	root := ".."
	if _, err := os.Stat(filepath.Join(root, "..", "scripts")); err == nil {
		root = filepath.Join("..", "..")
	}
	entries, err := os.ReadDir(filepath.Join(root, "scripts"))
	if err != nil {
		t.Skipf("scripts directory not readable from the test working dir: %v", err)
	}
	read := func(p string) string {
		b, err := os.ReadFile(filepath.Join(root, p))
		if err != nil {
			t.Fatalf("cannot read %s: %v", p, err)
		}
		return strings.ReplaceAll(string(b), "\r\n", "\n")
	}
	installer := read("scripts/install-ubuntu.sh")
	deb := read("scripts/build-deb.sh")
	sudoers := read("packaging/sudoers/saguaro-adapter")

	// A generic loop covers every adapter at once; only fall back to checking
	// for an explicit mention when a script still enumerates them.
	installerLoops := strings.Contains(installer, `for adapter in "$SOURCE_DIR"/scripts/saguaro-*`)
	debLoops := strings.Contains(deb, `for adapter in "$ROOT"/scripts/saguaro-*`)

	var adapters []string
	for _, e := range entries {
		n := e.Name()
		if !strings.HasPrefix(n, "saguaro-") || e.IsDir() {
			continue
		}
		// Not a sudo adapter: run by networkd-dispatcher, installed separately.
		if n == "saguaro-kea-linkwatch" {
			continue
		}
		adapters = append(adapters, strings.TrimSuffix(n, ".sh"))
	}
	if len(adapters) < 15 {
		t.Fatalf("only %d adapters found — is the scripts directory right?", len(adapters))
	}

	for _, name := range adapters {
		if !installerLoops && !strings.Contains(installer, name) {
			t.Errorf("%s is not installed by scripts/install-ubuntu.sh", name)
		}
		if !debLoops && !strings.Contains(deb, name) {
			t.Errorf("%s is not packaged by scripts/build-deb.sh", name)
		}
		// The backup job and the link watcher are invoked by systemd, not
		// through sudo, so they need no sudoers entry.
		if name == "saguaro-backup" {
			continue
		}
		if !strings.Contains(sudoers, "/usr/sbin/"+name+" ") {
			t.Errorf("%s has no sudoers grant — the control plane cannot call it", name)
		}
	}
}
