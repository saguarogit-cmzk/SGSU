package nftgen

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestGeneratedRulesetParses feeds a representative generated ruleset to the
// real `nft` parser in check mode (`nft -c -f`). It catches syntax regressions
// the pure string-matching tests cannot. It skips gracefully when nft is absent
// or the process lacks privilege (local dev), so it is meaningful only in CI,
// where it runs under sudo with nftables installed.
func TestGeneratedRulesetParses(t *testing.T) {
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("nft not installed; skipping real-parser check")
	}
	cfg := Config{
		AdminNetwork: "192.168.50.0/24", ClientNetwork: "10.10.10.0/24",
		GatewayEnabled: true, WANInterface: "enp1", LANInterface: "enp2", NATEnabled: true,
		HairpinNAT: true, IPSEnabled: true,
		PortForwards: []PortForward{{Proto: "tcp", ExtPort: 8443, DestIP: "10.10.10.5", DestPort: 443}},
		SNATRules:    []SNATRule{{Source: "10.10.10.0/28", ToAddress: "203.0.113.7"}},
		PBRUplinks:   []PBRUplink{{Interface: "enp1", Mark: 1}, {Interface: "enp3", Mark: 2}},
		TunnelNets:   []TunnelNet{{Local: []string{"10.10.10.0/24"}, Remote: []string{"192.168.20.0/24", "10.50.0.0/16"}}},
		Zones: []Zone{
			{Name: "lan", Kind: "lan", Interface: "enp2", Network: "10.10.10.0/24"},
			{Name: "dmz", Kind: "dmz", Interface: "enp3", Network: "10.20.0.0/24"},
			{Name: "guest", Kind: "guest", Interface: "enp4", Network: "10.30.0.0/24"},
		},
		Aliases: []Alias{
			{Name: "servers", Type: "host", Values: []string{"10.10.10.5", "10.10.10.6"}},
			{Name: "guests", Type: "network", Values: []string{"192.168.30.0/24"}},
			{Name: "pool", Type: "range", Values: []string{"10.0.0.10-10.0.0.20"}},
		},
		Rules: []Rule{
			{Name: "block guests to servers", Action: "drop", Proto: "any", SrcAlias: "guests", DstAlias: "servers", Enabled: true},
			{Name: "allow web", Action: "accept", Proto: "tcp", DstAlias: "servers", DstPort: 443, Category: "wan2lan", Enabled: true},
		},
	}
	ruleset, err := cfg.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	f := filepath.Join(t.TempDir(), "ruleset.nft")
	if err := os.WriteFile(f, []byte(ruleset), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(nft, "-c", "-f", f).CombinedOutput()
	if err != nil {
		low := strings.ToLower(string(out))
		if strings.Contains(low, "permission denied") || strings.Contains(low, "operation not permitted") {
			t.Skipf("nft -c needs privilege here; skipping: %s", out)
		}
		t.Fatalf("nft rejected the generated ruleset: %v\n%s\n--- ruleset ---\n%s", err, out, ruleset)
	}
}
