package suricata

import (
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	ok := Config{Mode: ModeIDS, Interface: "enp1s0", HomeNet: "192.168.10.0/24"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid: %v", err)
	}
	cases := map[string]Config{
		"bad mode":       {Mode: "monitor", Interface: "enp1s0"},
		"ids no iface":   {Mode: ModeIDS},
		"iface chars":    {Mode: ModeIDS, Interface: "eth0; rm"},
		"homenet quotes": {Mode: ModeIDS, Interface: "enp1s0", HomeNet: `192.168.0.0/16"`},
	}
	for name, c := range cases {
		if err := c.Validate(); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
}

func TestGenerateIDS(t *testing.T) {
	text, err := Config{Mode: ModeIDS, Interface: "enp1s0", HomeNet: "192.168.10.0/24"}.Generate()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"af-packet:", "- interface: enp1s0", `HOME_NET: "[192.168.10.0/24]"`, "eve-log:", "- alert:"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}
	if strings.Contains(text, "nfq:") {
		t.Fatal("IDS config must not contain NFQUEUE")
	}
}

func TestGenerateIPS(t *testing.T) {
	text, err := Config{Mode: ModeIPS}.Generate()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"nfq:", "fail-open: yes", "mode: accept"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}
	if strings.Contains(text, "af-packet:") {
		t.Fatal("IPS config must not contain af-packet")
	}
}

func TestGenerateOffFails(t *testing.T) {
	if _, err := (Config{Mode: ModeOff}).Generate(); err == nil {
		t.Fatal("mode off must not generate")
	}
}

// The ET ruleset references the standard variables; a config that defines only
// HOME_NET/EXTERNAL_NET makes `suricata -T` fail on every real ruleset, so the
// engine can never be enabled.
func TestGenerateDefinesStandardVars(t *testing.T) {
	c := Config{Mode: ModeIDS, Interface: "wan1", HomeNet: "10.10.10.0/24"}
	out, err := c.Generate()
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{
		`HOME_NET: "[10.10.10.0/24]"`,
		`EXTERNAL_NET: "!$HOME_NET"`,
		`HTTP_SERVERS: "$HOME_NET"`,
		`SMTP_SERVERS: "$HOME_NET"`,
		`SQL_SERVERS: "$HOME_NET"`,
		`DNS_SERVERS: "$HOME_NET"`,
		`TELNET_SERVERS: "$HOME_NET"`,
		`AIM_SERVERS: "$EXTERNAL_NET"`,
		`DC_SERVERS: "$HOME_NET"`,
		"port-groups:",
		`HTTP_PORTS: "80"`,
		`SHELLCODE_PORTS: "!80"`,
		"SSH_PORTS: 22",
		"FTP_PORTS: 21",
		`FILE_DATA_PORTS: "[$HTTP_PORTS,110,143]"`,
	} {
		if !strings.Contains(out, w) {
			t.Errorf("generated config missing %q:\n%s", w, out)
		}
	}
}
