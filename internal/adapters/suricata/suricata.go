// Package suricata generates the Suricata configuration for the SNA
// security module: af-packet IDS first, NFQUEUE IPS (fail-open bypass) after
// the observation period — wizard W9. Generation is pure; applying happens
// through the root adapter /usr/sbin/saguaro-ids.
package suricata

import (
	"fmt"
	"strings"
)

type Mode string

const (
	ModeOff Mode = "off"
	ModeIDS Mode = "ids"
	ModeIPS Mode = "ips"
)

type Config struct {
	Mode      Mode   `json:"mode"`
	Interface string `json:"interface"` // monitored interface (WAN) — IDS mode
	HomeNet   string `json:"homeNet"`   // CIDR of the protected network
}

func validIface(name string) bool {
	if name == "" || len(name) > 15 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func (c Config) Validate() error {
	switch c.Mode {
	case ModeIDS, ModeIPS:
	case ModeOff:
		return nil
	default:
		return fmt.Errorf("mode must be off, ids or ips")
	}
	if c.Mode == ModeIDS && !validIface(c.Interface) {
		return fmt.Errorf("IDS mode requires a valid interface name")
	}
	if c.HomeNet != "" && strings.ContainsAny(c.HomeNet, " \t\n\"'") {
		return fmt.Errorf("invalid homeNet value")
	}
	return nil
}

// Generate renders the Suricata YAML for the requested mode. IPS mode reads
// from NFQUEUE 0 (the nftables forward chain queues new connections with
// `queue num 0 bypass` — fail-open by design: if Suricata dies, traffic
// continues to flow instead of taking published services down).
func (c Config) Generate() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	if c.Mode == ModeOff {
		return "", fmt.Errorf("nothing to generate for mode off")
	}
	home := c.HomeNet
	if home == "" {
		home = "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
	} else {
		home = "[" + home + "]"
	}
	var b strings.Builder
	b.WriteString("%YAML 1.1\n---\n")
	b.WriteString("# Managed by Saguaro (generated). Manual edits are overwritten on apply.\n")
	// The full standard variable set, not just HOME_NET/EXTERNAL_NET: the
	// Emerging Threats ruleset references $HTTP_PORTS, $HTTP_SERVERS and the
	// rest, and Suricata refuses to parse a signature whose variable is
	// undefined. With only the two address groups defined, `suricata -T` fails
	// on the very first real ruleset — the engine could never be enabled.
	// Values follow the upstream suricata.yaml defaults.
	b.WriteString("vars:\n  address-groups:\n")
	fmt.Fprintf(&b, "    HOME_NET: \"%s\"\n", home)
	b.WriteString("    EXTERNAL_NET: \"!$HOME_NET\"\n")
	for _, g := range []string{"HTTP_SERVERS", "SMTP_SERVERS", "SQL_SERVERS", "DNS_SERVERS", "TELNET_SERVERS", "DNP3_SERVER", "DNP3_CLIENT", "MODBUS_CLIENT", "MODBUS_SERVER", "ENIP_CLIENT", "ENIP_SERVER"} {
		fmt.Fprintf(&b, "    %s: \"$HOME_NET\"\n", g)
	}
	b.WriteString("    AIM_SERVERS: \"$EXTERNAL_NET\"\n")
	b.WriteString("    DC_SERVERS: \"$HOME_NET\"\n")
	b.WriteString("  port-groups:\n")
	b.WriteString("    HTTP_PORTS: \"80\"\n")
	b.WriteString("    SHELLCODE_PORTS: \"!80\"\n")
	b.WriteString("    ORACLE_PORTS: 1521\n")
	b.WriteString("    SSH_PORTS: 22\n")
	b.WriteString("    DNP3_PORTS: 20000\n")
	b.WriteString("    MODBUS_PORTS: 502\n")
	b.WriteString("    FILE_DATA_PORTS: \"[$HTTP_PORTS,110,143]\"\n")
	b.WriteString("    FTP_PORTS: 21\n")
	b.WriteString("    GENEVE_PORTS: 6081\n")
	b.WriteString("    VXLAN_PORTS: 4789\n")
	b.WriteString("    TEREDO_PORTS: 3544\n\n")
	b.WriteString("default-log-dir: /var/log/suricata\n\n")
	b.WriteString("stats:\n  enabled: yes\n  interval: 60\n\n")
	b.WriteString("outputs:\n")
	b.WriteString("  - eve-log:\n")
	b.WriteString("      enabled: yes\n")
	b.WriteString("      filetype: regular\n")
	b.WriteString("      filename: eve.json\n")
	b.WriteString("      types:\n")
	b.WriteString("        - alert:\n")
	b.WriteString("            metadata: yes\n")
	b.WriteString("        - stats\n\n")
	if c.Mode == ModeIDS {
		fmt.Fprintf(&b, "af-packet:\n  - interface: %s\n    cluster-id: 99\n    cluster-type: cluster_flow\n    defrag: yes\n\n", c.Interface)
	} else {
		// IPS: packets arrive via NFQUEUE 0; accept is the failure policy.
		b.WriteString("nfq:\n  mode: accept\n  fail-open: yes\n\n")
	}
	b.WriteString("app-layer:\n  protocols:\n    tls:\n      enabled: yes\n    http:\n      enabled: yes\n    dns:\n      enabled: yes\n\n")
	b.WriteString("default-rule-path: /var/lib/suricata/rules\n")
	b.WriteString("rule-files:\n  - suricata.rules\n")
	return b.String(), nil
}
