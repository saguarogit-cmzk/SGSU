// Package nginxgen generates the Nginx vhost file for published services
// (wizard W5). One generated file carries every published app; applying goes
// through the root adapter /usr/sbin/saguaro-proxy, which validates with
// nginx -t and reverts on failure.
package nginxgen

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// TLS sources for a published service. ACME automation (step-ca / Let's
// Encrypt) arrives with the certificates module (W6); until then the
// appliance bootstrap certificate or custom paths are used.
const (
	TLSAppliance = "appliance" // /etc/saguaro/bootstrap-tls.{crt,key}
	TLSCustom    = "custom"    // caller-provided absolute paths
	TLSManaged   = "managed"   // certificate issued by the W6 module (CertName)
	TLSNone      = "none"      // plain HTTP on port 80
)

const managedCertDir = "/etc/saguaro/certs"

const (
	applianceCert = "/etc/saguaro/bootstrap-tls.crt"
	applianceKey  = "/etc/saguaro/bootstrap-tls.key"
)

type App struct {
	Name         string   `json:"name"` // identifier, [a-z0-9-]
	Hostname     string   `json:"hostname"`
	UpstreamIP   string   `json:"upstreamIp"`
	UpstreamPort int      `json:"upstreamPort"`
	TLS          string   `json:"tls"` // appliance | custom | managed | none
	CertPath     string   `json:"certPath,omitempty"`
	KeyPath      string   `json:"keyPath,omitempty"`
	CertName     string   `json:"certName,omitempty"` // managed TLS: name from the certificates module
	AllowCIDRs   []string `json:"allowCidrs"`         // empty = open access
	WebSocket    bool     `json:"webSocket"`
}

var (
	nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)
	hostRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)
)

func (a App) Validate() error {
	if !nameRe.MatchString(a.Name) {
		return fmt.Errorf("invalid service name %q (lowercase, digits, dashes)", a.Name)
	}
	if !hostRe.MatchString(strings.ToLower(a.Hostname)) {
		return fmt.Errorf("invalid hostname %q", a.Hostname)
	}
	if ip := net.ParseIP(a.UpstreamIP); ip == nil {
		return fmt.Errorf("invalid upstream IP %q", a.UpstreamIP)
	}
	if a.UpstreamPort < 1 || a.UpstreamPort > 65535 {
		return fmt.Errorf("upstream port must be 1-65535")
	}
	switch a.TLS {
	case TLSAppliance, TLSNone:
	case TLSManaged:
		if !nameRe.MatchString(a.CertName) {
			return fmt.Errorf("managed TLS requires a valid certName")
		}
	case TLSCustom:
		if !strings.HasPrefix(a.CertPath, "/") || !strings.HasPrefix(a.KeyPath, "/") {
			return fmt.Errorf("custom TLS requires absolute certPath and keyPath")
		}
		if strings.ContainsAny(a.CertPath+a.KeyPath, " ;\"'\n\t") {
			return fmt.Errorf("invalid characters in certificate paths")
		}
	default:
		return fmt.Errorf("tls must be appliance, custom or none")
	}
	for _, c := range a.AllowCIDRs {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(c)); err != nil {
			return fmt.Errorf("invalid access CIDR %q", c)
		}
	}
	return nil
}

// Generate renders the full published-services vhost file.
func Generate(apps []App) (string, error) {
	seenName := map[string]bool{}
	seenHost := map[string]bool{}
	var b strings.Builder
	b.WriteString("# Managed by Saguaro (generated). Manual edits are overwritten on apply.\n")
	for _, a := range apps {
		if err := a.Validate(); err != nil {
			return "", err
		}
		host := strings.ToLower(a.Hostname)
		if seenName[a.Name] {
			return "", fmt.Errorf("duplicate service name %q", a.Name)
		}
		if seenHost[host] {
			return "", fmt.Errorf("duplicate hostname %q", host)
		}
		seenName[a.Name] = true
		seenHost[host] = true

		cert, key := a.CertPath, a.KeyPath
		switch a.TLS {
		case TLSAppliance:
			cert, key = applianceCert, applianceKey
		case TLSManaged:
			cert = managedCertDir + "/" + a.CertName + ".crt"
			key = managedCertDir + "/" + a.CertName + ".key"
		}
		fmt.Fprintf(&b, "\n# service: %s\nserver {\n", a.Name)
		if a.TLS == TLSNone {
			b.WriteString("    listen 80;\n")
		} else {
			b.WriteString("    listen 443 ssl;\n")
			fmt.Fprintf(&b, "    ssl_certificate %s;\n", cert)
			fmt.Fprintf(&b, "    ssl_certificate_key %s;\n", key)
		}
		fmt.Fprintf(&b, "    server_name %s;\n", host)
		for _, c := range a.AllowCIDRs {
			fmt.Fprintf(&b, "    allow %s;\n", strings.TrimSpace(c))
		}
		if len(a.AllowCIDRs) > 0 {
			b.WriteString("    deny all;\n")
		}
		b.WriteString("    location / {\n")
		fmt.Fprintf(&b, "        proxy_pass http://%s;\n", net.JoinHostPort(a.UpstreamIP, fmt.Sprintf("%d", a.UpstreamPort)))
		b.WriteString("        proxy_set_header Host $host;\n")
		b.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
		b.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
		b.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
		if a.WebSocket {
			b.WriteString("        proxy_http_version 1.1;\n")
			b.WriteString("        proxy_set_header Upgrade $http_upgrade;\n")
			b.WriteString("        proxy_set_header Connection \"upgrade\";\n")
		}
		b.WriteString("    }\n}\n")
	}
	return b.String(), nil
}
