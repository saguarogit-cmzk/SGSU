package nginxgen

import (
	"strings"
	"testing"
)

func appOK() App {
	return App{Name: "wiki", Hostname: "wiki.example.internal", UpstreamIP: "192.168.10.5",
		UpstreamPort: 8080, TLS: TLSAppliance, AllowCIDRs: []string{"192.168.10.0/24"}, WebSocket: true}
}

func TestValidate(t *testing.T) {
	if err := appOK().Validate(); err != nil {
		t.Fatalf("valid: %v", err)
	}
	cases := map[string]func(*App){
		"bad name":       func(a *App) { a.Name = "Wiki App" },
		"bad hostname":   func(a *App) { a.Hostname = "not_a_host" },
		"bad ip":         func(a *App) { a.UpstreamIP = "999.1.1.1" },
		"bad port":       func(a *App) { a.UpstreamPort = 0 },
		"bad tls":        func(a *App) { a.TLS = "letsencrypt" },
		"custom no path": func(a *App) { a.TLS = TLSCustom },
		"path injection": func(a *App) { a.TLS = TLSCustom; a.CertPath = "/x;reload"; a.KeyPath = "/k" },
		"bad cidr":       func(a *App) { a.AllowCIDRs = []string{"10.0.0.0"} },
	}
	for name, mutate := range cases {
		a := appOK()
		mutate(&a)
		if err := a.Validate(); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
}

func TestGenerate(t *testing.T) {
	text, err := Generate([]App{appOK()})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"listen 443 ssl;",
		"ssl_certificate /etc/saguaro/bootstrap-tls.crt;",
		"server_name wiki.example.internal;",
		"allow 192.168.10.0/24;",
		"deny all;",
		"proxy_pass http://192.168.10.5:8080;",
		`proxy_set_header Connection "upgrade";`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}
}

func TestGeneratePlainHTTPAndOpenAccess(t *testing.T) {
	a := appOK()
	a.TLS = TLSNone
	a.AllowCIDRs = nil
	a.WebSocket = false
	text, err := Generate([]App{a})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "listen 80;") || strings.Contains(text, "ssl_certificate") {
		t.Fatalf("plain HTTP wrong:\n%s", text)
	}
	if strings.Contains(text, "deny all;") || strings.Contains(text, "Upgrade") {
		t.Fatalf("open access / no-ws wrong:\n%s", text)
	}
}

func TestGenerateRejectsDuplicates(t *testing.T) {
	a, b := appOK(), appOK()
	b.Name = "wiki2"
	if _, err := Generate([]App{a, b}); err == nil {
		t.Fatal("duplicate hostname must be refused")
	}
	b = appOK()
	b.Hostname = "other.example.internal"
	if _, err := Generate([]App{a, b}); err == nil {
		t.Fatal("duplicate name must be refused")
	}
}

func TestGenerateManagedTLS(t *testing.T) {
	a := appOK()
	a.TLS = TLSManaged
	a.CertName = "wiki"
	text, err := Generate([]App{a})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "ssl_certificate /etc/saguaro/certs/wiki.crt;") ||
		!strings.Contains(text, "ssl_certificate_key /etc/saguaro/certs/wiki.key;") {
		t.Fatalf("managed cert paths missing:\n%s", text)
	}
	a.CertName = "Bad Name"
	if _, err := Generate([]App{a}); err == nil {
		t.Fatal("invalid certName must be refused")
	}
}

func TestGenerateCustomTLS(t *testing.T) {
	a := appOK()
	a.TLS = TLSCustom
	a.CertPath, a.KeyPath = "/etc/ssl/certs/wiki.crt", "/etc/ssl/private/wiki.key"
	text, err := Generate([]App{a})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "ssl_certificate /etc/ssl/certs/wiki.crt;") {
		t.Fatalf("custom cert missing:\n%s", text)
	}
}
