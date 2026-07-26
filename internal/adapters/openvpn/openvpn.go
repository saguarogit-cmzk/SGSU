// Package openvpn generates the OpenVPN server config, a self-contained PKI
// (its own CA, server and per-client certificates via crypto/x509 -- no
// easy-rsa), a tls-crypt key and a CRL for revocation, plus inline client
// .ovpn profiles. Split-tunnel is the default: the server only pushes routes to
// the configured internal networks, never redirect-gateway, so a remote user's
// ordinary internet keeps going out their own connection.
package openvpn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"regexp"
	"strings"
	"time"
)

const DefaultPort = 1194

var nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,30}[a-z0-9])?$`)

// Client is one issued VPN user. The private key is never stored; only the
// certificate and serial are kept so the CRL can revoke it.
type Client struct {
	Name      string    `json:"name"`
	Serial    string    `json:"serial"`             // hex
	CertPEM   string    `json:"certPem"`            //
	PassHash  string    `json:"passHash,omitempty"` // argon2 PHC; user+password auth on top of the cert
	Revoked   bool      `json:"revoked,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt,omitempty"`
}

// Config is the persisted OpenVPN configuration. The private keys are held
// sealed (encrypted) by the caller; the *Enc fields carry the ciphertext.
type Config struct {
	Enabled       bool     `json:"enabled"`
	Subnet        string   `json:"subnet"`   // e.g. 10.9.0.0/24
	Port          int      `json:"port"`     // default 1194
	Endpoint      string   `json:"endpoint"` // public host clients connect to
	DNS           string   `json:"dns"`      // pushed to clients
	SplitNetworks []string `json:"splitNetworks"`

	CACertPEM     string `json:"caCertPem,omitempty"`
	CAKeyEnc      string `json:"caKeyEnc,omitempty"`
	ServerCertPEM string `json:"serverCertPem,omitempty"`
	ServerKeyEnc  string `json:"serverKeyEnc,omitempty"`
	TLSCryptEnc   string `json:"tlsCryptEnc,omitempty"`

	Clients []Client `json:"clients"`
}

func (c Config) PortOrDefault() int {
	if c.Port <= 0 {
		return DefaultPort
	}
	return c.Port
}

func validCIDR4(s string) bool {
	ip, _, err := net.ParseCIDR(strings.TrimSpace(s))
	return err == nil && ip.To4() != nil
}

func (c Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if !validCIDR4(c.Subnet) {
		return fmt.Errorf("VPN subnet must be an IPv4 CIDR (e.g. 10.9.0.0/24)")
	}
	if p := c.PortOrDefault(); p < 1 || p > 65535 {
		return fmt.Errorf("port must be 1-65535")
	}
	if c.Endpoint == "" {
		return fmt.Errorf("endpoint (public host clients connect to) is required")
	}
	if c.DNS != "" && net.ParseIP(c.DNS) == nil {
		return fmt.Errorf("DNS must be an IP address")
	}
	for _, s := range c.SplitNetworks {
		if !validCIDR4(s) {
			return fmt.Errorf("internal network %q must be an IPv4 CIDR", s)
		}
	}
	return nil
}

// --- PKI -------------------------------------------------------------------

func pemEncode(typ string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))
}

func newSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func marshalKey(k *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return "", err
	}
	return pemEncode("PRIVATE KEY", der), nil
}

// GenerateCA creates a self-signed CA (certificate PEM, key PEM).
func GenerateCA() (certPEM, keyPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := newSerial()
	if err != nil {
		return "", "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Saguaro OpenVPN CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	km, err := marshalKey(key)
	if err != nil {
		return "", "", err
	}
	return pemEncode("CERTIFICATE", der), km, nil
}

func parseCA(caCertPEM, caKeyPEM string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cb, _ := pem.Decode([]byte(caCertPEM))
	kb, _ := pem.Decode([]byte(caKeyPEM))
	if cb == nil || kb == nil {
		return nil, nil, fmt.Errorf("invalid CA PEM")
	}
	caCert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	caKey, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("CA key is not ECDSA")
	}
	return caCert, caKey, nil
}

func signLeaf(caCertPEM, caKeyPEM, cn string, notAfter time.Time, eku x509.ExtKeyUsage) (certPEM, keyPEM, serialHex string, err error) {
	caCert, caKey, err := parseCA(caCertPEM, caKeyPEM)
	if err != nil {
		return "", "", "", err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", err
	}
	serial, err := newSerial()
	if err != nil {
		return "", "", "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return "", "", "", err
	}
	km, err := marshalKey(key)
	if err != nil {
		return "", "", "", err
	}
	return pemEncode("CERTIFICATE", der), km, hex.EncodeToString(serial.Bytes()), nil
}

// SignServer issues the server certificate (10 years).
func SignServer(caCertPEM, caKeyPEM string) (certPEM, keyPEM string, err error) {
	cp, kp, _, err := signLeaf(caCertPEM, caKeyPEM, "saguaro-openvpn-server", time.Now().AddDate(10, 0, 0), x509.ExtKeyUsageServerAuth)
	return cp, kp, err
}

// SignClient issues a client certificate; notAfter zero means a default 2 years.
func SignClient(caCertPEM, caKeyPEM, name string, notAfter time.Time) (certPEM, keyPEM, serialHex string, err error) {
	if !nameRe.MatchString(name) {
		return "", "", "", fmt.Errorf("client name must be lowercase letters/digits . _ - (2-32)")
	}
	if notAfter.IsZero() {
		notAfter = time.Now().AddDate(2, 0, 0)
	}
	return signLeaf(caCertPEM, caKeyPEM, name, notAfter, x509.ExtKeyUsageClientAuth)
}

// GenerateTLSCrypt returns an OpenVPN tls-crypt static key.
func GenerateTLSCrypt() (string, error) {
	buf := make([]byte, 256)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	h := hex.EncodeToString(buf)
	var b strings.Builder
	b.WriteString("-----BEGIN OpenVPN Static key V1-----\n")
	for i := 0; i < len(h); i += 32 {
		b.WriteString(h[i:i+32] + "\n")
	}
	b.WriteString("-----END OpenVPN Static key V1-----\n")
	return b.String(), nil
}

// GenerateCRL builds a CRL revoking the serials of the given revoked clients.
func GenerateCRL(caCertPEM, caKeyPEM string, revoked []Client) (string, error) {
	caCert, caKey, err := parseCA(caCertPEM, caKeyPEM)
	if err != nil {
		return "", err
	}
	var entries []x509.RevocationListEntry
	for _, c := range revoked {
		raw, err := hex.DecodeString(c.Serial)
		if err != nil {
			continue
		}
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   new(big.Int).SetBytes(raw),
			RevocationTime: time.Now(),
		})
	}
	tmpl := &x509.RevocationList{
		RevokedCertificateEntries: entries,
		Number:                    big.NewInt(time.Now().Unix()),
		ThisUpdate:                time.Now().Add(-time.Hour),
		NextUpdate:                time.Now().AddDate(10, 0, 0),
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, caCert, caKey)
	if err != nil {
		return "", err
	}
	return pemEncode("X509 CRL", der), nil
}

// GenerateAuthFile renders "username:argon2phc" lines for active clients, read
// by the auth-verify helper. Clients without a password are omitted (they can't
// authenticate, so they are effectively disabled -- passwords are required).
func GenerateAuthFile(clients []Client) string {
	var b strings.Builder
	for _, c := range clients {
		if c.Revoked || c.PassHash == "" {
			continue
		}
		b.WriteString(c.Name + ":" + c.PassHash + "\n")
	}
	return b.String()
}

// --- config rendering ------------------------------------------------------

// GenerateServerConf renders /etc/openvpn/server/saguaro.conf. File paths are
// where the adapter installs the PKI material.
func (c Config) GenerateServerConf() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	ip, ipnet, _ := net.ParseCIDR(strings.TrimSpace(c.Subnet))
	server := ip.Mask(ipnet.Mask)
	mask := net.IP(ipnet.Mask)
	var b strings.Builder
	b.WriteString("# Managed by Saguaro (generated). Manual edits are overwritten on apply.\n")
	fmt.Fprintf(&b, "port %d\n", c.PortOrDefault())
	b.WriteString("proto udp\n")
	b.WriteString("dev tun\n")
	b.WriteString("topology subnet\n")
	fmt.Fprintf(&b, "server %s %s\n", server.String(), mask.String())
	b.WriteString("ca /etc/openvpn/server/saguaro-ca.crt\n")
	b.WriteString("cert /etc/openvpn/server/saguaro-server.crt\n")
	b.WriteString("key /etc/openvpn/server/saguaro-server.key\n")
	b.WriteString("dh none\n")
	b.WriteString("tls-crypt /etc/openvpn/server/saguaro-tlscrypt.key\n")
	b.WriteString("crl-verify /etc/openvpn/server/saguaro-crl.pem\n")
	// A second factor on top of the client certificate: username + password,
	// verified by the Saguaro binary against the stored argon2 hashes.
	b.WriteString("auth-user-pass-verify /etc/openvpn/server/saguaro-authverify via-file\n")
	b.WriteString("script-security 2\n")
	b.WriteString("username-as-common-name\n")
	b.WriteString("data-ciphers AES-256-GCM\n")
	b.WriteString("auth SHA256\n")
	b.WriteString("keepalive 10 60\n")
	b.WriteString("persist-key\n")
	b.WriteString("persist-tun\n")
	b.WriteString("user nobody\n")
	b.WriteString("group nogroup\n")
	b.WriteString("verb 3\n")
	// Split-tunnel: push only the internal networks, never redirect-gateway, so
	// the client's own internet is untouched.
	for _, n := range c.SplitNetworks {
		sip, snet, err := net.ParseCIDR(strings.TrimSpace(n))
		if err != nil {
			continue
		}
		fmt.Fprintf(&b, "push \"route %s %s\"\n", sip.Mask(snet.Mask).String(), net.IP(snet.Mask).String())
	}
	if c.DNS != "" {
		fmt.Fprintf(&b, "push \"dhcp-option DNS %s\"\n", strings.TrimSpace(c.DNS))
	}
	return b.String(), nil
}

// GenerateClientOVPN renders a self-contained client profile with inline certs.
func (c Config) GenerateClientOVPN(clientCertPEM, clientKeyPEM, tlsCrypt string) string {
	var b strings.Builder
	b.WriteString("client\n")
	b.WriteString("dev tun\n")
	b.WriteString("proto udp\n")
	fmt.Fprintf(&b, "remote %s %d\n", c.Endpoint, c.PortOrDefault())
	b.WriteString("resolv-retry infinite\n")
	b.WriteString("nobind\n")
	b.WriteString("persist-key\n")
	b.WriteString("persist-tun\n")
	b.WriteString("remote-cert-tls server\n")
	b.WriteString("auth-user-pass\n")
	b.WriteString("data-ciphers AES-256-GCM\n")
	b.WriteString("auth SHA256\n")
	b.WriteString("verb 3\n")
	fmt.Fprintf(&b, "<ca>\n%s</ca>\n", strings.TrimSpace(c.CACertPEM)+"\n")
	fmt.Fprintf(&b, "<cert>\n%s</cert>\n", strings.TrimSpace(clientCertPEM)+"\n")
	fmt.Fprintf(&b, "<key>\n%s</key>\n", strings.TrimSpace(clientKeyPEM)+"\n")
	fmt.Fprintf(&b, "<tls-crypt>\n%s</tls-crypt>\n", strings.TrimSpace(tlsCrypt)+"\n")
	return b.String()
}
