package mail

import (
	"bufio"
	"bytes"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCryptoRoundtrip(t *testing.T) {
	key, err := LoadOrCreateKey(filepath.Join(t.TempDir(), "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := Encrypt(key, "s3cret-smtp-pass")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(enc, "s3cret") {
		t.Fatal("ciphertext leaks plaintext")
	}
	dec, err := Decrypt(key, enc)
	if err != nil || dec != "s3cret-smtp-pass" {
		t.Fatalf("roundtrip: %q %v", dec, err)
	}
	wrong := make([]byte, 32)
	if _, err := Decrypt(wrong, enc); err == nil {
		t.Fatal("decrypt with wrong key must fail")
	}
}

func TestLoadKeyIsStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")
	k1, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatal("key must be stable across loads")
	}
}

func TestConfigValidate(t *testing.T) {
	good := Config{Host: "smtp.example.com", Port: 587, TLSMode: "starttls", From: "sna@example.com", Recipients: []string{"ops@example.com"}}
	if err := good.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for name, bad := range map[string]Config{
		"no host":       {Port: 587, TLSMode: "starttls", From: "a@b", Recipients: []string{"c@d"}},
		"bad port":      {Host: "h", Port: 0, TLSMode: "starttls", From: "a@b", Recipients: []string{"c@d"}},
		"bad tls":       {Host: "h", Port: 25, TLSMode: "ssl3", From: "a@b", Recipients: []string{"c@d"}},
		"bad from":      {Host: "h", Port: 25, TLSMode: "none", From: "nope", Recipients: []string{"c@d"}},
		"no recipients": {Host: "h", Port: 25, TLSMode: "none", From: "a@b"},
		"bad recipient": {Host: "h", Port: 25, TLSMode: "none", From: "a@b", Recipients: []string{"nope"}},
	} {
		if err := bad.Validate(); err == nil {
			t.Fatalf("%s: expected validation error", name)
		}
	}
}

// fakeSMTP speaks just enough SMTP for net/smtp on a loopback socket and
// captures the DATA payload.
func fakeSMTP(t *testing.T) (port int, data *bytes.Buffer, done *sync.WaitGroup) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	data = &bytes.Buffer{}
	done = &sync.WaitGroup{}
	done.Add(1)
	go func() {
		defer done.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)
		w := func(s string) { conn.Write([]byte(s + "\r\n")) }
		w("220 fake ESMTP")
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if inData {
				if line == "." {
					inData = false
					w("250 ok stored")
					continue
				}
				data.WriteString(line + "\n")
				continue
			}
			switch {
			case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
				w("250-fake")
				w("250 AUTH PLAIN")
			case strings.HasPrefix(line, "AUTH PLAIN"):
				w("235 ok")
			case strings.HasPrefix(line, "MAIL FROM"), strings.HasPrefix(line, "RCPT TO"):
				w("250 ok")
			case line == "DATA":
				inData = true
				w("354 go ahead")
			case line == "QUIT":
				w("221 bye")
				return
			default:
				w("250 ok")
			}
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, data, done
}

func TestSendPlainWithAuth(t *testing.T) {
	port, data, done := fakeSMTP(t)
	key, _ := LoadOrCreateKey(filepath.Join(t.TempDir(), "k"))
	enc, _ := Encrypt(key, "smtp-pass")
	cfg := Config{
		Host: "127.0.0.1", Port: port, TLSMode: "none",
		From: "sna@example.com", Username: "sna", PasswordEnc: enc,
		Recipients: []string{"ops@example.com"},
	}
	if err := Send(cfg, key, "[SNA] Test", "hello from test"); err != nil {
		t.Fatalf("send: %v", err)
	}
	done.Wait()
	body := data.String()
	if !strings.Contains(body, "Subject: [SNA] Test") || !strings.Contains(body, "hello from test") {
		t.Fatalf("captured message incomplete:\n%s", body)
	}
	if !strings.Contains(body, "To: ops@example.com") {
		t.Fatalf("missing To header:\n%s", body)
	}
}

func TestSendConnectFailure(t *testing.T) {
	cfg := Config{Host: "127.0.0.1", Port: 1, TLSMode: "none", From: "a@b", Recipients: []string{"c@d"}}
	if err := Send(cfg, nil, "s", "b"); err == nil {
		t.Fatal("expected connection error")
	}
}
