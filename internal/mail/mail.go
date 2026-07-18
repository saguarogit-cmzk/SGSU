// Package mail implements the SNA mail module: SMTP configuration with an
// AES-256-GCM-encrypted password, sending (STARTTLS, implicit TLS or plain),
// and the alert aggregation rule "first event immediately, duplicates for
// 10 minutes, then a summary".
package mail

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// Config is the persisted mail-module configuration. PasswordEnc holds the
// AES-256-GCM-sealed SMTP password; the plaintext never touches disk.
type Config struct {
	Enabled     bool     `json:"enabled"`
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	TLSMode     string   `json:"tlsMode"` // starttls | tls | none
	From        string   `json:"from"`
	Username    string   `json:"username"`
	PasswordEnc string   `json:"passwordEnc,omitempty"`
	Recipients  []string `json:"recipients"`
	MinSeverity string   `json:"minSeverity"` // events at or above this level alert
}

func (c Config) Validate() error {
	if c.Host == "" {
		return fmt.Errorf("SMTP host is required")
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("SMTP port must be 1-65535")
	}
	switch c.TLSMode {
	case "starttls", "tls", "none":
	default:
		return fmt.Errorf("tlsMode must be starttls, tls or none")
	}
	if !strings.Contains(c.From, "@") {
		return fmt.Errorf("from address is invalid")
	}
	if len(c.Recipients) == 0 {
		return fmt.Errorf("at least one recipient is required")
	}
	for _, r := range c.Recipients {
		if !strings.Contains(r, "@") {
			return fmt.Errorf("recipient %q is invalid", r)
		}
	}
	return nil
}

const dialTimeout = 5 * time.Second

// Send delivers one message with the configured transport. key decrypts the
// stored password; pass key=nil with an empty PasswordEnc for open relays.
func Send(cfg Config, key []byte, subject, body string) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	addr := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.Port))
	var (
		conn net.Conn
		err  error
	)
	if cfg.TLSMode == "tls" {
		d := &net.Dialer{Timeout: dialTimeout}
		conn, err = tls.DialWithDialer(d, "tcp", addr, &tls.Config{ServerName: cfg.Host})
	} else {
		conn, err = net.DialTimeout("tcp", addr, dialTimeout)
	}
	if err != nil {
		return fmt.Errorf("connect %s: %w", addr, err)
	}
	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if cfg.TLSMode == "starttls" {
		if err := c.StartTLS(&tls.Config{ServerName: cfg.Host}); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	}
	if cfg.Username != "" && cfg.PasswordEnc != "" {
		password, err := Decrypt(key, cfg.PasswordEnc)
		if err != nil {
			return fmt.Errorf("cannot decrypt SMTP password: %w", err)
		}
		if err := c.Auth(smtp.PlainAuth("", cfg.Username, password, cfg.Host)); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(cfg.From); err != nil {
		return err
	}
	for _, rcpt := range cfg.Recipients {
		if err := c.Rcpt(rcpt); err != nil {
			return fmt.Errorf("rcpt %s: %w", rcpt, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n",
		cfg.From, strings.Join(cfg.Recipients, ", "), subject, body)
	if _, err := w.Write([]byte(msg)); err != nil {
		w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
