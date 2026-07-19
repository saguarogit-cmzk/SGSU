package main

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"saguaro.local/network-manager/internal/siem"
)

type siemConfig struct {
	Enabled     bool   `json:"enabled"`
	Protocol    string `json:"protocol"` // udp | tcp | tls
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Format      string `json:"format"` // rfc5424 | cef | json
	MinSeverity string `json:"minSeverity"`
	SkipVerify  bool   `json:"skipVerify"` // accept self-signed on tls
}

func (c siemConfig) validate() error {
	switch c.Protocol {
	case "udp", "tcp", "tls":
	default:
		return fmt.Errorf("protocol must be udp, tcp or tls")
	}
	if c.Host == "" {
		return fmt.Errorf("host is required")
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("port must be 1-65535")
	}
	switch c.Format {
	case "rfc5424", "cef", "json":
	default:
		return fmt.Errorf("format must be rfc5424, cef or json")
	}
	if _, ok := map[string]bool{"info": true, "notice": true, "warning": true, "error": true, "critical": true, "security": true}[c.MinSeverity]; !ok {
		return fmt.Errorf("invalid minimum severity")
	}
	return nil
}

// siemForwarder streams events to an external collector. A single worker owns
// the connection; enqueue never blocks the request path (it drops on overflow).
type siemForwarder struct {
	mu      sync.Mutex
	cfg     siemConfig
	conn    net.Conn
	ch      chan siem.Event
	host    string
	version string
	log     *slog.Logger
}

func newSIEMForwarder(host, version string, log *slog.Logger) *siemForwarder {
	f := &siemForwarder{ch: make(chan siem.Event, 512), host: host, version: version, log: log}
	go f.worker()
	return f
}

func (f *siemForwarder) worker() {
	for e := range f.ch {
		if err := f.send(e); err != nil {
			f.mu.Lock()
			if f.conn != nil {
				f.conn.Close()
				f.conn = nil
			}
			f.mu.Unlock()
			if f.log != nil {
				f.log.Warn("SIEM forward failed", "error", err)
			}
		}
	}
}

func (f *siemForwarder) setConfig(c siemConfig) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cfg = c
	if f.conn != nil { // force redial with the new target
		f.conn.Close()
		f.conn = nil
	}
}

func (f *siemForwarder) config() siemConfig {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cfg
}

func (f *siemForwarder) dialLocked() (net.Conn, error) {
	addr := net.JoinHostPort(f.cfg.Host, strconv.Itoa(f.cfg.Port))
	d := net.Dialer{Timeout: 5 * time.Second}
	switch f.cfg.Protocol {
	case "udp":
		return d.Dial("udp", addr)
	case "tls":
		return tls.DialWithDialer(&d, "tcp", addr, &tls.Config{ServerName: f.cfg.Host, InsecureSkipVerify: f.cfg.SkipVerify})
	default:
		return d.Dial("tcp", addr)
	}
}

// send writes one event to the collector. The enabled/severity gate is applied
// at enqueue time (siemForward), so a direct call here always transmits — this
// is what makes the connectivity test work while forwarding is still off.
func (f *siemForwarder) send(e siem.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cfg.Host == "" {
		return fmt.Errorf("SIEM host not configured")
	}
	if f.conn == nil {
		conn, err := f.dialLocked()
		if err != nil {
			return err
		}
		f.conn = conn
	}
	line := siem.Format(f.cfg.Format, e, "saguaro", f.version) + "\n"
	_ = f.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := f.conn.Write([]byte(line))
	return err
}

// testSend delivers one event synchronously so the GUI can report success.
func (f *siemForwarder) testSend(e siem.Event) error {
	if err := f.send(e); err != nil {
		f.mu.Lock()
		if f.conn != nil {
			f.conn.Close()
			f.conn = nil
		}
		f.mu.Unlock()
		return err
	}
	return nil
}

func (a *app) siemForward(e auditEvent) {
	f := a.siem
	if f == nil {
		return
	}
	cfg := f.config()
	if !cfg.Enabled || !siem.AtLeast(e.Severity, cfg.MinSeverity) {
		return
	}
	ev := siem.Event{Time: e.Time, Host: f.host, Severity: e.Severity, Actor: e.Actor,
		Action: e.Action, Target: e.Target, Result: e.Result, Message: e.Action + " " + e.Target}
	select {
	case f.ch <- ev:
	default: // queue full: drop rather than block the request path
	}
}

func (a *app) getSIEM() siemConfig {
	a.store.mu.RLock()
	defer a.store.mu.RUnlock()
	if a.store.data.SIEM == nil {
		return siemConfig{Protocol: "udp", Port: 514, Format: "rfc5424", MinSeverity: "warning"}
	}
	return *a.store.data.SIEM
}

func (a *app) setSIEM(c siemConfig) error {
	a.store.mu.Lock()
	a.store.data.SIEM = &c
	err := a.store.saveLocked()
	a.store.mu.Unlock()
	if a.siem != nil {
		a.siem.setConfig(c)
	}
	return err
}

func (a *app) apiSIEMGet(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.getSIEM())
}

func (a *app) apiSIEMPut(w http.ResponseWriter, r *http.Request) {
	var in siemConfig
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	if in.Enabled {
		if err := in.validate(); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if err := a.setSIEM(in); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist SIEM configuration")
		return
	}
	a.recordSev(r, a.actor(r), "siem-config", in.Host, "success", "warning",
		map[string]any{"enabled": in.Enabled, "protocol": in.Protocol, "format": in.Format})
	writeJSON(w, http.StatusOK, in)
}

func (a *app) apiSIEMTest(w http.ResponseWriter, r *http.Request) {
	cfg := a.getSIEM()
	if err := cfg.validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if a.siem == nil {
		writeError(w, http.StatusServiceUnavailable, "SIEM forwarder unavailable")
		return
	}
	// Apply the (possibly unsaved) current stored config and send a probe.
	a.siem.setConfig(cfg)
	ev := siem.Event{Time: time.Now().UTC(), Host: a.siem.host, Severity: "notice",
		Actor: a.actor(r), Action: "siem-test", Target: "connectivity", Result: "test",
		Message: "Saguaro SIEM connectivity test"}
	if err := a.siem.testSend(ev); err != nil {
		writeError(w, http.StatusBadGateway, "test failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
