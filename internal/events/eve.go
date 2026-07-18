package events

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"time"
)

// eveRecord is the subset of Suricata's eve.json the collector ingests.
type eveRecord struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	DestIP    string `json:"dest_ip"`
	Proto     string `json:"proto"`
	InIface   string `json:"in_iface"`
	Alert     struct {
		Action      string `json:"action"`
		SignatureID int64  `json:"signature_id"`
		Signature   string `json:"signature"`
		Category    string `json:"category"`
		Severity    int    `json:"severity"`
	} `json:"alert"`
}

// SeverityFromSuricata maps Suricata alert severity (1 = highest) to the SNA
// scale; high-severity alerts become security events, which also feeds the
// [SNA][SECURITY] mail path.
func SeverityFromSuricata(s int) string {
	switch s {
	case 1:
		return "security"
	case 2:
		return "warning"
	default:
		return "notice"
	}
}

// ParseEveLine converts one eve.json line into an Event; ok is false for
// non-alert records (stats, flow, dns, ...) and unparseable lines.
func ParseEveLine(line []byte) (Event, bool) {
	var rec eveRecord
	if err := json.Unmarshal(line, &rec); err != nil || rec.EventType != "alert" {
		return Event{}, false
	}
	ts := time.Now().UTC()
	if t, err := time.Parse("2006-01-02T15:04:05.999999-0700", rec.Timestamp); err == nil {
		ts = t.UTC()
	}
	raw, _ := json.Marshal(map[string]any{
		"sid": rec.Alert.SignatureID, "category": rec.Alert.Category,
		"action": rec.Alert.Action, "proto": rec.Proto,
	})
	msg := rec.Alert.Signature
	if msg == "" {
		msg = "suricata alert"
	}
	return Event{
		TS:       ts,
		Module:   "ids",
		Severity: SeverityFromSuricata(rec.Alert.Severity),
		SrcIP:    rec.SrcIP,
		DstIP:    rec.DestIP,
		Iface:    rec.InIface,
		Action:   rec.Alert.Action,
		Result:   rec.Alert.Category,
		Message:  msg,
		Raw:      raw,
	}, true
}

// TailEve follows a Suricata eve.json file: it starts at the end, emits
// parsed alert events, survives a missing file (Suricata not enabled yet)
// and reopens after rotation or truncation. poll controls how often new
// data is checked; pass 0 for the 2 s default.
func TailEve(ctx context.Context, path string, poll time.Duration, emit func(Event)) {
	if poll <= 0 {
		poll = 2 * time.Second
	}
	var (
		f    *os.File
		r    *bufio.Reader
		read int64
	)
	openTail := func(seekEnd bool) {
		var err error
		f, err = os.Open(path)
		if err != nil {
			f = nil
			return
		}
		read = 0
		if seekEnd {
			if st, err := f.Stat(); err == nil {
				read, _ = f.Seek(st.Size(), io.SeekStart)
			}
		}
		r = bufio.NewReaderSize(f, 256*1024)
	}
	defer func() {
		if f != nil {
			f.Close()
		}
	}()
	openTail(true)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if f == nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(poll):
			}
			openTail(false)
			continue
		}
		line, err := r.ReadBytes('\n')
		if len(line) > 0 && err == nil {
			read += int64(len(line))
			if e, ok := ParseEveLine(line); ok {
				emit(e)
			}
			continue
		}
		// EOF (or partial line): wait, then check for rotation/truncation.
		select {
		case <-ctx.Done():
			return
		case <-time.After(poll):
		}
		if st, serr := os.Stat(path); serr != nil || st.Size() < read {
			f.Close()
			f = nil
		}
	}
}
