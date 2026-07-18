// Package events implements the SNA two-layer logging: journald stays the
// raw firehose, PostgreSQL holds structured events (monthly partitions,
// retention = DROP PARTITION) and the append-only audit_log.
package events

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// Severity levels, ordered. Matches the CHECK constraint in the events table.
var severities = []string{"info", "notice", "warning", "error", "critical", "security"}

// Rank returns the position of a severity for min-severity filtering;
// unknown strings rank below info.
func Rank(severity string) int {
	for i, s := range severities {
		if s == severity {
			return i
		}
	}
	return -1
}

// ValidSeverity reports whether s is one of the defined levels.
func ValidSeverity(s string) bool { return Rank(s) >= 0 }

// SeveritiesAtLeast returns every severity at or above min (min itself
// included); nil for unknown input.
func SeveritiesAtLeast(min string) []string {
	r := Rank(min)
	if r < 0 {
		return nil
	}
	return append([]string(nil), severities[r:]...)
}

// FromJournalPriority maps syslog/journald PRIORITY (0=emerg..7=debug) to an
// SNA severity.
func FromJournalPriority(p int) string {
	switch {
	case p <= 2:
		return "critical"
	case p == 3:
		return "error"
	case p == 4:
		return "warning"
	case p == 5:
		return "notice"
	default:
		return "info"
	}
}

// Event is one row in the events table. Empty strings become SQL NULLs for
// the typed columns (inet/macaddr refuse empty input).
type Event struct {
	ID       int64           `json:"id,omitempty"`
	TS       time.Time       `json:"ts"`
	Module   string          `json:"module"`
	Severity string          `json:"severity"`
	Host     string          `json:"host,omitempty"`
	Username string          `json:"username,omitempty"`
	SrcIP    string          `json:"srcIp,omitempty"`
	DstIP    string          `json:"dstIp,omitempty"`
	MAC      string          `json:"mac,omitempty"`
	Iface    string          `json:"iface,omitempty"`
	Action   string          `json:"action,omitempty"`
	Result   string          `json:"result,omitempty"`
	Message  string          `json:"message"`
	Raw      json.RawMessage `json:"raw,omitempty"`
}

// AuditEntry is one row in the append-only audit_log.
type AuditEntry struct {
	TS       time.Time       `json:"ts"`
	Actor    string          `json:"actor"`
	Action   string          `json:"action"`
	Target   string          `json:"target"`
	OldValue json.RawMessage `json:"oldValue,omitempty"`
	NewValue json.RawMessage `json:"newValue,omitempty"`
	Result   string          `json:"result"`
	RemoteIP string          `json:"remoteIp,omitempty"`
}

type Store struct{ db *sql.DB }

func Open(dsn string) (*Store, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// EnsureSchema creates the events parent table and (for development
// databases) audit_log, then makes sure the current and next monthly
// partitions exist. In production the installer pre-creates audit_log as the
// postgres superuser with INSERT/SELECT-only grants, which is what actually
// enforces append-only; CREATE TABLE IF NOT EXISTS is then a no-op.
func (s *Store) EnsureSchema(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS events (
			id BIGINT GENERATED ALWAYS AS IDENTITY,
			ts TIMESTAMPTZ NOT NULL,
			module TEXT NOT NULL,
			severity TEXT NOT NULL CHECK (severity IN
				('info','notice','warning','error','critical','security')),
			host TEXT, username TEXT,
			src_ip INET, dst_ip INET, mac MACADDR, iface TEXT,
			action TEXT, result TEXT, message TEXT NOT NULL,
			device_id BIGINT, rule_id BIGINT,
			raw JSONB, correlation_id UUID
		) PARTITION BY RANGE (ts)`,
		`CREATE INDEX IF NOT EXISTS events_ts_idx ON events (ts DESC)`,
		`CREATE INDEX IF NOT EXISTS events_severity_idx ON events (severity, ts DESC)`,
		`CREATE TABLE IF NOT EXISTS audit_log (
			id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
			ts TIMESTAMPTZ NOT NULL DEFAULT now(),
			actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
			old_value JSONB, new_value JSONB,
			result TEXT NOT NULL, remote_ip INET,
			config_version INT, correlation_id UUID
		)`,
	}
	for _, q := range stmts {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("schema: %w", err)
		}
	}
	return s.EnsurePartitions(ctx, time.Now().UTC())
}

// PartitionName returns the partition identifier for the month of t (UTC).
func PartitionName(t time.Time) string { return t.UTC().Format("events_200601") }

// PartitionBounds returns the [from, to) month boundaries for t in UTC.
func PartitionBounds(t time.Time) (time.Time, time.Time) {
	t = t.UTC()
	from := time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
	return from, from.AddDate(0, 1, 0)
}

// EnsurePartitions creates the partitions for the month of now and the next
// month, so month rollover never races an insert.
func (s *Store) EnsurePartitions(ctx context.Context, now time.Time) error {
	for _, t := range []time.Time{now, now.AddDate(0, 1, 0)} {
		from, to := PartitionBounds(t)
		q := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s PARTITION OF events FOR VALUES FROM ('%s') TO ('%s')`,
			PartitionName(t), from.Format("2006-01-02"), to.Format("2006-01-02"))
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("partition %s: %w", PartitionName(t), err)
		}
	}
	return nil
}

var partitionRe = regexp.MustCompile(`^events_(\d{6})$`)

// PruneOldPartitions drops event partitions older than keepMonths whole
// months (retention = DROP PARTITION, as designed). audit_log is never
// touched here.
func (s *Store) PruneOldPartitions(ctx context.Context, now time.Time, keepMonths int) (dropped []string, err error) {
	if keepMonths < 1 {
		keepMonths = 1
	}
	cutoff, _ := PartitionBounds(now.AddDate(0, -keepMonths, 0))
	rows, err := s.db.QueryContext(ctx,
		`SELECT tablename FROM pg_tables WHERE schemaname = current_schema() AND tablename LIKE 'events_%'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var candidates []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		m := partitionRe.FindStringSubmatch(name)
		if m == nil {
			continue
		}
		month, err := time.Parse("200601", m[1])
		if err != nil {
			continue
		}
		if month.Before(cutoff) {
			candidates = append(candidates, name)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, name := range candidates {
		if _, err := s.db.ExecContext(ctx, `DROP TABLE IF EXISTS `+name); err != nil {
			return dropped, fmt.Errorf("drop %s: %w", name, err)
		}
		dropped = append(dropped, name)
	}
	return dropped, nil
}

func ns(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func nj(v json.RawMessage) any {
	if len(v) == 0 {
		return nil
	}
	return []byte(v)
}

func (s *Store) Insert(ctx context.Context, e Event) error {
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO events
		(ts, module, severity, host, username, src_ip, dst_ip, mac, iface, action, result, message, raw)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		e.TS, e.Module, e.Severity, ns(e.Host), ns(e.Username), ns(e.SrcIP), ns(e.DstIP),
		ns(e.MAC), ns(e.Iface), ns(e.Action), ns(e.Result), e.Message, nj(e.Raw))
	return err
}

// InsertBatch writes a batch in one transaction; an empty batch is a no-op.
func (s *Store) InsertBatch(ctx context.Context, batch []Event) error {
	if len(batch) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO events
		(ts, module, severity, host, username, src_ip, dst_ip, mac, iface, action, result, message, raw)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, e := range batch {
		if e.TS.IsZero() {
			e.TS = time.Now().UTC()
		}
		if _, err := stmt.ExecContext(ctx, e.TS, e.Module, e.Severity, ns(e.Host), ns(e.Username),
			ns(e.SrcIP), ns(e.DstIP), ns(e.MAC), ns(e.Iface), ns(e.Action), ns(e.Result), e.Message, nj(e.Raw)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) InsertAudit(ctx context.Context, a AuditEntry) error {
	if a.TS.IsZero() {
		a.TS = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_log
		(ts, actor, action, target, old_value, new_value, result, remote_ip)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		a.TS, a.Actor, a.Action, a.Target, nj(a.OldValue), nj(a.NewValue), a.Result, ns(a.RemoteIP))
	return err
}

// MaxID returns the current highest event id (0 for an empty table) so an
// alert poller can start from "now" without alerting on history.
func (s *Store) MaxID(ctx context.Context) (int64, error) {
	var id sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT max(id) FROM events`).Scan(&id); err != nil {
		return 0, err
	}
	return id.Int64, nil
}

// QueryAfter returns events with id greater than afterID whose severity is in
// severities (which must come from SeveritiesAtLeast — the values are
// interpolated as validated literals), oldest first.
func (s *Store) QueryAfter(ctx context.Context, afterID int64, sevs []string, limit int) ([]Event, error) {
	if len(sevs) == 0 {
		return nil, nil
	}
	for _, sv := range sevs {
		if !ValidSeverity(sv) {
			return nil, fmt.Errorf("invalid severity %q", sv)
		}
	}
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	list := "'" + sevs[0] + "'"
	for _, sv := range sevs[1:] {
		list += ",'" + sv + "'"
	}
	q := fmt.Sprintf(`SELECT id, ts, module, severity,
		COALESCE(host,''), COALESCE(username,''),
		COALESCE(src_ip::text,''), COALESCE(dst_ip::text,''), COALESCE(mac::text,''),
		COALESCE(iface,''), COALESCE(action,''), COALESCE(result,''), message
		FROM events WHERE id > $1 AND severity IN (%s) ORDER BY id ASC LIMIT $2`, list)
	rows, err := s.db.QueryContext(ctx, q, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.TS, &e.Module, &e.Severity, &e.Host, &e.Username,
			&e.SrcIP, &e.DstIP, &e.MAC, &e.Iface, &e.Action, &e.Result, &e.Message); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// QueryOpts filters the events listing; zero values mean "no filter".
type QueryOpts struct {
	Module   string
	Severity string // exact match
	Since    time.Time
	Limit    int
}

func (s *Store) Query(ctx context.Context, o QueryOpts) ([]Event, error) {
	if o.Limit <= 0 || o.Limit > 1000 {
		o.Limit = 100
	}
	q := `SELECT id, ts, module, severity,
		COALESCE(host,''), COALESCE(username,''),
		COALESCE(src_ip::text,''), COALESCE(dst_ip::text,''), COALESCE(mac::text,''),
		COALESCE(iface,''), COALESCE(action,''), COALESCE(result,''), message
		FROM events WHERE true`
	args := []any{}
	if o.Module != "" {
		args = append(args, o.Module)
		q += fmt.Sprintf(" AND module = $%d", len(args))
	}
	if o.Severity != "" {
		args = append(args, o.Severity)
		q += fmt.Sprintf(" AND severity = $%d", len(args))
	}
	if !o.Since.IsZero() {
		args = append(args, o.Since)
		q += fmt.Sprintf(" AND ts >= $%d", len(args))
	}
	args = append(args, o.Limit)
	q += fmt.Sprintf(" ORDER BY ts DESC LIMIT $%d", len(args))
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.TS, &e.Module, &e.Severity, &e.Host, &e.Username,
			&e.SrcIP, &e.DstIP, &e.MAC, &e.Iface, &e.Action, &e.Result, &e.Message); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
