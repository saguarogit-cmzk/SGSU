package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// sessionRecord is one authenticated browser session. Only the SHA-256 hash of
// the bearer token is ever stored; the ID is a short hash prefix safe to show
// in the GUI and to use in revocation URLs.
type sessionRecord struct {
	TokenHash string    `json:"tokenHash"`
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	RemoteIP  string    `json:"remoteIp"`
	// CSRFHash is the SHA-256 of the per-session CSRF token; mutating requests
	// must present the raw token in X-CSRF-Token (double-submit, session-bound).
	CSRFHash string `json:"csrfHash"`
}

type sessionStore interface {
	Create(rec sessionRecord) error
	// Get returns the record for a token hash; ok is false when absent.
	Get(tokenHash string) (rec sessionRecord, ok bool, err error)
	Delete(tokenHash string) error
	// DeleteByID revokes by short ID and reports whether a session was removed.
	DeleteByID(id string) (bool, error)
	List() ([]sessionRecord, error)
	PruneExpired(now time.Time) error
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func sessionID(tokenHash string) string { return tokenHash[:16] }

// --- file-backed store (development and single-node without PostgreSQL) ---

type fileSessions struct {
	mu    sync.Mutex
	path  string
	items map[string]sessionRecord
}

func openFileSessions(path string) (*fileSessions, error) {
	s := &fileSessions{path: path, items: map[string]sessionRecord{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.items); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *fileSessions) saveLocked() error {
	b, err := json.Marshal(s.items)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *fileSessions) Create(rec sessionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[rec.TokenHash] = rec
	return s.saveLocked()
}

func (s *fileSessions) Get(tokenHash string) (sessionRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.items[tokenHash]
	return rec, ok, nil
}

func (s *fileSessions) Delete(tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, tokenHash)
	return s.saveLocked()
}

func (s *fileSessions) DeleteByID(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, rec := range s.items {
		if rec.ID == id {
			delete(s.items, hash)
			return true, s.saveLocked()
		}
	}
	return false, nil
}

func (s *fileSessions) List() ([]sessionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]sessionRecord, 0, len(s.items))
	for _, rec := range s.items {
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *fileSessions) PruneExpired(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for hash, rec := range s.items {
		if now.After(rec.ExpiresAt) {
			delete(s.items, hash)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return s.saveLocked()
}

// --- PostgreSQL-backed store (production; survives restarts and supports
// revocation from any control-plane replica) ---

type pgSessions struct{ db *sql.DB }

func openPGSessions(dsn string) (*pgSessions, error) {
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
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS sessions (
		token_hash TEXT PRIMARY KEY,
		id         TEXT NOT NULL,
		username   TEXT NOT NULL,
		created_at TIMESTAMPTZ NOT NULL,
		expires_at TIMESTAMPTZ NOT NULL,
		remote_ip  TEXT NOT NULL DEFAULT '',
		csrf_hash  TEXT NOT NULL DEFAULT ''
	)`); err != nil {
		db.Close()
		return nil, err
	}
	// Upgrade path for databases created before the CSRF column existed; the
	// empty default simply forces those sessions to re-authenticate on mutation.
	if _, err := db.ExecContext(ctx, `ALTER TABLE sessions ADD COLUMN IF NOT EXISTS csrf_hash TEXT NOT NULL DEFAULT ''`); err != nil {
		db.Close()
		return nil, err
	}
	return &pgSessions{db: db}, nil
}

func (s *pgSessions) Create(rec sessionRecord) error {
	_, err := s.db.Exec(`INSERT INTO sessions (token_hash, id, username, created_at, expires_at, remote_ip, csrf_hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		rec.TokenHash, rec.ID, rec.Username, rec.CreatedAt, rec.ExpiresAt, rec.RemoteIP, rec.CSRFHash)
	return err
}

func (s *pgSessions) Get(tokenHash string) (sessionRecord, bool, error) {
	var rec sessionRecord
	err := s.db.QueryRow(`SELECT token_hash, id, username, created_at, expires_at, remote_ip, csrf_hash
		FROM sessions WHERE token_hash = $1`, tokenHash).
		Scan(&rec.TokenHash, &rec.ID, &rec.Username, &rec.CreatedAt, &rec.ExpiresAt, &rec.RemoteIP, &rec.CSRFHash)
	if errors.Is(err, sql.ErrNoRows) {
		return sessionRecord{}, false, nil
	}
	if err != nil {
		return sessionRecord{}, false, err
	}
	return rec, true, nil
}

func (s *pgSessions) Delete(tokenHash string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token_hash = $1`, tokenHash)
	return err
}

func (s *pgSessions) DeleteByID(id string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM sessions WHERE id = $1`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func (s *pgSessions) List() ([]sessionRecord, error) {
	rows, err := s.db.Query(`SELECT token_hash, id, username, created_at, expires_at, remote_ip, csrf_hash
		FROM sessions ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []sessionRecord
	for rows.Next() {
		var rec sessionRecord
		if err := rows.Scan(&rec.TokenHash, &rec.ID, &rec.Username, &rec.CreatedAt, &rec.ExpiresAt, &rec.RemoteIP, &rec.CSRFHash); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *pgSessions) PruneExpired(now time.Time) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at < $1`, now)
	return err
}
