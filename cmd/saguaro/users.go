package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"sort"
	"sync"
	"time"
)

// Roles per the SNA specification. Reads are allowed to every authenticated
// user; mutations are gated by the permission table in authz.go.
const (
	roleAdmin           = "admin"
	roleNetworkOperator = "network-operator"
	roleDNSOperator     = "dns-operator"
	roleAuditor         = "auditor"
	roleReadOnly        = "read-only"
)

var validRoles = map[string]bool{
	roleAdmin: true, roleNetworkOperator: true, roleDNSOperator: true,
	roleAuditor: true, roleReadOnly: true,
}

var usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,31}$`)

type userRecord struct {
	Username  string    `json:"username"`
	PHC       string    `json:"phc"`
	Role      string    `json:"role"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"createdAt"`
	// MustChangePassword forces a password change before anything else works
	// (wizard W1); set for the seeded bootstrap admin, admin-created users
	// and after an admin password reset.
	MustChangePassword bool `json:"mustChangePassword"`
}

type userStore interface {
	Get(username string) (userRecord, bool, error)
	List() ([]userRecord, error)
	Upsert(rec userRecord) error
	Delete(username string) (bool, error)
	Count() (int, error)
}

// --- file-backed store (development) ---

type fileUsers struct {
	mu    sync.Mutex
	path  string
	items map[string]userRecord
}

func openFileUsers(path string) (*fileUsers, error) {
	s := &fileUsers{path: path, items: map[string]userRecord{}}
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

func (s *fileUsers) saveLocked() error {
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

func (s *fileUsers) Get(username string) (userRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.items[username]
	return rec, ok, nil
}

func (s *fileUsers) List() ([]userRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]userRecord, 0, len(s.items))
	for _, rec := range s.items {
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out, nil
}

func (s *fileUsers) Upsert(rec userRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[rec.Username] = rec
	return s.saveLocked()
}

func (s *fileUsers) Delete(username string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[username]; !ok {
		return false, nil
	}
	delete(s.items, username)
	return true, s.saveLocked()
}

func (s *fileUsers) Count() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items), nil
}

// --- PostgreSQL-backed store (production) ---

type pgUsers struct{ db *sql.DB }

func openPGUsers(db *sql.DB) (*pgUsers, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS users (
		username    TEXT PRIMARY KEY,
		phc         TEXT NOT NULL,
		role        TEXT NOT NULL,
		enabled     BOOLEAN NOT NULL DEFAULT true,
		created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
		must_change BOOLEAN NOT NULL DEFAULT false
	)`); err != nil {
		return nil, err
	}
	if _, err := db.ExecContext(ctx, `ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change BOOLEAN NOT NULL DEFAULT false`); err != nil {
		return nil, err
	}
	return &pgUsers{db: db}, nil
}

func (s *pgUsers) Get(username string) (userRecord, bool, error) {
	var rec userRecord
	err := s.db.QueryRow(`SELECT username, phc, role, enabled, created_at, must_change FROM users WHERE username = $1`, username).
		Scan(&rec.Username, &rec.PHC, &rec.Role, &rec.Enabled, &rec.CreatedAt, &rec.MustChangePassword)
	if errors.Is(err, sql.ErrNoRows) {
		return userRecord{}, false, nil
	}
	if err != nil {
		return userRecord{}, false, err
	}
	return rec, true, nil
}

func (s *pgUsers) List() ([]userRecord, error) {
	rows, err := s.db.Query(`SELECT username, phc, role, enabled, created_at, must_change FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []userRecord
	for rows.Next() {
		var rec userRecord
		if err := rows.Scan(&rec.Username, &rec.PHC, &rec.Role, &rec.Enabled, &rec.CreatedAt, &rec.MustChangePassword); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *pgUsers) Upsert(rec userRecord) error {
	_, err := s.db.Exec(`INSERT INTO users (username, phc, role, enabled, created_at, must_change)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (username) DO UPDATE SET phc = $2, role = $3, enabled = $4, must_change = $6`,
		rec.Username, rec.PHC, rec.Role, rec.Enabled, rec.CreatedAt, rec.MustChangePassword)
	return err
}

func (s *pgUsers) Delete(username string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM users WHERE username = $1`, username)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func (s *pgUsers) Count() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

// seedAdmin creates the bootstrap administrator on first start. Once any
// user exists the store is authoritative and the bootstrap credential is
// only used to log in as that seeded admin.
func seedAdmin(store userStore, username, phc string) (bool, error) {
	n, err := store.Count()
	if err != nil {
		return false, err
	}
	if n > 0 {
		return false, nil
	}
	return true, store.Upsert(userRecord{Username: username, PHC: phc, Role: roleAdmin,
		Enabled: true, CreatedAt: time.Now().UTC(), MustChangePassword: true})
}
