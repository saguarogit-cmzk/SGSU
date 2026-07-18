package main

import (
	"path/filepath"
	"testing"
	"time"
)

func newTestFileSessions(t *testing.T) (*fileSessions, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sessions.json")
	s, err := openFileSessions(path)
	if err != nil {
		t.Fatalf("openFileSessions: %v", err)
	}
	return s, path
}

func testRecord(token string, ttl time.Duration) sessionRecord {
	hash := hashToken(token)
	now := time.Now().UTC()
	return sessionRecord{TokenHash: hash, ID: sessionID(hash), Username: "admin", CreatedAt: now, ExpiresAt: now.Add(ttl), RemoteIP: "192.0.2.10"}
}

func TestFileSessionsCRUD(t *testing.T) {
	s, _ := newTestFileSessions(t)
	rec := testRecord("token-one", time.Hour)
	if err := s.Create(rec); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, ok, err := s.Get(rec.TokenHash)
	if err != nil || !ok {
		t.Fatalf("Get after Create: ok=%v err=%v", ok, err)
	}
	if got.Username != "admin" || got.ID != rec.ID {
		t.Fatalf("unexpected record: %+v", got)
	}
	if err := s.Delete(rec.TokenHash); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok, _ := s.Get(rec.TokenHash); ok {
		t.Fatal("record present after Delete")
	}
}

func TestFileSessionsRevokeByID(t *testing.T) {
	s, _ := newTestFileSessions(t)
	rec := testRecord("token-two", time.Hour)
	if err := s.Create(rec); err != nil {
		t.Fatalf("Create: %v", err)
	}
	removed, err := s.DeleteByID(rec.ID)
	if err != nil || !removed {
		t.Fatalf("DeleteByID: removed=%v err=%v", removed, err)
	}
	removed, err = s.DeleteByID(rec.ID)
	if err != nil || removed {
		t.Fatalf("second DeleteByID must be a no-op: removed=%v err=%v", removed, err)
	}
}

func TestFileSessionsPersistAcrossReopen(t *testing.T) {
	s, path := newTestFileSessions(t)
	rec := testRecord("token-three", time.Hour)
	if err := s.Create(rec); err != nil {
		t.Fatalf("Create: %v", err)
	}
	reopened, err := openFileSessions(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, ok, _ := reopened.Get(rec.TokenHash); !ok {
		t.Fatal("session lost across restart")
	}
}

func TestFileSessionsPruneExpired(t *testing.T) {
	s, _ := newTestFileSessions(t)
	live := testRecord("token-live", time.Hour)
	dead := testRecord("token-dead", -time.Minute)
	if err := s.Create(live); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(dead); err != nil {
		t.Fatal(err)
	}
	if err := s.PruneExpired(time.Now()); err != nil {
		t.Fatalf("PruneExpired: %v", err)
	}
	if _, ok, _ := s.Get(dead.TokenHash); ok {
		t.Fatal("expired session survived prune")
	}
	if _, ok, _ := s.Get(live.TokenHash); !ok {
		t.Fatal("live session removed by prune")
	}
}

func TestSessionIDLength(t *testing.T) {
	hash := hashToken("abc")
	if len(hash) != 64 {
		t.Fatalf("token hash length: %d", len(hash))
	}
	if len(sessionID(hash)) != 16 {
		t.Fatalf("session id length: %d", len(sessionID(hash)))
	}
}
