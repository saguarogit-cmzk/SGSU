package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBackupConfigureSFTP(t *testing.T) {
	srv, c, a := newTestServer(t)
	var actions []string
	a.runBackupCfg = func(_ context.Context, args ...string) ([]byte, error) {
		actions = append(actions, args[0])
		return []byte("ok"), nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	// Missing SFTP fields are rejected.
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/backup/apply", `{"target":"sftp","schedule":"daily","retentionDays":14,"sftpHost":"","sftpUser":"u","sftpPath":"/b"}`); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("incomplete sftp: got %d, want 400", r.StatusCode)
	}
	body := `{"target":"sftp","schedule":"daily","retentionDays":14,"sftpHost":"backup.example.com","sftpPort":2222,"sftpUser":"saguaro","sftpPath":"/srv/backups","sftpKeyPath":"/etc/saguaro/backup-sftp.key"}`
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/backup/apply", body); r.StatusCode != http.StatusOK {
		t.Fatalf("sftp apply: got %d", r.StatusCode)
	}
	env, err := os.ReadFile(filepath.Join(filepath.Dir(a.store.path), stagedBackupEnvName))
	if err != nil {
		t.Fatalf("staged env missing (should have been consumed by the adapter, but test stub does not remove it): %v", err)
	}
	for _, want := range []string{"SAGUARO_BACKUP_TARGET=sftp", "SAGUARO_SFTP_HOST=backup.example.com", "SAGUARO_SFTP_PORT=2222", "SAGUARO_SFTP_KEY=/etc/saguaro/backup-sftp.key"} {
		if !strings.Contains(string(env), want) {
			t.Fatalf("staged env missing %q:\n%s", want, env)
		}
	}
	cfg := a.getBackup()
	if cfg.SecretEnc == "" || strings.Contains(cfg.SecretEnc, "backup-sftp.key") {
		t.Fatalf("secret must be sealed: %+v", cfg)
	}
	if strings.Join(actions, ",") != "apply" {
		t.Fatalf("adapter calls wrong: %v", actions)
	}
}

func TestBackupS3SecretRedactedInView(t *testing.T) {
	srv, c, a := newTestServer(t)
	a.runBackupCfg = func(_ context.Context, _ ...string) ([]byte, error) { return nil, nil }
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	body := `{"target":"s3","schedule":"weekly","retentionDays":60,"s3Bucket":"sna-backups","s3Region":"eu-central-1","s3AccessId":"AKIA","s3Secret":"topsecret"}`
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/backup/apply", body); r.StatusCode != http.StatusOK {
		t.Fatalf("s3 apply: got %d", r.StatusCode)
	}
	resp, _ := c.Get(srv.URL + "/api/backup")
	rawBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	raw := string(rawBytes)
	if strings.Contains(raw, "topsecret") || strings.Contains(raw, "secretEnc") {
		t.Fatalf("secret leaked in view: %s", raw)
	}
	if !strings.Contains(raw, `"hasSecret":true`) {
		t.Fatalf("hasSecret flag missing: %s", raw)
	}
	_ = a
}

func TestBackupRejectsShellInjection(t *testing.T) {
	srv, c, a := newTestServer(t)
	var calls []string
	a.runBackupCfg = func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, args[0])
		return nil, nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	// A command-substitution payload in a target field must be rejected before
	// anything is staged or the adapter is called (backup.env is sourced by
	// the root backup service).
	for _, payload := range []string{
		`{"target":"sftp","schedule":"daily","sftpHost":"x$(touch /tmp/pwned)","sftpUser":"u","sftpPath":"/b"}`,
		`{"target":"sftp","schedule":"daily","sftpHost":"h","sftpUser":"u","sftpPath":"/b; reboot"}`,
		"{\"target\":\"s3\",\"schedule\":\"daily\",\"s3Bucket\":\"b\",\"s3AccessId\":\"k\",\"s3Secret\":\"a`id`b\"}",
	} {
		if r := reqJSON(t, srv, c, http.MethodPost, "/api/backup/apply", payload); r.StatusCode != http.StatusBadRequest {
			t.Fatalf("injection %q: got %d, want 400", payload, r.StatusCode)
		}
	}
	if len(calls) != 0 {
		t.Fatalf("adapter must not run for rejected input: %v", calls)
	}
	// The env the control plane would write for a legitimate config carries no
	// shell-active characters.
	env, err := a.buildBackupEnv(backupConfig{Target: "s3", RetentionDays: 30,
		S3Bucket: "sna-backups", S3Region: "eu-central-1", S3AccessID: "AKIA"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(env, "`;&|") || strings.Contains(env, "$(") {
		t.Fatalf("generated env contains shell-active characters:\n%s", env)
	}
}

func TestBackupRunAndRestoreDrill(t *testing.T) {
	srv, c, a := newTestServer(t)
	var actions []string
	a.runBackupCfg = func(_ context.Context, args ...string) ([]byte, error) {
		actions = append(actions, args[0])
		return nil, nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/backup/run", "{}"); r.StatusCode != http.StatusOK {
		t.Fatalf("run: got %d", r.StatusCode)
	}
	// Drill starts due (never performed).
	resp, _ := c.Get(srv.URL + "/api/backup")
	var view struct {
		RestoreDrillDue bool `json:"restoreDrillDue"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&view)
	resp.Body.Close()
	if !view.RestoreDrillDue {
		t.Fatal("restore drill should start due")
	}
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/backup/drill", "{}"); r.StatusCode != http.StatusOK {
		t.Fatalf("mark drill: got %d", r.StatusCode)
	}
	if cfg := a.getBackup(); cfg.LastDrill.IsZero() || time.Since(cfg.LastDrill) > time.Minute {
		t.Fatalf("drill timestamp not set: %+v", cfg.LastDrill)
	}
	resp, _ = c.Get(srv.URL + "/api/backup")
	_ = json.NewDecoder(resp.Body).Decode(&view)
	resp.Body.Close()
	if view.RestoreDrillDue {
		t.Fatal("restore drill should be satisfied after marking")
	}
	if strings.Join(actions, ",") != "run" {
		t.Fatalf("adapter calls wrong: %v", actions)
	}
}

func TestMultiWANRequiresGateway(t *testing.T) {
	srv, c, a := newTestServer(t)
	a.runWAN = func(_ context.Context, _ string) ([]byte, error) { return nil, nil }
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	body := `{"enabled":true,"uplinks":[{"name":"wan1","interface":"enp1s0","gateway":"192.0.2.1","weight":2,"healthCheck":"1.1.1.1"},{"name":"wan2","interface":"enp3s0","gateway":"198.51.100.1","weight":1,"healthCheck":"8.8.8.8"}]}`
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/multiwan/apply", body); r.StatusCode != http.StatusConflict {
		t.Fatalf("multiwan without gateway: got %d, want 409", r.StatusCode)
	}
	// Enable gateway, then multi-WAN applies.
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/gateway", gwBody); r.StatusCode != http.StatusOK {
		t.Fatalf("gateway config: got %d", r.StatusCode)
	}
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/multiwan/apply", body); r.StatusCode != http.StatusOK {
		t.Fatalf("multiwan apply: got %d", r.StatusCode)
	}
	spec, err := os.ReadFile(filepath.Join(filepath.Dir(a.store.path), stagedWANName))
	if err != nil || !strings.Contains(string(spec), "wan1 enp1s0 192.0.2.1 2") {
		t.Fatalf("staged spec wrong: %v %s", err, spec)
	}
	if cfg := a.getWAN(); !cfg.Enabled || len(cfg.Uplinks) != 2 {
		t.Fatalf("state wrong: %+v", cfg)
	}
}
