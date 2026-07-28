package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	mailmod "saguaro.local/network-manager/internal/mail"
)

// backupValueRe is the safe charset for values written into backup.env, which
// the root backup service sources. It excludes every shell-active character
// ($ ` ; & | ( ) space quotes newline) so a value can never inject a command.
var backupValueRe = regexp.MustCompile(`^[A-Za-z0-9._:/@=+-]*$`)

func safeBackupValue(fields map[string]string) (string, bool) {
	for name, v := range fields {
		if !backupValueRe.MatchString(v) {
			return name, false
		}
	}
	return "", true
}

const (
	stagedBackupEnvName   = "staged-backup.env"
	stagedBackupSchedName = "staged-backup.schedule"
	restoreDrillDays      = 90
)

// backupConfig is persisted in state.json. Secrets (SFTP key/password, S3
// secret key) are sealed with the appliance secret key.
type backupConfig struct {
	Target        string `json:"target"` // local | sftp | s3
	Schedule      string `json:"schedule"`
	RetentionDays int    `json:"retentionDays"`
	// SFTP
	SFTPHost string `json:"sftpHost,omitempty"`
	SFTPPort int    `json:"sftpPort,omitempty"`
	SFTPUser string `json:"sftpUser,omitempty"`
	SFTPPath string `json:"sftpPath,omitempty"`
	// S3
	S3Bucket   string `json:"s3Bucket,omitempty"`
	S3Endpoint string `json:"s3Endpoint,omitempty"`
	S3Region   string `json:"s3Region,omitempty"`
	S3AccessID string `json:"s3AccessId,omitempty"`
	// sealed secret (SFTP password OR S3 secret key, depending on target)
	SecretEnc string    `json:"secretEnc,omitempty"`
	LastDrill time.Time `json:"lastDrill,omitempty"`
	// ScheduleOff is true when the scheduled-backup timer has been turned off via
	// the disable action. Apply re-enables it (sets this back to false); on-demand
	// "run" still works regardless.
	ScheduleOff bool `json:"scheduleOff,omitempty"`
}

func defaultRunBackupCfg(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	full := append([]string{"-n", "/usr/sbin/saguaro-backup-config"}, args...)
	return exec.CommandContext(ctx, "sudo", full...).CombinedOutput()
}

func (a *app) getBackup() backupConfig {
	a.store.mu.RLock()
	defer a.store.mu.RUnlock()
	if a.store.data.Backup == nil {
		return backupConfig{Target: "local", Schedule: "daily", RetentionDays: 30}
	}
	return *a.store.data.Backup
}

func (a *app) setBackup(cfg backupConfig) error {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	a.store.data.Backup = &cfg
	return a.store.saveLocked()
}

func backupView(cfg backupConfig) map[string]any {
	drillDue := cfg.LastDrill.IsZero() || time.Since(cfg.LastDrill) > restoreDrillDays*24*time.Hour
	return map[string]any{
		"target": cfg.Target, "schedule": cfg.Schedule, "retentionDays": cfg.RetentionDays,
		"sftpHost": cfg.SFTPHost, "sftpPort": cfg.SFTPPort, "sftpUser": cfg.SFTPUser, "sftpPath": cfg.SFTPPath,
		"s3Bucket": cfg.S3Bucket, "s3Endpoint": cfg.S3Endpoint, "s3Region": cfg.S3Region, "s3AccessId": cfg.S3AccessID,
		"hasSecret": cfg.SecretEnc != "",
		"lastDrill": cfg.LastDrill, "restoreDrillDue": drillDue, "restoreDrillDays": restoreDrillDays,
		"scheduleOff": cfg.ScheduleOff,
	}
}

func (a *app) apiBackupGet(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, backupView(a.getBackup()))
}

// buildBackupEnv renders the /etc/saguaro/backup.env the backup script reads.
func (a *app) buildBackupEnv(cfg backupConfig) (string, error) {
	var b strings.Builder
	b.WriteString("# Managed by Saguaro (generated).\n")
	fmt.Fprintf(&b, "SAGUARO_BACKUP_TARGET=%s\n", cfg.Target)
	fmt.Fprintf(&b, "SAGUARO_BACKUP_RETENTION_DAYS=%d\n", cfg.RetentionDays)
	secret := ""
	if cfg.SecretEnc != "" {
		if a.mailKey == nil {
			return "", fmt.Errorf("secret key unavailable; cannot unseal the backup secret")
		}
		var err error
		if secret, err = mailmod.Decrypt(a.mailKey, cfg.SecretEnc); err != nil {
			return "", fmt.Errorf("cannot unseal backup secret: %w", err)
		}
	}
	switch cfg.Target {
	case "sftp":
		port := cfg.SFTPPort
		if port == 0 {
			port = 22
		}
		fmt.Fprintf(&b, "SAGUARO_SFTP_HOST=%s\n", cfg.SFTPHost)
		fmt.Fprintf(&b, "SAGUARO_SFTP_PORT=%d\n", port)
		fmt.Fprintf(&b, "SAGUARO_SFTP_USER=%s\n", cfg.SFTPUser)
		fmt.Fprintf(&b, "SAGUARO_SFTP_PATH=%s\n", cfg.SFTPPath)
		// SFTP uses a deployed key file path; the sealed secret is that path.
		if secret != "" {
			fmt.Fprintf(&b, "SAGUARO_SFTP_KEY=%s\n", secret)
		}
	case "s3":
		fmt.Fprintf(&b, "SAGUARO_S3_BUCKET=%s\n", cfg.S3Bucket)
		if cfg.S3Endpoint != "" {
			fmt.Fprintf(&b, "SAGUARO_S3_ENDPOINT=%s\n", cfg.S3Endpoint)
		}
		fmt.Fprintf(&b, "SAGUARO_S3_REGION=%s\n", cfg.S3Region)
		fmt.Fprintf(&b, "SAGUARO_S3_ACCESS_KEY=%s\n", cfg.S3AccessID)
		fmt.Fprintf(&b, "SAGUARO_S3_SECRET_KEY=%s\n", secret)
	}
	return b.String(), nil
}

func validBackupSchedule(s string) bool {
	// Accept a small allowlist plus systemd OnCalendar-ish tokens.
	switch s {
	case "hourly", "daily", "weekly", "monthly":
		return true
	}
	return !strings.ContainsAny(s, "\n\r;&|$`")
}

func (a *app) apiBackupApply(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Target        string `json:"target"`
		Schedule      string `json:"schedule"`
		RetentionDays int    `json:"retentionDays"`
		SFTPHost      string `json:"sftpHost"`
		SFTPPort      int    `json:"sftpPort"`
		SFTPUser      string `json:"sftpUser"`
		SFTPPath      string `json:"sftpPath"`
		SFTPKeyPath   string `json:"sftpKeyPath"`
		S3Bucket      string `json:"s3Bucket"`
		S3Endpoint    string `json:"s3Endpoint"`
		S3Region      string `json:"s3Region"`
		S3AccessID    string `json:"s3AccessId"`
		S3Secret      string `json:"s3Secret"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	switch in.Target {
	case "local", "sftp", "s3":
	default:
		writeError(w, http.StatusBadRequest, "target must be local, sftp or s3")
		return
	}
	if in.RetentionDays < 1 {
		in.RetentionDays = 30
	}
	if in.Schedule == "" {
		in.Schedule = "daily"
	}
	if !validBackupSchedule(in.Schedule) {
		writeError(w, http.StatusBadRequest, "invalid schedule")
		return
	}
	// backup.env is sourced by the root backup service; every value must be
	// free of shell-active characters (defense in depth — the root adapter
	// re-validates too).
	if bad, ok := safeBackupValue(map[string]string{
		"sftpHost": in.SFTPHost, "sftpUser": in.SFTPUser, "sftpPath": in.SFTPPath, "sftpKeyPath": in.SFTPKeyPath,
		"s3Bucket": in.S3Bucket, "s3Endpoint": in.S3Endpoint, "s3Region": in.S3Region, "s3AccessId": in.S3AccessID,
		"s3Secret": in.S3Secret,
	}); !ok {
		writeError(w, http.StatusBadRequest, "field "+bad+" contains characters not allowed in a backup target")
		return
	}
	cfg := a.getBackup()
	cfg.Target, cfg.Schedule, cfg.RetentionDays = in.Target, in.Schedule, in.RetentionDays
	cfg.SFTPHost, cfg.SFTPPort, cfg.SFTPUser, cfg.SFTPPath = in.SFTPHost, in.SFTPPort, in.SFTPUser, in.SFTPPath
	cfg.S3Bucket, cfg.S3Endpoint, cfg.S3Region, cfg.S3AccessID = in.S3Bucket, in.S3Endpoint, in.S3Region, in.S3AccessID
	cfg.ScheduleOff = false // apply (re)installs and enables the timer

	// Off-site targets must be encrypted in transit AND require a secret; the
	// archives themselves are already age-encrypted (mandatory).
	newSecret := ""
	switch in.Target {
	case "sftp":
		if in.SFTPHost == "" || in.SFTPUser == "" || in.SFTPPath == "" {
			writeError(w, http.StatusBadRequest, "SFTP target requires host, user and path")
			return
		}
		newSecret = strings.TrimSpace(in.SFTPKeyPath)
	case "s3":
		if in.S3Bucket == "" || in.S3AccessID == "" {
			writeError(w, http.StatusBadRequest, "S3 target requires bucket and access key")
			return
		}
		newSecret = in.S3Secret
	}
	if newSecret != "" {
		if a.mailKey == nil {
			writeError(w, http.StatusInternalServerError, "secret key unavailable; cannot store the backup secret")
			return
		}
		enc, err := mailmod.Encrypt(a.mailKey, newSecret)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "cannot seal backup secret")
			return
		}
		cfg.SecretEnc = enc
	}
	if in.Target == "local" {
		cfg.SecretEnc = ""
	}

	envText, err := a.buildBackupEnv(cfg)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	dir := filepath.Dir(a.store.path)
	if err := os.WriteFile(filepath.Join(dir, stagedBackupEnvName), []byte(envText), 0600); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot write staged backup env")
		return
	}
	if err := os.WriteFile(filepath.Join(dir, stagedBackupSchedName), []byte(cfg.Schedule+"\n"), 0644); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot write staged schedule")
		return
	}
	if out, err := a.runBackupCfg(r.Context(), "apply"); err != nil {
		writeError(w, http.StatusBadGateway, "apply failed: "+truncate(string(out), 300))
		return
	}
	if err := a.setBackup(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist backup configuration")
		return
	}
	a.record(r, a.actor(r), "backup-config", cfg.Target, "success",
		map[string]any{"schedule": cfg.Schedule, "retentionDays": cfg.RetentionDays})
	writeJSON(w, http.StatusOK, backupView(cfg))
}

func (a *app) apiBackupRunNow(w http.ResponseWriter, r *http.Request) {
	if out, err := a.runBackupCfg(r.Context(), "run"); err != nil {
		writeError(w, http.StatusBadGateway, "backup run failed: "+truncate(string(out), 300))
		return
	}
	a.record(r, a.actor(r), "backup-run", "on-demand", "success", nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// apiBackupDisable stops the scheduled-backup timer. The backup env stays in
// place and on-demand "run" still works; re-enable by applying the config again.
func (a *app) apiBackupDisable(w http.ResponseWriter, r *http.Request) {
	if out, err := a.runBackupCfg(r.Context(), "disable"); err != nil {
		writeError(w, http.StatusBadGateway, "disable failed: "+truncate(string(out), 300))
		return
	}
	cfg := a.getBackup()
	cfg.ScheduleOff = true
	if err := a.setBackup(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist backup configuration")
		return
	}
	a.record(r, a.actor(r), "backup-disable", "schedule", "success", nil)
	writeJSON(w, http.StatusOK, backupView(cfg))
}

var backupFileRe = regexp.MustCompile(`^saguaro-[A-Za-z0-9._-]+\.(age|sha256)$`)

// apiBackupFiles lists the local backup artifacts (name, size, time) via the
// adapter, so the operator can download a copy off-box.
func (a *app) apiBackupFiles(w http.ResponseWriter, r *http.Request) {
	out, err := a.runBackupCfg(r.Context(), "list")
	files := []map[string]any{}
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			parts := strings.Split(line, "\t")
			if len(parts) != 3 {
				continue
			}
			size, _ := strconv.ParseInt(parts[1], 10, 64)
			epoch, _ := strconv.ParseInt(parts[2], 10, 64)
			files = append(files, map[string]any{
				"name": parts[0], "size": size,
				"time": time.Unix(epoch, 0).UTC().Format(time.RFC3339),
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"files": files})
}

// apiBackupDownload streams one local backup artifact for download. The archives
// are age-encrypted, so only ciphertext leaves the box; the filename is strictly
// validated (charset + fixed dir in the adapter) to block path traversal.
func (a *app) apiBackupDownload(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !backupFileRe.MatchString(name) {
		writeError(w, http.StatusBadRequest, "invalid backup filename")
		return
	}
	out, err := a.runBackupCfg(r.Context(), "get", name)
	if err != nil {
		writeError(w, http.StatusNotFound, "backup not found: "+truncate(string(out), 200))
		return
	}
	a.record(r, a.actor(r), "backup-download", name, "success", map[string]any{"bytes": len(out)})
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+name+"\"")
	w.Header().Set("Content-Length", strconv.Itoa(len(out)))
	_, _ = w.Write(out)
}

// apiBackupMarkDrill records that a restore drill was performed, clearing the
// 90-day reminder.
func (a *app) apiBackupMarkDrill(w http.ResponseWriter, r *http.Request) {
	cfg := a.getBackup()
	cfg.LastDrill = time.Now().UTC()
	if err := a.setBackup(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist backup configuration")
		return
	}
	a.record(r, a.actor(r), "backup-restore-drill", "verified", "success", nil)
	writeJSON(w, http.StatusOK, backupView(cfg))
}

// checkRestoreDrill emits a Warning event when the restore drill is overdue;
// called from the daily health goroutine.
func (a *app) checkRestoreDrill() {
	if a.events == nil {
		return
	}
	cfg := a.getBackup()
	if !cfg.LastDrill.IsZero() && time.Since(cfg.LastDrill) <= restoreDrillDays*24*time.Hour {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	msg := "restore drill overdue: verify a backup can be restored (last never)"
	if !cfg.LastDrill.IsZero() {
		msg = fmt.Sprintf("restore drill overdue: last performed %s", cfg.LastDrill.Format("2006-01-02"))
	}
	_ = a.events.Insert(ctx, backupDrillEvent(msg))
}
