// saguaro-eventd follows journald and writes structured events into the
// PostgreSQL events table (SNA layer 2 logging). journald itself remains the
// raw log; this collector stores notice-and-above (configurable) for the GUI,
// reports and mail alerting.
package main

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"saguaro.local/network-manager/internal/events"
)

const (
	batchSize  = 100
	flushEvery = 2 * time.Second
)

func envDefault(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	dsn := os.Getenv("SAGUARO_DB_DSN")
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "SAGUARO_DB_DSN is required: the event collector stores events in PostgreSQL")
		os.Exit(2)
	}
	minSev := envDefault("SAGUARO_EVENTD_MIN_SEVERITY", "notice")
	if !events.ValidSeverity(minSev) {
		fmt.Fprintf(os.Stderr, "invalid SAGUARO_EVENTD_MIN_SEVERITY %q\n", minSev)
		os.Exit(2)
	}
	minRank := events.Rank(minSev)
	retention, err := strconv.Atoi(envDefault("SAGUARO_EVENT_RETENTION_MONTHS", "6"))
	if err != nil || retention < 1 {
		retention = 6
	}
	units := events.DefaultUnits
	if v := os.Getenv("SAGUARO_EVENTD_UNITS"); v != "" {
		units = strings.Split(v, ",")
	}

	store, err := events.Open(dsn)
	if err != nil {
		log.Error("cannot open event store", "error", err)
		os.Exit(1)
	}
	defer store.Close()
	if err := store.EnsureSchema(context.Background()); err != nil {
		log.Error("cannot ensure event schema", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Daily housekeeping: pre-create next month's partition, drop expired ones.
	go func() {
		for {
			if err := store.EnsurePartitions(ctx, time.Now().UTC()); err != nil {
				log.Error("partition maintenance failed", "error", err)
			}
			if dropped, err := store.PruneOldPartitions(ctx, time.Now().UTC(), retention); err != nil {
				log.Error("partition retention failed", "error", err)
			} else if len(dropped) > 0 {
				log.Info("dropped expired event partitions", "partitions", dropped)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(24 * time.Hour):
			}
		}
	}()

	in := make(chan events.Event, 1024)
	go batcher(ctx, log, store, in)

	// Suricata eve.json alerts (W9): the tailer idles quietly until the
	// security module is enabled and the file appears.
	evePath := envDefault("SAGUARO_EVE_PATH", "/var/log/suricata/eve.json")
	go events.TailEve(ctx, evePath, 0, func(e events.Event) {
		if events.Rank(e.Severity) < minRank {
			return
		}
		select {
		case in <- e:
		default:
			log.Warn("event buffer full, dropping IDS event")
		}
	})

	log.Info("saguaro-eventd starting", "units", len(units), "minSeverity", minSev, "retentionMonths", retention)
	cursor := ""
	for ctx.Err() == nil {
		var err error
		cursor, err = follow(ctx, log, units, cursor, minRank, in)
		if ctx.Err() != nil {
			break
		}
		log.Error("journalctl stream ended; restarting", "error", err)
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
	}
	log.Info("saguaro-eventd stopping")
}

// follow runs one journalctl -f process and feeds parsed entries into the
// batcher. It returns the last seen cursor so a restart resumes without
// duplicates or gaps.
func follow(ctx context.Context, log *slog.Logger, units []string, cursor string, minRank int, in chan<- events.Event) (string, error) {
	args := []string{"-f", "-o", "json", "--no-pager"}
	if cursor != "" {
		args = append(args, "--after-cursor", cursor)
	} else {
		args = append(args, "--since", "now")
	}
	for _, u := range units {
		u = strings.TrimSpace(u)
		if u != "" {
			args = append(args, "-u", u)
		}
	}
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return cursor, err
	}
	if err := cmd.Start(); err != nil {
		return cursor, err
	}
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		e, c, ok := events.ParseJournalLine(sc.Bytes())
		if c != "" {
			cursor = c
		}
		if !ok || events.Rank(e.Severity) < minRank {
			continue
		}
		select {
		case in <- e:
		case <-ctx.Done():
			_ = cmd.Wait()
			return cursor, ctx.Err()
		default:
			// Channel full: drop rather than block the journal stream; the
			// raw record still exists in journald.
			log.Warn("event buffer full, dropping event", "module", e.Module)
		}
	}
	scanErr := sc.Err()
	waitErr := cmd.Wait()
	if scanErr != nil {
		return cursor, scanErr
	}
	return cursor, waitErr
}

// batcher groups events and writes them in transactions: a flush happens at
// batchSize events or after flushEvery, whichever comes first.
func batcher(ctx context.Context, log *slog.Logger, store *events.Store, in <-chan events.Event) {
	batch := make([]events.Event, 0, batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		wctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := store.InsertBatch(wctx, batch); err != nil {
			log.Error("event insert failed", "error", err, "count", len(batch))
		}
		cancel()
		batch = batch[:0]
	}
	t := time.NewTicker(flushEvery)
	defer t.Stop()
	for {
		select {
		case e := <-in:
			batch = append(batch, e)
			if len(batch) >= batchSize {
				flush()
			}
		case <-t.C:
			flush()
		case <-ctx.Done():
			flush()
			return
		}
	}
}
