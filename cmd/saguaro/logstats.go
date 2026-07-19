package main

import (
	"context"
	"net/http"
	"os/exec"
	"time"

	"saguaro.local/network-manager/internal/logstats"
)

func defaultRunLogs(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	full := append([]string{"-n", "/usr/sbin/saguaro-logs"}, args...)
	return exec.CommandContext(ctx, "sudo", full...).CombinedOutput()
}

func (a *app) apiUnboundStats(w http.ResponseWriter, r *http.Request) {
	out, err := a.runLogs(r.Context(), "unbound-stats")
	if err != nil {
		writeJSON(w, http.StatusOK, logstats.UnboundStats{Available: false})
		return
	}
	writeJSON(w, http.StatusOK, logstats.ParseUnboundStats(out))
}

func (a *app) apiSuricataAlerts(w http.ResponseWriter, r *http.Request) {
	out, _ := a.runLogs(r.Context(), "suricata-alerts", "50")
	alerts := logstats.ParseSuricataAlerts(out, 50)
	if alerts == nil {
		alerts = []logstats.Alert{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"available": true, "alerts": alerts})
}
