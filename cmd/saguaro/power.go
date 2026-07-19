package main

import (
	"context"
	"net/http"
	"os/exec"
	"time"
)

func defaultRunPower(ctx context.Context, action string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "sudo", "-n", "/usr/sbin/saguaro-power", action).CombinedOutput()
}

// apiSystemPower reboots or powers off the appliance. It is admin-only
// (permPower) and audited as a security event BEFORE the adapter runs, because
// once the system starts shutting down the response and any later write may not
// complete.
func (a *app) apiSystemPower(w http.ResponseWriter, r *http.Request) {
	action := r.PathValue("action")
	if action != "reboot" && action != "poweroff" {
		writeError(w, http.StatusNotFound, "action must be reboot or poweroff")
		return
	}
	a.recordSev(r, a.actor(r), "system-power", action, "success", "security", map[string]any{"action": action})
	if out, err := a.runPower(r.Context(), action); err != nil {
		a.recordSev(r, a.actor(r), "system-power", action, "failed", "security",
			map[string]any{"output": truncate(string(out), 200)})
		writeError(w, http.StatusBadGateway, action+" failed: "+truncate(string(out), 200))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "action": action,
		"message": "device is " + map[string]string{"reboot": "rebooting", "poweroff": "powering off"}[action]})
}
