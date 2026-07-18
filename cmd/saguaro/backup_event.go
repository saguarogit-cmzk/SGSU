package main

import (
	"time"

	evstore "saguaro.local/network-manager/internal/events"
)

// backupDrillEvent builds the Warning event emitted when the restore drill
// is overdue (W11).
func backupDrillEvent(msg string) evstore.Event {
	return evstore.Event{
		TS:       time.Now().UTC(),
		Module:   "backup",
		Severity: "warning",
		Action:   "restore-drill-overdue",
		Result:   "reminder",
		Message:  msg,
	}
}
