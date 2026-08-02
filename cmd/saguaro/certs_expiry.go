package main

import (
	"context"
	"fmt"
	"time"

	evstore "saguaro.local/network-manager/internal/events"
)

// An expired certificate takes the GUI, a reverse-proxied application or a VPN
// down without warning, and until now the expiry date was only visible to
// whoever opened the certificate list. Renewal is automated, but automation
// fails quietly (a DNS-01 challenge that stopped resolving, a timer that never
// ran), so the appliance now says so before the certificate dies rather than
// after.
const (
	// certWarnDays is when a certificate starts being reported as expiring.
	// Let's Encrypt renews at 30 days left, so a warning at 21 means "the
	// automation has already had time to act and did not".
	certWarnDays = 21
	// certCriticalDays escalates the same finding as it gets close.
	certCriticalDays = 7
)

func certExpiryEvent(severity, msg string) evstore.Event {
	return evstore.Event{
		TS:       time.Now().UTC(),
		Module:   "certs",
		Severity: severity,
		Action:   "certificate-expiring",
		Result:   "reminder",
		Message:  msg,
	}
}

// certExpiryReport returns one line per certificate that is expiring or already
// expired, most urgent first. Certificates whose file cannot be read are
// skipped rather than guessed at.
type certExpiryItem struct {
	Name     string    `json:"name"`
	NotAfter time.Time `json:"notAfter"`
	DaysLeft int       `json:"daysLeft"`
	Severity string    `json:"severity"` // warning | critical
	Expired  bool      `json:"expired,omitempty"`
}

func (a *app) certExpiryReport() []certExpiryItem {
	var out []certExpiryItem
	for _, c := range a.getCerts() {
		exp := certExpiry(c.Name)
		if exp.IsZero() {
			continue
		}
		days := int(time.Until(exp).Hours() / 24)
		switch {
		case days < 0:
			out = append(out, certExpiryItem{Name: c.Name, NotAfter: exp, DaysLeft: days,
				Severity: "critical", Expired: true})
		case days <= certCriticalDays:
			out = append(out, certExpiryItem{Name: c.Name, NotAfter: exp, DaysLeft: days, Severity: "critical"})
		case days <= certWarnDays:
			out = append(out, certExpiryItem{Name: c.Name, NotAfter: exp, DaysLeft: days, Severity: "warning"})
		}
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].DaysLeft < out[j-1].DaysLeft; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// checkCertExpiry raises one event per expiring certificate. Called daily, so a
// certificate that stays unrenewed keeps reminding instead of warning once.
func (a *app) checkCertExpiry() {
	items := a.certExpiryReport()
	if len(items) == 0 || a.events == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, it := range items {
		msg := fmt.Sprintf("certifikat %q istječe za %d dana (%s)", it.Name, it.DaysLeft,
			it.NotAfter.Format("2006-01-02"))
		if it.Expired {
			msg = fmt.Sprintf("certifikat %q je ISTEKAO %s", it.Name, it.NotAfter.Format("2006-01-02"))
		}
		_ = a.events.Insert(ctx, certExpiryEvent(it.Severity, msg))
	}
}
