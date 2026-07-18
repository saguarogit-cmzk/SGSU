package mail

import (
	"sync"
	"time"
)

// Aggregator implements the SNA alerting rule: the first event of a kind is
// sent immediately; identical events within the window are counted silently;
// when the window expires a summary ("N repeats") is emitted.
type Aggregator struct {
	mu     sync.Mutex
	window time.Duration
	seen   map[string]*aggState
}

type aggState struct {
	firstSent  time.Time
	suppressed int
	last       string // most recent message text for the summary
}

// Summary describes suppressed duplicates for one key after its window closed.
type Summary struct {
	Key   string
	Count int
	Last  string
}

func NewAggregator(window time.Duration) *Aggregator {
	if window <= 0 {
		window = 10 * time.Minute
	}
	return &Aggregator{window: window, seen: map[string]*aggState{}}
}

// Offer registers an event occurrence. sendNow is true only for the first
// occurrence of the key within its window.
func (a *Aggregator) Offer(key, message string, now time.Time) (sendNow bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	st, ok := a.seen[key]
	if !ok || now.Sub(st.firstSent) > a.window {
		// New key, or previous window already flushed/expired: alert now.
		a.seen[key] = &aggState{firstSent: now}
		return true
	}
	st.suppressed++
	st.last = message
	return false
}

// Flush returns summaries for keys whose window has expired, and forgets
// them. Keys with no suppressed duplicates expire silently.
func (a *Aggregator) Flush(now time.Time) []Summary {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []Summary
	for key, st := range a.seen {
		if now.Sub(st.firstSent) < a.window {
			continue
		}
		if st.suppressed > 0 {
			out = append(out, Summary{Key: key, Count: st.suppressed, Last: st.last})
		}
		delete(a.seen, key)
	}
	return out
}
