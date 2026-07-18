package main

import (
	"sync"
	"time"
)

// loginLimiter tracks failed login attempts per key (client IP or username)
// and enforces an exponential lockout: the first freeAttempts failures are
// free, then each further failure locks the key for base*2^n up to cap.
// State is in-memory by design — a restart clears it, which only helps a
// legitimate admin, while an attacker still faces the network round-trips.
type loginLimiter struct {
	mu           sync.Mutex
	entries      map[string]*limiterEntry
	freeAttempts int
	base         time.Duration
	cap          time.Duration
}

type limiterEntry struct {
	failures    int
	lockedUntil time.Time
	lastSeen    time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{
		entries:      map[string]*limiterEntry{},
		freeAttempts: 5,
		base:         30 * time.Second,
		cap:          15 * time.Minute,
	}
}

// check reports whether the key is currently locked and for how much longer.
func (l *loginLimiter) check(key string, now time.Time) (locked bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok || now.After(e.lockedUntil) {
		return false, 0
	}
	return true, e.lockedUntil.Sub(now)
}

// fail records a failed attempt and returns the lock duration this failure
// triggered (0 while still within the free attempts).
func (l *loginLimiter) fail(key string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok {
		e = &limiterEntry{}
		l.entries[key] = e
	}
	e.failures++
	e.lastSeen = now
	over := e.failures - l.freeAttempts
	if over <= 0 {
		return 0
	}
	d := l.base
	for i := 1; i < over && d < l.cap; i++ {
		d *= 2
	}
	if d > l.cap {
		d = l.cap
	}
	e.lockedUntil = now.Add(d)
	return d
}

// success clears the key after a valid login.
func (l *loginLimiter) success(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// prune drops entries idle longer than the maximum lockout, so the map cannot
// grow without bound from address-spoofed noise.
func (l *loginLimiter) prune(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for key, e := range l.entries {
		if now.Sub(e.lastSeen) > l.cap && now.After(e.lockedUntil) {
			delete(l.entries, key)
		}
	}
}
