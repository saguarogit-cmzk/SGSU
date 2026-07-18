package main

import (
	"testing"
	"time"
)

func TestLimiterFreeAttemptsThenLock(t *testing.T) {
	l := newLoginLimiter()
	now := time.Now()
	for i := 1; i <= 5; i++ {
		if d := l.fail("k", now); d != 0 {
			t.Fatalf("attempt %d should be free, got lock %v", i, d)
		}
	}
	if d := l.fail("k", now); d != 30*time.Second {
		t.Fatalf("6th failure should lock 30s, got %v", d)
	}
	locked, retry := l.check("k", now)
	if !locked || retry <= 0 {
		t.Fatalf("expected locked with positive retry, got %v %v", locked, retry)
	}
}

func TestLimiterExponentialGrowthAndCap(t *testing.T) {
	l := newLoginLimiter()
	now := time.Now()
	var last time.Duration
	for i := 1; i <= 20; i++ {
		last = l.fail("k", now)
	}
	if last != 15*time.Minute {
		t.Fatalf("lock should cap at 15m, got %v", last)
	}
	l2 := newLoginLimiter()
	for i := 1; i <= 6; i++ {
		l2.fail("k", now)
	}
	if d := l2.fail("k", now); d != 60*time.Second {
		t.Fatalf("7th failure should lock 60s, got %v", d)
	}
}

func TestLimiterUnlockAfterExpiryAndSuccessReset(t *testing.T) {
	l := newLoginLimiter()
	now := time.Now()
	for i := 1; i <= 6; i++ {
		l.fail("k", now)
	}
	if locked, _ := l.check("k", now.Add(31*time.Second)); locked {
		t.Fatal("lock should expire after its duration")
	}
	l.success("k")
	if d := l.fail("k", now); d != 0 {
		t.Fatalf("failure count should reset after success, got lock %v", d)
	}
}

func TestLimiterPrune(t *testing.T) {
	l := newLoginLimiter()
	now := time.Now()
	l.fail("stale", now)
	l.fail("fresh", now.Add(20*time.Minute))
	l.prune(now.Add(20 * time.Minute))
	if _, ok := l.entries["stale"]; ok {
		t.Fatal("stale entry should be pruned")
	}
	if _, ok := l.entries["fresh"]; !ok {
		t.Fatal("fresh entry should survive prune")
	}
}
