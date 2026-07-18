package mail

import (
	"testing"
	"time"
)

func TestAggregatorFirstSendsThenSuppresses(t *testing.T) {
	a := NewAggregator(10 * time.Minute)
	now := time.Now()
	if !a.Offer("k1", "m1", now) {
		t.Fatal("first occurrence must send immediately")
	}
	if a.Offer("k1", "m2", now.Add(time.Minute)) {
		t.Fatal("duplicate within window must be suppressed")
	}
	if !a.Offer("k2", "other", now) {
		t.Fatal("distinct key must send immediately")
	}
}

func TestAggregatorFlushSummarizes(t *testing.T) {
	a := NewAggregator(10 * time.Minute)
	now := time.Now()
	a.Offer("k1", "first", now)
	a.Offer("k1", "second", now.Add(time.Minute))
	a.Offer("k1", "third", now.Add(2*time.Minute))
	if s := a.Flush(now.Add(5 * time.Minute)); len(s) != 0 {
		t.Fatal("window not expired yet — nothing to flush")
	}
	sums := a.Flush(now.Add(11 * time.Minute))
	if len(sums) != 1 || sums[0].Count != 2 || sums[0].Last != "third" {
		t.Fatalf("summary wrong: %+v", sums)
	}
	// After the flush the key is fresh again.
	if !a.Offer("k1", "again", now.Add(12*time.Minute)) {
		t.Fatal("after flush the next occurrence must send immediately")
	}
}

func TestAggregatorSilentExpiryWithoutDuplicates(t *testing.T) {
	a := NewAggregator(10 * time.Minute)
	now := time.Now()
	a.Offer("k1", "only one", now)
	if sums := a.Flush(now.Add(11 * time.Minute)); len(sums) != 0 {
		t.Fatalf("no duplicates — no summary expected, got %+v", sums)
	}
}
