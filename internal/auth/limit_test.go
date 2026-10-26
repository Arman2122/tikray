package auth

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// addr is the nth address of a test: 10.0.<n/256>.<n%256>.
func addr(n int) netip.Addr {
	return netip.AddrFrom4([4]byte{10, 0, byte(n / 256), byte(n % 256)})
}

// ipCount is the number of per-IP buckets the limiter holds.
func ipCount(l *Limiter) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.ips)
}

// TestRateLimitBeforeHashing is the limiter as a whole: the bucket of one IP,
// the forms of an address, the global bucket, the buckets that go idle and the
// memory that a flood can't grow. None of it runs a hash: it is what is asked
// before one.
func TestRateLimitBeforeHashing(t *testing.T) {
	t.Run("per IP", testRateLimitPerIP)
	t.Run("forms of an address", testRateLimitIPForms)
	t.Run("global", testRateLimitGlobal)
	t.Run("idle buckets are dropped", testRateLimitIdleDropped)
	t.Run("memory is bounded", testRateLimitMemoryBounded)
}

func testRateLimitPerIP(t *testing.T) {
	clk := newClock()
	l := NewLimiter(clk.Now)
	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")

	// The limiter is the thing that answers before any hash: it never runs
	// one.
	var runs atomic.Int32
	argonHook = func() { runs.Add(1) }
	t.Cleanup(func() { argonHook = nil })

	// A fresh IP is allowed, and asking costs it nothing.
	for range 20 {
		if ok, retry := l.Allow(a); !ok || retry != 0 {
			t.Fatalf("Allow of a fresh IP = (%v, %v), want (true, 0)", ok, retry)
		}
	}
	if n := ipCount(l); n != 0 {
		t.Errorf("asking made %d buckets, want none", n)
	}

	// Four failures leave a token; the fifth takes the last.
	for i := range 4 {
		l.Fail(a)
		if ok, _ := l.Allow(a); !ok {
			t.Fatalf("Allow is false after %d failures, want true until 5", i+1)
		}
	}
	l.Fail(a)
	ok, retry := l.Allow(a)
	if ok {
		t.Fatal("Allow is true after 5 failures")
	}
	if retry != 60*time.Second {
		t.Errorf("the retry after 5 failures is %v, want 60s", retry)
	}
	// Another IP is not affected.
	if ok, _ := l.Allow(b); !ok {
		t.Error("the failures of one IP closed another")
	}

	// The bucket refills 1 per 60 s: the retry counts down, and at 60 s one
	// try is allowed.
	clk.Advance(20 * time.Second)
	if ok, retry := l.Allow(a); ok || retry != 40*time.Second {
		t.Errorf("20 s on: Allow = (%v, %v), want (false, 40s)", ok, retry)
	}
	clk.Advance(40*time.Second - time.Nanosecond)
	if ok, retry := l.Allow(a); ok || retry != time.Nanosecond {
		t.Errorf("a nanosecond short of 60 s: Allow = (%v, %v), want (false, 1ns)", ok, retry)
	}
	clk.Advance(time.Nanosecond)
	if ok, retry := l.Allow(a); !ok || retry != 0 {
		t.Errorf("60 s on: Allow = (%v, %v), want (true, 0)", ok, retry)
	}
	// That one try fails too, and the next wait is a full 60 s again.
	l.Fail(a)
	if ok, retry := l.Allow(a); ok || retry != 60*time.Second {
		t.Errorf("after the refilled try failed: Allow = (%v, %v), want (false, 60s)", ok, retry)
	}

	// The bucket holds 5 and no more: after 5 minutes of quiet there are five
	// tries, not six, and not more for having waited longer.
	clk.Advance(24 * time.Hour)
	for i := range 5 {
		if ok, _ := l.Allow(a); !ok {
			t.Fatalf("try %d after a long quiet is refused", i+1)
		}
		l.Fail(a)
	}
	if ok, _ := l.Allow(a); ok {
		t.Error("a sixth try after a long quiet is allowed: the bucket holds more than 5")
	}

	// Failures that go on after the bucket is empty cost no more than that:
	// they don't stretch the wait past one refill.
	for range 50 {
		l.Fail(a)
	}
	if ok, retry := l.Allow(a); ok || retry != 60*time.Second {
		t.Errorf("after 50 more failures: Allow = (%v, %v), want (false, 60s)", ok, retry)
	}
	clk.Advance(60 * time.Second)
	if ok, _ := l.Allow(a); !ok {
		t.Error("the wait grew with the failures that came after the bucket was empty")
	}

	if n := runs.Load(); n != 0 {
		t.Errorf("the limiter ran argon2 %d times, want 0", n)
	}
}

func testRateLimitIPForms(t *testing.T) {
	clk := newClock()
	l := NewLimiter(clk.Now)
	v4 := netip.MustParseAddr("192.0.2.7")
	mapped := netip.MustParseAddr("::ffff:192.0.2.7")
	zoned := netip.MustParseAddr("fe80::1%eth0")
	plain := netip.MustParseAddr("fe80::1")

	// An IPv4 address and its IPv4-mapped form are one client.
	for range 3 {
		l.Fail(v4)
	}
	for range 2 {
		l.Fail(mapped)
	}
	if ok, _ := l.Allow(v4); ok {
		t.Error("five failures from an address and its mapped form do not close it")
	}
	if ok, _ := l.Allow(mapped); ok {
		t.Error("five failures from an address and its mapped form do not close the mapped form")
	}
	// A zone is not another client.
	for range 5 {
		l.Fail(zoned)
	}
	if ok, _ := l.Allow(plain); ok {
		t.Error("an address with a zone is another client than the same without it")
	}
	if n := ipCount(l); n != 2 {
		t.Errorf("%d buckets for two clients", n)
	}
}

func testRateLimitGlobal(t *testing.T) {
	clk := newClock()
	l := NewLimiter(clk.Now)

	// 100 failures, each from an IP of its own (so no per-IP bucket is empty),
	// empty the global bucket.
	for i := range 99 {
		l.Fail(addr(i))
	}
	if ok, _ := l.Allow(addr(1000)); !ok {
		t.Fatal("99 failures closed the global bucket")
	}
	l.Fail(addr(99))
	ok, retry := l.Allow(addr(1000))
	if ok {
		t.Fatal("100 failures did not close the global bucket")
	}
	if retry != 9*time.Second {
		t.Errorf("the global retry is %v, want 9s", retry)
	}
	// An IP that never failed is closed too; so is every other.
	if ok, _ := l.Allow(addr(5)); ok {
		t.Error("the global bucket is empty and an IP is allowed")
	}

	// Refilling 1 per 9 s.
	clk.Advance(8 * time.Second)
	if ok, retry := l.Allow(addr(1000)); ok || retry != time.Second {
		t.Errorf("8 s on: Allow = (%v, %v), want (false, 1s)", ok, retry)
	}
	clk.Advance(time.Second)
	if ok, _ := l.Allow(addr(1000)); !ok {
		t.Error("9 s on, the global bucket has no token")
	}
	l.Fail(addr(1000))
	if ok, retry := l.Allow(addr(1001)); ok || retry != 9*time.Second {
		t.Errorf("after that try failed: Allow = (%v, %v), want (false, 9s)", ok, retry)
	}

	// The wait is the longer of the two buckets: an IP with its own bucket
	// empty (60 s) waits for that, though the global one is back.
	clk.Advance(9 * time.Second)
	for range 5 {
		l.Fail(addr(2000))
	}
	// The five failures emptied the global bucket again as well (9 s).
	if ok, retry := l.Allow(addr(2000)); ok || retry != 60*time.Second {
		t.Errorf("an IP with an empty bucket: Allow = (%v, %v), want (false, 60s)", ok, retry)
	}

	// The global bucket holds 100, and no more, after a long quiet.
	clk.Advance(48 * time.Hour)
	for i := range 100 {
		if ok, _ := l.Allow(addr(3000 + i)); !ok {
			t.Fatalf("failure %d after a long quiet: the global bucket is not full", i)
		}
		l.Fail(addr(3000 + i))
	}
	if ok, _ := l.Allow(addr(4000)); ok {
		t.Error("the global bucket holds more than 100")
	}
}

func testRateLimitIdleDropped(t *testing.T) {
	clk := newClock()
	l := NewLimiter(clk.Now)
	for i := range 3 {
		l.Fail(addr(i))
	}
	if n := ipCount(l); n != 3 {
		t.Fatalf("%d buckets after 3 failures from 3 IPs", n)
	}

	// An IP is kept while it has been seen in the last hour. The failure of
	// IP 0 half an hour on is a sign of life.
	clk.Advance(30 * time.Minute)
	l.Fail(addr(0))
	clk.Advance(29 * time.Minute)
	l.Allow(addr(9))
	if n := ipCount(l); n != 3 {
		t.Errorf("%d buckets 59 min on, want 3: nothing is idle for an hour yet", n)
	}

	// An hour of quiet drops the bucket of IP 1 and 2, not that of IP 0. The
	// buckets go on the next call after a minute's sweep, whichever it is.
	clk.Advance(2 * time.Minute)
	l.Allow(addr(9))
	if n := ipCount(l); n != 1 {
		t.Errorf("%d buckets 61 min on, want 1 (the one that failed 31 min ago)", n)
	}
	clk.Advance(time.Hour)
	l.Fail(addr(10))
	if n := ipCount(l); n != 1 {
		t.Errorf("%d buckets after another hour, want 1 (the new one)", n)
	}
	// A bucket that went was a full one, so the IP has all its tries again.
	for range 4 {
		l.Fail(addr(1))
	}
	if ok, _ := l.Allow(addr(1)); !ok {
		t.Error("an IP that came back after its bucket was dropped has fewer than 5 tries")
	}
	l.Fail(addr(1))
	if ok, _ := l.Allow(addr(1)); ok {
		t.Error("an IP that came back after its bucket was dropped has more than 5 tries")
	}
}

func testRateLimitMemoryBounded(t *testing.T) {
	clk := newClock()
	l := NewLimiter(clk.Now)

	// Only a failure that the limiter would have let in makes a bucket: with
	// the global bucket empty, a flood from ever new addresses (a caller that
	// goes on telling it of failures it had refused, say) adds none.
	for i := range 100 {
		l.Fail(addr(i))
	}
	if n := ipCount(l); n != 100 {
		t.Fatalf("%d buckets after 100 failures from 100 IPs", n)
	}
	for i := 100; i < 5000; i++ {
		l.Fail(addr(i))
	}
	if n := ipCount(l); n != 100 {
		t.Errorf("%d buckets after a flood with the global bucket empty, want 100", n)
	}
	// An IP that has a bucket keeps being counted.
	l.Fail(addr(0))
	if n := ipCount(l); n != 100 {
		t.Errorf("%d buckets, want 100", n)
	}
}

func TestLimiterConcurrentUse(t *testing.T) {
	l := NewLimiter(nil) // the real clock
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 200 {
				ip := addr(g*1000 + i%7)
				l.Allow(ip)
				if i%3 == 0 {
					l.Fail(ip)
				}
			}
		}()
	}
	wg.Wait()
	if n := ipCount(l); n == 0 || n > 8*7 {
		t.Errorf("%d buckets after the run, want between 1 and 56", n)
	}
}
