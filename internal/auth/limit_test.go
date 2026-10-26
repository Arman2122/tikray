package auth

import (
	"net/netip"
	"sync"
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

// failOnce makes an attempt from ip that fails: it asks, and when it is let in
// it says the attempt failed. It returns what Allow said.
func failOnce(l *Limiter, ip netip.Addr) (bool, time.Duration) {
	done, ok, retry := l.Allow(ip)
	if ok {
		done(true)
	}
	return ok, retry
}

// mustFail is failOnce for an attempt that has to be let in.
func mustFail(t *testing.T, l *Limiter, ip netip.Addr) {
	t.Helper()
	if ok, retry := failOnce(l, ip); !ok {
		t.Fatalf("an attempt from %v that should be let in is refused for %v", ip, retry)
	}
}

// probe asks from ip and, when it is let in, says the attempt succeeded, which
// gives the tokens back. It shows what Allow says and changes nothing.
func probe(l *Limiter, ip netip.Addr) (bool, time.Duration) {
	done, ok, retry := l.Allow(ip)
	if ok {
		done(false)
	}
	return ok, retry
}

// together asks for n attempts at one moment, from n goroutines released
// together, the ith from ip(i). It returns the done of each that was let in,
// and the wait that each of the others was told.
func together(l *Limiter, n int, ip func(i int) netip.Addr) (dones []func(bool), refused []time.Duration) {
	var mu sync.Mutex
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			done, ok, retry := l.Allow(ip(i))
			mu.Lock()
			defer mu.Unlock()
			if ok {
				dones = append(dones, done)
			} else {
				refused = append(refused, retry)
			}
		}()
	}
	close(start)
	wg.Wait()
	return dones, refused
}

// TestRateLimitBeforeHashing is the limiter as a whole: the bucket of one IP,
// the forms of an address, the global bucket, the buckets that go idle and the
// memory that a flood can't grow. It is what is asked before a hash, and what
// answers 429 with no hash when a bucket is empty.
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

	// A fresh IP is let in. Attempts that all succeed cost it nothing, and
	// leave nothing behind.
	for range 20 {
		if ok, retry := probe(l, a); !ok || retry != 0 {
			t.Fatalf("Allow of a fresh IP = (%v, %v), want (true, 0)", ok, retry)
		}
	}
	if n := ipCount(l); n != 0 {
		t.Errorf("attempts that all succeeded left %d buckets, want none", n)
	}

	// Four failures leave a token; the fifth takes the last.
	for i := range 4 {
		mustFail(t, l, a)
		if ok, _ := probe(l, a); !ok {
			t.Fatalf("Allow is false after %d failures, want true until 5", i+1)
		}
	}
	mustFail(t, l, a)
	done, ok, retry := l.Allow(a)
	if ok || done != nil {
		t.Fatalf("Allow after 5 failures = (done %v, ok %v), want a refusal with no done", done != nil, ok)
	}
	if retry != 60*time.Second {
		t.Errorf("the retry after 5 failures is %v, want 60s", retry)
	}
	// Another IP is not affected.
	if ok, _ := probe(l, b); !ok {
		t.Error("the failures of one IP closed another")
	}

	// The bucket refills 1 per 60 s: the retry counts down, and at 60 s one
	// try is let in.
	clk.Advance(20 * time.Second)
	if ok, retry := probe(l, a); ok || retry != 40*time.Second {
		t.Errorf("20 s on: Allow = (%v, %v), want (false, 40s)", ok, retry)
	}
	clk.Advance(40*time.Second - time.Nanosecond)
	if ok, retry := probe(l, a); ok || retry != time.Nanosecond {
		t.Errorf("a nanosecond short of 60 s: Allow = (%v, %v), want (false, 1ns)", ok, retry)
	}
	clk.Advance(time.Nanosecond)
	if ok, retry := probe(l, a); !ok || retry != 0 {
		t.Errorf("60 s on: Allow = (%v, %v), want (true, 0)", ok, retry)
	}
	// That one try fails too, and the next wait is a full 60 s again.
	mustFail(t, l, a)
	if ok, retry := probe(l, a); ok || retry != 60*time.Second {
		t.Errorf("after the refilled try failed: Allow = (%v, %v), want (false, 60s)", ok, retry)
	}

	// The bucket holds 5 and no more: after a long quiet there are five tries,
	// not six, and not more for having waited longer.
	clk.Advance(24 * time.Hour)
	for i := range 5 {
		if ok, _ := failOnce(l, a); !ok {
			t.Fatalf("try %d after a long quiet is refused", i+1)
		}
	}
	if ok, _ := probe(l, a); ok {
		t.Error("a sixth try after a long quiet is let in: the bucket holds more than 5")
	}

	// A refused attempt takes nothing: asking again and again does not make
	// the wait longer.
	for range 50 {
		if ok, _ := failOnce(l, a); ok {
			t.Fatal("an attempt from an IP with an empty bucket was let in")
		}
	}
	if ok, retry := probe(l, a); ok || retry != 60*time.Second {
		t.Errorf("after 50 refused attempts: Allow = (%v, %v), want (false, 60s)", ok, retry)
	}
	clk.Advance(60 * time.Second)
	if ok, _ := probe(l, a); !ok {
		t.Error("the wait grew with the attempts that were refused")
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
		mustFail(t, l, v4)
	}
	for range 2 {
		mustFail(t, l, mapped)
	}
	if ok, _ := probe(l, v4); ok {
		t.Error("five failures from an address and its mapped form do not close it")
	}
	if ok, _ := probe(l, mapped); ok {
		t.Error("five failures from an address and its mapped form do not close the mapped form")
	}
	// A zone is not another client.
	for range 5 {
		mustFail(t, l, zoned)
	}
	if ok, _ := probe(l, plain); ok {
		t.Error("an address with a zone is another client than the same without it")
	}
	if n := ipCount(l); n != 2 {
		t.Errorf("%d buckets for two clients", n)
	}
}

func testRateLimitGlobal(t *testing.T) {
	clk := newClock()
	l := NewLimiter(clk.Now)

	// One IP fails 5 times and empties its own bucket; 95 others, each from an
	// IP of its own (so that no bucket of theirs is empty), take the global
	// bucket to 0.
	for range 5 {
		mustFail(t, l, addr(2000))
	}
	for i := range 94 {
		mustFail(t, l, addr(i))
	}
	if ok, _ := probe(l, addr(1000)); !ok {
		t.Fatal("99 failures closed the global bucket")
	}
	mustFail(t, l, addr(94))
	ok, retry := probe(l, addr(1000))
	if ok {
		t.Fatal("100 failures did not close the global bucket")
	}
	if retry != 9*time.Second {
		t.Errorf("the global retry is %v, want 9s", retry)
	}
	// An IP with a failure of its own is closed too; so is every other.
	if ok, _ := probe(l, addr(5)); ok {
		t.Error("the global bucket is empty and an IP is let in")
	}
	// The wait is the longer of the two buckets: the IP with its own bucket
	// empty (60 s) waits for that, the others for the global one (9 s).
	if ok, retry := probe(l, addr(2000)); ok || retry != 60*time.Second {
		t.Errorf("an IP with an empty bucket: Allow = (%v, %v), want (false, 60s)", ok, retry)
	}

	// Refilling 1 per 9 s.
	clk.Advance(8 * time.Second)
	if ok, retry := probe(l, addr(1000)); ok || retry != time.Second {
		t.Errorf("8 s on: Allow = (%v, %v), want (false, 1s)", ok, retry)
	}
	clk.Advance(time.Second)
	if ok, _ := probe(l, addr(1000)); !ok {
		t.Error("9 s on, the global bucket has no token")
	}
	if ok, retry := probe(l, addr(2000)); ok || retry != 51*time.Second {
		t.Errorf("9 s on, the IP with its own bucket empty: Allow = (%v, %v), want (false, 51s)", ok, retry)
	}
	mustFail(t, l, addr(1000))
	if ok, retry := probe(l, addr(1001)); ok || retry != 9*time.Second {
		t.Errorf("after that try failed: Allow = (%v, %v), want (false, 9s)", ok, retry)
	}

	// The global bucket holds 100, and no more, after a long quiet.
	clk.Advance(48 * time.Hour)
	for i := range 100 {
		if ok, _ := failOnce(l, addr(3000+i)); !ok {
			t.Fatalf("failure %d after a long quiet: the global bucket is not full", i)
		}
	}
	if ok, _ := probe(l, addr(4000)); ok {
		t.Error("the global bucket holds more than 100")
	}
}

func testRateLimitIdleDropped(t *testing.T) {
	clk := newClock()
	l := NewLimiter(clk.Now)
	for i := range 3 {
		mustFail(t, l, addr(i))
	}
	if n := ipCount(l); n != 3 {
		t.Fatalf("%d buckets after 3 failures from 3 IPs", n)
	}

	// An IP is kept while it has been seen in the last hour. The failure of
	// IP 0 half an hour on is a sign of life.
	clk.Advance(30 * time.Minute)
	mustFail(t, l, addr(0))
	clk.Advance(29 * time.Minute)
	probe(l, addr(9))
	if n := ipCount(l); n != 3 {
		t.Errorf("%d buckets 59 min on, want 3: nothing is idle for an hour yet", n)
	}

	// An hour of quiet drops the bucket of IP 1 and 2, not that of IP 0. The
	// buckets go on the next call after a minute's sweep, whichever it is.
	clk.Advance(2 * time.Minute)
	probe(l, addr(9))
	if n := ipCount(l); n != 1 {
		t.Errorf("%d buckets 61 min on, want 1 (the one that failed 31 min ago)", n)
	}
	clk.Advance(time.Hour)
	mustFail(t, l, addr(10))
	if n := ipCount(l); n != 1 {
		t.Errorf("%d buckets after another hour, want 1 (the new one)", n)
	}
	// A bucket that went was a full one, so the IP has all its tries again.
	for range 4 {
		mustFail(t, l, addr(1))
	}
	if ok, _ := probe(l, addr(1)); !ok {
		t.Error("an IP that came back after its bucket was dropped has fewer than 5 tries")
	}
	mustFail(t, l, addr(1))
	if ok, _ := probe(l, addr(1)); ok {
		t.Error("an IP that came back after its bucket was dropped has more than 5 tries")
	}
}

func testRateLimitMemoryBounded(t *testing.T) {
	clk := newClock()
	l := NewLimiter(clk.Now)

	// A bucket is made only by an attempt that is let in, which takes a token
	// of the global bucket as well: 100 failures from 100 IPs make 100.
	for i := range 100 {
		mustFail(t, l, addr(i))
	}
	if n := ipCount(l); n != 100 {
		t.Fatalf("%d buckets after 100 failures from 100 IPs", n)
	}
	// With the global bucket empty, a flood from ever new addresses is refused
	// before it makes one.
	for i := 100; i < 5000; i++ {
		if ok, _ := failOnce(l, addr(i)); ok {
			t.Fatalf("attempt %d was let in with the global bucket empty", i)
		}
	}
	if n := ipCount(l); n != 100 {
		t.Errorf("%d buckets after a flood with the global bucket empty, want 100", n)
	}

	// Attempts that succeed give their tokens back and leave no bucket, so any
	// number of them from any number of addresses adds none. (After 48 h the
	// 100 that failed are idle and gone.)
	clk.Advance(48 * time.Hour)
	for i := range 5000 {
		if ok, _ := probe(l, addr(10000+i)); !ok {
			t.Fatalf("a success from a new address %d was refused", i)
		}
	}
	if n := ipCount(l); n != 0 {
		t.Errorf("%d buckets after 5000 successes from new addresses, want none", n)
	}
}

// TestConcurrentAttemptsReserve is the reason Allow takes the token when it
// says yes: attempts that ask together must not all pass on the strength of the
// one token that is there.
func TestConcurrentAttemptsReserve(t *testing.T) {
	sameIP := func(int) netip.Addr { return netip.MustParseAddr("192.0.2.1") }

	t.Run("one IP", func(t *testing.T) {
		clk := newClock()
		l := NewLimiter(clk.Now)

		dones, refused := together(l, 20, sameIP)
		if len(dones) != 5 || len(refused) != 15 {
			t.Fatalf("20 attempts together from one IP: %d let in, %d refused, want 5 and 15", len(dones), len(refused))
		}
		for _, w := range refused {
			if w != 60*time.Second {
				t.Errorf("a refused attempt was told to wait %v, want 60s", w)
			}
		}
		// They all fail: the tokens stay taken, and the refill is one per
		// 60 s, so one more is let in after it, and no more.
		for _, done := range dones {
			done(true)
		}
		if dones, _ := together(l, 20, sameIP); len(dones) != 0 {
			t.Errorf("%d attempts were let in with the bucket empty", len(dones))
		}
		clk.Advance(60 * time.Second)
		dones, refused = together(l, 20, sameIP)
		if len(dones) != 1 || len(refused) != 19 {
			t.Errorf("20 attempts together after a refill of one: %d let in, %d refused, want 1 and 19", len(dones), len(refused))
		}
		for _, done := range dones {
			done(true)
		}
		// The bucket holds 5: a long quiet is five tries, not 20.
		clk.Advance(24 * time.Hour)
		if dones, _ := together(l, 20, sameIP); len(dones) != 5 {
			t.Errorf("20 attempts together after a long quiet: %d let in, want 5", len(dones))
		}
	})

	t.Run("a success gives the token back", func(t *testing.T) {
		clk := newClock()
		l := NewLimiter(clk.Now)

		// Five let in and all succeed: the bucket is as full as it was, again
		// and again.
		for round := range 3 {
			dones, _ := together(l, 20, sameIP)
			if len(dones) != 5 {
				t.Fatalf("round %d: %d let in, want 5", round, len(dones))
			}
			for _, done := range dones {
				done(false)
			}
		}
		if n := ipCount(l); n != 0 {
			t.Errorf("%d buckets after attempts that all succeeded, want none", n)
		}

		// Two of five fail and three succeed: three tries are left.
		dones, _ := together(l, 20, sameIP)
		for i, done := range dones {
			done(i < 2)
		}
		if dones, _ := together(l, 20, sameIP); len(dones) != 3 {
			t.Errorf("after 2 failures and 3 successes: %d let in, want 3", len(dones))
		}
	})

	t.Run("a refund never fills a bucket past its capacity", func(t *testing.T) {
		clk := newClock()
		l := NewLimiter(clk.Now)

		done, ok, _ := l.Allow(sameIP(0))
		if !ok {
			t.Fatal("a fresh IP was refused")
		}
		// The attempt is slow: the bucket fills up while it runs, and the
		// success then gives back a token that was refilled already.
		clk.Advance(24 * time.Hour)
		done(false)
		if dones, _ := together(l, 20, sameIP); len(dones) != 5 {
			t.Errorf("%d let in after a late refund, want 5: the refund raised the bucket past 5", len(dones))
		}

		// A second call of done does nothing: it must not give back twice.
		clk2 := newClock()
		l2 := NewLimiter(clk2.Now)
		dones, _ := together(l2, 20, sameIP)
		if len(dones) != 5 {
			t.Fatalf("%d let in, want 5", len(dones))
		}
		dones[0](false)
		dones[0](false)
		dones[0](true)
		if dones, _ := together(l2, 20, sameIP); len(dones) != 1 {
			t.Errorf("%d let in after one success called done three times, want 1", len(dones))
		}
	})

	t.Run("a done that is never called is a failure", func(t *testing.T) {
		clk := newClock()
		l := NewLimiter(clk.Now)
		dones, _ := together(l, 20, sameIP)
		if len(dones) != 5 {
			t.Fatalf("%d let in, want 5", len(dones))
		}
		// Nobody calls done: the tokens are spent.
		if dones, _ := together(l, 20, sameIP); len(dones) != 0 {
			t.Errorf("%d let in after 5 attempts that never said how they ended", len(dones))
		}
	})

	t.Run("global", func(t *testing.T) {
		clk := newClock()
		l := NewLimiter(clk.Now)
		// 100 IPs, two attempts each, all together: every IP has room for
		// both, so only the global bucket limits them, to 100 in all.
		pair := func(i int) netip.Addr { return addr(i / 2) }
		dones, refused := together(l, 200, pair)
		if len(dones) != 100 || len(refused) != 100 {
			t.Fatalf("200 attempts together: %d let in, %d refused, want 100 and 100", len(dones), len(refused))
		}
		for _, w := range refused {
			if w != 9*time.Second {
				t.Errorf("a refused attempt was told to wait %v, want 9s", w)
			}
		}
		// They all fail: the global bucket is empty, and a new IP is refused.
		for _, done := range dones {
			done(true)
		}
		if dones, _ := together(l, 20, func(i int) netip.Addr { return addr(5000 + i) }); len(dones) != 0 {
			t.Errorf("%d new IPs were let in with the global bucket empty", len(dones))
		}
		// After 9 s one token is back, and exactly one of many is let in.
		clk.Advance(9 * time.Second)
		dones, _ = together(l, 20, func(i int) netip.Addr { return addr(5000 + i) })
		if len(dones) != 1 {
			t.Errorf("%d let in after one global refill, want 1", len(dones))
		}
		// Successes give the global tokens back as well.
		for _, done := range dones {
			done(false)
		}
		clk.Advance(48 * time.Hour)
		dones, _ = together(l, 200, pair)
		if len(dones) != 100 {
			t.Fatalf("%d let in with a full global bucket, want 100", len(dones))
		}
		for _, done := range dones {
			done(false)
		}
		if dones, _ := together(l, 200, pair); len(dones) != 100 {
			t.Errorf("%d let in after 100 successes gave their tokens back, want 100", len(dones))
		}
	})
}

func TestLimiterConcurrentUse(t *testing.T) {
	l := NewLimiter(nil) // the real clock
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 200 {
				done, ok, _ := l.Allow(addr(g*1000 + i%7))
				if !ok {
					continue
				}
				// A third of the attempts fail, the rest succeed.
				done(i%3 == 0)
			}
		}()
	}
	wg.Wait()
	if n := ipCount(l); n == 0 || n > 8*7 {
		t.Errorf("%d buckets after the run, want between 1 and 56", n)
	}
}
