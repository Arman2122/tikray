package auth

import (
	"net/netip"
	"sync"
	"time"
)

// The limit on failed setups and sign-ins, in two buckets that a failure takes
// a token from. One is for each client address: it holds 5 and gets one back
// every 60 s. The other is for all the clients together: it holds 100 and gets
// one back every 9 s. A request is let in while both have a token.
const (
	ipBurst      = 5
	ipRefill     = 60 * time.Second
	globalBurst  = 100
	globalRefill = 9 * time.Second

	// A per-address bucket that has seen no failure for this long is dropped.
	// It has been full again for a good while by then (5 minutes fill it), so
	// a dropped bucket and a fresh one are the same.
	limiterIdle = time.Hour
	// The buckets are looked over for idle ones at most this often.
	limiterSweep = time.Minute
)

// bucket is a token bucket, kept as the time its tokens run out: it holds a
// token for each refill that fits between now and the time it is full again.
// It needs no counting of tokens, and no rounding.
type bucket struct {
	full time.Time // when it is full again; not after now means it is full now
	last time.Time // the last failure
}

// wait is how long until the bucket has a token: zero when it has one.
func (b *bucket) wait(now time.Time, refill time.Duration, burst int) time.Duration {
	used := b.full.Sub(now) // the part that is empty, in time to refill
	if used <= 0 {
		return 0 // full (and a bucket that was never used is full from the year 1)
	}
	if whole := time.Duration(burst) * refill; used > whole {
		used = whole // a clock that went back
	}
	// With the empty part at most burst-1 refills it has a token to give.
	if w := used - time.Duration(burst-1)*refill; w > 0 {
		return w
	}
	return 0
}

// take takes a token, and no more than the bucket holds: failures that come
// after it is empty don't make the wait longer.
func (b *bucket) take(now time.Time, refill time.Duration, burst int) {
	if b.full.Before(now) {
		b.full = now
	}
	b.full = b.full.Add(refill)
	if top := now.Add(time.Duration(burst) * refill); b.full.After(top) {
		b.full = top
	}
	b.last = now
}

// Limiter limits failed setups and sign-ins by the address of the client and
// all together. The caller asks Allow before it does anything costly (a hash,
// above all) and says Fail for each attempt that Allow let in and that failed.
// Its methods are safe for concurrent use.
//
// The per-address buckets are made by failures only, and a failure makes one
// only while the global bucket has a token (the failures that Allow let in
// are that many at most), so no more than 100 are made at once and one more
// per 9 s (400 an hour). An idle one is dropped after an hour, so the map
// holds about 500 buckets at the most, however many addresses ask.
type Limiter struct {
	now func() time.Time

	mu     sync.Mutex
	ips    map[netip.Addr]*bucket
	global bucket
	swept  time.Time // when the idle buckets were last dropped
}

// NewLimiter makes a Limiter that reads the time from now (time.Now when it is
// nil: a test passes its own).
func NewLimiter(now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{now: now, ips: make(map[netip.Addr]*bucket), swept: now()}
}

// key is the address a client is counted by: an IPv4 address in its IPv6 form
// is the IPv4 one, and a zone is not part of who a client is.
func key(ip netip.Addr) netip.Addr {
	return ip.Unmap().WithZone("")
}

// Allow reports whether a failed setup or sign-in has left ip, and everybody,
// with a try to spare. When it has not, retryAfter is how long until it has,
// for a Retry-After header: the longer of the two waits. It takes nothing and
// makes nothing: asking is free.
func (l *Limiter) Allow(ip netip.Addr) (ok bool, retryAfter time.Duration) {
	now := l.now()
	ip = key(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(now)
	retryAfter = l.global.wait(now, globalRefill, globalBurst)
	if b := l.ips[ip]; b != nil {
		retryAfter = max(retryAfter, b.wait(now, ipRefill, ipBurst))
	}
	return retryAfter == 0, retryAfter
}

// Fail notes a failed setup or sign-in from ip: it takes a token from the
// bucket of ip and from the global one. Call it for an attempt that Allow let
// in, and not for one it refused.
func (l *Limiter) Fail(ip netip.Addr) {
	now := l.now()
	ip = key(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(now)
	room := l.global.wait(now, globalRefill, globalBurst) == 0
	l.global.take(now, globalRefill, globalBurst)
	b := l.ips[ip]
	if b == nil {
		if !room {
			// The global bucket was empty: Allow would have refused this one,
			// so it is not given a bucket of its own (that would let a flood
			// of new addresses grow the map).
			return
		}
		b = &bucket{}
		l.ips[ip] = b
	}
	b.take(now, ipRefill, ipBurst)
}

// sweepLocked drops the per-address buckets that have had no failure for an
// hour, at most once a minute. Callers hold l.mu.
func (l *Limiter) sweepLocked(now time.Time) {
	if d := now.Sub(l.swept); d < limiterSweep {
		if d < 0 { // a clock that went back
			l.swept = now
		}
		return
	}
	l.swept = now
	for ip, b := range l.ips {
		if now.Sub(b.last) >= limiterIdle {
			delete(l.ips, ip)
		}
	}
}
