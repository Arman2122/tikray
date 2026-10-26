package auth

import (
	"net/netip"
	"sync"
	"time"
)

// The limit on failed setups and sign-ins, in two buckets. One is for each
// client address: it holds 5 and gets one back every 60 s. The other is for
// all the clients together: it holds 100 and gets one back every 9 s. An
// attempt is let in while both have a token, and the token is taken when it is
// let in, not when it fails: attempts that come together can't all pass on the
// strength of one token. It is given back when the attempt turns out to be a
// success, so that only failures count.
const (
	ipBurst      = 5
	ipRefill     = 60 * time.Second
	globalBurst  = 100
	globalRefill = 9 * time.Second

	// A per-address bucket that has let in no attempt for this long is dropped.
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
	last time.Time // the last token taken
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

// take takes a token, and no more than the bucket holds (it matters only for a
// clock that went back: Allow takes from a bucket that has a token).
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

// give puts a token back, the one that take took, and never raises the bucket
// above what it holds: a bucket that has filled up since is as full as it was.
func (b *bucket) give(now time.Time, refill time.Duration) {
	b.full = b.full.Add(-refill)
	if b.full.Before(now) {
		b.full = now
	}
}

// Limiter limits failed setups and sign-ins by the address of the client and
// all together. The caller asks Allow before it does anything costly (a hash,
// above all), and when Allow says yes the token is already taken from both
// buckets, so any number of attempts that ask together get no more tries than
// the buckets hold. Its methods are safe for concurrent use.
//
// The per-address buckets are made by an Allow that says yes, which takes a
// token of the global bucket too, so no more than 100 are made at once and one
// more per 9 s (400 an hour); one that is full again after a refund is
// dropped at once, and an idle one after an hour. The map holds about 500
// buckets at the most, however many addresses ask.
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

// Allow asks to make an attempt from ip. When both the bucket of ip and the
// global one have a token it says ok, and the token is taken from each of them
// already: the caller makes its attempt and then calls done, exactly once.
// done(true) says the attempt failed, and the tokens stay taken; done(false)
// says it did not (a sign-in that worked), and gives them back, so that only
// failures count. An attempt that never calls done counts as a failure. A
// second call of done does nothing.
//
// When there is no token, done is nil, nothing is taken, and retryAfter is how
// long until there is one (for a Retry-After header): the longer of the two
// waits. The caller then answers 429, and does nothing costly.
func (l *Limiter) Allow(ip netip.Addr) (done func(failed bool), ok bool, retryAfter time.Duration) {
	now := l.now()
	ip = key(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(now)
	b := l.ips[ip]
	retryAfter = l.global.wait(now, globalRefill, globalBurst)
	if b != nil {
		retryAfter = max(retryAfter, b.wait(now, ipRefill, ipBurst))
	}
	if retryAfter > 0 {
		return nil, false, retryAfter
	}
	if b == nil {
		b = &bucket{}
		l.ips[ip] = b
	}
	l.global.take(now, globalRefill, globalBurst)
	b.take(now, ipRefill, ipBurst)

	var once sync.Once
	return func(failed bool) {
		once.Do(func() {
			if !failed {
				l.refund(ip)
			}
		})
	}, true, 0
}

// refund gives back the token that an Allow took for ip from each bucket. The
// bucket of ip is dropped when that leaves it full: it is then the same as one
// that was never made.
func (l *Limiter) refund(ip netip.Addr) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.global.give(now, globalRefill)
	if b := l.ips[ip]; b != nil {
		b.give(now, ipRefill)
		if !b.full.After(now) {
			delete(l.ips, ip)
		}
	}
}

// sweepLocked drops the per-address buckets that have had no attempt let in
// for an hour, at most once a minute. Callers hold l.mu.
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
