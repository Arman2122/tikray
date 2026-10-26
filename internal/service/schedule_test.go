package service

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/store"
)

// startScheduler runs the scheduler alone, apart from the apply loop, until
// the test ends, and waits for it to arm its first timer.
func (e *env) startScheduler() {
	e.t.Helper()
	ctx, cancel := context.WithCancel(bg)
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.s.schedule(ctx)
	}()
	e.t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			e.t.Error("the scheduler did not stop when its context ended")
		}
	})
	within(e.t, "the scheduler to wait", e.schedQuiet)
}

// tick moves the service's time and the scheduler's timers on by d and, if
// that made a timer fire, waits for the scheduler to wait again.
func (e *env) tick(d time.Duration) {
	e.t.Helper()
	e.clock.advance(d)
	if e.ticks.advance(d) {
		within(e.t, "the scheduler to settle", e.schedQuiet)
	}
}

// schedSub is a subscription at https://sub.example.net/<name> that was
// fetched ago before t0 (never, when ago is 0).
func schedSub(name string, ago time.Duration, disabled bool) store.Subscription {
	sub := store.Subscription{
		ID:       store.NewID(),
		Name:     name,
		URL:      "https://" + subHost + "/" + name,
		Interval: store.Duration(24 * time.Hour),
		Disabled: disabled,
	}
	if ago > 0 {
		sub.LastFetch = t0.Add(-ago)
	}
	return sub
}

func TestScheduleDue(t *testing.T) {
	e, feed := newSubEnv(t)
	never := schedSub("never", 0, false)
	// Fetched 59 min 30 s ago: due, with a day between fetches, at 23 h 0 min
	// 30 s, which is when the scheduler looks.
	fresh := schedSub("fresh", time.Hour-30*time.Second, false)
	overdue := schedSub("overdue", 25*time.Hour, false)
	failing := schedSub("failing", 0, false)
	off := schedSub("off", 0, true)
	for _, sub := range []store.Subscription{never, fresh, overdue, failing, off} {
		e.putSub(sub)
	}
	feed.setDirect(okFeed(feedBody(feedLink(11, "a"))))
	feed.setPer("/failing", feedReply{status: 500})
	feed.setProxy(feedReply{status: 500})
	e.startScheduler()

	// The first look is 30 s after the start.
	e.tick(29 * time.Second)
	if got := feed.requests(); len(got) != 0 {
		t.Fatalf("fetched %q after 29 s, want nothing", got)
	}
	e.tick(time.Second)
	want := []string{"direct /never", "direct /overdue", "direct /failing", "proxy /failing"}
	if got := feed.requests(); !slices.Equal(got, want) {
		t.Fatalf("fetched %q at 30 s, want %q: the subscriptions that are due, in order", got, want)
	}
	if got := e.subOf(never.ID).LastFetch; !got.Equal(t0.Add(30 * time.Second)) {
		t.Errorf("never: LastFetch = %v, want 30 s in", got)
	}
	if got := e.subOf(overdue.ID).LastFetch; !got.Equal(t0.Add(30 * time.Second)) {
		t.Errorf("overdue: LastFetch = %v, want 30 s in", got)
	}
	if got := e.subOf(fresh.ID).LastFetch; !got.Equal(fresh.LastFetch) {
		t.Errorf("fresh: LastFetch = %v, want it as it was", got)
	}
	if got := e.subOf(failing.ID); got.LastError == "" || !got.LastFetch.IsZero() {
		t.Errorf("failing: LastError %q, LastFetch %v; want the error and no fetch", got.LastError, got.LastFetch)
	}

	// A minute on, the fetched ones are fresh and the failed one waits an hour.
	e.tick(time.Minute)
	e.tick(57 * time.Minute) // 58 min 30 s
	e.tick(time.Minute)      // 59 min 30 s
	if got := feed.requests(); len(got) != len(want) {
		t.Fatalf("fetched %q before the hour was up, want no more than %q", got, want)
	}

	// An hour after it failed at 30 s, it tries again, and fails again.
	e.tick(time.Minute) // 60 min 30 s
	want = append(want, "direct /failing", "proxy /failing")
	if got := feed.requests(); !slices.Equal(got, want) {
		t.Fatalf("fetched %q at 60 min 30 s, want %q: the failed one retried", got, want)
	}

	// The provider recovers: the next try, an hour on, works.
	feed.setPer("/failing", okFeed(feedBody(feedLink(12, "b"))))
	e.tick(time.Hour) // 120 min 30 s
	want = append(want, "direct /failing")
	if got := feed.requests(); !slices.Equal(got, want) {
		t.Fatalf("fetched %q at 120 min 30 s, want %q", got, want)
	}
	if got := e.subOf(failing.ID); got.LastError != "" || !got.LastFetch.Equal(t0.Add(2*time.Hour+30*time.Second)) {
		t.Errorf("failing: LastError %q, LastFetch %v; want it fetched and the error cleared", got.LastError, got.LastFetch)
	}

	// The fresh one is due when LastFetch + Interval is now, and not before.
	e.tick(20*time.Hour + 59*time.Minute) // 22 h 59 min 30 s
	if got := feed.requests(); len(got) != len(want) {
		t.Fatalf("fetched %q a minute before fresh was due, want no more than %q", got, want)
	}
	e.tick(time.Minute) // 23 h 0 min 30 s
	want = append(want, "direct /fresh")
	if got := feed.requests(); !slices.Equal(got, want) {
		t.Fatalf("fetched %q when fresh was due, want %q", got, want)
	}
	for _, r := range feed.requests() {
		if strings.HasSuffix(r, "/off") {
			t.Error("a disabled subscription was fetched")
		}
	}
}

func TestScheduleTimers(t *testing.T) {
	e, _ := newSubEnv(t)
	e.startScheduler()
	if got, want := e.ticks.armed(), []time.Duration{30 * time.Second}; !slices.Equal(got, want) {
		t.Fatalf("timers %v, want %v: the first look is 30 s after the start", got, want)
	}
	e.tick(30 * time.Second)
	e.tick(time.Minute)
	e.tick(time.Minute)
	if got, want := e.ticks.armed(), []time.Duration{30 * time.Second, time.Minute, time.Minute, time.Minute}; !slices.Equal(got, want) {
		t.Errorf("timers %v, want %v: then a look every minute", got, want)
	}
}

// A failure's wait is lifted when the subscription is pointed elsewhere.
func TestScheduleURLChangeLiftsTheHold(t *testing.T) {
	e, feed := newSubEnv(t)
	sub := schedSub("moved", 0, false)
	e.putSub(sub)
	feed.setDirect(feedReply{status: 500})
	feed.setProxy(feedReply{status: 500})
	feed.setPer("/new", okFeed(feedBody(feedLink(11, "a"))))
	e.startScheduler()
	e.tick(30 * time.Second) // fails: held for an hour

	next := "https://" + subHost + "/new"
	if _, _, err := e.s.UpdateSubscription(bg, store.AnyRevision, sub.ID, SubscriptionPatch{URL: &next}); err != nil {
		t.Fatal(show(err))
	}
	e.tick(time.Minute)
	if got := e.subOf(sub.ID); got.LastError != "" || got.LastFetch.IsZero() {
		t.Errorf("LastError %q, LastFetch %v; want the new URL fetched at the next look", got.LastError, got.LastFetch)
	}
}

// A subscription pointed elsewhere while its old address failed is not held
// for that failure: the next look fetches the new address.
func TestScheduleFailureOfAnOldAddressHoldsNothing(t *testing.T) {
	e, feed := newSubEnv(t)
	sub := schedSub("old", 0, false)
	e.putSub(sub)
	feed.setPer("/old", feedReply{status: 500})
	feed.setProxy(feedReply{status: 500})
	feed.setPer("/new", okFeed(feedBody(feedLink(11, "a"))))
	done := false
	feed.onDirect = func(path string) {
		if path != "/old" || done {
			return
		}
		done = true
		next := "https://" + subHost + "/new"
		if _, _, err := e.s.UpdateSubscription(bg, store.AnyRevision, sub.ID, SubscriptionPatch{URL: &next}); err != nil {
			t.Error(show(err))
		}
	}
	e.startScheduler()
	e.tick(30 * time.Second) // /old fails, after the subscription moved on
	if got := e.subOf(sub.ID); got.LastError != "" || !got.LastFetch.IsZero() {
		t.Fatalf("LastError %q, LastFetch %v; want the old address's failure not to show", got.LastError, got.LastFetch)
	}

	e.tick(time.Minute)
	if got := e.subOf(sub.ID); got.LastError != "" || !got.LastFetch.Equal(t0.Add(90*time.Second)) {
		t.Errorf("LastError %q, LastFetch %v; want the new address fetched at the next look", got.LastError, got.LastFetch)
	}
	if got := feed.requests(); !slices.Contains(got, "direct /new") {
		t.Errorf("requests %q, want one for /new", got)
	}
	if got := e.eventsOf(KindError); len(got) != 0 {
		t.Errorf("error events %q, want none", got)
	}
}

// A refresh that failed for a reason other than the fetch is told as an event,
// and tried again at the next look.
func TestScheduleRecordsARefreshThatCouldNotBeStored(t *testing.T) {
	e, feed := newSubEnv(t)
	sub := schedSub("moving", 0, false)
	e.putSub(sub)
	feed.setDirect(okFeed(feedBody(feedLink(11, "a"))))
	done := false
	feed.onDirect = func(string) {
		if done {
			return
		}
		done = true
		next := "https://" + subHost + "/elsewhere"
		if _, _, err := e.s.UpdateSubscription(bg, store.AnyRevision, sub.ID, SubscriptionPatch{URL: &next}); err != nil {
			t.Error(show(err))
		}
	}
	e.startScheduler()
	e.tick(30 * time.Second)
	got := e.eventsOf(KindError)
	if len(got) != 1 || !strings.Contains(got[0], sub.ID) || !strings.Contains(got[0], "state changed") {
		t.Fatalf("error events %q, want one that names the subscription and the conflict", got)
	}
	wantNoURL(t, "the event", got[0])

	e.tick(time.Minute)
	if got := e.subOf(sub.ID); got.LastFetch.IsZero() {
		t.Error("the next look did not refresh: a conflict is no failure to wait out")
	}
}

// breakStore makes every write of the env's store fail, as a full disk does:
// each state file is now a directory, which a rename can't replace.
func (e *env) breakStore() {
	e.t.Helper()
	files, err := filepath.Glob(filepath.Join(e.data, "state", "state.v*.json"))
	if err != nil || len(files) == 0 {
		e.t.Fatalf("no state file to break (%v)", err)
	}
	for _, f := range files {
		if err := os.Remove(f); err != nil {
			e.t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(f, "in-the-way"), 0o755); err != nil {
			e.t.Fatal(err)
		}
	}
}

// A refresh that fetched and tested its list and could not store the merge,
// as on a full disk, waits out min(1 h, Interval) as a failed fetch does,
// with an error event: the scheduler does not fetch the list and have the
// runner test it again at every look.
func TestScheduleHoldsARefreshThatCouldNotBeWritten(t *testing.T) {
	e, feed := newSubEnv(t)
	sub := schedSub("full", 0, false)
	e.putSub(sub)
	feed.setDirect(okFeed(feedBody(feedLink(11, "a"))))
	e.breakStore()
	e.startScheduler()
	e.tick(30 * time.Second)
	if got := feed.requests(); len(got) != 1 {
		t.Fatalf("fetched %q at 30 s, want once", got)
	}
	got := e.eventsOf(KindError)
	if len(got) != 1 || !strings.Contains(got[0], sub.ID) || !strings.Contains(got[0], "not stored") {
		t.Fatalf("error events %q, want one that names the subscription and says the refresh was not stored", got)
	}
	wantNoURL(t, "the event", got[0])

	for at := 90 * time.Second; at < time.Hour+30*time.Second; at += time.Minute {
		e.tick(time.Minute)
		if got := feed.requests(); len(got) != 1 {
			t.Fatalf("fetched %q by %s, want no more before the hour is up", got, at)
		}
	}
	e.tick(time.Minute) // 60 min 30 s
	if got := feed.requests(); len(got) != 2 {
		t.Errorf("fetched %q at 60 min 30 s, want the second try", got)
	}
}

// Run starts the scheduler, and waits for it to stop with the monitor.
func TestRunStartsTheScheduler(t *testing.T) {
	e, feed := newSubEnv(t)
	sub := schedSub("provider", 0, false)
	e.putSub(sub)
	feed.setDirect(okFeed(feedBody(feedLink(11, "a"))))
	e.start()
	within(t, "the scheduler to wait", e.schedQuiet)
	if got, want := e.ticks.pending(), []time.Duration{30 * time.Second}; !slices.Equal(got, want) {
		t.Fatalf("scheduler timers %v, want %v", got, want)
	}
	e.tick(30 * time.Second)
	if got := e.subOf(sub.ID); got.LastFetch.IsZero() {
		t.Error("the subscription was not fetched")
	}
	e.shutdown() // fails if Run does not return
}
