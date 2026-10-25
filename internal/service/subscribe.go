package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/health"
	"github.com/Arman2122/tikray/internal/store"
	"github.com/Arman2122/tikray/internal/subscription"
)

const (
	// defaultInterval is how often a subscription is fetched when its owner
	// gives no interval.
	defaultInterval = 24 * time.Hour
	// fetchTimeout bounds one attempt to download a subscription, body
	// included.
	fetchTimeout = 60 * time.Second
	// maxLineRunes is how much of a link a Skipped line keeps, as
	// subscription.Parse's do.
	maxLineRunes = 80
)

// ErrFetchFailed is wrapped by the error of a refresh that could not get the
// subscription, by either route: the provider can't be reached, answers with
// an error, or sends something that holds no server, such as a block page or
// the notice of an expired account. The servers are as they were.
var ErrFetchFailed = errors.New("service: the subscription could not be fetched")

// defaultFetcher is the Fetcher of a service that is given none: direct
// first, and through the runner's SOCKS inbound at socks, when the monitor
// says the proxy works and there is an address, if that fails. The proxy
// attempt exists only with an address: an empty one would make a direct client
// that is called the proxy.
func defaultFetcher(socks string, m *health.Monitor) func(store.State) subscription.Fetcher {
	f := subscription.Fetcher{Direct: artifacts.HTTPClient("", fetchTimeout)}
	if socks != "" {
		f.Proxy = artifacts.HTTPClient(socks, fetchTimeout)
	}
	if m != nil {
		f.ProxyHealthy = m.ProxyHealthy
	}
	return func(store.State) subscription.Fetcher { return f }
}

// subscriptionIndex is the position of the subscription id in subs, or -1.
func subscriptionIndex(subs []store.Subscription, id string) int {
	return slices.IndexFunc(subs, func(sub store.Subscription) bool { return sub.ID == id })
}

// NewSubscription is a subscription to add. A zero Interval means 24 h.
type NewSubscription struct {
	Name, URL string
	Interval  store.Duration
}

// AddSubscription adds a subscription, with a new ID, and returns it and the
// new revision. rev is the revision the caller read, or store.AnyRevision.
// The subscription is not fetched: it has not been, so the scheduler
// refreshes it at its next look.
func (s *Service) AddSubscription(ctx context.Context, rev uint64, n NewSubscription) (store.Subscription, uint64, error) {
	sub := store.Subscription{Name: n.Name, URL: strings.TrimSpace(n.URL), Interval: n.Interval}
	if sub.Interval == 0 {
		sub.Interval = store.Duration(defaultInterval)
	}
	st, next, err := s.change(rev, func(st *store.State) ([]note, error) {
		for sub.ID == "" || subscriptionIndex(st.Subscriptions, sub.ID) >= 0 {
			sub.ID = store.NewID()
		}
		st.Subscriptions = append(st.Subscriptions, sub)
		return nil, nil
	})
	if err != nil {
		return store.Subscription{}, 0, err
	}
	return st.Subscriptions[subscriptionIndex(st.Subscriptions, sub.ID)], next, nil
}

// SubscriptionPatch is a change to a subscription: each field that is set
// replaces the subscription's. A URL that differs from the current one
// forgets the last fetch and its error, so that the subscription is fetched
// at the next look; its servers stay until then.
type SubscriptionPatch struct {
	Name     *string
	URL      *string
	Disabled *bool
	Interval *store.Duration
}

// UpdateSubscription changes subscription id as p says and returns it and the
// new revision; ErrNotFound if there is no such subscription.
func (s *Service) UpdateSubscription(ctx context.Context, rev uint64, id string, p SubscriptionPatch) (store.Subscription, uint64, error) {
	moved := false
	st, next, err := s.change(rev, func(st *store.State) ([]note, error) {
		i := subscriptionIndex(st.Subscriptions, id)
		if i < 0 {
			return nil, notFound(*st, "subscription", id)
		}
		sub := &st.Subscriptions[i]
		if p.Name != nil {
			sub.Name = *p.Name
		}
		if p.Disabled != nil {
			sub.Disabled = *p.Disabled
		}
		if p.Interval != nil {
			sub.Interval = *p.Interval
		}
		if p.URL != nil {
			if url := strings.TrimSpace(*p.URL); url != sub.URL {
				sub.URL, sub.LastFetch, sub.LastError = url, time.Time{}, ""
				moved = true
			}
		}
		return nil, nil
	})
	if err != nil {
		return store.Subscription{}, 0, err
	}
	if moved {
		s.lift(id)
	}
	return st.Subscriptions[subscriptionIndex(st.Subscriptions, id)], next, nil
}

// RemoveSubscription removes subscription id and the servers that came from
// it, and returns the new revision; ErrNotFound if there is no such
// subscription. As with RemoveServer, a pin on a server that goes is cleared
// and the custom rules that send traffic through one are dropped, each with a
// cleanup event.
func (s *Service) RemoveSubscription(ctx context.Context, rev uint64, id string) (uint64, error) {
	_, next, err := s.change(rev, func(st *store.State) ([]note, error) {
		i := subscriptionIndex(st.Subscriptions, id)
		if i < 0 {
			return nil, notFound(*st, "subscription", id)
		}
		st.Subscriptions = slices.Delete(st.Subscriptions, i, i+1)
		var notes []note
		left := make([]store.Server, 0, len(st.Servers))
		for _, srv := range st.Servers {
			if srv.Subscription == id {
				notes = append(notes, forget(st, srv)...)
			} else {
				left = append(left, srv)
			}
		}
		st.Servers = left
		return notes, nil
	})
	if err != nil {
		return 0, err
	}
	s.lift(id)
	return next, nil
}

// RefreshResult is what a refresh did to a subscription's servers.
type RefreshResult struct {
	// Added servers are new; Updated ones kept their ID but not their link,
	// name or outbound; Kept ones are as they were; Removed ones are no
	// longer in the subscription.
	Added   int `json:"added"`
	Updated int `json:"updated"`
	Removed int `json:"removed"`
	Kept    int `json:"kept"`
	// Skipped are the lines that gave no server: those that did not parse,
	// and the servers that xray rejected. A rejected server's Err is xray's
	// words, redacted. Line may hold a credential, as a share link does.
	Skipped []subscription.Skipped `json:"skipped"`
	// Via is the route the list came by: "direct" or "proxy".
	Via string `json:"via"`
}

// RefreshSubscription downloads subscription id and merges its servers into
// the state, and returns what changed.
//
// The list is fetched directly, and through the proxy if that fails; a body
// that holds no server (a block page, the notice of an expired account) fails
// an attempt like an error status, so it is never merged. When both fail the
// error wraps ErrFetchFailed, and the subscription's LastError says why; the
// servers, and LastFetch, are as they were. Every server that is new or whose
// outbound changed is tested by the runner's xray, one at a time, and one that
// xray rejects is left out and listed in Skipped; when the runner can't test,
// they are saved all the same, with one untested event. If xray rejects every
// server the list holds, nothing is merged and the error is a *Refused.
//
// Then the list is merged as subscription.Merge does, which keeps the IDs. A
// pin on a server that is no longer listed is cleared and the custom rules
// that name one are dropped, each with a cleanup event, so that the state is
// valid. Fetching and testing take as long as they take and hold no lock; the
// state is written once, if it is still the one the refresh began with. When
// it is not, the merge is done again on the new state, once, with the
// entries already fetched and tested; a second change in the meantime ends
// the refresh with store.ErrConflict. Refreshes run one at a time.
//
// A kept server that has a reason in Invalid and gets a new outbound that
// passes the checks loses the reason, and stays Disabled, as with
// UpdateServer; the same outbound keeps it.
//
// A subscription that is disabled is not fetched: *Refused.
func (s *Service) RefreshSubscription(ctx context.Context, id string) (RefreshResult, error) {
	if err := s.acquireRefresh(ctx); err != nil {
		return RefreshResult{}, err
	}
	defer func() { <-s.refreshing }()

	st, rev := s.store.State()
	i := subscriptionIndex(st.Subscriptions, id)
	if i < 0 {
		return RefreshResult{}, notFound(st, "subscription", id)
	}
	sub := st.Subscriptions[i]
	if sub.Disabled {
		return RefreshResult{}, &Refused{Reason: fmt.Sprintf("subscription %s (%s) is disabled", sub.ID, sub.Name)}
	}

	var parsed subscription.Result
	f := s.fetcher(st)
	f.Accept = func(body []byte) error {
		r := subscription.Parse(body)
		if len(r.Entries) == 0 {
			return errors.New("no server in the body")
		}
		parsed = r
		return nil
	}
	_, via, err := f.Fetch(ctx, sub.URL)
	if err != nil {
		if ctx.Err() != nil {
			return RefreshResult{}, s.redactError(err)
		}
		reason := s.redact(err.Error())
		s.refreshFailed(sub, reason)
		return RefreshResult{}, fmt.Errorf("%w: %s", ErrFetchFailed, reason)
	}

	got, untested, err := s.testEntries(ctx, st, id, parsed)
	if err != nil {
		return RefreshResult{}, err
	}
	if len(got.entries) == 0 {
		// Nothing is left to merge, and merging nothing removes every server.
		reason := "xray rejected every server the subscription lists"
		s.refreshFailed(sub, reason)
		return RefreshResult{}, &Refused{Reason: reason}
	}
	got.url, got.via = sub.URL, via

	var extra []note
	if untested > 0 {
		extra = append(extra, note{KindUntested, fmt.Sprintf("subscription %s (%s): %d servers saved without a runner test", sub.ID, sub.Name, untested)})
	}
	var res RefreshResult
	merge := s.mergeFetched(id, got, &res)
	if _, _, err = s.change(rev, merge, extra...); errors.Is(err, store.ErrConflict) {
		_, rev = s.store.State()
		_, _, err = s.change(rev, merge, extra...)
	}
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			s.record(KindError, fmt.Sprintf("subscription %s (%s): the refresh was not stored: %v", sub.ID, sub.Name, err))
		}
		return RefreshResult{}, err
	}
	s.lift(id)
	return res, nil
}

// acquireRefresh takes the right to refresh, waiting until it is free or ctx
// ends.
func (s *Service) acquireRefresh(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("service: refreshing: %w", err)
	}
	select {
	case s.refreshing <- struct{}{}:
		return nil
	default:
	}
	if s.onWait != nil {
		s.onWait()
	}
	select {
	case s.refreshing <- struct{}{}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("service: waiting for another refresh: %w", ctx.Err())
	}
}

// fetched is what a refresh has to merge.
type fetched struct {
	url, via string
	// entries are what xray did not reject, in the list's order.
	entries []subscription.Entry
	// skipped are the lines of the list that gave no server, and the entries
	// that xray rejected.
	skipped []subscription.Skipped
}

// testEntries has the runner's xray test each entry of parsed that is new
// to subscription subID in st, or whose outbound differs from the server it
// would merge into, and returns what is left to merge. An entry that xray
// rejects goes to skipped, with xray's words redacted. When the runner can't
// test, that entry and those after it are left untested and merged all the
// same, and untested is how many: the trial of the apply is the net. An error
// is for a ctx that ends.
func (s *Service) testEntries(ctx context.Context, st store.State, subID string, parsed subscription.Result) (got fetched, untested int, err error) {
	got.skipped = append([]subscription.Skipped{}, parsed.Skipped...)
	// The merge is done on a copy to see which servers the entries would be:
	// Merge alone knows which entry keeps which. Its new IDs are not kept.
	merged := subscription.Merge(st.Servers, subID, parsed.Entries)
	before := map[string]store.Server{}
	for _, srv := range st.Servers {
		if srv.Subscription == subID {
			before[srv.ID] = srv
		}
	}
	would := slices.DeleteFunc(slices.Clone(merged), func(srv store.Server) bool { return srv.Subscription != subID })

	canTest := true
	for j, srv := range would {
		entry := parsed.Entries[j]
		if prev, ok := before[srv.ID]; ok && sameJSON(prev.Outbound, srv.Outbound) {
			got.entries = append(got.entries, entry)
			continue
		}
		var reason string
		if canTest {
			v, err := s.tryServer(ctx, srv)
			switch {
			case ctx.Err() != nil:
				return fetched{}, 0, s.redactError(fmt.Errorf("service: testing the servers of subscription %s: %w", subID, ctx.Err()))
			case err != nil:
				reason = err.Error()
			case v.unavailable != nil:
				canTest = false
			default:
				reason = v.rejected
			}
		}
		if reason != "" {
			// The runner's words repeat the entry's credentials; refuse
			// redacts them with those of the state it would have joined.
			with := st
			with.Servers = append(slices.Clone(st.Servers), srv)
			got.skipped = append(got.skipped, subscription.Skipped{Line: cutLine(entry.Link), Err: refuse(with, reason).Reason})
			continue
		}
		if !canTest {
			untested++
		}
		got.entries = append(got.entries, entry)
	}
	return got, untested, nil
}

// mergeFetched is the edit that merges got into subscription id of whatever
// state it is given, and leaves what it did in res; the edit can run twice.
// The events it returns are the refresh's, the cleanups' and the warnings'.
func (s *Service) mergeFetched(id string, got fetched, res *RefreshResult) edit {
	return func(st *store.State) ([]note, error) {
		i := subscriptionIndex(st.Subscriptions, id)
		if i < 0 {
			return nil, notFound(*st, "subscription", id)
		}
		sub := &st.Subscriptions[i]
		if sub.URL != got.url {
			// The list is the old address's: not for this subscription.
			return nil, store.ErrConflict
		}
		var olds []store.Server // the subscription's servers, in state order
		before := map[string]store.Server{}
		for _, srv := range st.Servers {
			if srv.Subscription == id {
				olds = append(olds, srv)
				before[srv.ID] = srv
			}
		}
		merged := subscription.Merge(st.Servers, id, got.entries)
		*res = RefreshResult{Skipped: got.skipped, Via: got.via}
		var warnings []note
		stays := map[string]bool{}
		j := 0 // the entry of the next server of the subscription
		for k := range merged {
			srv := &merged[k]
			if srv.Subscription != id {
				continue
			}
			stays[srv.ID] = true
			prev, ok := before[srv.ID]
			changed := !ok || !sameJSON(prev.Outbound, srv.Outbound)
			switch {
			case !ok:
				res.Added++
			case changed || prev.Link != srv.Link || prev.Name != srv.Name:
				res.Updated++
			default:
				res.Kept++
			}
			if changed {
				warnings = append(warnings, warningNotes(*srv, got.entries[j].Server.Warnings)...)
			}
			// Merge copies Invalid from the old server. A new outbound that
			// passes the checks (and the runner's test, which testEntries
			// did) clears it, as UpdateServer's does, and Disabled stays as
			// it is: enabling the server is for its owner. An outbound
			// that is the same keeps its reason.
			if ok && changed && srv.Invalid != "" && passesChecks(*srv) {
				srv.Invalid = ""
			}
			j++
		}
		st.Servers = merged
		var cleanup []note
		for _, srv := range olds {
			if !stays[srv.ID] {
				res.Removed++
				cleanup = append(cleanup, forget(st, srv)...)
			}
		}
		sub.LastFetch, sub.LastError = s.now().UTC(), ""

		notes := []note{{KindRefresh, fmt.Sprintf("subscription %s (%s): added %d, updated %d, removed %d, kept %d, skipped %d via %s",
			sub.ID, sub.Name, res.Added, res.Updated, res.Removed, res.Kept, len(res.Skipped), res.Via)}}
		return append(append(notes, cleanup...), warnings...), nil
	}
}

// errMoved is the edit's answer when the subscription a refresh failed for is
// gone, or points elsewhere now.
var errMoved = errors.New("service: the subscription is gone or points elsewhere")

// refreshFailed keeps reason as the LastError of the subscription, and records
// it as an error event; the servers and LastFetch are not touched. The
// scheduler leaves the subscription alone for min(1 h, Interval) after this.
// reason must be redacted already.
//
// It is the failure of the refresh of sub's URL. A subscription that was
// removed, or pointed at another URL, while that was fetched has nothing to
// answer for it: nothing is written, held or recorded.
func (s *Service) refreshFailed(sub store.Subscription, reason string) {
	var name string
	var wait time.Duration
	_, _, err := s.store.Update(store.AnyRevision, func(st *store.State) error {
		i := subscriptionIndex(st.Subscriptions, sub.ID)
		if i < 0 || st.Subscriptions[i].URL != sub.URL {
			return errMoved
		}
		cur := &st.Subscriptions[i]
		cur.LastError = reason
		name, wait = cur.Name, min(time.Hour, time.Duration(cur.Interval))
		return nil
	})
	if errors.Is(err, errMoved) {
		return
	}
	s.mu.Lock()
	s.holds[sub.ID] = s.now().Add(wait)
	s.mu.Unlock()
	if err != nil {
		reason += fmt.Sprintf(" (and the error could not be kept: %v)", err)
	}
	s.record(KindError, fmt.Sprintf("subscription %s (%s): %s", sub.ID, name, reason))
}

// passesChecks reports whether srv, with its reason for being invalid
// cleared, passes the store's checks of a server on its own: its name, its
// outbound and the outbound policy.
func passesChecks(srv store.Server) bool {
	srv.Invalid, srv.Subscription = "", ""
	st := store.Default()
	st.Servers = []store.Server{srv}
	return st.Validate() == nil
}

// lift ends the wait that a failed refresh put on subscription id.
func (s *Service) lift(id string) {
	s.mu.Lock()
	delete(s.holds, id)
	s.mu.Unlock()
}

// cutLine is the first maxLineRunes runes of a share link, as valid UTF-8.
func cutLine(link string) string {
	n := 0
	for i := range link {
		if n == maxLineRunes {
			link = link[:i]
			break
		}
		n++
	}
	return strings.ToValidUTF8(link, string(utf8.RuneError))
}

// sameJSON reports whether a and b are the same JSON value, whatever the order
// of the keys and the white space, with numbers as written. Text that is not
// JSON is the same only as itself.
func sameJSON(a, b json.RawMessage) bool {
	x, okA := decodeJSON(a)
	y, okB := decodeJSON(b)
	if !okA || !okB {
		return bytes.Equal(a, b)
	}
	return reflect.DeepEqual(x, y)
}

func decodeJSON(raw json.RawMessage) (any, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return nil, false
	}
	_, err := dec.Token()
	return v, errors.Is(err, io.EOF) // nothing after the value
}
