package service

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/Arman2122/tikray/internal/store"
)

// ErrNotFound means that the server or the device a change names is not in the
// state. The error that wraps it names which.
var ErrNotFound = errors.New("service: not found")

// Refused is the error for a change tikray will not make: the state it would
// lead to fails the checks of store.State.Validate (xraypolicy's among them), a
// share link can't be read, or the runner's xray rejects the server. Reason
// is for the person who asked, with every secret of the state the change was
// about redacted (see RedactorFor).
//
// A change made on a revision that is no longer the current one is not
// refused: that is store.ErrConflict, as it is.
type Refused struct{ Reason string }

func (e *Refused) Error() string { return "refused: " + e.Reason }

// refuse returns a *Refused for text, redacted with the secrets of st, which
// is the state the refused change would have led to: it holds the new
// server's credentials, which xray's output repeats.
func refuse(st store.State, text string) *Refused {
	return &Refused{Reason: RedactorFor(st)(text)}
}

// validated returns nil if st passes store.State.Validate, and a *Refused
// with the problems, joined by "; ", if not.
func validated(st store.State) error {
	err := st.Validate()
	if err == nil {
		return nil
	}
	text := err.Error()
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		var problems []string
		for _, p := range j.Unwrap() {
			problems = append(problems, p.Error())
		}
		text = strings.Join(problems, "; ")
	}
	return refuse(st, text)
}

// notFound is ErrNotFound for the thing of the given kind, such as "server",
// named as the caller gave it, which is redacted with the secrets of st: a
// credential pasted where an ID goes must not come back in the error.
func notFound(st store.State, kind, which string) error {
	return fmt.Errorf("%w: %s %s", ErrNotFound, kind, RedactorFor(st)(which))
}

// note is an event to record once a change is written. record reads the
// state, so a change can't record from the function store.Update runs.
type note struct{ kind, msg string }

// edit changes a state and returns the events to record if the change is
// written.
type edit func(st *store.State) ([]note, error)

// change makes the edit at revision rev (store.AnyRevision skips the check)
// and returns the new state and revision. What it leaves the state as must
// pass Validate, or the change is refused (see Refused). After the write it
// records the events of the edit and extra, in that order, and kicks the
// apply loop. On an error nothing is written, recorded or kicked.
func (s *Service) change(rev uint64, fn edit, extra ...note) (store.State, uint64, error) {
	var notes []note
	st, next, err := s.store.Update(rev, func(st *store.State) (err error) {
		if notes, err = fn(st); err != nil {
			return err
		}
		// Update validates too, but it can't tell a refusal from a write
		// that failed, and it knows no secrets to redact.
		return validated(*st)
	})
	if err != nil {
		return store.State{}, 0, err
	}
	for _, n := range append(notes, extra...) {
		s.record(n.kind, n.msg)
	}
	s.Kick()
	return st, next, nil
}

// set is change for an edit that can't fail and has nothing to record.
func (s *Service) set(rev uint64, fn func(st *store.State)) (uint64, error) {
	_, next, err := s.change(rev, func(st *store.State) ([]note, error) {
		fn(st)
		return nil, nil
	})
	return next, err
}

// preview returns the state that the edit leads to from the current one,
// checked as change checks it, so that a refusal or a stale revision comes
// before anything slow is done for the change. It writes and records nothing.
func (s *Service) preview(rev uint64, fn edit) (store.State, error) {
	st, cur := s.store.State()
	if rev != store.AnyRevision && rev != cur {
		return store.State{}, store.ErrConflict
	}
	if _, err := fn(&st); err != nil {
		return store.State{}, err
	}
	if err := validated(st); err != nil {
		return store.State{}, err
	}
	return st, nil
}

// SetDevice adds a device, or replaces the one with the same address (in
// place), and returns the new revision.
func (s *Service) SetDevice(ctx context.Context, rev uint64, d store.Device) (uint64, error) {
	return s.set(rev, func(st *store.State) {
		if i := slices.IndexFunc(st.Devices, func(o store.Device) bool { return o.Address == d.Address }); i >= 0 {
			st.Devices[i] = d
		} else {
			st.Devices = append(st.Devices, d)
		}
	})
}

// RemoveDevice removes the device with address addr and returns the new
// revision; ErrNotFound if there is none.
func (s *Service) RemoveDevice(ctx context.Context, rev uint64, addr netip.Prefix) (uint64, error) {
	_, next, err := s.change(rev, func(st *store.State) ([]note, error) {
		i := slices.IndexFunc(st.Devices, func(d store.Device) bool { return d.Address == addr })
		if i < 0 {
			return nil, notFound(*st, "device", addr.String())
		}
		st.Devices = slices.Delete(st.Devices, i, i+1)
		return nil, nil
	})
	return next, err
}

// SetDefaultPolicy sets the policy of the devices that are not listed and
// returns the new revision.
func (s *Service) SetDefaultPolicy(ctx context.Context, rev uint64, p store.Policy) (uint64, error) {
	return s.set(rev, func(st *store.State) { st.DefaultPolicy = p })
}

// SetRouting replaces the routing, the pin and the custom rules included, and
// returns the new revision.
func (s *Service) SetRouting(ctx context.Context, rev uint64, r store.Routing) (uint64, error) {
	return s.set(rev, func(st *store.State) { st.Routing = r })
}

// SetDNS replaces the resolvers and returns the new revision.
func (s *Service) SetDNS(ctx context.Context, rev uint64, d store.DNS) (uint64, error) {
	return s.set(rev, func(st *store.State) { st.DNS = d })
}

// SetHealth replaces the connectivity probe's settings and returns the new
// revision.
func (s *Service) SetHealth(ctx context.Context, rev uint64, h store.Health) (uint64, error) {
	return s.set(rev, func(st *store.State) { st.Health = h })
}
