package service

import (
	"fmt"
	"time"
)

// Kinds of Event.
const (
	// KindApply: an apply, by the loop or by ApplyNow, and how it ended.
	KindApply = "apply"
	// KindCore: a core update or rollback, and how it ended.
	KindCore = "core"
	// KindRefresh: a subscription refresh.
	KindRefresh = "refresh"
	// KindDegraded: a server that Open disabled, as this tikray refuses it.
	KindDegraded = "degraded"
	// KindUntested: a server saved without the runner's test of it.
	KindUntested = "untested"
	// KindCleanup: a pin cleared or a rule dropped because its server went.
	KindCleanup = "cleanup"
	// KindWarning: something the share-link parser changed or ignored in a
	// server that was saved from the link, such as an allowInsecure.
	KindWarning = "warning"
	// KindError: a failure outside any of the above, such as a state that
	// does not render.
	KindError = "error"
)

// maxEvents is how many events the service keeps.
const maxEvents = 200

// Event is one thing the service did or found. Seq grows by one with each
// event; Message is redacted.
type Event struct {
	Seq     uint64    `json:"seq"`
	At      time.Time `json:"at"`
	Kind    string    `json:"kind"`
	Message string    `json:"message"`
}

// Events returns the events kept whose Seq is above after, oldest first: of
// the last 200, those that came after. It is an empty list when there are
// none.
func (s *Service) Events(after uint64) []Event {
	s.emu.Lock()
	defer s.emu.Unlock()
	i := 0
	if n := len(s.events); n > 0 && after >= s.events[0].Seq {
		i = int(min(after-s.events[0].Seq+1, uint64(n)))
	}
	return append([]Event{}, s.events[i:]...)
}

// record keeps an event of kind with msg, redacted, and writes it to the log.
// It is the one way an event is made. It reads the state to redact, so it
// must not be called from the function a store.Update runs.
func (s *Service) record(kind, msg string) {
	msg = s.redact(msg)
	s.emu.Lock()
	defer s.emu.Unlock()
	s.seq++
	if len(s.events) == maxEvents {
		s.events = append(s.events[:0], s.events[1:]...)
	}
	s.events = append(s.events, Event{Seq: s.seq, At: s.now().UTC(), Kind: kind, Message: msg})
	if s.log != nil {
		fmt.Fprintf(s.log, "%s: %s\n", kind, msg)
	}
}
