package service

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/store"
)

func TestEventsRing(t *testing.T) {
	e := newEnv(t)
	for i := 1; i <= 250; i++ {
		e.s.record(KindApply, fmt.Sprintf("event %d", i))
	}
	all := e.s.Events(0)
	if len(all) != 200 {
		t.Fatalf("Events(0) has %d events, want the last 200", len(all))
	}
	for i, ev := range all {
		if want := uint64(51 + i); ev.Seq != want || ev.Message != fmt.Sprintf("event %d", want) || ev.Kind != KindApply {
			t.Fatalf("event %d = %+v, want seq %d", i, ev, want)
		}
		if !ev.At.Equal(t0) {
			t.Fatalf("event %d is at %v, want the service's clock, %v", i, ev.At, t0)
		}
	}
	if got := e.s.Events(240); len(got) != 10 || got[0].Seq != 241 || got[9].Seq != 250 {
		t.Errorf("Events(240) = %+v, want 241 to 250", got)
	}
	if got := e.s.Events(10); len(got) != 200 || got[0].Seq != 51 {
		t.Errorf("Events(10) has %d events, want the 200 the ring holds, from 51", len(got))
	}
	if got := e.s.Events(250); got == nil || len(got) != 0 {
		t.Errorf("Events(250) = %#v, want an empty list", got)
	}
}

// Every event goes through the redactor before it is kept or logged.
func TestEventsAreRedacted(t *testing.T) {
	e := newEnv(t)
	e.addServer("v", vlessOutbound)
	var log strings.Builder
	e.s = e.newService(Config{Log: &log})
	e.s.record(KindError, "xray says: user "+vlessID+" is invalid")
	evs := e.s.Events(0)
	if len(evs) != 1 {
		t.Fatalf("%d events, want 1", len(evs))
	}
	if evs[0].Message != "xray says: user "+redacted+" is invalid" {
		t.Errorf("the event holds %q, want the id redacted", strings.ReplaceAll(evs[0].Message, vlessID, "<the id>"))
	}
	if got := log.String(); got != "error: xray says: user "+redacted+" is invalid\n" {
		t.Errorf("the log has %q, want the redacted event", strings.ReplaceAll(got, vlessID, "<the id>"))
	}
}

// What Open disabled becomes one degraded event per server; Status lists
// every server that carries a reason, the ones an earlier start disabled
// too.
func TestDegradedServers(t *testing.T) {
	data := t.TempDir()
	dir := filepath.Join(data, "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	st := store.Default()
	st.Servers = []store.Server{
		{ID: "0000000a", Name: "earlier", Disabled: true, Invalid: "an older reason", Outbound: json.RawMessage(`{"protocol":"direct"}`)},
		{ID: "0000000b", Name: "fine", Outbound: json.RawMessage(`{"protocol":"vless"}`)},
		{ID: "0000000c", Name: "refused", Outbound: json.RawMessage(`{"protocol":"direct"}`)},
	}
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.v1.json"), fmt.Appendf(nil, `{"version":1,"revision":4,"state":%s}`, raw), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t)
	e.s = e.newService(Config{Store: s, Data: data})

	var degraded []Event
	for _, ev := range e.s.Events(0) {
		if ev.Kind == KindDegraded {
			degraded = append(degraded, ev)
		}
	}
	held, _ := s.State()
	want := "server 0000000c (refused) disabled: " + held.Servers[2].Invalid
	if len(degraded) != 1 || degraded[0].Message != want || held.Servers[2].Invalid == "" {
		t.Errorf("degraded events %+v, want one: %q", degraded, want)
	}
	if got := e.s.Status(bg).Degraded; !slices.Equal(got, []string{"0000000a", "0000000c"}) {
		t.Errorf("Status.Degraded = %v, want the servers that carry a reason", got)
	}
	if got := newEnv(t).s.Status(bg).Degraded; got == nil || len(got) != 0 {
		t.Errorf("Status.Degraded with no degraded server = %#v, want an empty list", got)
	}
}
