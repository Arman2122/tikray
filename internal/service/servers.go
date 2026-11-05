package service

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/Arman2122/tikray/internal/sharelink"
	"github.com/Arman2122/tikray/internal/store"
)

// serverIndex is the position of the server id in servers, or -1.
func serverIndex(servers []store.Server, id string) int {
	return slices.IndexFunc(servers, func(srv store.Server) bool { return srv.ID == id })
}

// serverIn returns the server id of st, which must hold it.
func serverIn(st store.State, id string) store.Server { return st.Servers[serverIndex(st.Servers, id)] }

// source is the outbound that a request brings, and what it was made from.
type source struct {
	// name is the share link's name for the server, empty for raw JSON.
	name string
	// link is the share link, trimmed, empty for raw JSON.
	link     string
	outbound json.RawMessage
	// warnings are what the parser changed or ignored in the link, for the
	// warning events of the server saved from it.
	warnings []string
}

// warningNotes are the warning events for srv, saved from a link whose parser
// gave warnings: one each.
func warningNotes(srv store.Server, warnings []string) []note {
	notes := make([]note, len(warnings))
	for i, w := range warnings {
		notes[i] = note{KindWarning, fmt.Sprintf("server %s (%s): %s", srv.ID, srv.Name, w)}
	}
	return notes
}

// parseSource reads the share link or the raw outbound that a request
// brings, exactly one of which must be set. A raw outbound loses its tag,
// which tikray assigns.
func (s *Service) parseSource(link *string, raw json.RawMessage) (source, error) {
	switch {
	case link != nil && len(raw) > 0:
		return source{}, &Refused{Reason: "give a share link or an outbound, not both"}
	case link != nil:
		l := strings.TrimSpace(*link)
		sv, err := sharelink.Parse(l)
		if err != nil {
			// The parser repeats nothing of a link, but the link is a
			// credential: redact it from the text all the same.
			st, _ := s.store.State()
			st.Servers = append(st.Servers, store.Server{Link: l})
			return source{}, refuse(st, err.Error())
		}
		return source{name: sv.Name, link: l, outbound: sv.Outbound, warnings: sv.Warnings}, nil
	case len(raw) > 0:
		return source{outbound: withoutTag(raw)}, nil
	}
	return source{}, &Refused{Reason: "give a share link or an outbound"}
}

// withoutTag returns the JSON object raw without its tag keys, in any case
// (xray reads its keys without regard to case). Anything else, and an object
// with no tag, comes back as it is: Validate refuses what is not an outbound.
func withoutTag(raw json.RawMessage) json.RawMessage {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return raw
	}
	n := len(obj)
	for k := range obj {
		if strings.EqualFold(k, "tag") {
			delete(obj, k)
		}
	}
	if len(obj) == n {
		return raw
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return raw
	}
	return out
}

// testServer previews a server edit before testing its outbound. The edit it
// returns saves the verdict with that very outbound, in the same state write.
func (s *Service) testServer(ctx context.Context, rev uint64, id string, fn edit) (edit, error) {
	next, err := s.preview(rev, fn)
	if err != nil {
		return nil, err
	}
	srv := serverIn(next, id)
	rejected, err := s.testOutbounds(ctx, map[string]json.RawMessage{id: srv.Outbound})
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if reason := rejected[id]; reason != "" {
		return nil, refuse(next, reason)
	}
	var pending *note
	if err != nil {
		label := testLabel(next, id, srv.Name)
		why := RedactorFor(next)(s.runnerError(ctx, err).Error())
		pending = &note{KindUntested, fmt.Sprintf("server %s saved without xray's test of it: %s", label, why)}
	}
	return func(st *store.State) ([]note, error) {
		notes, err := fn(st)
		if err != nil {
			return nil, err
		}
		srv := &st.Servers[serverIndex(st.Servers, id)]
		srv.Untested = pending != nil
		if pending != nil {
			notes = append(notes, *pending)
		}
		return notes, nil
	}, nil
}

// A display name is user input and can itself contain an outbound credential.
// Keep the public ID when it is unsafe to include the name in a test event.
func testLabel(st store.State, id, name string) string {
	if name = batchRedactor(st, nil)(name); name != "" {
		return id + " (" + name + ")"
	}
	return id
}

// NewServer is a server to add: from a share link, or from an xray outbound
// object. Exactly one of Link and Outbound is set. A Name overrides the
// link's own; an outbound has none, so it needs one. A "tag" key in an
// outbound is dropped.
type NewServer struct {
	Link     string
	Name     string
	Outbound json.RawMessage
}

// AddServer adds a server, with a new ID, and returns it and the new
// revision. rev is the revision the caller read, or store.AnyRevision.
//
// The server's outbound is tested first, by the runner's xray in a config of
// its own: one that xray rejects is refused, with xray's words, redacted. When
// no xray is there to test (the runner can't be reached, or no core runs), the
// server is saved all the same, with an untested event. What the parser
// ignored in a link (its warnings) is recorded as one warning event each,
// once the server is saved.
func (s *Service) AddServer(ctx context.Context, rev uint64, n NewServer) (store.Server, uint64, error) {
	var link *string
	if strings.TrimSpace(n.Link) != "" {
		link = &n.Link
	}
	src, err := s.parseSource(link, n.Outbound)
	if err != nil {
		return store.Server{}, 0, err
	}
	srv := store.Server{ID: store.NewID(), Name: cmp.Or(n.Name, src.name), Link: src.link, Outbound: src.outbound}
	add := func(st *store.State) ([]note, error) {
		st.Servers = append(st.Servers, srv)
		return warningNotes(srv, src.warnings), nil
	}
	tested, err := s.testServer(ctx, rev, srv.ID, add)
	if err != nil {
		return store.Server{}, 0, err
	}
	st, next, err := s.change(rev, tested)
	if err != nil {
		return store.Server{}, 0, err
	}
	return serverIn(st, srv.ID), next, nil
}

// ServerPatch is a change to a server: each field that is set replaces the
// server's. A Link or an Outbound (not both) replaces its outbound, clears
// Invalid, and is tested like a new server's; an Outbound also clears the
// server's Link, which no longer describes it. A Link takes no name from the
// share link. A server that Open disabled stays disabled until a patch says
// otherwise.
type ServerPatch struct {
	Name     *string
	Disabled *bool
	Link     *string
	Outbound json.RawMessage
}

// UpdateServer changes server id as p says and returns it and the new
// revision; ErrNotFound if there is no such server. The runner tests a new
// link or outbound as AddServer's does, and no other change; a new link's
// warnings are recorded as AddServer's are.
func (s *Service) UpdateServer(ctx context.Context, rev uint64, id string, p ServerPatch) (store.Server, uint64, error) {
	var src source
	replace := p.Link != nil || len(p.Outbound) > 0
	if replace {
		var err error
		if src, err = s.parseSource(p.Link, p.Outbound); err != nil {
			return store.Server{}, 0, err
		}
	}
	patch := func(st *store.State) ([]note, error) {
		i := serverIndex(st.Servers, id)
		if i < 0 {
			return nil, notFound(*st, "server", id)
		}
		srv := &st.Servers[i]
		if p.Name != nil {
			srv.Name = *p.Name
		}
		if p.Disabled != nil {
			srv.Disabled = *p.Disabled
		}
		if replace {
			srv.Link, srv.Outbound, srv.Invalid = src.link, src.outbound, ""
		}
		return warningNotes(*srv, src.warnings), nil
	}
	if replace {
		var err error
		if patch, err = s.testServer(ctx, rev, id, patch); err != nil {
			return store.Server{}, 0, err
		}
	}
	st, next, err := s.change(rev, patch)
	if err != nil {
		return store.Server{}, 0, err
	}
	return serverIn(st, id), next, nil
}

// RemoveServer removes server id and returns the new revision; ErrNotFound if
// there is no such server. A pin on it is cleared and the custom rules that
// send traffic through it are dropped, each with a cleanup event: the state
// would be invalid otherwise.
func (s *Service) RemoveServer(ctx context.Context, rev uint64, id string) (uint64, error) {
	_, next, err := s.change(rev, func(st *store.State) ([]note, error) {
		i := serverIndex(st.Servers, id)
		if i < 0 {
			return nil, notFound(*st, "server", id)
		}
		srv := st.Servers[i]
		st.Servers = slices.Delete(st.Servers, i, i+1)
		return forget(st, srv), nil
	})
	return next, err
}

// forget clears the pin on srv, a server that st no longer holds, and drops
// the custom rules that send traffic through it, and returns a cleanup event
// for the pin, if it cleared one, and one for the rules, if it dropped any.
// The state would be invalid otherwise.
func forget(st *store.State, srv store.Server) []note {
	var notes []note
	if st.Routing.Pinned == srv.ID {
		st.Routing.Pinned = ""
		notes = append(notes, note{KindCleanup, fmt.Sprintf("server %s (%s) removed: the pin on it is cleared", srv.ID, srv.Name)})
	}
	before := len(st.Routing.Rules)
	st.Routing.Rules = slices.DeleteFunc(st.Routing.Rules, func(r store.Rule) bool {
		return r.Action == store.ActionServer && r.Server == srv.ID
	})
	if n := before - len(st.Routing.Rules); n > 0 {
		notes = append(notes, note{KindCleanup, fmt.Sprintf("server %s (%s) removed: %d custom routing rule(s) that sent traffic through it are dropped", srv.ID, srv.Name, n)})
	}
	return notes
}
