package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
)

func hasUntested(st store.State) bool {
	return slices.ContainsFunc(st.Servers, func(srv store.Server) bool { return srv.Untested })
}

// retest checks the servers that were saved without a core and reports whether
// the loop should try again. Its caller holds the apply lock: a core update
// cannot switch versions between the test and the write.
func (s *Service) retest(ctx context.Context) (retry bool) {
	st, rev := s.store.State()
	if !hasUntested(st) {
		return false
	}
	if ctx.Err() != nil {
		return true
	}
	rs, err := s.runner.Status(ctx)
	if err != nil {
		return true
	}
	if rs.State != runnerapi.StateRunning {
		// An empty runner waits for a core update. A trial or a restart
		// can finish without another kick.
		return rs.State == runnerapi.StateTrial || rs.State == runnerapi.StateRestarting
	}

	outbounds := make(map[string]json.RawMessage)
	for _, srv := range st.Servers {
		if srv.Untested {
			outbounds[srv.ID] = srv.Outbound
		}
	}
	rejected, err := s.testOutbounds(ctx, outbounds)
	if err != nil {
		return true
	}

	// The runner tested this revision. If an edit landed while it worked,
	// leave every verdict for the next pass rather than disabling a replacement.
	redact := RedactorFor(st)
	_, _, err = s.change(rev, func(next *store.State) ([]note, error) {
		var notes []note
		for i := range next.Servers {
			srv := &next.Servers[i]
			if !srv.Untested {
				continue
			}
			srv.Untested = false
			if why, bad := rejected[srv.ID]; bad {
				srv.Disabled, srv.Invalid = true, redact(why)
				notes = append(notes, note{KindDegraded, fmt.Sprintf("server %s disabled: %s", srv.ID, srv.Invalid)})
			}
		}
		return notes, nil
	})
	if err != nil && !errors.Is(err, store.ErrConflict) {
		s.record(KindError, fmt.Sprintf("could not save the server test results: %s", redact(err.Error())))
	}
	return err != nil
}
