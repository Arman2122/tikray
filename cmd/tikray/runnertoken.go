package main

import (
	"context"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Arman2122/tikray/internal/runnerapi"
)

// tokenPoll is how often the runner's token file is read again while there is
// none. It is a variable for the tests.
var tokenPoll = time.Second

// runnerToken is the token of the runner, from <data>/run/runner.token. The
// runner makes it when it starts, and RouterOS starts both containers
// together, so tikray serve may be ready before it: it does not exit for that.
// The runner client (runnerapi.Client.TokenFunc) fails fast with
// runnerapi.ErrNoToken until the token is there (the status shows it as the
// runner's error, and the service takes it for a runner it can't reach), and
// reads it again at each call; watch reads it every tokenPoll, so that the
// service learns of it at once. Once read the token is kept, until the runner
// refuses it (runnerapi.Client.Unauthorized): a runner that restarts may make
// a new one, and drop has the next call read the file again.
type runnerToken struct {
	path string
	tok  atomic.Pointer[string]
}

// newRunnerToken reads the token if it is there.
func newRunnerToken(path string) *runnerToken {
	t := &runnerToken{path: path}
	t.ready()
	return t
}

// load returns the token, reading the file if it is not known yet, and
// whether there is one. A file that is empty holds no token: the runner may
// have made it and not yet written it. The token is read from tok once, and
// the value is what is used: drop may clear tok at any time.
func (t *runnerToken) load() (string, bool) {
	if p := t.tok.Load(); p != nil {
		return *p, true
	}
	b, err := os.ReadFile(t.path)
	if err != nil {
		return "", false
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", false
	}
	t.tok.Store(&tok)
	return tok, true
}

// ready reports whether the token is known, reading the file if it is not yet.
func (t *runnerToken) ready() bool {
	_, ok := t.load()
	return ok
}

// get is the runnerapi.Client.TokenFunc.
func (t *runnerToken) get(context.Context) (string, error) {
	tok, ok := t.load()
	if !ok {
		return "", runnerapi.ErrNoToken
	}
	return tok, nil
}

// drop is the runnerapi.Client.Unauthorized: it forgets the token the runner
// refused, unless another call has read a new one since.
func (t *runnerToken) drop(refused string) {
	if p := t.tok.Load(); p != nil && *p == refused {
		t.tok.CompareAndSwap(p, nil)
	}
}

// watch reads the token file every tokenPoll until the token is there, and
// calls found (if it is not nil) once. It returns without that when ctx ends.
func (t *runnerToken) watch(ctx context.Context, found func()) {
	for !t.ready() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(tokenPoll):
		}
	}
	if found != nil {
		found()
	}
}
