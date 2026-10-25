package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// tokenPoll is how often the runner's token file is read again while there is
// none. It is a variable for the tests.
var tokenPoll = time.Second

// errNoRunnerToken is what a call to the runner fails with while its token is
// not there. It shows in the status as the runner's error.
var errNoRunnerToken = errors.New("waiting for the runner token")

// runnerToken is the token of the runner, from <data>/run/runner.token. The
// runner makes it when it starts, and RouterOS starts both containers
// together, so tikray serve may be ready before it: it does not exit for that.
// The runner client (runnerapi.Client.TokenFunc) fails fast with
// errNoRunnerToken until the token is there, and reads it again at each call;
// watch reads it every tokenPoll, so that the service learns of it at once.
// Once read the token is kept.
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

// ready reports whether the token is known, reading the file if it is not yet.
// A file that is empty holds no token: the runner may have made it and not yet
// written it.
func (t *runnerToken) ready() bool {
	if t.tok.Load() != nil {
		return true
	}
	b, err := os.ReadFile(t.path)
	if err != nil {
		return false
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return false
	}
	t.tok.Store(&tok)
	return true
}

// get is the runnerapi.Client.TokenFunc.
func (t *runnerToken) get(context.Context) (string, error) {
	if !t.ready() {
		return "", errNoRunnerToken
	}
	return *t.tok.Load(), nil
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
