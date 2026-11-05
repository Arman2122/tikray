package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/runnerapi"
)

type batchRunner struct {
	Runner
	test  func([]string) (runnerapi.TestResult, error)
	t     *testing.T
	calls int
}

func (r *batchRunner) Test(ctx context.Context, config []byte) (runnerapi.TestResult, error) {
	r.t.Helper()
	r.calls++
	if len(config) > 1<<20 {
		r.t.Fatal("test config exceeds the runner's request limit")
	}
	var body struct {
		Outbounds []struct{ Tag, Protocol string }
	}
	if err := json.Unmarshal(config, &body); err != nil {
		r.t.Fatal("invalid test config")
	}
	last := len(body.Outbounds) - 1
	if last < 1 || last > 32 || body.Outbounds[last].Tag != "direct" || body.Outbounds[last].Protocol != "freedom" {
		r.t.Fatal("test config must have 1 to 32 servers followed by direct")
	}
	ids := make([]string, last)
	for i, o := range body.Outbounds[:last] {
		id, ok := strings.CutPrefix(o.Tag, "srv-")
		if !ok || id == "" {
			r.t.Fatal("server outbound lacks its assigned tag")
		}
		ids[i] = id
	}
	return r.test(ids)
}

func batchInputs(n int) map[string]json.RawMessage {
	input := make(map[string]json.RawMessage, n)
	for i := range n {
		input[fmt.Sprintf("%08x", i)] = json.RawMessage(trojanOutbound)
	}
	return input
}

func TestBatchBisects(t *testing.T) {
	for _, tc := range []struct {
		name string
		bad  []string
	}{
		{"separate batches", []string{"0000000b", "000000a7"}},
		{"nearby rejections", []string{"00000001", "00000003"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := batchInputs(200)
			bad := tc.bad
			r := &batchRunner{t: t, test: func(ids []string) (runnerapi.TestResult, error) {
				for _, id := range bad {
					if slices.Contains(ids, id) {
						return runnerapi.TestResult{Output: "unknown user " + trojanPW}, nil
					}
				}
				return runnerapi.TestResult{OK: true}, nil
			}}
			e := newEnv(t)
			e.s.runner = r
			rejected, err := e.s.testOutbounds(t.Context(), input)
			if err != nil || len(rejected) != 2 {
				t.Fatal("expected both rejected servers")
			}
			for _, id := range bad {
				if rejected[id] != "xray rejected the server: unknown user "+redacted {
					t.Error("missing or unsafe singleton refusal")
				}
			}
			t.Logf("%d runner tests for two rejected servers in 200", r.calls)
			if r.calls > 20 {
				t.Errorf("%d runner tests for two rejected servers in 200; want at most 20", r.calls)
			}
		})
	}
}

func TestBatchRunnerDown(t *testing.T) {
	input := batchInputs(64)
	failure := fmt.Errorf("%w: %s", runnerapi.ErrNoCore, trojanPW)
	r := &batchRunner{t: t}
	r.test = func(ids []string) (runnerapi.TestResult, error) {
		if r.calls == 1 {
			return runnerapi.TestResult{OK: true}, nil
		}
		return runnerapi.TestResult{}, failure
	}
	e := newEnv(t)
	e.s.runner = r
	out, err := e.s.testOutboundSet(t.Context(), input)
	if !errors.Is(err, runnerapi.ErrNoCore) || strings.Contains(err.Error(), trojanPW) {
		t.Fatal("expected a safe runner error")
	}
	if len(out) != 32 || r.calls != 2 {
		t.Fatal("completed batch was lost or untested servers classified")
	}
	for id, reason := range out {
		if _, ok := input[id]; !ok || reason != "" {
			t.Fatal("wrong classification before failure")
		}
	}
}

func TestBatchRejectsOnlyConfirmedSingletons(t *testing.T) {
	input := batchInputs(3)
	r := &batchRunner{t: t, test: func(ids []string) (runnerapi.TestResult, error) {
		if len(ids) > 1 {
			return runnerapi.TestResult{Output: "incompatible together"}, nil
		}
		return runnerapi.TestResult{OK: true}, nil
	}}
	e := newEnv(t)
	e.s.runner = r
	out, err := e.s.testOutboundSet(t.Context(), input)
	if err != nil || len(out) != 3 {
		t.Fatal("expected three classified servers")
	}
	for _, reason := range out {
		if reason != "" {
			t.Error("a group rejection was attributed to an individual server")
		}
	}
}

func TestBatchConfigSizeAndMalformedInputs(t *testing.T) {
	raw := func(n int) json.RawMessage {
		return json.RawMessage(`{"protocol":"test","padding":"` + strings.Repeat("a", n) + `"}`)
	}
	input := map[string]json.RawMessage{"one": raw(700000), "two": raw(700000), "large": raw(1 << 20), "null": json.RawMessage("null")}
	r := &batchRunner{t: t, test: func(ids []string) (runnerapi.TestResult, error) {
		if len(ids) != 1 || (ids[0] != "one" && ids[0] != "two") {
			t.Fatal("unexpected servers or size in runner config")
		}
		return runnerapi.TestResult{OK: true}, nil
	}}
	e := newEnv(t)
	e.s.runner = r
	out, err := e.s.testOutbounds(t.Context(), input)
	if err != nil || len(out) != 2 || !strings.Contains(out["large"], "limit") || out["null"] == "" || r.calls != 2 {
		t.Error("expected two local refusals and separate tests of both valid servers")
	}
}

func TestBatchOmitsShortCredential(t *testing.T) {
	const short = "qz"
	input := map[string]json.RawMessage{"entry": json.RawMessage(`{"protocol":"trojan","settings":{"password":"` + short + `"}}`)}
	r := &batchRunner{t: t, test: func([]string) (runnerapi.TestResult, error) {
		return runnerapi.TestResult{Output: "password was " + short}, nil
	}}
	e := newEnv(t)
	e.s.runner = r
	out, err := e.s.testOutbounds(t.Context(), input)
	if err != nil || out["entry"] == "" || strings.Contains(out["entry"], short) {
		t.Error("a short credential appeared in the rejection or the verdict was lost")
	}
}

// An unchanged refresh needs neither a runner call nor a copy of the state.
func TestBatchEmpty(t *testing.T) {
	var s Service
	got, err := s.testOutbounds(t.Context(), nil)
	if err != nil || len(got) != 0 {
		t.Fatal("an empty set should have no results")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = s.testOutbounds(ctx, nil)
	if !errors.Is(err, context.Canceled) {
		t.Error("lost cancellation on an empty refresh")
	}
}

func TestBatchOmitsTruncatedCredential(t *testing.T) {
	for _, transport := range []bool{false, true} {
		prefix := trojanPW[:7]
		clipped := "refused: " + prefix + "\n[output truncated]"
		r := &batchRunner{t: t, test: func([]string) (runnerapi.TestResult, error) {
			if transport {
				return runnerapi.TestResult{}, errors.New(clipped)
			}
			return runnerapi.TestResult{Output: clipped}, nil
		}}
		e := newEnv(t)
		e.s.runner = r
		out, err := e.s.testOutbounds(t.Context(), batchInputs(1))
		if transport {
			if err == nil || strings.Contains(err.Error(), prefix) || len(out) != 0 {
				t.Error("truncated transport error leaked or produced a verdict")
			}
		} else if err != nil || out["00000000"] != "xray rejected the server" {
			t.Error("truncated refusal kept unsafe runner text or lost the verdict")
		}
	}
}
