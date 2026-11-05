package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
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

// A provider-wide template that the installed core refuses makes every new
// entry of a refresh fail. Testing each entry alone costs 200 runner calls;
// the batches may add only their first round to that.
func TestRefreshAllRefusedCallCount(t *testing.T) {
	e, feed := newSubEnv(t)
	sub, _ := e.addSub("provider", feedLink(1, "seed"))
	var links []string
	for n := 2; n < 202; n++ {
		links = append(links, feedLink(n, fmt.Sprintf("entry-%d", n)))
	}
	feed.setDirect(okFeed(feedBody(links...)))
	e.runner.setTestReject("xray failed to load config (exit 23)")

	_, err := e.s.RefreshSubscription(bg, sub.ID)
	if err == nil || !strings.Contains(err.Error(), "rejected every server") {
		t.Fatalf("want the every-server refusal, got %v", show(err))
	}
	if got, limit := len(e.runner.gotTests()), callLimit(200); got > limit {
		t.Errorf("%d runner tests for 200 refused entries; want at most %d", got, limit)
	}
}

// callLimit is what testBatchGroups may spend on n small servers: one call per
// server, as testing each alone costs, and the first round of groups.
func callLimit(n int) int { return n + (n+maxBatch-1)/maxBatch }

// batchSim runs testBatchGroups on n small servers.
type batchSim struct {
	outs  []testOutbound
	index map[string]int
}

func newBatchSim(n int) *batchSim {
	s := &batchSim{outs: make([]testOutbound, n), index: make(map[string]int, n)}
	for i := range s.outs {
		s.outs[i] = testOutbound{id: fmt.Sprintf("%08x", i), json: []byte(`{"protocol":"trojan"}`)}
		s.index[s.outs[i].id] = i
	}
	return s
}

// run tests the servers with a runner that refuses a config that holds a
// server in bad or both servers of a conflict: it refuses a bad server alone,
// but neither server of a conflict.
func (s *batchSim) run(t *testing.T, bad map[int]bool, conflicts [][2]int) (calls int, results map[string]string) {
	t.Helper()
	results = make(map[string]string, len(s.outs))
	refused, in := make([]bool, len(s.outs)), make([]bool, len(s.outs))
	for i, b := range bad {
		refused[i] = b
	}
	test := func(group []testOutbound) (bool, error) {
		calls++
		ok := true
		for _, out := range group {
			i := s.index[out.id]
			in[i] = true
			ok = ok && !refused[i]
		}
		for _, c := range conflicts {
			ok = ok && !(in[c[0]] && in[c[1]])
		}
		for _, out := range group {
			in[s.index[out.id]] = false
		}
		if ok {
			for _, out := range group {
				results[out.id] = ""
			}
		} else if len(group) == 1 {
			results[group[0].id] = "rejected"
		}
		return ok, nil
	}
	if err := testBatchGroups(slices.Clone(s.outs), results, test); err != nil {
		t.Fatal(err)
	}
	return calls, results
}

// check fails unless every server has a result and exactly those in bad are
// refused.
func (s *batchSim) check(t *testing.T, bad map[int]bool, results map[string]string, setting string) {
	t.Helper()
	if len(results) != len(s.outs) {
		t.Fatalf("%s: %d of %d servers classified", setting, len(results), len(s.outs))
	}
	for i, out := range s.outs {
		if refused := results[out.id] != ""; refused != bad[i] {
			t.Fatalf("%s: server %d refused=%t, want %t", setting, i, refused, bad[i])
		}
	}
}

// Whatever the share of refused servers and wherever they are, batching costs
// at most testing each server alone plus the first round of groups.
func TestBatchCallBound(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for _, n := range []int{1, 2, 5, 31, 32, 33, 64, 200} {
		sim := newBatchSim(n)
		// Twenty or so densities from none refused to all of them.
		var densities []int
		for k := 0; k < n; k += max(1, n/20) {
			densities = append(densities, k)
		}
		for _, k := range append(densities, n) {
			for trial := range 20 {
				bad := make(map[int]bool, k)
				for _, i := range rng.Perm(n)[:k] {
					bad[i] = true
				}
				calls, results := sim.run(t, bad, nil)
				setting := fmt.Sprintf("n=%d bad=%d trial %d", n, k, trial)
				sim.check(t, bad, results, setting)
				if calls > callLimit(n) {
					t.Fatalf("%s: %d runner calls; want at most %d", setting, calls, callLimit(n))
				}
			}
		}
	}
}

// Sparse refusals keep their small cost: one refused server among 200 in at
// most 17 calls and two, wherever they are, in at most 20.
func TestBatchSparseRefusalsCost(t *testing.T) {
	sim := newBatchSim(200)
	for a := range 200 {
		bad := map[int]bool{a: true}
		calls, results := sim.run(t, bad, nil)
		sim.check(t, bad, results, fmt.Sprintf("bad %d", a))
		if calls > 17 {
			t.Fatalf("%d runner calls for server %d refused among 200; want at most 17", calls, a)
		}
	}
	for a := range 200 {
		for b := a + 1; b < 200; b++ {
			bad := map[int]bool{a: true, b: true}
			calls, results := sim.run(t, bad, nil)
			sim.check(t, bad, results, fmt.Sprintf("bad %d and %d", a, b))
			if calls > 20 {
				t.Fatalf("%d runner calls for servers %d and %d refused among 200; want at most 20", calls, a, b)
			}
		}
	}
}

// A pair that the runner refuses only together blames neither server, alone
// or beside a server that is refused on its own, and the bound still holds.
func TestBatchGroupOnlyConflictBlamesNoOne(t *testing.T) {
	for _, n := range []int{2, 5, 32, 33, 64, 200} {
		sim := newBatchSim(n)
		for a := range n {
			for b := a + 1; b < n; b++ {
				calls, results := sim.run(t, nil, [][2]int{{a, b}})
				setting := fmt.Sprintf("n=%d conflict %d,%d", n, a, b)
				sim.check(t, nil, results, setting)
				if calls > callLimit(n) {
					t.Fatalf("%s: %d runner calls; want at most %d", setting, calls, callLimit(n))
				}
			}
		}
	}
	rng := rand.New(rand.NewPCG(7, 7))
	sims := make(map[int]*batchSim)
	for trial := range 20000 {
		n := 2 + rng.IntN(199)
		perm := rng.Perm(n)
		bad := map[int]bool{}
		var conflicts [][2]int
		if n >= 3 {
			bad[perm[0]] = true
			conflicts = append(conflicts, [2]int{perm[1], perm[2]})
		}
		if n >= 6 {
			bad[perm[3]] = true
			conflicts = append(conflicts, [2]int{perm[4], perm[5]})
		}
		if sims[n] == nil {
			sims[n] = newBatchSim(n)
		}
		calls, results := sims[n].run(t, bad, conflicts)
		setting := fmt.Sprintf("trial %d: n=%d bad=%v conflicts=%v", trial, n, bad, conflicts)
		sims[n].check(t, bad, results, setting)
		if calls > callLimit(n) {
			t.Fatalf("%s: %d runner calls; want at most %d", setting, calls, callLimit(n))
		}
	}
}
