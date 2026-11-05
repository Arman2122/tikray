package service

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"math/bits"
	"slices"
	"strings"

	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
)

const (
	maxBatch   = 32
	testPrefix = `{"outbounds":[`
	testSuffix = `{"protocol":"freedom","tag":"direct"}]}`
)

type testOutbound struct {
	id   string
	json []byte
}

// testOutbounds returns only refusals; callers that need to know how far the
// runner got before an error use testOutboundSet instead.
func (s *Service) testOutbounds(ctx context.Context, outbounds map[string]json.RawMessage) (map[string]string, error) {
	results, err := s.testOutboundSet(ctx, outbounds)
	maps.DeleteFunc(results, func(_ string, reason string) bool { return reason == "" })
	return results, err
}

// testOutboundSet records only confirmed results by server ID. A pass has an
// empty reason. An interrupted refresh can keep these results and leave only
// the remaining servers marked for another test.
func (s *Service) testOutboundSet(ctx context.Context, outbounds map[string]json.RawMessage) (map[string]string, error) {
	if len(outbounds) == 0 || ctx.Err() != nil {
		return nil, ctx.Err()
	}
	results := make(map[string]string)
	st, _ := s.store.State()
	// Most batches pass without diagnostics. Parse their secrets only if
	// a message will actually leave this function.
	var redact func(string) string
	redactDetail := func(detail string) string {
		if redact == nil {
			redact = batchRedactor(st, slices.Collect(maps.Values(outbounds)))
		}
		if safe := redact(detail); safe != "" {
			return ": " + safe
		}
		return ""
	}
	var remaining []testOutbound
	for _, id := range slices.Sorted(maps.Keys(outbounds)) {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(outbounds[id], &object); err != nil || object == nil {
			results[id] = "server outbound is not a JSON object"
			continue
		}
		for k := range object {
			if strings.EqualFold(k, "tag") {
				delete(object, k)
			}
		}
		tag, _ := json.Marshal(store.ServerTagPrefix + id)
		object["tag"] = tag
		raw, err := json.Marshal(object)
		if err != nil {
			results[id] = "server outbound is not valid JSON"
			continue
		}
		if len(testPrefix)+len(raw)+1+len(testSuffix) > runnerapi.MaxTestBody {
			results[id] = "server outbound exceeds the runner's test-config size limit"
			continue
		}
		remaining = append(remaining, testOutbound{id, raw})
	}

	// A passing config confirms all of its servers. A failing one only
	// identifies an individual server when tested on its own.
	test := func(group []testOutbound) (bool, error) {
		config := []byte(testPrefix)
		for _, out := range group {
			config = append(config, out.json...)
			config = append(config, ',')
		}
		config = append(config, testSuffix...)
		res, err := s.runner.Test(ctx, config)
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if err != nil {
			return false, &redactedError{err: err, text: "service: runner test failed" + redactDetail(err.Error())}
		}
		if res.OK {
			for _, out := range group {
				results[out.id] = ""
			}
		} else if len(group) == 1 {
			results[group[0].id] = "xray rejected the server" + redactDetail(runnerapi.RefusalReason(res.Output))
		}
		return res.OK, nil
	}

	err := testBatchGroups(remaining, results, test)
	return results, err
}

// testBatchGroups partitions the outbounds into configs the runner can take.
// Test records passes and singleton refusals in results. A failed group alone
// never identifies which member was refused.
//
// It costs at most what testing each server alone does, one call per server,
// the first round of groups and batchSlack. After that round, a call that may
// classify nobody is made only while the slack and the servers that passing
// groups classified pay for it; once nothing is left to, the rest are tested
// alone. Dense refusals would otherwise cost several probes for each refused
// server.
func testBatchGroups(remaining []testOutbound, results map[string]string, test func([]testOutbound) (bool, error)) error {
	b := &batchSearch{results: results, test: test, spare: batchSlack(len(remaining))}
	err := b.search(remaining)
	if errors.Is(err, errOverBudget) {
		err = b.alone(remaining)
	}
	return err
}

// batchSlack is ceil(log2(min(n, maxBatch))) + 1: enough calls to probe a
// failed group of the largest size for its index, and one more. Without it, a
// batch of one group, or of groups that all failed, has classified nobody to
// pay for a probe, and one refused server would cost a test of each.
func batchSlack(n int) int {
	return bits.Len(uint(max(min(n, maxBatch), 1)-1)) + 1
}

// errOverBudget ends a batch search when one more grouped call could take it
// past its budget, so that each remaining server is tested alone.
var errOverBudget = errors.New("service: batch test over budget")

// batchSearch is the account of one testBatchGroups.
type batchSearch struct {
	results map[string]string
	test    func([]testOutbound) (bool, error)
	// charged is set once the first round of groups is over.
	charged bool
	// spare is batchSlack and the servers classified so far, less the calls
	// charged: how many more calls may classify nobody without the charged
	// calls outnumbering the servers and the slack.
	spare int
}

func (b *batchSearch) done(out testOutbound) bool {
	_, done := b.results[out.id]
	return done
}

func (b *batchSearch) open(group []testOutbound) int {
	n := 0
	for _, out := range group {
		if !b.done(out) {
			n++
		}
	}
	return n
}

// call tests group, or returns errOverBudget if the account cannot pay for a
// call that may classify nobody. A server without a result that is tested
// alone always gets one, so that call pays for itself.
func (b *batchSearch) call(group []testOutbound) (bool, error) {
	open := b.open(group)
	if b.charged && b.spare < 1 && (len(group) != 1 || open != 1) {
		return false, errOverBudget
	}
	ok, err := b.test(group)
	b.spare += open - b.open(group)
	if b.charged {
		b.spare--
	}
	return ok, err
}

// alone tests each server of group that has no result on its own.
func (b *batchSearch) alone(group []testOutbound) error {
	for i := range group {
		if !b.done(group[i]) {
			if _, err := b.call(group[i : i+1]); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b *batchSearch) search(remaining []testOutbound) error {
	for len(remaining) > 0 {
		limit := maxBatch
		// For a large list, balance the groups without adding a runner
		// call. Smaller failed groups take fewer probes to isolate.
		if n := len(remaining); n > 2*maxBatch {
			groups := (n + maxBatch - 1) / maxBatch
			limit = (n + groups - 1) / groups
		}
		var failed [][]testOutbound
		check := func(group []testOutbound) error {
			ok, err := b.call(group)
			if err == nil && !ok && len(group) > 1 {
				failed = append(failed, group)
			}
			return err
		}
		for rest := remaining; len(rest) > 0; {
			size, end := len(testPrefix)+len(testSuffix), 0
			for end < min(limit, len(rest)) && size+len(rest[end].json)+1 <= runnerapi.MaxTestBody {
				size += len(rest[end].json) + 1
				end++
			}
			if err := check(rest[:end]); err != nil {
				return err
			}
			rest = rest[end:]
		}
		b.charged = true
		// While only one group has failed, testing both halves either finds
		// the other failure or confirms the entire good half in one call.
		for len(failed) == 1 {
			group := failed[0]
			failed = failed[:0]
			mid := len(group) / 2
			if err := check(group[:mid]); err != nil {
				return err
			}
			if err := check(group[mid:]); err != nil {
				return err
			}
		}
		for _, group := range failed {
			if err := b.isolate(group); err != nil {
				return err
			}
		}
		// A server that has not yet passed or failed on its own is tried
		// again, alongside the other groups' remaining candidates. The
		// caller's slice stays whole, for testing the rest alone.
		var next []testOutbound
		for _, out := range remaining {
			if !b.done(out) {
				next = append(next, out)
			}
		}
		remaining = next
	}
	return nil
}

// isolate probes the half of the original group with each index bit set. With
// one bad server, the failed probes give its index; every passing probe also
// clears servers outside the search for that index. With several bad servers
// or an interaction, the index can be wrong. Always test the candidate as a
// singleton, and leave every unproven sibling for another pass.
//
// When every probe fails, one bad server explains it only as the last of a
// group whose size is a power of two. Otherwise the group holds several, and
// finding each would take another pass of probes: test its servers alone.
func (b *batchSearch) isolate(group []testOutbound) error {
	index, every := 0, true
	for bit := 1; bit < len(group); bit <<= 1 {
		var half []testOutbound
		for i, out := range group {
			if i&bit != 0 {
				half = append(half, out)
			}
		}
		ok, err := b.call(half)
		if err != nil {
			return err
		}
		if ok {
			every = false
		} else {
			index |= bit
		}
	}
	if index >= len(group) {
		if every {
			return b.alone(group)
		}
		index = slices.IndexFunc(group, func(out testOutbound) bool { return !b.done(out) })
	}
	if index >= 0 && !b.done(group[index]) {
		ok, err := b.call(group[index : index+1])
		if err == nil && ok && every {
			err = b.alone(group)
		}
		return err
	}
	return nil
}

// batchRedactor includes unsaved outbounds in the runner's diagnostics. When
// one contains a short credential that could be repeated in runner output,
// withhold the detail altogether: the reason may become persistent in Invalid.
func batchRedactor(st store.State, documents []json.RawMessage) func(string) string {
	short := false
	check := func(value string) {
		if value != "" && len(value) < minSecret {
			short = true
		}
	}
	for _, srv := range st.Servers {
		outboundSecrets(srv.Outbound, check)
	}
	for _, doc := range documents {
		outboundSecrets(doc, check)
	}
	if short {
		return func(string) string { return "" }
	}
	red := RedactorWith(st, documents...)
	return func(detail string) string {
		if strings.Contains(detail, runnerapi.TestOutputTruncated) {
			// A cut can leave part of a credential that no longer matches
			// the full value in the state.
			return ""
		}
		return red(strings.TrimSpace(detail))
	}
}
