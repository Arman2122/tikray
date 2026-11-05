package service

import (
	"context"
	"encoding/json"
	"maps"
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
			results[group[0].id] = "xray rejected the server" + redactDetail(res.Output)
		}
		return res.OK, nil
	}

	err := testBatchGroups(remaining, results, test)
	return results, err
}

// testBatchGroups partitions the outbounds into configs the runner can take.
// Test records passes and singleton refusals in results. A failed group alone
// never identifies which member was refused.
func testBatchGroups(remaining []testOutbound, results map[string]string, test func([]testOutbound) (bool, error)) error {
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
			ok, err := test(group)
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
			if err := isolateOutbound(group, results, test); err != nil {
				return err
			}
		}
		// A server that has not yet passed or failed on its own is tried
		// again, alongside the other groups' remaining candidates.
		remaining = slices.DeleteFunc(remaining, func(out testOutbound) bool {
			_, done := results[out.id]
			return done
		})
	}
	return nil
}

// isolateOutbound probes the half of the original group with each index bit
// set. With one bad server, the failed probes give its index; every passing
// probe also clears servers outside the search for that index. With several
// bad servers or an interaction, the index can be wrong. Always test the
// candidate as a singleton, and leave every unproven sibling for another pass.
func isolateOutbound(group []testOutbound, results map[string]string, test func([]testOutbound) (bool, error)) error {
	index := 0
	for bit := 1; bit < len(group); bit <<= 1 {
		var half []testOutbound
		for i, out := range group {
			if i&bit != 0 {
				half = append(half, out)
			}
		}
		ok, err := test(half)
		if err != nil {
			return err
		}
		if !ok {
			index |= bit
		}
	}
	if index >= len(group) {
		index = slices.IndexFunc(group, func(out testOutbound) bool {
			_, done := results[out.id]
			return !done
		})
	}
	if index >= 0 {
		if _, done := results[group[index].id]; !done {
			_, err := test(group[index : index+1])
			return err
		}
	}
	return nil
}

// batchRedactor includes unsaved outbounds in the runner's diagnostics. When
// one contains a credential shorter than the state redactor's threshold,
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
