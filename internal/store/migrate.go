package store

import (
	"encoding/json"
	"fmt"
)

// migration turns the state of version N into the state of version N+1. It
// gets and returns the "state" member of a state file, as JSON, not a State:
// a State is always the current version's. Revisions do not change.
type migration func(json.RawMessage) (json.RawMessage, error)

// migrations holds, for each version N below Current, the migration from N to
// N+1. There are none while Current is 1.
var migrations = map[int]migration{}

// migrate applies the migrations from version from up to version to, one step
// at a time, and returns the resulting state.
func migrate(raw json.RawMessage, from, to int, steps map[int]migration) (json.RawMessage, error) {
	for v := from; v < to; v++ {
		step, ok := steps[v]
		if !ok {
			return nil, fmt.Errorf("no migration from version %d to %d", v, v+1)
		}
		out, err := step(raw)
		if err != nil {
			return nil, fmt.Errorf("migration from version %d to %d failed: %w", v, v+1, err)
		}
		if !json.Valid(out) {
			return nil, fmt.Errorf("migration from version %d to %d returned invalid JSON", v, v+1)
		}
		raw = out
	}
	return raw, nil
}
