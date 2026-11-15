package routeros

import (
	"context"
	"strings"
)

// Keep the entry guards in place while xray still runs the old assets.
// Each removal goes through the normal ownership, generation and reference
// checks. New exemptions are handled by Reconcile after the runner commits.
func (e *Engine) withdrawDomestic(ctx context.Context, p *pass) error {
	removals := func() ([]Op, error) {
		ops, err := Plan(p.a, p.rows)
		if err != nil {
			return nil, err
		}
		var old []Op
		for _, op := range ops {
			if op.Menu != addressListMenu || !strings.HasPrefix(op.Comment, "tikray:domestic:") {
				continue
			}
			switch op.Kind {
			case "remove":
				old = append(old, op)
			case "set":
				// A retained tag no longer describes its native row. Normal
				// repair must resolve its identity before starting a trial.
				return nil, errDrift
			}
		}
		return old, nil
	}
	old, err := removals()
	if err != nil {
		return err
	}
	if len(old) > 0 {
		if err = Execute(ctx, p.fence, p.a, old); err != nil {
			return err
		}
	}
	if err = e.verify(ctx, p); err != nil {
		return err
	}
	old, err = removals()
	if err != nil {
		return err
	}
	holds, err := PlanHolds(p.a, p.holds)
	if err != nil {
		return err
	}
	if len(old) != 0 || len(holds) != 0 {
		return errDrift
	}
	return nil
}
