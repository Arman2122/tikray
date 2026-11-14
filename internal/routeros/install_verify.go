package routeros

import (
	"context"
	"path/filepath"
	"reflect"
)

// A live socket can outlast a password change. Only the explicit installer
// challenge retires it. The existing supervisor still owns all logins, the
// backoff, and reconnecting the filtered listeners.
func (c *Client) reauthenticate(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return ErrUnavailable
	}
	c.mu.Lock()
	previous := c.current
	c.mu.Unlock()
	if previous != nil {
		previous.fail(ErrDisconnected)
	}
	next, err := c.ready(ctx)
	if err != nil || next == previous {
		return ErrUnavailable
	}
	return nil
}

func (m *Managed) VerifyInstallation(ctx context.Context, t Target) error {
	m.mu.RLock()
	e, client := m.engine, m.client
	m.mu.RUnlock()
	if e == nil || client == nil {
		return ErrUnavailable
	}
	var in Installation
	found, err := readPrivate(filepath.Join(m.dir, "routeros.json"), &in, 1<<20)
	if err != nil || !found || in.Address != m.cfg.Address || in.Version != 1 || in.Username != m.cfg.Username || in.Password != m.cfg.Password || in.Fingerprint != m.cfg.Fingerprint || !reflect.DeepEqual(in.Scope, m.scope) {
		return ErrUnavailable
	}
	return e.verifyInstallation(ctx, t, client.reauthenticate)
}

// Verification is read-only. The normal reconciliation loop decides whether
// and how to repair a mismatch, including retaining any outstanding guards.
func (e *Engine) verifyInstallation(ctx context.Context, t Target, reauthenticate func(context.Context) error) error {
	if err := e.lock(ctx); err != nil {
		return err
	}
	defer func() { <-e.gate }()
	j, err := e.readJournal()
	if err != nil || j.Verified == nil || len(j.Pending) != 0 || j.Revision != t.Revision || j.Policy == nil || !reflect.DeepEqual(*j.Policy, t.Policy) {
		return ErrUnavailable
	}
	// Leave an existing live session alone while the owner's emergency
	// command is active. Repeat this check on the freshly logged-in peer.
	if gen := e.c.Generation(); gen != 0 {
		marker, busy, err := EmergencyState(ctx, e.c, gen)
		if err != nil || marker != "" || busy {
			return ErrUnavailable
		}
	}
	if err := reauthenticate(ctx); err != nil {
		return ErrUnavailable
	}
	if e.managedBindings && ReconcileBindings(ctx, e.c, e.scope.Subnet, false) != nil {
		return ErrUnavailable
	}
	a, err := e.Snapshot(ctx)
	if err != nil {
		return ErrUnavailable
	}
	marker, busy, err := EmergencyState(ctx, e.c, a.Generation)
	if err != nil || busy || marker != "" {
		return ErrUnavailable
	}
	rows, err := Desired(t.Policy, a.Topology, t.Geo)
	if err != nil || !reflect.DeepEqual(*j.Verified, viewOf(rows, a.Topology)) {
		return ErrUnavailable
	}
	for _, r := range a.Rows {
		if isHold(r.Comment) {
			return ErrUnavailable
		}
	}
	ops, err := Plan(a, rows)
	if err != nil || len(ops) != 0 || a.Generation != e.c.Generation() {
		return ErrUnavailable
	}
	return nil
}
