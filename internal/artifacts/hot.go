package artifacts

// A hot change puts Apply's config into the running xray without a restart,
// when it differs from the active config in nothing but the servers'
// outbounds: xray api rmo removes the outbounds that went or changed, ado adds
// those that came or changed, and the runner then adopts the config as the
// active one, so that a restart gives the same xray. Anything else, and any
// hot change that fails, goes through the trial.

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Arman2122/tikray/internal/atomicfile"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
)

// defaultRunnerRun is where the runner's image mounts the run directory.
const defaultRunnerRun = "/data/run"

// plan is what a hot change does to the running xray: remove the outbounds
// tagged remove, then add the outbounds add. A changed outbound is in both.
// added, removed and changed count the servers' outbounds each way.
type plan struct {
	remove                  []string
	add                     []json.RawMessage
	added, removed, changed int
}

// hotPlan returns the plan that makes the running xray, on the config active,
// run what candidate says, and whether there is one: whether candidate
// differs from active in nothing but the servers' outbounds, those whose tag
// starts with store.ServerTagPrefix. Every top-level key but outbounds must be
// the same as canonical JSON (see canonical), and so must the other
// outbounds, in the same order. xray's first outbound is its default, which
// xray api never moves, so it must be one of those in both. Outbounds are
// matched by tag: one without a tag, or a tag twice, qualifies nothing. So does
// a config whose keys xray would read but hotPlan does not see, such as
// "Outbounds": it fails to match.
func hotPlan(active, candidate []byte) (plan, bool) {
	a, ok := parseHot(active)
	if !ok {
		return plan{}, false
	}
	c, ok := parseHot(candidate)
	switch {
	case !ok, !maps.Equal(a.rest, c.rest):
		return plan{}, false
	case !slices.EqualFunc(a.others(), c.others(), func(x, y hotOutbound) bool { return x.canonical == y.canonical }):
		return plan{}, false
	case len(a.outbounds) == 0 || len(c.outbounds) == 0 || isServer(a.outbounds[0].tag) || isServer(c.outbounds[0].tag):
		return plan{}, false
	}
	was, is := a.byTag(), c.byTag()
	var p plan
	for _, o := range a.servers() {
		switch n, ok := is[o.tag]; {
		case !ok:
			p.remove = append(p.remove, o.tag)
			p.removed++
		case n.canonical != o.canonical:
			p.remove = append(p.remove, o.tag)
			p.changed++
		}
	}
	for _, o := range c.servers() {
		switch old, ok := was[o.tag]; {
		case !ok:
			p.add = append(p.add, o.raw)
			p.added++
		case old.canonical != o.canonical:
			p.add = append(p.add, o.raw)
		}
	}
	return p, true
}

// hotConfig is an xray config as hotPlan compares it.
type hotConfig struct {
	rest      map[string]string // each top-level key but outbounds, as canonical JSON
	outbounds []hotOutbound
}

// hotOutbound is one outbound of a hotConfig.
type hotOutbound struct {
	tag       string
	canonical string
	raw       json.RawMessage // as the config has it
}

// parseHot reads data, an xray config, as hotPlan compares it. ok is false
// for anything but a JSON object with an outbounds list whose every entry is
// an object with a tag of its own.
func parseHot(data []byte) (hotConfig, bool) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil || top == nil {
		return hotConfig{}, false
	}
	var list []json.RawMessage
	if err := json.Unmarshal(top["outbounds"], &list); err != nil || list == nil {
		return hotConfig{}, false
	}
	c := hotConfig{rest: map[string]string{}}
	for k, raw := range top {
		if k == "outbounds" {
			continue
		}
		s, _, ok := canonical(raw)
		if !ok {
			return hotConfig{}, false
		}
		c.rest[k] = s
	}
	seen := map[string]bool{}
	for _, raw := range list {
		s, v, ok := canonical(raw)
		obj, isObj := v.(map[string]any)
		tag, isTag := obj["tag"].(string)
		if !ok || !isObj || !isTag || tag == "" || seen[tag] {
			return hotConfig{}, false
		}
		seen[tag] = true
		c.outbounds = append(c.outbounds, hotOutbound{tag: tag, canonical: s, raw: raw})
	}
	return c, true
}

// servers are c's outbounds of servers, others the rest, each in order.
func (c hotConfig) servers() []hotOutbound { return c.filter(true) }
func (c hotConfig) others() []hotOutbound  { return c.filter(false) }

func (c hotConfig) filter(servers bool) []hotOutbound {
	var out []hotOutbound
	for _, o := range c.outbounds {
		if isServer(o.tag) == servers {
			out = append(out, o)
		}
	}
	return out
}

// byTag is c's outbounds of servers by tag.
func (c hotConfig) byTag() map[string]hotOutbound {
	m := map[string]hotOutbound{}
	for _, o := range c.servers() {
		m[o.tag] = o
	}
	return m
}

func isServer(tag string) bool { return strings.HasPrefix(tag, store.ServerTagPrefix) }

// canonical is raw as canonical JSON, with what it decodes to: decoded with
// its numbers as they are written, and encoded again, which sorts the keys of
// every object. ok is false for raw that is not JSON.
func canonical(raw []byte) (string, any, bool) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return "", nil, false
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", nil, false
	}
	return string(b), v, true
}

// hotAttempt is how a try at a hot change ended.
type hotAttempt struct {
	// done says that res holds the outcome, and err is its error.
	done bool
	err  error
	// failed is why the hot change failed: the trial applies the config
	// instead, and says so. With done false and failed nil, the change was
	// not one for a hot change, and the trial applies it with no note.
	failed error
	// touched says that a call may have changed the running xray.
	touched bool
	// gate is the baseline's verdict once the hot path has taken it. The
	// trial keeps it: by then xray may run a part of the change, which says
	// nothing about the active config.
	gate *gate
}

// hot tries to apply cfg as a hot change to the runner whose status st was
// taken under the lock, with st.Active set and differing from cfg. It goes
// ahead only while the runner runs the active core (state running, the active
// core's version) and the active config can be read, and only with a plan
// (hotPlan). It then writes cfg and has the runner's xray test it, as a
// trial's xray run -test would: a rejection is the outcome, and nothing has
// reached xray. Then it takes the baseline, makes the change (see change), and
// records the commit as a committed trial would, pruning included.
func (u *CoreUpdater) hot(ctx context.Context, st runnerapi.Status, cfg *config, res *Result) hotAttempt {
	active := st.Active
	if st.State != runnerapi.StateRunning || st.XrayPID == 0 || runsCore(st, active.Core) != nil {
		return hotAttempt{}
	}
	// The name is the runner's: it must name a config under run/ and nothing
	// else before it is read.
	err := runnerapi.ValidateConfig(active.Config)
	var old []byte
	if err == nil {
		old, err = os.ReadFile(filepath.Join(u.runDir(), active.Config))
	}
	if err != nil {
		u.logf("artifacts: reading the active config: %v", err)
		return hotAttempt{}
	}
	p, ok := hotPlan(old, cfg.data)
	if !ok {
		return hotAttempt{}
	}
	if err := cfg.write(u.runDir()); err != nil {
		return hotAttempt{done: true, err: refuse(res, err)}
	}
	tr, err := u.Runner.Test(ctx, cfg.data)
	switch {
	case ctx.Err() != nil:
		return hotAttempt{done: true, err: refuse(res, ctx.Err())}
	case err != nil:
		return hotAttempt{failed: err}
	case !tr.OK:
		res.Outcome, res.Detail = runnerapi.OutcomeRejected, tr.Output
		return hotAttempt{done: true, err: &runnerapi.TestFailedError{Output: tr.Output}}
	}
	g, err := u.baselineGate(ctx, active.Core)
	if err != nil {
		return hotAttempt{done: true, err: refuse(res, err)}
	}
	h := hotAttempt{gate: &g}
	if h.failed = u.change(ctx, st, cfg, p, g, &h.touched); h.failed != nil {
		return h
	}
	res.Outcome, res.Hot = runnerapi.OutcomeCommitted, true
	res.Detail = fmt.Sprintf("applied without restarting xray: added %d, removed %d, changed %d", p.added, p.removed, p.changed)
	if g.skipped {
		note(res, baselineSkipped)
	}
	u.prune(res)
	u.pruneConfigs(ctx, runnerapi.Selection{Core: active.Core, Geo: active.Geo, Config: cfg.rel}, res)
	return hotAttempt{done: true}
}

// change makes the change p in the running xray, the one st shows: each rmo,
// the ado, the proxy probe when the baseline passed (g), and then the
// runner's adopt of cfg. The xray that took the change must still run after
// the adopt: one the runner restarted meanwhile, from the config that was
// active, lacks a part of it. touched is set before the first call that can
// change xray.
func (u *CoreUpdater) change(ctx context.Context, st runnerapi.Status, cfg *config, p plan, g gate, touched *bool) error {
	u.logf("xray-core %s: changing xray's outbounds without a restart", st.Active.Core)
	api := withTimeout(u.Runner, xrayAPIProbeTimeout)
	server := "--server=" + cmp.Or(u.XrayAPIServer, defaultStatsServer)
	for _, tag := range p.remove {
		*touched = true
		if err := xrayAPI(ctx, api, "rmo", server, tag); err != nil {
			return err
		}
	}
	if len(p.add) > 0 {
		*touched = true
		if err := u.addOutbounds(ctx, api, server, p.add); err != nil {
			return err
		}
	}
	if g.proxy != nil {
		if err := u.within(ctx, g.proxy.Check); err != nil {
			return fmt.Errorf("the proxy probe after the change: %w", err)
		}
	}
	if err := u.Runner.Adopt(ctx, cfg.rel); err != nil {
		return fmt.Errorf("adopting the config: %w", err)
	}
	after, err := u.Runner.Status(ctx)
	switch {
	case err != nil:
		return fmt.Errorf("checking on xray after the adopt: %w", err)
	case after.State != runnerapi.StateRunning || after.XrayPID != st.XrayPID:
		return fmt.Errorf("xray restarted during the change (pid %d, then %d, %s), so it may lack a part of it", st.XrayPID, after.XrayPID, after.State)
	}
	return nil
}

// addOutbounds has xray api ado add the outbounds add, from a file in
// run/hot/ that the runner reads at its own path of it (RunnerRun). The file
// holds the servers' credentials: it is 0600 in the 0700 run/hot/, which is
// emptied first, as a run killed during a hot change can leave a file there,
// and it is removed once ado is done, whatever ado said.
func (u *CoreUpdater) addOutbounds(ctx context.Context, api *runnerapi.Client, server string, add []json.RawMessage) error {
	body, err := json.Marshal(struct {
		Outbounds []json.RawMessage `json:"outbounds"`
	}{add})
	if err != nil {
		return err
	}
	dir := filepath.Join(u.runDir(), "hot")
	if err := emptyHotDir(dir); err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	name := hex.EncodeToString(sum[:]) + ".json"
	file := filepath.Join(dir, name)
	if err := atomicfile.WriteFile(file, body, 0o600); err != nil {
		return err
	}
	defer func() {
		if err := os.Remove(file); err != nil && !errors.Is(err, fs.ErrNotExist) {
			u.logf("artifacts: %v", err)
		}
	}()
	return xrayAPI(ctx, api, "ado", server, path.Join(cmp.Or(u.RunnerRun, defaultRunnerRun), "hot", name))
}

// emptyHotDir makes dir, run/hot/, with mode 0700, and removes every file in
// it.
func emptyHotDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// xrayAPI runs "xray api <args>" in the runner. Anything but exit 0 is an
// error, with what xray printed.
func xrayAPI(ctx context.Context, c *runnerapi.Client, args ...string) error {
	resp, err := c.XrayAPI(ctx, args...)
	if err != nil {
		return fmt.Errorf("xray api %s: %w", args[0], err)
	}
	if resp.ExitCode != 0 {
		out := cmp.Or(strings.TrimSpace(resp.Stderr), strings.TrimSpace(resp.Stdout))
		return fmt.Errorf("xray api %s: exit status %d: %s", strings.Join(args, " "), resp.ExitCode, out)
	}
	return nil
}

// fellBack completes res, the outcome of the trial that applied the config
// after the hot change h failed: its Detail starts with why. When a call may
// have changed xray and the trial never restarted it, being refused, or
// rejected by xray run -test, xray is restarted from the active config, so
// that it runs nothing the runner does not record.
func (u *CoreUpdater) fellBack(ctx context.Context, h hotAttempt, res *Result) {
	msg := "the hot change failed (" + u.redact(h.failed.Error()) + "), so it was applied with a trial"
	if res.Detail != "" {
		msg += ": " + res.Detail
	}
	res.Detail = msg
	if !h.touched || (res.Outcome != OutcomeRefused && res.Outcome != runnerapi.OutcomeRejected) {
		return
	}
	cctx, cancel := cleanupContext(ctx)
	defer cancel()
	if err := u.Runner.Restart(cctx); err != nil {
		note(res, "restarting xray from the active config failed: "+err.Error())
		return
	}
	note(res, "xray was restarted from the active config")
}
