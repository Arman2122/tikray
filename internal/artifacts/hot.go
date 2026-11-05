package artifacts

// A hot change puts Apply's config into the running xray without a restart,
// when it differs from the active config in nothing but the servers'
// outbounds: xray api rmo removes the outbounds that went or changed, ado adds
// those that came or changed, and the runner then adopts the config as the
// active one, so that a restart gives the same xray. Anything else, and any
// hot change that fails, goes through the trial.
//
// From its first xray api call until xray is known to run the active config
// again, a hot change keeps a marker, run/hot/pending. A tikray that dies
// meanwhile leaves it, and the next Apply heals xray (see HotPending, heal).

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

const (
	// defaultRunnerRun is where the runner's image mounts the run directory.
	defaultRunnerRun = "/data/run"
	// pendingName is the marker's name in run/hot/.
	pendingName = "pending"
	// hotUnfinished starts the Detail of an Apply that found the marker.
	hotUnfinished = "a hot change had not finished"
)

// HotPending reports whether the data root holds the marker of a hot change
// that did not end in a known state: xray may run outbounds that the runner's
// active config lacks, so the next Apply must run even when the state's
// render is the active config, and it then restarts xray or puts the config
// on trial. A marker that can't be looked at counts as there.
func HotPending(data string) bool {
	_, err := os.Lstat(pendingPath(data))
	return !errors.Is(err, fs.ErrNotExist)
}

func pendingPath(data string) string { return filepath.Join(data, "run", "hot", pendingName) }

func (u *CoreUpdater) hotDir() string { return filepath.Join(u.runDir(), "hot") }

// makeHotDir makes run/hot/, with mode 0700 even if it was there.
func (u *CoreUpdater) makeHotDir() error {
	if err := os.MkdirAll(u.hotDir(), 0o700); err != nil {
		return err
	}
	return os.Chmod(u.hotDir(), 0o700)
}

// markPending writes the marker, naming the config the hot change is for,
// before the change's first xray api call.
func (u *CoreUpdater) markPending(config string) error {
	if err := u.makeHotDir(); err != nil {
		return err
	}
	return atomicfile.WriteFile(pendingPath(u.Data), []byte(config+"\n"), 0o600)
}

// clearPending removes the marker, once xray is known to run the active
// config. A marker that stays only costs the next Apply a restart or a
// trial, and res says so.
func (u *CoreUpdater) clearPending(res *Result) {
	if err := removeSynced(pendingPath(u.Data)); err != nil {
		note(res, "the mark of the hot change was not removed: "+err.Error())
	}
}

// sweepHot removes from run/hot/ every file but the marker: the outbounds
// file of a hot change that a killed run left there holds credentials. It
// runs under the lock, as sweepTemp does, so no hot change is using it.
func (u *CoreUpdater) sweepHot() {
	ents, err := os.ReadDir(u.hotDir())
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		u.logf("artifacts: %v", err)
	}
	for _, e := range ents {
		if e.IsDir() || e.Name() == pendingName {
			continue
		}
		if err := os.Remove(filepath.Join(u.hotDir(), e.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
			u.logf("artifacts: %v", err)
		}
	}
}

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
	if err := json.Unmarshal(data, &top); err != nil || top == nil || !uniqueFields(json.NewDecoder(bytes.NewReader(data))) {
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

// xray decodes objects into structs, case-insensitively, and merges repeated
// object fields. A map comparison could lose a rule or target the wrong
// outbound in a config imported before tikray rendered it. Use a trial whenever
// the input admits both readings. parseHot has already validated the JSON.
func uniqueFields(d *json.Decoder) bool {
	d.UseNumber()
	tok, err := d.Token()
	if err != nil {
		return false
	}
	delim, container := tok.(json.Delim)
	if !container {
		return true
	}
	var seen map[string]bool
	if delim == '{' {
		seen = make(map[string]bool)
	}
	for d.More() {
		if seen != nil {
			key, err := d.Token()
			name, ok := key.(string)
			name = strings.ToLower(name)
			if err != nil || !ok || seen[name] {
				return false
			}
			seen[name] = true
		}
		if !uniqueFields(d) {
			return false
		}
	}
	_, err = d.Token()
	return err == nil
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

// A runner container gets a new PID namespace each time it starts. The public
// per-process ID from the supervisor also distinguishes xray starts in it.
type xrayProcess struct {
	pid      int
	instance string
}

func processOf(st runnerapi.Status) xrayProcess {
	return xrayProcess{pid: st.XrayPID, instance: st.XrayInstance}
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
	// touched says that the marker is there: a call may have changed the
	// running xray.
	touched bool
	// process is sampled after the last xray api call or adopt. A different
	// identified process then started after the change, from a saved config.
	process xrayProcess
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
	if st.State != runnerapi.StateRunning || st.XrayPID == 0 || st.XrayInstance == "" || runsCore(st, active.Core) != nil {
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
		detail := cmp.Or(tr.Output, "xray rejected the candidate config")
		res.Outcome, res.Detail = runnerapi.OutcomeRejected, detail
		return hotAttempt{done: true, err: &runnerapi.TestFailedError{Output: detail}}
	}
	g, err := u.baselineGate(ctx, active.Core)
	if err != nil {
		return hotAttempt{done: true, err: refuse(res, err)}
	}
	h := hotAttempt{gate: &g, process: processOf(st)}
	if h.failed = u.change(ctx, st, cfg, p, g, &h); h.failed != nil {
		return h
	}
	res.Outcome, res.Hot = runnerapi.OutcomeCommitted, true
	res.Detail = fmt.Sprintf("applied without restarting xray: added %d, removed %d, changed %d", p.added, p.removed, p.changed)
	if g.skipped {
		note(res, baselineSkipped)
	}
	if h.touched {
		u.clearPending(res)
	}
	u.prune(res)
	u.pruneConfigs(ctx, runnerapi.Selection{Core: active.Core, Geo: active.Geo, Config: cfg.rel}, res)
	return hotAttempt{done: true}
}

// change makes the change p in the running xray, the one st shows: the
// marker, each rmo, the ado, the proxy probe when the baseline passed (g),
// and then the runner's adopt of cfg. The xray that took the change must
// still run after the adopt: one the runner restarted meanwhile, from the
// config that was active, lacks a part of it. h.touched is set once the
// marker is written, before the first xray api call, and h.process follows the
// xray that the change saw.
func (u *CoreUpdater) change(ctx context.Context, st runnerapi.Status, cfg *config, p plan, g gate, h *hotAttempt) error {
	if len(p.remove) > 0 || len(p.add) > 0 {
		if err := u.markPending(cfg.rel); err != nil {
			return fmt.Errorf("marking the hot change: %w", err)
		}
		h.touched = true
	}
	// The runner may have started xray again since st, so the calls may have
	// reached another xray than st's: a failure takes the process identity from after it.
	failed := func(err error) error {
		h.process = u.processNow(ctx)
		return err
	}
	u.logf("xray-core %s: changing xray's outbounds without a restart", st.Active.Core)
	api := withTimeout(u.Runner, xrayAPIProbeTimeout)
	server := "--server=" + cmp.Or(u.XrayAPIServer, defaultStatsServer)
	for _, tag := range p.remove {
		if err := xrayAPI(ctx, api, "rmo", server, tag); err != nil {
			return failed(err)
		}
	}
	if len(p.add) > 0 {
		if err := u.addOutbounds(ctx, api, server, p.add); err != nil {
			return failed(err)
		}
	}
	if g.proxy != nil {
		if err := u.within(ctx, g.proxy.Check); err != nil {
			return failed(fmt.Errorf("the proxy probe after the change: %w", err))
		}
	}
	aerr := u.Runner.Adopt(ctx, cfg.rel)
	// Taken or not (an answer can be lost), the adopt may have made cfg the
	// active config: only an xray seen after it is known to run what the
	// runner records.
	h.process = xrayProcess{}
	cctx, cancel := cleanupContext(ctx)
	after, serr := u.Runner.Status(cctx)
	cancel()
	if serr == nil {
		h.process = processOf(after)
	}
	switch {
	case aerr != nil:
		return fmt.Errorf("adopting the config: %w", aerr)
	case serr != nil:
		return fmt.Errorf("checking on xray after the adopt: %w", serr)
	case after.State != runnerapi.StateRunning || h.process != processOf(st):
		return fmt.Errorf("xray restarted during the change (pid %d, then %d, %s), so it may lack a part of it", st.XrayPID, after.XrayPID, after.State)
	}
	return nil
}

// processNow samples xray even once the caller's context has ended.
func (u *CoreUpdater) processNow(ctx context.Context) xrayProcess {
	cctx, cancel := cleanupContext(ctx)
	defer cancel()
	st, err := u.Runner.Status(cctx)
	if err != nil {
		return xrayProcess{}
	}
	return processOf(st)
}

// addOutbounds has xray api ado add the outbounds add, from a file in
// run/hot/ that the runner reads at its own path of it (RunnerRun). The file
// holds the servers' credentials: it is 0600 in the 0700 run/hot/, which the
// lock's sweep (sweepHot) emptied of what a killed run left, and it is
// removed once ado is done, whatever ado said.
func (u *CoreUpdater) addOutbounds(ctx context.Context, api *runnerapi.Client, server string, add []json.RawMessage) error {
	body, err := json.Marshal(struct {
		Outbounds []json.RawMessage `json:"outbounds"`
	}{add})
	if err != nil {
		return err
	}
	if err := u.makeHotDir(); err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	name := hex.EncodeToString(sum[:]) + ".json"
	file := filepath.Join(u.hotDir(), name)
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

// Only the operation and exit status are public. An xray error can echo an
// old server that the current state no longer has.
func xrayAPI(ctx context.Context, c *runnerapi.Client, args ...string) error {
	resp, err := c.XrayAPI(ctx, args...)
	if err != nil {
		return fmt.Errorf("xray api %s request failed", args[0])
	}
	if resp.ExitCode != 0 {
		return fmt.Errorf("xray api %s: exit status %d", args[0], resp.ExitCode)
	}
	return nil
}

// fellBack completes res, the outcome of the trial that applied the config
// after the hot change h failed: its Detail starts with why. When the change
// may have reached xray (the marker is there), xray is brought back to what
// the runner records (see resync).
func (u *CoreUpdater) fellBack(ctx context.Context, h hotAttempt, res *Result) {
	lead(res, "the hot change failed ("+u.redact(h.failed.Error())+"), so a trial was tried")
	if h.touched {
		u.resync(ctx, h.process, res)
	}
}

// heal is Apply while the marker of an unfinished hot change is there, which
// st, the runner's status, and cfg, the render, are for: xray may run
// outbounds that the active config lacks. There is no noop and no hot
// change. A render that is the active config has xray restarted from it; any
// other goes on trial, after which xray is brought back to the active config
// if nothing restarted it (resync). The marker stays until xray is known to
// run the active config.
func (u *CoreUpdater) heal(ctx context.Context, st runnerapi.Status, cfg *config, res *Result) error {
	active := st.Active
	if cfg.rel == active.Config {
		if err := u.Runner.Restart(ctx); err != nil {
			return refuse(res, fmt.Errorf("%s, and restarting xray from the active config failed: %w", hotUnfinished, err))
		}
		res.Outcome, res.Detail = runnerapi.OutcomeCommitted, hotUnfinished+", so xray was restarted from the active config"
		u.clearPending(res)
		return nil
	}
	var err error
	if err = u.unsaved(active, cfg, "create a state first"); err != nil {
		err = refuse(res, err)
		lead(res, hotUnfinished)
	} else {
		err = u.applyTrial(ctx, *active, cfg, res, nil)
		lead(res, hotUnfinished+", so a trial was tried")
	}
	u.resync(ctx, processOf(st), res)
	return err
}

// resync makes sure that xray runs what the runner records as active, after a
// hot change that may have reached it. If another identified process is
// already running, it started after the change. Otherwise restart explicitly;
// a failed restart keeps the marker for the next Apply.
func (u *CoreUpdater) resync(ctx context.Context, seen xrayProcess, res *Result) {
	cctx, cancel := cleanupContext(ctx)
	defer cancel()
	if seen.instance != "" {
		st, err := u.Runner.Status(cctx)
		if err == nil && st.XrayInstance != "" && st.XrayPID > 0 && processOf(st) != seen {
			u.clearPending(res)
			return
		}
	}
	if err := u.Runner.Restart(cctx); err != nil {
		note(res, "restarting xray from the active config failed: "+err.Error())
		return
	}
	note(res, "xray was restarted from the active config")
	u.clearPending(res)
}

// lead puts msg before what res.Detail holds, with ": " between them when it
// holds anything.
func lead(res *Result, msg string) {
	if res.Detail != "" {
		msg += ": " + res.Detail
	}
	res.Detail = msg
}
