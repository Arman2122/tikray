//go:build compat

package compat

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/xray"
	"github.com/Arman2122/tikray/internal/xrayver"
	"github.com/Arman2122/tikray/test/lab"
)

const (
	// hotProbeInterval is the observatory's probe interval in this test: short,
	// so that a round soon picks up an outbound that was added, or drops one
	// that was removed.
	hotProbeInterval = 2 * time.Second
	// observeWait bounds the wait for the observatory to list an outbound that
	// was added, or to drop one that was removed.
	observeWait = 30 * time.Second
	// lingerWait is how long a release that keeps the status of a removed
	// outbound (see observatoryPrunes) is given to drop it, before the test
	// only logs what it still lists: a few rounds.
	lingerWait = 3 * hotProbeInterval
	// hotCallTimeout bounds one xray api call; the hot path allows it 20 s.
	hotCallTimeout = 20 * time.Second
)

// observatoryPrunes is the first xray-core release whose observatory drops the
// status of an outbound that was removed: it calls clearRemovedOutbounds
// (app/observatory/observer.go) on every round, which v26.4.13 added. Before
// it, updateStatus there is a no-op ("TODO should remove old inbound that is
// removed"), and OutboundStatus lists a removed outbound for good, with the
// result of its last probe, until xray restarts. The balancer does not
// target such an outbound (its candidates come from xray's outbound manager),
// and tikray's health reads OutboundStatus only by the tags of the state's
// servers, so the hot path does not wait on the observatory's dropping.
var observatoryPrunes = xrayver.Version{Major: 26, Minor: 4, Patch: 13}

// The outbounds of the test, as the hot path would send them: server
// outbounds, tagged srv-.
const (
	outboundB        = `{"tag":"srv-b","protocol":"freedom"}`
	outboundBChanged = `{"tag":"srv-b","protocol":"freedom","settings":{"userLevel":1}}`
	outboundC        = `{"tag":"srv-c","protocol":"freedom"}`
	outboundD        = `{"tag":"srv-d","protocol":"freedom"}`
	outboundE        = `{"tag":"srv-e","protocol":"freedom"}`
	outboundF        = `{"tag":"srv-f","protocol":"freedom"}`
)

// TestHotAgainstReleases checks what internal/artifacts' hot path (hot.go)
// assumes of "xray api rmo" and "xray api ado", on each release compatVersions
// gives: it starts xray with the HandlerService and an observatory over the
// servers' outbounds, makes the calls the hot path makes, in its argument
// forms, and looks at what xray does with them, in the observatory
// (OutboundStatus) and, directly, in "xray api lso". The steps:
//
//   - ado adds an outbound, which the observatory then lists;
//   - rmo removes an outbound, which lso drops and the balancer stops
//     targeting; the observatory drops it too from observatoryPrunes on, and
//     before that keeps its entry (logged, not asserted);
//   - rmo of a tag xray does not have exits 0, as for a tag it has: rmo is
//     idempotent, and the hot path's safety does not rest on it failing;
//   - ado of a tag xray already has exits non-zero (the healing relies on it);
//   - ado of several outbounds in one file adds them in order;
//   - ado of several outbounds stops at the first that fails and leaves the
//     ones before it in place;
//   - rmo and then ado of one tag with a changed outbound, which is how a
//     changed server goes in; the observatory then probes it afresh.
//
// A release that does something else is a finding for the hot path's gate
// (render.Features), not something to pass over: the failure names the release
// and the step, and the log has each call's exit code and output.
func TestHotAgainstReleases(t *testing.T) {
	ctx := t.Context()
	versions, err := compatVersions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// What the probe asks for: any answer is an alive outbound.
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(probe.Close)

	for _, v := range versions {
		core, err := lab.XrayCoreVersion(v)
		if err != nil {
			t.Fatal(err)
		}
		release, err := xrayver.Parse(core)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(core, func(t *testing.T) {
			bin, err := lab.XrayBinaryVersion(ctx, lab.CacheDir(), v, runtime.GOARCH)
			if err != nil {
				t.Fatalf("build xray-core %s: %v", v, err)
			}
			port := freePort(t)
			addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
			x := startXray(t, bin, hotConfig(port, probe.URL))
			t.Cleanup(func() {
				if t.Failed() {
					t.Logf("xray-core %s's output:\n%s", core, x.out)
				}
			})
			c := &xray.Client{Addr: addr, Timeout: 5 * time.Second}
			waitForAPI(ctx, t, x, c)
			rig := &hotRig{core: core, release: release, bin: bin, server: "--server=" + addr, dir: t.TempDir(), c: c}

			// The steps share one xray, and each leaves it for the next.
			for _, step := range []struct {
				name string
				run  func(*hotStep)
			}{
				{"baseline", stepBaseline},
				{"ado adds an outbound", stepAdo},
				{"rmo removes an outbound", stepRmo},
				{"rmo of a missing tag", stepRmoMissing},
				{"ado of an existing tag", stepAdoExisting},
				{"ado of several outbounds", stepAdoMany},
				{"ado of several outbounds, one failing", stepAdoManyFails},
				{"rmo and ado of a changed outbound", stepReplace},
			} {
				t.Run(strings.ReplaceAll(step.name, " ", "_"), func(t *testing.T) {
					step.run(&hotStep{T: t, ctx: ctx, rig: rig, name: step.name})
				})
			}
		})
	}
}

// hotConfig is an xray config with its API on 127.0.0.1:port, with the
// HandlerService that the hot path calls, and an observatory over the
// outbounds tagged srv-, which probes at probeURL every hotProbeInterval: the
// proxy-open leastPing balancer over srv-, and the outbound srv-a. The first
// outbound, xray's default, is one that is not a server's, as the hot path
// requires of the configs it changes.
func hotConfig(port int, probeURL string) []byte {
	return apiConfigWith(port, probeURL, hotProbeInterval.String(),
		[]string{"HandlerService", "RoutingService", "StatsService", "ObservatoryService"},
		[]any{
			map[string]any{"tag": "direct", "protocol": "freedom"},
			map[string]any{"tag": "srv-a", "protocol": "freedom"},
		})
}

// hotRig is one running xray that the steps work on.
type hotRig struct {
	core    string // the release, such as 26.1.18
	release xrayver.Version
	bin     string
	server  string // "--server=<api address>", the form the hot path passes
	dir     string // where the outbound files go
	c       *xray.Client
}

// hotStep is one step of the test on one release. Its errors say which.
type hotStep struct {
	*testing.T
	ctx  context.Context
	rig  *hotRig
	name string
}

func (s *hotStep) errorf(format string, args ...any) {
	s.Helper()
	s.Errorf("xray-core %s, step %q: %s", s.rig.core, s.name, fmt.Sprintf(format, args...))
}

func (s *hotStep) fatalf(format string, args ...any) {
	s.Helper()
	s.Fatalf("xray-core %s, step %q: %s", s.rig.core, s.name, fmt.Sprintf(format, args...))
}

// apiCall is how one xray api call ended.
type apiCall struct {
	exit           int
	stdout, stderr string
}

func (a apiCall) String() string {
	return fmt.Sprintf("exit %d, stdout %q, stderr %q", a.exit, a.stdout, a.stderr)
}

// runAPI runs "xray api <args>" with the release's binary, as the runner does:
// no shell, and the exit code, what xray printed to each stream.
func (s *hotStep) runAPI(args ...string) apiCall {
	s.Helper()
	ctx, cancel := context.WithTimeout(s.ctx, hotCallTimeout)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, s.rig.bin, append([]string{"api"}, args...)...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = time.Second
	var call apiCall
	var exit *exec.ExitError
	switch err := cmd.Run(); {
	case err == nil:
	case errors.As(err, &exit) && exit.ExitCode() >= 0:
		call.exit = exit.ExitCode()
	default:
		s.fatalf("xray api %s did not run: %v", strings.Join(args, " "), err)
	}
	call.stdout, call.stderr = stdout.String(), stderr.String()
	return call
}

// xrayAPI is runAPI that logs the call, with its exit code and output.
func (s *hotStep) xrayAPI(args ...string) apiCall {
	s.Helper()
	call := s.runAPI(args...)
	s.Logf("xray api %s: %s", strings.Join(args, " "), call)
	return call
}

// list returns the tags of the outbounds xray has now, sorted, by xray api
// lso. ok is false if the release has no lso.
func (s *hotStep) list() (tags []string, ok bool) {
	s.Helper()
	call := s.runAPI("lso", s.rig.server)
	if call.exit != 0 {
		if strings.Contains(call.stdout+call.stderr, "unknown command") {
			s.Logf("this release has no xray api lso, so the outbounds are not checked directly")
			return nil, false
		}
		s.fatalf("xray api lso: %s", call)
	}
	var out struct {
		Outbounds []struct {
			Tag string `json:"tag"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal([]byte(call.stdout), &out); err != nil {
		s.fatalf("xray api lso: %v: %s", err, call)
	}
	for _, o := range out.Outbounds {
		tags = append(tags, o.Tag)
	}
	slices.Sort(tags)
	s.Logf("xray api lso: %q", tags)
	return tags, true
}

// poll asks the observatory for OutboundStatus until done is true of what it
// lists, for at most wait. It returns the outbounds listed last, and whether
// done was true of them.
func (s *hotStep) poll(wait time.Duration, done func([]xray.OutboundStatus) bool) ([]xray.OutboundStatus, bool) {
	s.Helper()
	deadline := time.Now().Add(wait)
	for {
		st, err := s.rig.c.OutboundStatus(s.ctx)
		if err != nil {
			s.fatalf("OutboundStatus: %v", err)
		}
		if done(st) {
			return st, true
		}
		if time.Now().After(deadline) {
			return st, false
		}
		select {
		case <-s.ctx.Done():
			s.fatalf("%v", s.ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// listing is the entry of the outbound tag in st, if there is one.
func listing(st []xray.OutboundStatus, tag string) (xray.OutboundStatus, bool) {
	i := slices.IndexFunc(st, func(o xray.OutboundStatus) bool { return o.Tag == tag })
	if i < 0 {
		return xray.OutboundStatus{}, false
	}
	return st[i], true
}

// observe waits until the observatory lists the outbound tag (want true) or
// does not (want false), for at most wait. It returns the outbounds the
// observatory listed last, and whether it was as wanted.
func (s *hotStep) observe(tag string, want bool, wait time.Duration) ([]xray.OutboundStatus, bool) {
	s.Helper()
	st, ok := s.poll(wait, func(st []xray.OutboundStatus) bool {
		_, listed := listing(st, tag)
		return listed == want
	})
	if ok {
		s.Logf("OutboundStatus, %s %s: %+v", tag, map[bool]string{true: "listed", false: "dropped"}[want], st)
	}
	return st, ok
}

// observeProbe waits, for at most observeWait, until the observatory lists the
// outbound tag with a last try later than at: a probe that began after at. The
// last try is in whole seconds, so at is cut to the second: a try at a later
// second is surely later than at.
func (s *hotStep) observeProbe(tag string, at time.Time) ([]xray.OutboundStatus, bool) {
	s.Helper()
	after := at.Truncate(time.Second)
	st, ok := s.poll(observeWait, func(st []xray.OutboundStatus) bool {
		o, listed := listing(st, tag)
		return listed && o.LastTry.After(after)
	})
	if ok {
		o, _ := listing(st, tag)
		s.Logf("OutboundStatus, %s probed at %v, after the call that ended at %v: %+v", tag, o.LastTry.UTC().Format(time.TimeOnly), at.UTC().Format(time.TimeOnly), o)
	}
	return st, ok
}

// expectListed fails the step, but goes on, unless the observatory lists
// tag within observeWait.
func (s *hotStep) expectListed(tag string) {
	s.Helper()
	if st, ok := s.observe(tag, true, observeWait); !ok {
		s.errorf("OutboundStatus does not list %s within %v: %+v", tag, observeWait, st)
	}
}

// expectDropped fails the step, but goes on, unless the observatory has
// dropped tag within observeWait.
func (s *hotStep) expectDropped(tag string) {
	s.Helper()
	if st, ok := s.observe(tag, false, observeWait); !ok {
		s.errorf("OutboundStatus still lists %s after %v: %+v", tag, observeWait, st)
	}
}

// expectTags fails the step, but goes on, when lso (if the release has it)
// lists a tag in present that is not there or one in absent that is.
func (s *hotStep) expectTags(present, absent []string, why string) {
	s.Helper()
	tags, ok := s.list()
	if !ok {
		return
	}
	for _, tag := range present {
		if !slices.Contains(tags, tag) {
			s.errorf("lso lists %q, want %s among them: %s", tags, tag, why)
		}
	}
	for _, tag := range absent {
		if slices.Contains(tags, tag) {
			s.errorf("lso lists %q, want %s not among them: %s", tags, tag, why)
		}
	}
}

// balancer logs what the proxy-open balancer targets, and returns it. Whether
// it picks an outbound that was added is up to its strategy and the
// observatory.
func (s *hotStep) balancer() (targets []string, ok bool) {
	s.Helper()
	override, targets, err := s.rig.c.BalancerTargets(s.ctx, "proxy-open")
	if err != nil {
		s.errorf("BalancerTargets(proxy-open): %v", err)
		return nil, false
	}
	s.Logf("BalancerTargets(proxy-open): override %q, targets %q", override, targets)
	return targets, true
}

// outbounds writes a file for xray api ado with the outbounds (JSON objects),
// in the shape and with the name the hot path gives it: {"outbounds":[...]},
// 0600 in a 0700 directory, named after the SHA-256 of its content. It returns
// the path.
func (s *hotStep) outbounds(outbounds ...string) string {
	s.Helper()
	list := make([]json.RawMessage, len(outbounds))
	for i, o := range outbounds {
		list[i] = json.RawMessage(o)
	}
	body, err := json.Marshal(struct {
		Outbounds []json.RawMessage `json:"outbounds"`
	}{list})
	if err != nil {
		s.fatalf("%v", err)
	}
	dir := filepath.Join(s.rig.dir, "hot")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		s.fatalf("%v", err)
	}
	sum := sha256.Sum256(body)
	file := filepath.Join(dir, hex.EncodeToString(sum[:])+".json")
	if err := os.WriteFile(file, body, 0o600); err != nil {
		s.fatalf("%v", err)
	}
	return file
}

// stepBaseline checks that xray starts with the outbounds the config gives,
// and that the observatory lists srv-a.
func stepBaseline(s *hotStep) {
	s.expectTags([]string{"direct", "srv-a"}, nil, "the outbounds of the config")
	if st, ok := s.observe("srv-a", true, observeWait); !ok {
		s.fatalf("OutboundStatus does not list srv-a within %v: %+v", observeWait, st)
	}
}

// stepAdo adds srv-b, which lso and then the observatory list.
func stepAdo(s *hotStep) {
	call := s.xrayAPI("ado", s.rig.server, s.outbounds(outboundB))
	if call.exit != 0 {
		s.fatalf("xray api ado of a new outbound: %s, want exit 0", call)
	}
	s.expectTags([]string{"direct", "srv-a", "srv-b"}, nil, "ado added srv-b")
	s.expectListed("srv-b")
	s.balancer()
}

// stepRmo removes srv-a. On every release lso drops it at once and the
// balancer stops targeting it. The observatory drops its status too from
// observatoryPrunes on; before that it keeps the entry, which the step logs
// and does not assert either way.
func stepRmo(s *hotStep) {
	call := s.xrayAPI("rmo", s.rig.server, "srv-a")
	if call.exit != 0 {
		s.fatalf("xray api rmo of a tag xray has: %s, want exit 0", call)
	}
	s.expectTags([]string{"direct", "srv-b"}, []string{"srv-a"}, "rmo removed srv-a")
	if targets, ok := s.balancer(); ok && slices.Contains(targets, "srv-a") {
		s.errorf("BalancerTargets(proxy-open) = %q after the rmo of srv-a, want srv-a not among them", targets)
	}
	if s.rig.release.Less(observatoryPrunes) {
		st, dropped := s.observe("srv-a", false, lingerWait)
		if o, listed := listing(st, "srv-a"); !dropped && listed {
			s.Logf("before xray-core %s the observatory keeps the status of a removed outbound: after %v it still lists %+v", observatoryPrunes, lingerWait, o)
		}
		return
	}
	s.expectDropped("srv-a")
}

// stepRmoMissing removes a tag xray does not have. Real xray's RemoveOutbound
// does not mind: rmo exits 0, printing "removing: <tag>" and {} as it does for
// a tag it has, and changes nothing. So rmo is idempotent, and the hot path
// does not rely on it failing (it relies on the pending marker and the PID
// checks).
func stepRmoMissing(s *hotStep) {
	before, _ := s.list()
	call := s.xrayAPI("rmo", s.rig.server, "srv-missing")
	if call.exit != 0 {
		s.errorf("xray api rmo of a tag xray does not have: %s, want exit 0", call)
	}
	if after, ok := s.list(); ok && !slices.Equal(before, after) {
		s.errorf("lso lists %q after the rmo of a tag xray does not have, it listed %q before", after, before)
	}
}

// stepAdoExisting adds srv-b a second time, which must fail, and must change
// nothing. The hot path's healing relies on the failure.
func stepAdoExisting(s *hotStep) {
	s.expectTags([]string{"srv-b"}, nil, "the outbound that ado is to add a second time")
	before, _ := s.list()
	call := s.xrayAPI("ado", s.rig.server, s.outbounds(outboundB))
	if call.exit == 0 {
		s.errorf("xray api ado of a tag xray already has: %s, want a non-zero exit", call)
	}
	if after, ok := s.list(); ok && !slices.Equal(before, after) {
		s.errorf("lso lists %q after the ado of a tag xray already has, it listed %q before", after, before)
	}
}

// stepAdoMany adds srv-c and srv-d from one file, which must go in that order.
func stepAdoMany(s *hotStep) {
	call := s.xrayAPI("ado", s.rig.server, s.outbounds(outboundC, outboundD))
	if call.exit != 0 {
		s.fatalf("xray api ado of two new outbounds: %s, want exit 0", call)
	}
	// xray says "adding: <tag>" before it adds each outbound.
	c, d := strings.Index(call.stdout, "adding: srv-c"), strings.Index(call.stdout, "adding: srv-d")
	if c < 0 || d < c {
		s.errorf("xray api ado did not add srv-c before srv-d: %s", call)
	}
	s.expectTags([]string{"srv-c", "srv-d"}, nil, "ado added both")
	s.expectListed("srv-c")
	s.expectListed("srv-d")
}

// stepAdoManyFails adds srv-e, srv-b and srv-f from one file, of which srv-b
// xray has already: ado must fail, stop there (srv-f is not added), and leave
// srv-e, which it added before the failure, in place.
func stepAdoManyFails(s *hotStep) {
	s.expectTags([]string{"srv-b"}, []string{"srv-e", "srv-f"}, "the starting point: srv-b to fail, srv-e and srv-f to be new")
	call := s.xrayAPI("ado", s.rig.server, s.outbounds(outboundE, outboundB, outboundF))
	if call.exit == 0 {
		s.errorf("xray api ado of a file with an outbound xray already has: %s, want a non-zero exit", call)
	}
	if strings.Contains(call.stdout, "adding: srv-f") {
		s.errorf("xray api ado went on after the failure and tried srv-f: %s", call)
	}
	tags, ok := s.list()
	if !ok {
		// A fresh probe distinguishes a live srv-e from an old observatory entry.
		if _, fresh := s.observeProbe("srv-e", time.Now()); !fresh {
			s.errorf("srv-e has no fresh probe after the failed ado")
		}
		// A single ado succeeds only if the batch stopped before installing srv-f.
		if add := s.xrayAPI("ado", s.rig.server, s.outbounds(outboundF)); add.exit != 0 {
			s.errorf("ado of srv-f after the failed batch: %s, want exit 0", add)
		} else if rm := s.xrayAPI("rmo", s.rig.server, "srv-f"); rm.exit != 0 {
			s.errorf("removing the check's srv-f: %s, want exit 0", rm)
		}
		return
	}
	if !slices.Contains(tags, "srv-e") {
		s.errorf("lso lists %q: srv-e, which ado added before the failure, is not there (rolled back?): %s", tags, call)
	}
	if slices.Contains(tags, "srv-f") {
		s.errorf("lso lists %q: srv-f, which comes after the failure, is there (ado did not stop): %s", tags, call)
	}
}

// stepReplace removes srv-b and adds it again with other settings, as a
// changed outbound goes in. The observatory must then probe srv-b afresh: a
// probe that began after the ado, within observeWait. A changed server shows
// its old result only until the next round, also on a release that keeps the
// status of a removed outbound, where the new outbound takes over the old
// entry.
func stepReplace(s *hotStep) {
	call := s.xrayAPI("rmo", s.rig.server, "srv-b")
	if call.exit != 0 {
		s.fatalf("xray api rmo of a tag xray has: %s, want exit 0", call)
	}
	s.expectTags(nil, []string{"srv-b"}, "rmo removed srv-b")
	call = s.xrayAPI("ado", s.rig.server, s.outbounds(outboundBChanged))
	if call.exit != 0 {
		s.fatalf("xray api ado of a tag that rmo removed: %s, want exit 0", call)
	}
	adoDone := time.Now()
	s.expectTags([]string{"srv-b"}, nil, "ado added srv-b again")
	if st, ok := s.observeProbe("srv-b", adoDone); !ok {
		s.errorf("OutboundStatus has no probe of srv-b that began after the ado (at %v) within %v: %+v", adoDone.UTC().Format(time.TimeOnly), observeWait, st)
	}
}
