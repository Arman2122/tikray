//go:build lab

package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

const attackRun = dataRoot + "/run/m3-spoof"

type spoofObservation struct {
	Phase, MAC, Failure        string
	Frames, HTTP, TLS, Witness int
}

func (f *installLab) spoofObservation(ctx context.Context) (spoofObservation, bool) {
	out, e := f.CHR.RunPrivate(ctx, `:put [/file/get [find where name="`+attackRun+`.observed"] contents]`)
	var result spoofObservation
	ok := e == nil && json.Unmarshal([]byte(strings.TrimSpace(out)), &result) == nil
	return result, ok
}

func (f *installLab) awaitSpoof(ctx context.Context, t *testing.T, phase string) spoofObservation {
	t.Helper()
	var s spoofObservation
	_, ok := poll(ctx, 35*time.Second, 200*time.Millisecond, func() bool {
		var ready bool
		s, ready = f.spoofObservation(ctx)
		if s.Failure != "" {
			t.Fatal("runner attack setup failed in", s.Failure)
		}
		return ready && s.Phase == phase && (phase == "idle" || s.Frames >= 4)
	})
	if !ok {
		t.Fatalf("runner did not enter %s mode", phase)
	}
	return s
}

func (f *installLab) spoofMode(ctx context.Context, t *testing.T, mode string) spoofObservation {
	t.Helper()
	f.mustRun(ctx, t, `/file/set [find name="`+attackRun+`.mode"] contents="`+mode+`"`)
	return f.awaitSpoof(ctx, t, mode)
}

func (f *installLab) launchSpoof(ctx context.Context, t *testing.T, id, controlMAC string) {
	t.Helper()
	bin := filepath.Join(f.workDir, "runner-spoof")
	c := exec.CommandContext(ctx, "go", "build", "-trimpath", "-ldflags=-s -w", "-o", bin, "./test/e2e/testdata/runner-spoof")
	c.Dir = repoRoot()
	c.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+f.Arch.GOARCH(), "CGO_ENABLED=0")
	if c.Run() != nil || f.CHR.Push(ctx, bin, attackRun) != nil {
		t.Fatal("could not stage runner namespace fixture")
	}
	cfg, _ := json.Marshal(map[string]string{"Control": installControl, "Router": "172.30.252.1", "Runner": installRunner, "ControlMAC": controlMAC, "ID": id})
	local := filepath.Join(f.workDir, "attacker.json")
	if os.WriteFile(local, cfg, 0600) != nil || f.CHR.Push(ctx, local, attackRun+".config") != nil {
		t.Fatal("could not stage public attack settings")
	}
	f.mustRun(ctx, t, `/file/add name="`+attackRun+`.mode" type=file contents="idle"`)
	f.mustRun(ctx, t, `/container/shell [find where name=tikray] cmd="chmod 700 /data/run/m3-spoof"`)
	f.mustRun(ctx, t, `/container/stop [find where name=tikray-runner]`)
	if f.waitForContainer(ctx, "tikray-runner", "stopped") != nil {
		t.Fatal("runner did not stop")
	}
	// CHR's scratch runner has no shell. The test entrypoint forks only its
	// helper and execs the original /tikray-runner binary as PID 1.
	f.mustRun(ctx, t, `/container/set [find where name=tikray-runner] entrypoint="/data/run/m3-spoof"`)
	f.mustRun(ctx, t, `/container/start [find where name=tikray-runner]`)
	if f.waitForContainer(ctx, "tikray-runner", "running") != nil {
		t.Fatal("runner did not start with fixture")
	}
	f.awaitSpoof(ctx, t, "idle")
	f.checkReady(ctx, t)
}

func (f *installLab) routerHealth(ctx context.Context, scheme, addr, id string) bool {
	// Like the production probe this request contains only public data.
	options := ""
	if scheme == "https" {
		options = "check-certificate=no"
	}
	s := fmt.Sprintf(`{ :local matches false; :do { :local r [/tool/fetch url="%s://%s/healthz" src-address=172.30.252.1 %s http-max-redirect-count=0 duration=3s idle-timeout=2s output=user as-value]; :local b [:deserialize from=json options=json.no-string-conversion value=($r->"data")]; :set matches ((($b->"ok")=true) and (($b->"installation_id")="%s")) } on-error={}; :put $matches }`, scheme, addr, options, id)
	out, e := f.CHR.RunPrivate(ctx, s)
	return e == nil && strings.TrimSpace(out) == "true"
}

func (f *installLab) witnessPackets(ctx context.Context, t *testing.T) int {
	t.Helper()
	p := f.mustRun(ctx, t, `:put [/interface/bridge/filter/get [find comment="lab:genuine-health-response"] packets]`)
	n, e := strconv.Atoi(strings.TrimSpace(p))
	if e != nil {
		t.Fatal("health response evidence unavailable")
	}
	return n
}

func (f *installLab) spoofDirectFlow(ctx context.Context, t *testing.T) {
	t.Helper()
	out, e := f.Net.Client(ctx, "curl", "--noproxy", "*", "-fsS", "--max-time", "4", "http://203.0.113.30/whoami").Output()
	if e != nil || strings.TrimSpace(string(out)) != egressDirect {
		t.Fatal("unmanaged LAN traffic lost its direct WAN path")
	}
}

// TestM3WatchdogImpersonation runs against actual signed installer images.
// It ends with a destructive counterfactual on the disposable overlay: the
// same attacker must satisfy the same HTTPS transport when L2 binding is gone.
func TestM3WatchdogImpersonation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 18*time.Minute)
	defer cancel()
	f := DeployM3(ctx, t)
	f.stage(ctx, t, true)
	f.requireSuccess(ctx, t)
	f.checkReady(ctx, t)
	id := f.file(ctx, t, dataRoot+"/state/install.id")
	if len(id) != 32 {
		t.Fatal("expected public installation ID")
	}
	f.mustRun(ctx, t, `/system/scheduler/disable [find comment="tikray:watchdog-scheduler"]`)
	mac := f.mustRun(ctx, t, `:put [/interface/veth/get [find comment="tikray:veth-ctl"] container-mac-address]`)
	if _, e := net.ParseMAC(mac); e != nil {
		t.Fatal("missing control peer MAC")
	}
	f.launchSpoof(ctx, t, id, mac)
	if !f.routerHealth(ctx, "http", installRunner, id) || !f.routerHealth(ctx, "https", installRunner, id) {
		t.Fatal("attacker failed independent HTTP and HTTPS positive controls")
	}
	before, _ := f.spoofObservation(ctx)
	if before.Witness < 2 {
		t.Fatal("attacker did not record the independent router requests")
	}
	f.mustRun(ctx, t, `/interface/bridge/filter/add chain=input in-interface=tikray-ctl mac-protocol=ip ip-protocol=tcp src-address=172.30.252.2/32 dst-address=172.30.252.1/32 src-port=443 action=passthrough comment="lab:genuine-health-response"`)
	tick := func() {
		t.Helper()
		out, e := f.CHR.RunPrivate(ctx, `:onerror why in={ /system/script/run tikray-watchdog; :put "tick-ok" } do={ :put ("m3-refused=" . [:convert [:tostr $why] to=base64]) }`)
		if e == nil && strings.Contains(out, "tick-ok") {
			return
		}
		_, encoded, _ := strings.Cut(out, "m3-refused=")
		msg, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
		category := "native refusal"
		for _, word := range []string{"syntax error", "expected end", "not enough permissions", "invalid internal item", "invalid value", "no such item", "argument", "watchdog state", "ownership", "return", "certificate"} {
			if strings.Contains(strings.ToLower(string(msg)), word) {
				category = word
				break
			}
		}
		t.Fatal("watchdog tick", category, regexp.MustCompile(`line [0-9]+ column [0-9]+`).FindString(string(msg)))
	}
	// With an original installer the working attacker must win, rather than
	// interpreting an unavailable probe as successful network protection.
	if f.mustRun(ctx, t, `:put [/interface/bridge/get [find name="tikray"] arp]`) != "reply-only" {
		f.mustRun(ctx, t, "/container/stop [find name=tikray]")
		if f.waitForContainer(ctx, "tikray", "stopped") != nil {
			t.Fatal("unbound control did not stop")
		}
		f.spoofMode(ctx, t, "clone")
		_, exposed := poll(ctx, 22*time.Second, 250*time.Millisecond, func() bool {
			return f.routerHealth(ctx, "https", installControl, id) && f.routerHealth(ctx, "http", installControl, id)
		})
		s, _ := f.spoofObservation(ctx)
		if exposed && s.TLS > 0 && s.HTTP > 0 {
			t.Fatal("unbound router counted a matching-ID runner as the stopped control, over HTTPS and HTTP")
		}
		t.Fatal("expected binding absent and unbound attack was inconclusive")
	}
	for _, phase := range []string{"alias", "clone"} {
		s := f.spoofMode(ctx, t, phase)
		if phase == "clone" && !strings.EqualFold(s.MAC, mac) {
			t.Fatal("runner did not clone control MAC")
		}
		n := f.witnessPackets(ctx, t)
		tick()
		if f.witnessPackets(ctx, t) <= n {
			t.Fatalf("watchdog did not receive HTTPS response from control port during %s attack", phase)
		}
		if f.watchdogRecord(ctx, t).Control.Misses != 0 {
			t.Fatalf("genuine service failed during %s attack", phase)
		}
		if !f.routerHealth(ctx, "https", installControl, id) {
			t.Fatal("router could not reach genuine control")
		}
		s, _ = f.spoofObservation(ctx)
		if s.TLS != 0 || s.HTTP != 0 {
			t.Fatal("runner received a control-address request while genuine control was up")
		}
		f.spoofDirectFlow(ctx, t)
	}
	// Keep the owned row running, but make its genuine HTTPS endpoint
	// unreachable from the router. This forces the real watchdog's network
	// probe; its stopped-container shortcut alone could hide impersonation.
	f.mustRun(ctx, t, `/interface/bridge/filter/add chain=input in-interface=tikray-ctl mac-protocol=ip ip-protocol=tcp src-address=172.30.252.2/32 dst-address=172.30.252.1/32 src-port=443 action=drop comment="lab:genuine-unavailable"`)
	tick()
	if f.watchdogRecord(ctx, t).Control.Misses != 1 {
		t.Fatal("watchdog counted a matching-ID impostor healthy during control HTTPS outage")
	}
	f.mustRun(ctx, t, `/interface/bridge/filter/remove [find comment="lab:genuine-unavailable"]`)
	tick()
	if f.watchdogRecord(ctx, t).Control.Misses != 0 {
		t.Fatal("control health did not recover after genuine replies returned")
	}
	f.mustRun(ctx, t, "/container/stop [find where name=tikray]")
	if f.waitForContainer(ctx, "tikray", "stopped") != nil {
		t.Fatal("could not stop genuine control")
	}
	tick()
	if f.routerHealth(ctx, "https", installControl, id) || f.routerHealth(ctx, "http", installControl, id) || f.watchdogRecord(ctx, t).Control.Misses != 1 {
		t.Fatal("a stopped control still had a healthy transport or watchdog state")
	}
	after, _ := f.spoofObservation(ctx)
	if after.Phase != "clone" || after.TLS != 0 || after.HTTP != 0 {
		t.Fatal("runner received protected traffic in the absence of control")
	}
	f.spoofDirectFlow(ctx, t)
	// Positive exposure using exactly the same running attacker. Its code,
	// assigned IP/MAC, TLS leaf and claimed public ID are unchanged.
	f.mustRun(ctx, t, `/interface/bridge/set [find name=tikray] arp=enabled`)
	f.mustRun(ctx, t, `/interface/bridge/port/set [find bridge=tikray] learn=yes unknown-unicast-flood=yes`)
	f.mustRun(ctx, t, `/ip/arp/remove [find interface=tikray and address=172.30.252.2 and !dynamic and comment="tikray:arp-ctl"]`)
	f.mustRun(ctx, t, `/interface/bridge/host/remove [find bridge=tikray and comment="tikray:fdb-ctl"]`)
	_, ok := poll(ctx, 20*time.Second, 300*time.Millisecond, func() bool {
		return f.routerHealth(ctx, "https", installControl, id) && f.routerHealth(ctx, "http", installControl, id)
	})
	if !ok {
		t.Fatal("removing the protections did not expose the attacker; negative proof is inconclusive")
	}
	end, _ := f.spoofObservation(ctx)
	if end.TLS < 1 || end.HTTP < 1 {
		t.Fatal("unbound positive control did not reach the attacker's own .2 sockets")
	}
	t.Log("runner claimed .2, sent unsolicited ARP and cloned the control MAC; only genuine control answered with protection, and the same matching-ID impostor answered both transports when unbound")
}
