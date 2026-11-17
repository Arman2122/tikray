//go:build lab

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/health"
	"github.com/Arman2122/tikray/internal/service"
	"github.com/Arman2122/tikray/internal/store"
)

const (
	outageOwnerNS = "tkoutage-owner"
	outageOwnerIP = "192.168.88.120"
)

type outageLab struct {
	*routingLab
	wire *imageWANProof
}

func deployOutage(ctx context.Context, t *testing.T, emitOpen bool) *outageLab {
	t.Helper()
	f := deployRouting(ctx, t, t)
	if exec.CommandContext(ctx, "ip", "netns", "add", outageOwnerNS).Run() != nil {
		t.Fatal("independent direct client namespace unavailable")
	}
	t.Cleanup(func() {
		if exec.Command("ip", "netns", "del", outageOwnerNS).Run() != nil {
			t.Error("independent direct client cleanup failed")
		}
	})
	for _, args := range [][]string{
		{"link", "add", "tklab-owner-h", "type", "veth", "peer", "name", "eth0", "netns", outageOwnerNS},
		{"link", "set", "tklab-owner-h", "master", "tklab-lan", "up"},
		{"-n", outageOwnerNS, "link", "set", "lo", "up"},
		{"-n", outageOwnerNS, "link", "set", "eth0", "up"},
		{"-n", outageOwnerNS, "addr", "add", outageOwnerIP + "/24", "dev", "eth0"},
		{"-n", outageOwnerNS, "route", "add", "default", "via", "192.168.88.1"},
	} {
		if exec.CommandContext(ctx, "ip", args...).Run() != nil {
			t.Fatal("independent direct client link unavailable")
		}
	}
	m, e := outageOwner(ctx, "cat", "/sys/class/net/eth0/address").Output()
	mac, err := net.ParseMAC(strings.TrimSpace(string(m)))
	if e != nil || err != nil || len(mac) != 6 || mac.String() == f.mac || mac.String() == f.peerMAC {
		t.Fatal("independent direct client MAC unavailable")
	}
	f.mustRun(ctx, t, fmt.Sprintf(`/ip/dhcp-server/lease/add server=m3-routing-dhcp address=%s mac-address=%s comment="lab:outage-direct"`, outageOwnerIP, mac))
	if outageOwner(ctx, "python3", "-c", routingDHCP, outageOwnerIP).Run() != nil {
		t.Fatal("independent direct client did not receive DHCP ACK")
	}
	c := &outageLab{routingLab: f, wire: f.imageWAN(ctx, t, emitOpen)}
	c.requireDirectOwner(ctx, t)
	return c
}

func outageOwner(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, "ip", append([]string{"netns", "exec", outageOwnerNS}, args...)...)
}

func (f *outageLab) directOwner(ctx context.Context) bool {
	out, err := outageOwner(ctx, "curl", "--noproxy", "*", "-fsS", "--max-time", "3", "http://"+routingRemote+"/whoami").Output()
	return err == nil && strings.TrimSpace(string(out)) == egressDirect
}

func (f *outageLab) requireDirectOwner(ctx context.Context, t *testing.T) {
	t.Helper()
	if !f.directOwner(ctx) || outageOwner(ctx, "nc", "-z", "-w", "3", "192.168.88.1", "22").Run() != nil {
		t.Fatal("unmanaged client's direct forwarding or RouterOS access failed")
	}
}

func (f *outageLab) requireNoLeak(t *testing.T) {
	t.Helper()
	if sample := f.wire.sample(t); sample.closedDirect != 0 || sample.unknown != 0 {
		t.Fatalf("WAN saw invalid traffic: closed direct %d, untranslated %d", sample.closedDirect, sample.unknown)
	}
}

func (f *outageLab) requireFallback(ctx context.Context, t *testing.T) {
	t.Helper()
	before := f.wire.directCounts(t)
	if _, ok := poll(ctx, 80*time.Second, time.Second, func() bool {
		return f.peerEgress(ctx, routingRemote) == egressDirect && newWirePackets(before, f.wire.directCounts(t)) > 0
	}); !ok {
		t.Fatal("fresh open flows did not reach WAN through both observers")
	}
	if f.egress(ctx, routingRemote) != "" || f.egress(ctx, routingDomestic) != "" {
		t.Fatal("closed full policy forwarded data during runner loss")
	}
	f.requireDirectOwner(ctx, t)
	f.requireNoLeak(t)
}

func (f *outageLab) requireDNSMode(ctx context.Context, t *testing.T, fallback bool) {
	t.Helper()
	for _, proto := range []string{"udp", "tcp"} {
		tag := "tikray:dns-full-open-" + proto
		if _, ok := poll(ctx, 30*time.Second, time.Second, func() bool {
			rows := f.readROS(ctx, t, "/ip/firewall/nat", "disabled", "?comment="+tag)
			return len(rows) == 1 && (rows[0]["disabled"] == "true") == fallback
		}); !ok {
			t.Fatal("open DNS rule did not follow the runner gateway", proto)
		}
		closed := f.readROS(ctx, t, "/ip/firewall/nat", "disabled", "?comment=tikray:dns-full-closed-"+proto)
		if len(closed) != 1 || closed[0]["disabled"] == "true" {
			t.Fatal("closed DNS rule changed during gateway transition", proto)
		}
	}
	if fallback {
		f.imageDNSFallback(ctx, t)
		return
	}
	for _, proto := range []string{"udp", "tcp"} {
		for _, peer := range []bool{true, false} {
			name := strconv.FormatInt(time.Now().UnixNano(), 10) + ".foreign.routing-probe.test."
			if got := f.protocolDNS(ctx, t, peer, name, "A", proto, routingRemote); !slices.Equal(got, []string{"198.18.53.2"}) {
				t.Fatal("runner DNS did not receive an answer again", proto)
			}
		}
	}
}

// The fixture temporarily moves the active selection and uses the production
// Reload endpoint. This stops xray in the existing runner without altering
// binaries, privileges, or the bindings used by RouterOS.
func (f *outageLab) runnerOutageCommand(ctx context.Context, t *testing.T, command, state string) {
	t.Helper()
	const auth = `:local b [/file/get [find where name="disk1/tikray/data/run/runner.token"] contents]; :set b [:pick $b 0 [:find ($b . "\n") "\n"]]; `
	const request = `[/tool/fetch url="http://172.30.252.3:8080/v1/`
	const bearer = `" duration=4s http-header-field=("Authorization: Bearer " . $b) output=user as-value]`
	const read = `{:local r ` + request + `status` + bearer + `; :local s [:deserialize from=json value=($r->"data")]; `
	var predicate string
	switch state {
	case "empty":
		predicate = `(($s->"state")="empty" and ([:typeof ($s->"xray_pid")]="nil" or [:typeof ($s->"xray_pid")]="nothing" or ($s->"xray_pid")=0) and [:len ($s->"active")]=0)`
	case "running":
		predicate = `(($s->"state")="running" and ($s->"xray_pid")>0 and ($s->"gateway_up")=true)`
	default:
		t.Fatal("unsupported runner witness")
	}
	operation := ""
	if command == "reload" {
		operation = `:local reload ` + request + `reload" http-method=post http-data="{}" duration=4s http-header-field=("Authorization: Bearer " . $b) output=user as-value]; :if (($reload->"status")!="finished") do={:error "lab reload"}; `
	}
	if _, ok := poll(ctx, 30*time.Second, time.Second, func() bool {
		out, err := f.CHR.RunPrivate(ctx, "{"+auth+operation+read+":if "+predicate+` do={:put "|m3-outage-runner-ok|"}}}`)
		return err == nil && strings.Contains(out, "|m3-outage-runner-ok|")
	}); !ok {
		t.Fatal("authenticated running container did not confirm xray state", state)
	}
}

func (f *outageLab) renameOutageSelection(ctx context.Context, t *testing.T, from, to string) {
	t.Helper()
	f.mustRun(ctx, t, fmt.Sprintf(`{:local i [/file/find where name="%s"]; :if (([:len $i]!=1) or ([:len [/file/find where name="%s"]]>0)) do={:error "lab selection identity"}; /file/set $i name="%s"}`, from, to, to))
}

func (f *outageLab) requireProxy(ctx context.Context, t *testing.T) {
	t.Helper()
	if _, ok := poll(ctx, f.proxiedWithin(), time.Second, func() bool {
		return isRoutingProxy(f.peerEgress(ctx, routingRemote)) && isRoutingProxy(f.egress(ctx, routingRemote))
	}); !ok {
		t.Fatal("both policy clients did not recover through the proxy")
	}
	f.requireDirectOwner(ctx, t)
	f.requireNoLeak(t)
}

func (f *outageLab) serveOutageDoH(ctx context.Context, t *testing.T) string {
	t.Helper()
	const address = "203.0.113.53"
	dir := t.TempDir()
	cert, key, witness := filepath.Join(dir, "tls.pem"), filepath.Join(dir, "tls.key"), filepath.Join(dir, "wire")
	generate := exec.CommandContext(ctx, "openssl", "req", "-x509", "-newkey", "ec",
		"-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "1",
		"-subj", "/CN=lab-outage", "-addext", "subjectAltName=IP:"+address, "-out", cert, "-keyout", key)
	if generate.Run() != nil {
		t.Fatal("could not create isolated DoH certificate")
	}
	helper := filepath.Join(dir, "outage-doh")
	build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", helper, "./test/e2e/testdata/outage-doh")
	build.Dir = repoRoot()
	if build.Run() != nil {
		t.Fatal("could not build the HTTP/2 DoH fixture")
	}
	startRoutingProcess(t, f.Net.Inet(ctx, helper, address, cert, key, witness, egressDirect, serverEgress["a"], serverEgress["b"]))
	if _, ok := poll(ctx, 5*time.Second, 100*time.Millisecond, func() bool { _, err := os.Stat(witness); return err == nil }); !ok {
		t.Fatal("TLS DNS endpoint unavailable")
	}
	if f.CHR.Push(ctx, cert, dataRoot+"/run/lab-outage.pem") != nil {
		t.Fatal("could not stage the public DoH certificate")
	}
	f.scheduler(ctx, t, false)
	f.containerAction(ctx, t, "runner", "stop", "stopped")
	f.mustRun(ctx, t, `/container/envs/add list=tikray-runner key=SSL_CERT_FILE value="/data/run/lab-outage.pem" comment="lab:outage-doh"`)
	f.containerAction(ctx, t, "runner", "start", "running")
	if _, err := f.api.SetDNS(ctx, store.DNS{Remote: "https://" + address + "/dns-query", Domestic: netip.MustParseAddr("203.0.113.54")}); err != nil {
		t.Fatal("could not configure the private DoH endpoint")
	}
	f.checkReady(ctx, t)
	f.requireProxy(ctx, t)
	f.requireDoH(ctx, t, witness, false)
	return witness
}

func (f *outageLab) requireDoH(ctx context.Context, t *testing.T, witness string, direct bool) {
	t.Helper()
	marker, answer := byte('P'), "198.18.55.2"
	if direct {
		marker, answer = 'D', "198.18.55.1"
	}
	for _, proto := range []string{"udp", "tcp"} {
		prior, _ := os.ReadFile(witness)
		name := strconv.FormatInt(time.Now().UnixNano(), 10) + ".foreign.routing-probe.test."
		got := f.protocolDNS(ctx, t, false, name, "A", proto, routingRemote)
		after, err := os.ReadFile(witness)
		if !slices.Equal(got, []string{answer}) || err != nil || bytes.Count(after, []byte{marker}) <= bytes.Count(prior, []byte{marker}) {
			t.Fatal("closed client did not receive a fresh encrypted DNS response on the expected path", proto)
		}
	}
}
func (f *outageLab) retainedUDP(ctx context.Context, t *testing.T) string {
	t.Helper()
	// A tuple can expire during a native read, especially on LTS. Use a
	// separate observer so the owner's continuity proof stays independent.
	reader := f.ownerSession(ctx, t)
	defer reader.Close()
	bound, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	var id string
	if _, ok := poll(bound, 8*time.Second, 200*time.Millisecond, func() bool {
		rows, err := reader.CommandAt(bound, reader.Generation(), []string{
			"/ip/firewall/connection/print", "=.proplist=.id,connection-mark",
			"?protocol=udp", "?src-address=" + routingPeer, "?src-port=32242", "?dst-address=" + routingRemote, "?dst-port=31948",
		})
		if err != nil || len(rows) > 1 {
			return false
		}
		if len(rows) == 1 && rows[0]["connection-mark"] == "tikray-open-runner" {
			id = rows[0][".id"]
		}
		return true
	}); !ok {
		t.Fatal("could not read the exact retained UDP binding")
	}
	return id
}

func (f *outageLab) udpWatchTests(ctx context.Context, t *testing.T) int {
	t.Helper()
	rows := f.readROS(ctx, t, "/tool/netwatch", "done-tests", "?comment=tikray:udp-watch")
	if len(rows) != 1 {
		t.Fatal("open UDP watch identity unavailable")
	}
	n, err := strconv.Atoi(rows[0]["done-tests"])
	if err != nil {
		t.Fatal("open UDP watch count unavailable")
	}
	return n
}

func requireOutageDatagram(ctx context.Context, t *testing.T, socket *imagePeerFlow, path byte) {
	t.Helper()
	start := socket.count(socket.replies, path)
	if _, ok := poll(ctx, 35*time.Second, 200*time.Millisecond, func() bool {
		return socket.count(socket.replies, path) >= start+2
	}); !ok || socket.count(socket.wire, '?') > 0 {
		t.Fatalf("original open UDP socket failed %c path: replies=%d invalid_wan_sources=%d",
			path, socket.count(socket.replies, path)-start, socket.count(socket.wire, '?'))
	}
}

func TestM3Outage(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Minute)
	defer cancel()
	l := &Lab{Version: env("TIKRAY_LAB_CHANNEL", "stable"), Arch: labArch()}
	check := l.recordM3Checks(t, "m3-outage")
	deploy := func(t *testing.T) *outageLab {
		t.Helper()
		f := deployOutage(ctx, t, true)
		l.Version = f.Version
		return f
	}

	check("all_servers_down", func(t *testing.T) {
		f := deploy(t)
		doh := f.serveOutageDoH(ctx, t)
		for _, name := range []string{"a", "b"} {
			if f.Inet.SetServer(name, false) != nil {
				t.Fatal("could not stop both proxy servers")
			}
		}
		if _, ok := poll(ctx, f.proxiedWithin(), time.Second, func() bool {
			resp, err := f.api.Status(ctx)
			var s service.Status
			return err == nil && resp.Decode(&s) == nil && s.Health.Level == health.LevelOutage &&
				!aliveIn(s.Health, f.serverIDs["a"]) && !aliveIn(s.Health, f.serverIDs["b"]) &&
				f.peerEgress(ctx, routingRemote) == egressDirect
		}); !ok || !f.runnerRespondsToPing(ctx) {
			t.Fatal("observatory outage could not be distinguished from gateway loss")
		}
		if f.egress(ctx, routingRemote) != "" || f.egress(ctx, routingDomestic) != "" {
			t.Fatal("closed full traffic escaped during observatory outage")
		}
		f.requireNoLeak(t)
		f.setClientPolicy(ctx, t, store.Policy{Mode: store.ModeSmart, KillSwitch: true})
		if f.egress(ctx, routingDomestic) != egressDirect || f.egress(ctx, routingRemote) != "" {
			t.Fatal("closed smart policy did not preserve only its domestic exception")
		}
		f.requireDoH(ctx, t, doh, true)
		f.requireDirectOwner(ctx, t)
		f.requireNoLeak(t)
	})
	check("runner_stopped", func(t *testing.T) {
		f := deploy(t)
		socket := f.keepImagePeerFlow(ctx, t)
		ssh := f.ownerLANSSH(ctx, t)
		f.scheduler(ctx, t, false)
		f.containerAction(ctx, t, "tikray", "stop", "stopped")
		stale := f.retainedUDP(ctx, t)
		if stale == "" {
			t.Fatal("could not identify living open UDP binding before outage")
		}
		const owner = "lab:outage-shared-mark"
		f.mustRun(ctx, t, `/ip/firewall/filter/add chain=lab-outage-owner action=return connection-mark=tikray-open-runner comment="lab:outage-shared-mark"`)
		rows := f.readROS(ctx, t, "/ip/firewall/filter", ".id", "?comment="+owner)
		if len(rows) != 1 || rows[0][".id"] == "" {
			t.Fatal("independent owner consumer unavailable")
		}
		f.containerAction(ctx, t, "runner", "stop", "stopped")
		f.requireFallback(ctx, t)
		scans := f.udpWatchTests(ctx, t)
		if _, ok := poll(ctx, 23*time.Second, time.Second, func() bool { return f.udpWatchTests(ctx, t) >= scans+2 }); !ok {
			t.Fatal("native watch did not exercise owner-conflict boundary")
		}
		if f.retainedUDP(ctx, t) != stale || socket.count(socket.replies, 'D') != 0 {
			t.Fatal("native cleanup retired a binding used by an owner rule")
		}
		f.routingWrite(ctx, t, "/ip/firewall/filter/remove", "=.id="+rows[0][".id"])
		requireOutageDatagram(ctx, t, socket, 'D')
		f.requireDNSMode(ctx, t, true)
		ssh()
		f.containerAction(ctx, t, "runner", "start", "running")
		f.requireProxy(ctx, t)
		requireOutageDatagram(ctx, t, socket, 'P')
		f.requireNoLeak(t)
		ssh()
	})
	check("xray_dead_runner_up", func(t *testing.T) {
		f := deploy(t)
		f.scheduler(ctx, t, false)
		f.containerAction(ctx, t, "tikray", "stop", "stopped")
		original, ok := f.containerImage(ctx, "runner")
		if !ok {
			t.Fatal("running image identity unavailable")
		}
		active := dataRoot + "/run/active.json"
		hidden := dataRoot + "/run/outage-selection.json"
		f.runnerOutageCommand(ctx, t, "", "running")
		f.renameOutageSelection(ctx, t, active, hidden)
		f.runnerOutageCommand(ctx, t, "reload", "empty")
		f.requireFallback(ctx, t)
		f.requireDNSMode(ctx, t, true)
		f.runnerOutageCommand(ctx, t, "", "empty")
		if row, ok := f.containerImage(ctx, "runner"); !ok || row.id != original.id || row.imageID != original.imageID || row.root != original.root || f.waitForContainer(ctx, "tikray-runner", "running") != nil {
			t.Fatal("the same runner did not remain up through convergence")
		}
		f.renameOutageSelection(ctx, t, hidden, active)
		f.runnerOutageCommand(ctx, t, "reload", "running")
		f.requireProxy(ctx, t)
	})
	check("control_stopped", func(t *testing.T) {
		f := deploy(t)
		socket := f.keepImagePeerFlow(ctx, t)
		ssh := f.ownerLANSSH(ctx, t)
		f.scheduler(ctx, t, false)
		f.containerAction(ctx, t, "tikray", "stop", "stopped")
		f.requireProxy(ctx, t)
		f.requireDNSMode(ctx, t, false)
		socket.requireProxy(ctx, t)
		ssh()
		f.containerAction(ctx, t, "tikray", "start", "running")
		f.checkReady(ctx, t)
		f.requireNoLeak(t)
	})
	check("early_reboot", func(t *testing.T) {
		f := deploy(t)
		f.scheduler(ctx, t, false)
		for _, component := range []string{"tikray", "runner"} {
			before, ok := f.containerImage(ctx, component)
			if !ok {
				t.Fatal("boot fixture could not verify the installed container", component)
			}
			f.routingWrite(ctx, t, "/container/set", "=.id="+before.id, "=start-on-boot=no")
			after, ok := f.containerImage(ctx, component)
			if !ok || after.id != before.id || (after.settings["start-on-boot"] != "false" && after.settings["start-on-boot"] != "no") {
				t.Fatal("could not defer container startup for the forwarding witness", component)
			}
		}
		// RouterOS can recover a container that was interrupted while
		// running even when start-on-boot is disabled. Record both as
		// explicitly stopped before cutting power.
		f.containerAction(ctx, t, "tikray", "stop", "stopped")
		f.containerAction(ctx, t, "runner", "stop", "stopped")
		before := f.wire.directCounts(t)
		f.ros.Close()
		if f.CHR.PowerCycle(ctx) != nil {
			t.Fatal("real CHR power cycle failed")
		}
		f.ros = f.ownerSession(ctx, t)
		if f.waitForContainer(ctx, "tikray", "stopped") != nil || f.waitForContainer(ctx, "tikray-runner", "stopped") != nil {
			t.Fatal("unexpected container startup during early forwarding window")
		}
		f.requireFallback(ctx, t)
		if newWirePackets(before, f.wire.directCounts(t)) < 1 {
			t.Fatal("external capture missed early router forwarding")
		}
		f.requireDNSMode(ctx, t, true)
		for _, component := range []string{"tikray", "runner"} {
			row, ok := f.containerImage(ctx, component)
			if !ok {
				t.Fatal("could not verify the original container after reboot", component)
			}
			f.routingWrite(ctx, t, "/container/set", "=.id="+row.id, "=start-on-boot=yes")
		}
		f.containerAction(ctx, t, "runner", "start", "running")
		f.containerAction(ctx, t, "tikray", "start", "running")
		f.requireProxy(ctx, t)
		f.checkReady(ctx, t)
	})
	check("recovery", func(t *testing.T) {
		f := deploy(t)
		socket := f.keepImagePeerFlow(ctx, t)
		ssh := f.ownerLANSSH(ctx, t)
		f.scheduler(ctx, t, false)
		f.requireDNSMode(ctx, t, false)
		f.containerAction(ctx, t, "runner", "stop", "stopped")
		f.requireFallback(ctx, t)
		requireOutageDatagram(ctx, t, socket, 'D')
		f.requireDNSMode(ctx, t, true)
		f.containerAction(ctx, t, "runner", "start", "running")
		f.requireProxy(ctx, t)
		requireOutageDatagram(ctx, t, socket, 'P')
		f.requireDNSMode(ctx, t, false)
		f.checkReady(ctx, t)
		ssh()
		f.requireNoLeak(t)
	})
}
