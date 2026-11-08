//go:build lab

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/routeros"
	"github.com/Arman2122/tikray/internal/store"
	"github.com/Arman2122/tikray/test/lab"
)

const removalFile = "m3-lab-uninstall.rsc"
const siblingFile = "disk1/tikray-owner-sibling"

type removalLab struct {
	*installLab
	script, id, cert string
	baseline         serviceBaseline
	foreignARP       string
	serial           int
}

type serviceBaseline struct {
	Certificate string
	Disabled    bool
	Port        int
	Grants      []netip.Prefix
}

func observedService(ctx context.Context, t *testing.T, f *installLab) serviceBaseline {
	t.Helper()
	got := f.mustRun(ctx, t, `{:local c [/ip/service/get [:pick [/ip/service/find where name="api-ssl" and !dynamic] 0]]; :put [:serialize to=json options=json.no-string-conversion value={"disabled"=($c->"disabled");"certificate"=[:tostr ($c->"certificate")];"address"=[:tostr ($c->"address")];"port"=($c->"port")}]}`)
	var wire struct {
		Certificate, Address string
		Disabled             bool
		Port                 int
	}
	if json.Unmarshal([]byte(got), &wire) != nil || wire.Port < 1 {
		t.Fatal("API-SSL baseline unavailable")
	}
	v := serviceBaseline{Certificate: wire.Certificate, Disabled: wire.Disabled, Port: wire.Port}
	for _, item := range strings.FieldsFunc(wire.Address, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
		p, e := netip.ParsePrefix(item)
		if e != nil {
			a, err := netip.ParseAddr(item)
			if err != nil {
				t.Fatal("unreadable service grant")
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		v.Grants = append(v.Grants, p.Masked())
	}
	slices.SortFunc(v.Grants, func(a, b netip.Prefix) int {
		if n := a.Addr().Compare(b.Addr()); n != 0 {
			return n
		}
		return a.Bits() - b.Bits()
	})
	return v
}

func setupRemoval(ctx context.Context, t *testing.T, reuse bool) *removalLab {
	t.Helper()
	f := DeployM3(ctx, t)
	if reuse {
		f.mustRun(ctx, t, `/certificate/add name=owner-api common-name=owner-api subject-alt-name=IP:172.30.252.1 key-size=prime256v1 key-usage=key-cert-sign,digital-signature,tls-server; /certificate/sign owner-api; /ip/service/set [find where name=api-ssl and !dynamic] certificate=owner-api disabled=no`)
	}
	u := &removalLab{installLab: f, baseline: observedService(ctx, t, f)}
	f.mustRun(ctx, t, `/ip/arp/add interface=ether2 address=192.168.88.111 mac-address=02:11:22:33:44:55 comment="owner:tikray:arp-ctl"`)
	u.foreignARP = f.mustRun(ctx, t, `:put [:tostr [/ip/arp/find where comment="owner:tikray:arp-ctl"]]`)
	if u.foreignARP == "" {
		t.Fatal("unrelated static ARP witness absent")
	}
	f.mustRun(ctx, t, `/file/add name="disk1/tikray-owner-sibling" type=file contents="owner stays"`)
	f.stage(ctx, t, true)
	f.requireSuccess(ctx, t)
	f.checkReady(ctx, t)
	var cfg routeros.Installation
	if json.Unmarshal([]byte(f.file(ctx, t, dataRoot+"/state/routeros.json")), &cfg) != nil {
		t.Fatal("credential audit fixture unavailable")
	}
	private := []string{cfg.Password, f.file(ctx, t, apiToken), f.file(ctx, t, runnerToken), f.file(ctx, t, dataRoot+"/state/setup.code")}
	events, err := f.pinned(ctx, t).Events(ctx, 0)
	if err != nil {
		t.Fatal("pre-removal events unavailable")
	}
	t.Cleanup(func() {
		sub, stop := context.WithTimeout(context.Background(), 45*time.Second)
		defer stop()
		f.auditKnown(sub, t, events.Body, private...)
	})
	u.id = f.checkHealthIdentity(ctx, t)
	u.cert = observedService(ctx, t, f).Certificate
	wantCert := "tikray-api"
	if reuse {
		wantCert = "owner-api"
	}
	if u.cert != wantCert {
		t.Fatal("unexpected service identity in uninstall fixture")
	}
	if f.mustRun(ctx, t, `:put [:len [/ip/arp/find where interface=tikray and !dynamic and comment~"^tikray:arp-"]]`) != "2" || f.mustRun(ctx, t, `:put [:len [/interface/bridge/host/find where bridge=tikray and !dynamic and comment~"^tikray:fdb-"]]`) != "2" {
		t.Fatal("binding teardown fixture lacks both owned peer bindings")
	}
	file := filepath.Join(f.workDir, "uninstall.rsc")
	cmd := exec.CommandContext(ctx, "go", "run", "./cmd/tikray-installer", "-uninstall-out", file)
	cmd.Dir = repoRoot()
	if cmd.Run() != nil {
		t.Fatal("cannot package production owner uninstaller")
	}
	b, err := os.ReadFile(file)
	if err != nil || len(b) == 0 || bytes.Contains(b, []byte("# @TIKRAY_")) {
		t.Fatal("invalid uninstall artifact")
	}
	if delivered := os.Getenv("TIKRAY_LAB_UNINSTALLER"); delivered != "" {
		d, e := os.ReadFile(delivered)
		if e != nil || !bytes.Equal(b, d) {
			t.Fatal("delivered owner uninstaller differs from reviewed source")
		}
		file = delivered
	}
	if f.CHR.Push(ctx, file, removalFile) != nil {
		t.Fatal("uninstall upload failed")
	}
	u.script = string(b)
	f.mustRun(ctx, t, `/system/script/add name=m3-removal-observer policy=read source="" comment="owner:removal-observer"`)
	return u
}

// The terminal can include expanded peer values. Return only a matching
// constant from the packaged program, a syntax coordinate, or a fixed class.
func (f *removalLab) remove(ctx context.Context, name, choice string) error {
	return f.removeVia(ctx, name, choice, f.CHR.RunPrivate)
}

func (f *removalLab) removeVia(ctx context.Context, name, choice string, invoke func(context.Context, string) (string, error)) error {
	f.serial++
	cmd := fmt.Sprintf(`{ :global tikrayUninstallData; :set tikrayUninstallData "%s"; :local observer [/system/script/find where name=m3-removal-observer]; /system/script/set $observer comment="entered-%d"; :onerror reason in={ /import file-name="%s"; /system/script/set $observer comment="complete-%d"; :put "m3-remove-ok" } do={ /system/script/set $observer comment="refused-%d"; :put ("m3-remove-error=" . [:convert [:tostr $reason] to=base64]) } }`, choice, f.serial, name, f.serial, f.serial)
	sub, stop := context.WithTimeout(ctx, 15*time.Minute)
	defer stop()
	out, e := invoke(sub, cmd)
	if e != nil {
		return errors.New("private uninstall command failed")
	}
	parts := strings.Split(strings.TrimSpace(out), "\n")
	last := strings.TrimSpace(parts[len(parts)-1])
	if last == "m3-remove-ok" {
		return nil
	}
	encoded, ok := strings.CutPrefix(last, "m3-remove-error=")
	if !ok {
		// The owner SSH exec occasionally omits terminal output. Only a separate
		// read of this invocation's post-import receipt proves it returned.
		completed := false
		_, _ = poll(sub, 15*time.Second, 250*time.Millisecond, func() bool {
			seen, err := f.CHR.RunPrivate(sub, `:put ("m3-outcome=" . [/system/script/get [find where name=m3-removal-observer] comment] . "|end")`)
			if err != nil {
				return false
			}
			completed = strings.Contains(seen, fmt.Sprintf("m3-outcome=complete-%d|end", f.serial))
			return completed || strings.Contains(seen, fmt.Sprintf("m3-outcome=refused-%d|end", f.serial))
		})
		if completed {
			return nil
		}
		for _, reason := range []string{"syntax error", "expected end of command", "expected command name", "input does not match any value", "failure:", "interrupted", "connection closed", "error occurred", "shared_reference_refuses", "tikray: uninstall complete", "tikray: owner data kept", "tikray: already uninstalled"} {
			if strings.Contains(strings.ToLower(out), strings.ToLower(reason)) {
				return fmt.Errorf("uninstall acknowledgement missing (%s %s, bytes %d)", reason, importPosition.FindString(out), len(out))
			}
		}
		return fmt.Errorf("uninstall acknowledgement missing (bytes %d)", len(out))
	}
	b, e := base64.StdEncoding.DecodeString(encoded)
	if e != nil {
		return errors.New("uninstall diagnostic unavailable")
	}
	msg := string(b)
	for _, m := range sourceError.FindAllStringSubmatch(f.script, -1) {
		if strings.Contains(msg, m[1]) {
			return errors.New(m[1])
		}
	}
	for _, category := range []string{"m3-fixture-interrupted", "tikray: shared_reference_refuses", "expected end of command", "input does not match any value", "invalid internal item number", "no such item", "not enough permissions", "already have", "cannot remove", "syntax error", "invalid value", "expected argument"} {
		if strings.Contains(msg, category) {
			return fmt.Errorf("%s %s", category, importPosition.FindString(msg))
		}
	}
	return fmt.Errorf("unclassified uninstall refusal %s", importPosition.FindString(msg))
}

func (f *removalLab) clean(ctx context.Context, t *testing.T, reuse bool) {
	t.Helper()
	if !f.installClean(ctx) {
		t.Fatal("owned RouterOS objects remain after uninstall")
	}
	after := observedService(ctx, t, f.installLab)
	if after.Certificate != f.baseline.Certificate || after.Port != f.baseline.Port || after.Disabled != f.baseline.Disabled || !slices.Equal(after.Grants, f.baseline.Grants) {
		t.Fatal("original API-SSL settings were not exactly restored")
	}
	got := f.mustRun(ctx, t, `:put [:len [/certificate/find where name="`+f.cert+`"]]`)
	if (reuse && got != "1") || (!reuse && got != "0") {
		t.Fatal("incorrect disposition of API certificate")
	}
	if f.file(ctx, t, siblingFile) != "owner stays" {
		t.Fatal("sibling file changed")
	}
	if f.mustRun(ctx, t, `:put [:tostr [/ip/arp/find where comment="owner:tikray:arp-ctl" and interface=ether2 and address=192.168.88.111 and mac-address=02:11:22:33:44:55]]`) != f.foreignARP {
		t.Fatal("unrelated static ARP identity changed")
	}
	if f.containerTmpDir(ctx, t) != f.ownerTmpDir {
		t.Fatal("owner container configuration changed")
	}
	f.checkOwnerRules(ctx, t)
	f.ownerPortForward(ctx, t)
	if f.whoami(ctx) != egressDirect {
		t.Fatal("LAN routing failed after uninstall")
	}
}

// IDs alone cannot establish that preflight preserved an active installation:
// disabling a scheduler, clearing start-on-boot, or changing API-SSL keeps its ID.
func (f *removalLab) refusalState(ctx context.Context, t *testing.T) (string, error) {
	t.Helper()
	owned, err := f.owned(ctx)
	if err != nil {
		return "", err
	}
	flags := f.mustRun(ctx, t, `{:foreach n in={"tikray";"tikray-runner"} do={:local rows [/container/find where name=$n];:put ([:len [/container/find where name=$n and running]] . "|" . [/container/get $rows start-on-boot])};:put [/system/scheduler/get [find where comment="tikray:watchdog-scheduler"] disabled]}`)
	service, _ := json.Marshal(observedService(ctx, t, f.installLab))
	return owned + "\n" + flags + "\n" + string(service), nil
}

// A second client's stream continues while RouterOS deletes steering state.
// Compare the original native binding ID and *new* echoed packets afterward.
func (f *removalLab) unchangedFlow(ctx context.Context, t *testing.T) func() {
	t.Helper()
	f.mustRun(ctx, t, `/ip/firewall/connection/tracking/set enabled=yes udp-timeout=8m udp-stream-timeout=8m`)
	start := func(c *exec.Cmd) {
		t.Helper()
		if c.Start() != nil {
			t.Fatal("unaffected-flow process did not start")
		}
		t.Cleanup(func() {
			if c.Process != nil {
				_ = c.Process.Kill()
			}
			_ = c.Wait()
		})
	}
	start(f.Net.Inet(ctx, "python3", "-c", `import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("198.51.100.254",31931))
while True:
 b,peer=s.recvfrom(16);s.sendto(b,peer)`))
	file := filepath.Join(f.workDir, "unaffected-count")
	start(f.Net.Client(ctx, "python3", "-c", `import pathlib,socket,sys,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("192.168.88.10",31932));s.settimeout(1);i=0
while True:
 try:
  probe=str(i).encode();s.sendto(probe,("198.51.100.254",31931))
  if s.recv(64)==probe:i+=1;pathlib.Path(sys.argv[1]).write_text(str(i))
 except (OSError,TimeoutError):pass
 time.sleep(.25)`, file))
	count := func() int { b, _ := os.ReadFile(file); n, _ := strconv.Atoi(string(b)); return n }
	if _, ok := poll(ctx, 12*time.Second, 200*time.Millisecond, func() bool { return count() >= 2 }); !ok {
		t.Fatal("unrelated WAN stream has no positive replies")
	}
	const query = `{:local rows [/ip/firewall/connection/find where src-address=192.168.88.10 and dst-address=198.51.100.254 and protocol=udp and src-port=31932 and dst-port=31931];:put ("flow=" . [:len $rows] . "|" . [:convert [:tostr [:pick $rows 0]] to=hex] . "|end")}`
	identity := func() string {
		t.Helper()
		fields := regexp.MustCompile(`flow=([0-9]+)\|([a-fA-F0-9]*)\|end`).FindStringSubmatch(f.mustRun(ctx, t, query))
		if len(fields) != 3 || fields[1] == "0" {
			return ""
		}
		if fields[1] != "1" || len(fields[2]) == 0 {
			t.Fatal("unrelated WAN binding was not unique")
		}
		return fields[2]
	}
	var id string
	if _, ok := poll(ctx, 15*time.Second, 200*time.Millisecond, func() bool { id = identity(); return id != "" }); !ok {
		t.Fatal("connection table never exposed the live unrelated UDP stream")
	}
	return func() {
		t.Helper()
		n := count()
		if _, ok := poll(ctx, 10*time.Second, 200*time.Millisecond, func() bool { return count() > n }); !ok || identity() != id {
			t.Fatal("unrelated stream or native conntrack binding did not survive uninstall")
		}
	}
}

func TestM3Uninstall(t *testing.T) {
	ctx, stop := context.WithTimeout(t.Context(), 125*time.Minute)
	defer stop()
	v, e := lab.ResolveChannel(ctx, "", env("TIKRAY_LAB_CHANNEL", "stable"))
	if e != nil {
		t.Fatal("uninstall target unavailable")
	}
	check := (&Lab{Version: v, Arch: labArch()}).recordM3Checks(t, "m3-uninstall")
	check("keep_data", func(st *testing.T) {
		f := setupRemoval(ctx, st, false)
		api := f.pinned(ctx, st)
		code := f.file(ctx, st, dataRoot+"/state/setup.code")
		password := rand.Text()
		anon := authLabClient{base: api.BaseURL, http: api.HTTPClient()}
		login := anon.call(st, ctx, "POST", "/v1/auth/setup", map[string]string{"username": "owner", "password": password, "code": code}, 200)
		session := anon.withSession(st, login)
		// Non-default data and claimed owner credentials must survive keep.
		d := store.Device{Address: netip.MustParsePrefix("192.168.88.22/32"), MAC: "02:00:00:00:00:22", Policy: store.Policy{Mode: store.ModeFull, KillSwitch: true}}
		if _, err := api.SetDevice(ctx, d); err != nil {
			st.Fatal("could not seed a live routing policy")
		}
		f.checkReady(ctx, st)
		if f.mustRun(ctx, st, `:put [:len [/routing/table/find where comment="tikray:table-closed"]]`) != "1" {
			st.Fatal("cleanup fixture has no live routing table")
		}
		before, err := api.State(ctx)
		if err != nil {
			st.Fatal("owner state unavailable")
		}
		pub := f.file(ctx, st, apiCert)
		verifyFlow := f.unchangedFlow(ctx, st)
		if err = f.remove(ctx, removalFile, ""); err != nil {
			st.Fatal("default keep refused", err)
		}
		f.clean(ctx, st, false)
		verifyFlow()
		if f.file(ctx, st, apiCert) != pub || !strings.Contains(f.file(ctx, st, dataRoot+"/install.retained"), f.id) {
			st.Fatal("retained volume identity or UI certificate missing")
		}
		// The user supplies the previous public ID only for a retained tree.
		if _, e := f.runInstaller(ctx); e == nil || !f.installClean(ctx) {
			st.Fatal("a retained non-empty volume was adopted without owner input")
		}
		f.mustRun(ctx, st, `:global tikrayReuseID "`+f.id+`"`)
		f.requireSuccess(ctx, st)
		f.checkReady(ctx, st)
		session.wantState(st, ctx, false, true)
		after, err := api.State(ctx)
		if err != nil || !bytes.Equal(before.Body, after.Body) {
			st.Fatal("reinstall failed to preserve desired state")
		}
		f.audit(ctx, st, password, code, api.Token)
	})
	check("purge_owned_data", func(st *testing.T) {
		f := setupRemoval(ctx, st, true)
		const external = "disk1/tikray-external-probe"
		f.mustRun(ctx, st, `/file/add name="`+external+`" type=directory`)
		witnessFile := filepath.Join(f.workDir, "outside-file")
		if os.WriteFile(witnessFile, []byte("outside directory survives"), 0600) != nil || f.CHR.Push(ctx, witnessFile, external+"/payload") != nil || f.file(ctx, st, external+"/payload") != "outside directory survives" {
			st.Fatal("positive outside file content witness unavailable")
		}
		// Observe the physical inode from an independently owned, read-only
		// volume. RouterOS numeric file IDs do not prove ext4 inode identity.
		f.mustRun(ctx, st, `/interface/veth/add name=m3-owner-peer address=192.0.2.2/30 gateway=192.0.2.1 comment="owner:filesystem-witness"; /container/mounts/add list=m3-owner-volume src="`+external+`" dst=/outside mode=ro comment="owner:filesystem-witness"`)
		f.mustRun(ctx, st, `/container/add name=m3-owner-probe file="disk1/tikray/images/`+filepath.Base(f.controlTar)+`" root-dir=disk1/m3-owner-shell interface=m3-owner-peer mountlists=m3-owner-volume entrypoint=/bin/sleep cmd=3600 dns=192.0.2.1 logging=no start-on-boot=no comment="owner:filesystem-witness"`)
		if f.waitForContainer(ctx, "m3-owner-probe", "stopped") != nil {
			st.Fatal("owner witness extraction failed")
		}
		f.mustRun(ctx, st, `/container/start [find where name="m3-owner-probe"]`)
		if f.waitForContainer(ctx, "m3-owner-probe", "running") != nil {
			st.Fatal("owner witness unavailable")
		}
		inode := func() string {
			var physical string
			_, ok := poll(ctx, 10*time.Second, 250*time.Millisecond, func() bool {
				out, e := f.CHR.RunPrivate(ctx, `/container/shell [find name="m3-owner-probe"] cmd="stat -c 'm3-inode=%d:%i:%s|end' /outside/payload"`)
				m := regexp.MustCompile(`m3-inode=([0-9]+:[1-9][0-9]*:26)\|end`).FindStringSubmatch(out)
				if e != nil || len(m) != 2 {
					return false
				}
				physical = m[1]
				return true
			})
			if !ok {
				st.Fatal("positive owner inode witness unavailable")
			}
			return physical
		}
		physical := inode()
		if !regexp.MustCompile(`^[0-9]+:[1-9][0-9]*:26$`).MatchString(physical) {
			st.Fatal("positive owner inode witness unavailable")
		}
		// This link resolves to the owner's sibling in the router filesystem.
		// CHR may report a link, a plain file, or omit it from print.
		if f.probe(ctx, st, "uninstall-links") != "verified" {
			st.Fatal("outside symlink witness absent")
		}
		err := f.removeVia(ctx, removalFile, "purge", f.CHR.RunPrivateFresh)
		if expectedRefusal(err, "tikray: shared_reference_refuses") {
			if f.file(ctx, st, siblingFile) != "owner stays" || f.file(ctx, st, external+"/payload") != "outside directory survives" {
				st.Fatal("purge followed a link to owner data")
			}
			if f.probe(ctx, st, "uninstall-unlink") != "verified" {
				st.Fatal("could not retire scoped symlink witness")
			}
			err = f.removeVia(ctx, removalFile, "purge", f.CHR.RunPrivateFresh)
		}
		if err != nil {
			st.Fatal("explicit purge refused", err)
		}
		f.clean(ctx, st, true)
		if inode() != physical || f.file(ctx, st, external+"/payload") != "outside directory survives" {
			st.Fatal("owner directory alias was traversed")
		}
		if f.mustRun(ctx, st, `:put [:len [/file/find where name="disk1/tikray/data" or name~"^disk1/tikray/data/"]]`) != "0" {
			st.Fatal("owned data tree survived successful purge")
		}
	})
	check("shared_reference_refuses", func(st *testing.T) {
		f := setupRemoval(ctx, st, false)
		// The owner's IPv6 dependency must refer to a real policy table.
		device := store.Device{Address: netip.MustParsePrefix("192.168.88.22/32"), MAC: "02:00:00:00:00:22", Policy: store.Policy{Mode: store.ModeFull, KillSwitch: true}}
		if _, e := f.pinned(ctx, st).SetDevice(ctx, device); e != nil {
			st.Fatal("could not seed the shared routing table")
		}
		f.checkReady(ctx, st)
		if f.mustRun(ctx, st, `:put [:len [/routing/table/find where name="tikray-open" and comment="tikray:table-open"]]`) != "1" {
			st.Fatal("shared reference fixture lacks the owned table")
		}
		// A marker at a syntactically valid root is insufficient if the
		// installation ID is not the one independently anchored in RouterOS.
		previous, err := f.refusalState(ctx, st)
		if err != nil {
			st.Fatal("could not witness preflight")
		}
		other := "0" + f.id[1:]
		if other == f.id {
			other = "1" + f.id[1:]
		}
		f.mustRun(ctx, st, `/file/set [find where name="disk1/tikray/data/state/install.id"] contents="`+other+`"`)
		err = f.remove(ctx, removalFile, "purge")
		if !expectedRefusal(err, "tikray: shared_reference_refuses; wrong installation volume") {
			st.Fatal("purge did not reject a mismatched ID", err)
		}
		now, err := f.refusalState(ctx, st)
		if err != nil || now != previous || f.file(ctx, st, siblingFile) != "owner stays" {
			st.Fatal("invalid data identity changed router or owner data")
		}
		f.mustRun(ctx, st, `/file/set [find where name="disk1/tikray/data/state/install.id"] contents="`+f.id+`"`)
		f.mustRun(ctx, st, `/ip/service/set [find where name="www-ssl" and !dynamic] certificate=tikray-api`)
		err = f.remove(ctx, removalFile, "keep")
		if !expectedRefusal(err, "tikray: shared_reference_refuses; another service uses the certificate") {
			st.Fatal("owner TLS dependency was not identified", err)
		}
		now, err = f.refusalState(ctx, st)
		if err != nil || now != previous || f.mustRun(ctx, st, `:put [/ip/service/get [find where name="www-ssl" and !dynamic] certificate]`) != "tikray-api" {
			st.Fatal("uninstall changed shared TLS dependency")
		}
		f.mustRun(ctx, st, `/ip/service/set [find where name="www-ssl" and !dynamic] certificate=none`)
		unchangedRefusal := func(reason string) {
			st.Helper()
			a, e := f.refusalState(ctx, st)
			if e != nil {
				st.Fatal("preflight snapshot failed")
			}
			e = f.remove(ctx, removalFile, "purge")
			if !expectedRefusal(e, "tikray: shared_reference_refuses; "+reason) {
				st.Fatal("owner dependency was not identified", reason, e)
			}
			b, e := f.refusalState(ctx, st)
			if e != nil || b != a {
				st.Fatal("owner dependency refused after mutation", reason)
			}
		}
		f.mustRun(ctx, st, `/interface/wifi/capsman/set ca-certificate=tikray-api`)
		unchangedRefusal("wifi certificate dependency")
		if f.mustRun(ctx, st, `:put [/interface/wifi/capsman/get ca-certificate]`) != "tikray-api" {
			st.Fatal("Wi-Fi manager lost its certificate on refusal")
		}
		f.mustRun(ctx, st, `/interface/wifi/capsman/set ca-certificate=auto`)
		receipt := f.mustRun(ctx, st, `:put [/system/script/get [find where name=tikray-api-receipt] comment]`)
		if !strings.HasPrefix(receipt, "tikray:api-receipt ") {
			st.Fatal("created-certificate ownership receipt unavailable")
		}
		f.mustRun(ctx, st, `/system/script/remove [find where name=tikray-api-receipt]`)
		unchangedRefusal("required API-SSL receipt missing")
		f.mustRun(ctx, st, `{:local c [:convert "`+base64.StdEncoding.EncodeToString([]byte(receipt))+`" from=base64 to=raw]; /system/script/add name=tikray-api-receipt source="" policy=read comment=$c}`)
		for _, dep := range []struct{ menu, props, reason string }{
			{"/ipv6/route", "dst-address=2001:db8:ffff::2/128 gateway=ether1 routing-table=tikray-open disabled=yes", "foreign route in an owned table"},
			{"/interface/bridge/filter", "chain=forward in-interface=tikray-ctl action=accept disabled=yes", "foreign firewall, routing or queue consumer"},
			{"/interface/bridge/nat", "chain=srcnat out-interface=tikray-runner action=accept disabled=yes", "foreign firewall, routing or queue consumer"},
			{"/ip/route", "dst-address=192.0.2.55/32 gateway=tikray disabled=yes", "static owner route uses private interface"},
			{"/ipv6/route", "dst-address=2001:db8:ffff::1/128 gateway=fe80::1%tikray disabled=yes", "static owner route uses private interface"},
		} {
			f.mustRun(ctx, st, dep.menu+"/add "+dep.props+` comment="owner:uninstall-dependency"`)
			id := f.mustRun(ctx, st, `:put [:tostr [`+dep.menu+`/find where comment="owner:uninstall-dependency"]]`)
			if id == "" {
				st.Fatal("owner dependency missing", dep.menu)
			}
			unchangedRefusal(dep.reason)
			if f.mustRun(ctx, st, `:put [:tostr [`+dep.menu+`/find where comment="owner:uninstall-dependency"]]`) != id {
				st.Fatal("owner dependency removed/replaced", dep.menu)
			}
			f.mustRun(ctx, st, dep.menu+`/remove [find where comment="owner:uninstall-dependency"]`)
		}
		// Retag an exact natural key so that a broad per-menu find/remove
		// would dismantle the other half before discovering the collision.
		for _, item := range []struct{ menu, tag, reason string }{{"/ip/arp", "tikray:arp-runner", "ARP binding changed"}, {"/interface/bridge/host", "tikray:fdb-ctl", "forwarding binding changed"}} {
			f.mustRun(ctx, st, item.menu+`/set [find where comment="`+item.tag+`"] comment="owner:live-binding"`)
			before, err := f.refusalState(ctx, st)
			if err != nil {
				st.Fatal("could not snapshot owned rows")
			}
			foreign := f.mustRun(ctx, st, `:put [:tostr [`+item.menu+`/find where comment="owner:live-binding"]]`)
			if foreign == "" {
				st.Fatal("missing foreign witness")
			}
			err = f.remove(ctx, removalFile, "purge")
			if !expectedRefusal(err, "tikray: shared_reference_refuses; "+item.reason) && !expectedRefusal(err, "tikray: shared_reference_refuses; owner uses the bridge or veth") {
				st.Fatal("expected ownership refusal", err)
			}
			after, err := f.refusalState(ctx, st)
			if err != nil || after != before || f.mustRun(ctx, st, `:put [:tostr [`+item.menu+`/find where comment="owner:live-binding"]]`) != foreign {
				st.Fatal("ownership refusal changed a row or its identity")
			}
			f.mustRun(ctx, st, item.menu+`/set [find where comment="owner:live-binding"] comment="`+item.tag+`"`)
		}
		f.mustRun(ctx, st, `/certificate/set [find name=tikray-api] name=m3-saved-original; /certificate/add name=tikray-api common-name=m3-replacement key-size=prime256v1 key-usage=key-cert-sign,digital-signature,tls-server; /certificate/sign tikray-api; /ip/service/set [find where name=api-ssl and !dynamic] certificate=tikray-api`)
		replacement := f.mustRun(ctx, st, `:put [/certificate/get [find name=tikray-api] fingerprint]`)
		original := f.mustRun(ctx, st, `:put [/certificate/get [find name=m3-saved-original] fingerprint]`)
		if replacement == original || !regexp.MustCompile("^[a-fA-F0-9:]{64,95}$").MatchString(replacement) {
			st.Fatal("certificate substitution was ineffective")
		}
		before, err := f.refusalState(ctx, st)
		if err != nil {
			st.Fatal("owned inventory unavailable")
		}
		err = f.remove(ctx, removalFile, "keep")
		if err == nil || !strings.Contains(err.Error(), "certificate fingerprint changed") {
			st.Fatal("same-name replacement was accepted", err)
		}
		after, err := f.refusalState(ctx, st)
		if err != nil || after != before || replacement != f.mustRun(ctx, st, `:put [/certificate/get [find name=tikray-api] fingerprint]`) {
			st.Fatal("substitute identity or owned row changed during refusal")
		}
	})
	check("interrupted_and_repeat", func(st *testing.T) {
		f := setupRemoval(ctx, st, false)
		if _, err := f.pinned(ctx, st).SetDevice(ctx, store.Device{Address: netip.MustParsePrefix("192.168.88.22/32"), MAC: "02:00:00:00:00:22", Policy: store.Policy{Mode: store.ModeFull, KillSwitch: true}}); err != nil {
			st.Fatal("could not seed interruption policy")
		}
		f.checkReady(ctx, st)
		const bindings = `{:foreach k in={"tikray:arp-ctl";"tikray:arp-runner"} do={:put [:tostr [/ip/arp/find where comment=$k]]}; :foreach k in={"tikray:fdb-ctl";"tikray:fdb-runner"} do={:put [:tostr [/interface/bridge/host/find where comment=$k]]}}`
		beforeBindings := f.mustRun(ctx, st, bindings)
		if len(strings.Fields(beforeBindings)) != 4 {
			st.Fatal("incomplete initial binding identities")
		}
		// Deterministically interrupt just after the unmodified teardown has
		// removed the containers. Recovery always uses the production file.
		const cut = `$drop "/container" $inventory "all" $requireInstall $lease`
		if strings.Count(f.script, cut) != 1 {
			st.Fatal("interruption boundary changed")
		}
		body := strings.Replace(f.script, cut, cut+`; /file/add name=m3-uninstall-cut type=file contents="containers removed"; :error "m3-fixture-interrupted"`, 1)
		path := filepath.Join(f.workDir, "interrupted.rsc")
		if os.WriteFile(path, []byte(body), 0600) != nil || f.CHR.Push(ctx, path, "m3-interrupted.rsc") != nil {
			st.Fatal("could not stage interruption")
		}
		err := f.remove(ctx, "m3-interrupted.rsc", "keep")
		if err == nil || (!strings.Contains(err.Error(), "m3-fixture-interrupted") && !expectedRefusal(err, "tikray: uninstall stopped; inspect ownership and retry")) || f.file(ctx, st, "m3-uninstall-cut") != "containers removed" {
			st.Fatal("interruption boundary was not reached", err)
		}
		if f.mustRun(ctx, st, `:put [:len [/system/script/find where name=tikray-uninstall-state]]`) != "1" || f.mustRun(ctx, st, `:put [:len [/container/find where comment~"^tikray:"]]`) != "0" {
			st.Fatal("native interruption did not leave a resumable partial teardown")
		}
		if f.mustRun(ctx, st, bindings) != beforeBindings || f.mustRun(ctx, st, `:put [:tostr [/ip/arp/find where comment="owner:tikray:arp-ctl"]]`) != f.foreignARP {
			st.Fatal("interruption exposed the private bridge or changed an owner binding")
		}
		if err = f.remove(ctx, removalFile, ""); err != nil {
			st.Fatal("resume refused", err)
		}
		f.clean(ctx, st, false)
		if err = f.remove(ctx, removalFile, ""); err != nil {
			st.Fatal("repeat refused", err)
		}
		f.clean(ctx, st, false)
	})
}
