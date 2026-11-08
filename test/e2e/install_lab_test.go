//go:build lab

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/apiclient"
	"github.com/Arman2122/tikray/internal/routeros"
	"github.com/Arman2122/tikray/test/lab"
)

func TestM3Install(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Minute)
	defer cancel()
	target, err := lab.ResolveChannel(ctx, "", env("TIKRAY_LAB_CHANNEL", "stable"))
	if err != nil {
		t.Fatal("could not resolve installer target")
	}
	check := (&Lab{Version: target, Arch: labArch()}).recordChecks(t, "m3-install")
	// An interrupted install on a separate ready overlay also proves the
	// owner's pre-existing certificate is never claimed. Teardown completes
	// before the first truly clean import starts.
	check("interrupted_install", func(st *testing.T, note func(string, ...any)) {
		f := DeployM3(ctx, st)
		f.stage(ctx, st, false)
		f.mustRun(ctx, st, `/certificate/add name=owner-api common-name=owner-api subject-alt-name=IP:172.30.252.1 key-size=prime256v1 key-usage=key-cert-sign,digital-signature,tls-server; /certificate/sign owner-api`)
		f.mustRun(ctx, st, `/ip/service/set [find where name=api-ssl and !dynamic] certificate=owner-api disabled=no address=""`)
		if f.Net.Inet(ctx, "ip", "-6", "addr", "add", "2001:db8:4:1::99/128", "dev", "wan0", "nodad").Run() != nil {
			st.Fatal("could not attach independent unrestricted WAN origin")
		}
		empty := f.mustRun(ctx, st, `{:local g [/ip/service/get [find where name=api-ssl and !dynamic]];:local p [:pick [/ip/service/print as-value where name=api-ssl and !dynamic] 0]; :put ([:typeof ($g->"address")] . "|" . [:len ($g->"address")] . "|" . [:typeof ($p->"available-from")] . "|" . [:len ($p->"available-from")] . "|" . [:len [/ip/service/find where name=api-ssl and !dynamic and available-from=""]])}`)
		if !regexp.MustCompile(`^(nothing|nil|array|str)\|0\|(nothing|nil|array|str)\|0\|[01]$`).MatchString(empty) {
			st.Fatal("owner unrestricted fixture did not verify independently")
		}
		st.Logf("unrestricted grant shape GET|count|PRINT|count|empty predicate %s", empty)
		if !f.v6Port(ctx, 9879) {
			st.Fatal("positive existing IPv6 API access was unavailable before import")
		}

		f.requireRefusal(ctx, st, "tikray: retry bootstrap")
		api := f.pinned(ctx, st)
		if api.Healthz(ctx) != nil {
			st.Fatal("bootstrap failure took down management")
		}
		before, err := api.State(ctx)
		if err != nil {
			st.Fatal("managed state unavailable during interruption")
		}
		for _, run := range []func() (apiclient.Response, error){
			func() (apiclient.Response, error) { return api.AddServer(ctx, apiclient.NewServer{Link: linkA}) },
			func() (apiclient.Response, error) {
				return api.AddSubscription(ctx, apiclient.NewSubscription{Name: "fixture", URL: "http://203.0.113.30/sub/fixture"})
			},
		} {
			_, err := run()
			var refused *apiclient.Error
			if !errors.As(err, &refused) || refused.Status != 503 || refused.Code != "bootstrap_pending" {
				st.Fatal("unfinished bootstrap did not return the admission gate's fixed refusal")
			}
		}
		after, err := api.State(ctx)
		if err != nil || before.Revision != after.Revision || !bytes.Equal(before.Body, after.Body) {
			st.Fatal("failed admission changed state")
		}
		if f.mustRun(ctx, st, `:put [:len [/ip/firewall/mangle/find where comment~"^tikray:"]]`) != "0" {
			st.Fatal("unfinished direct install activated steering")
		}
		cred := f.file(ctx, st, dataRoot+"/state/routeros.json")
		f.stageCore(ctx, st)
		f.requireSuccess(ctx, st)
		if f.file(ctx, st, dataRoot+"/state/routeros.json") != cred || f.mustRun(ctx, st, `:put [:len [/system/script/find where name=tikray-api-receipt]]`) != "0" ||
			f.mustRun(ctx, st, `:put [/ip/service/get [find where name=api-ssl and !dynamic] certificate]`) != "owner-api" {
			st.Fatal("retry replaced reused certificate or credentials")
		}
		f.checkReady(ctx, st)
		acl := f.mustRun(ctx, st, `{:local r [/ip/service/get [find where name=api-ssl and !dynamic]]; :put [:len ($r->"address")]}`)
		if acl != "0" || !f.v6TLS(ctx, st) {
			st.Fatal("installer restricted the previously enabled unrestricted owner API")
		}
		f.audit(ctx, st, api.Token, f.file(ctx, st, dataRoot+"/state/setup.code"), linkA, "http://203.0.113.30/sub/fixture")
		note("Core absence kept HTTPS up and rejected admission. Retry committed the signed core and preserved the owner certificate.")
	})
	var f *installLab
	var installed bool
	var attempted bool
	fixture := func(st *testing.T) *installLab {
		st.Helper()
		if f == nil {
			f = deployM3(ctx, st, t)
			f.stage(ctx, st, true)
		}
		return f
	}
	ensure := func(st *testing.T) *installLab {
		st.Helper()
		f := fixture(st)
		if !installed {
			if attempted {
				st.Fatal("the shared clean-install prerequisite failed")
			}
			attempted = true
			f.requireSuccess(ctx, st)
			f.checkReady(ctx, st)
			installed = true
		}
		return f
	}
	check("preflight", func(st *testing.T, note func(string, ...any)) {
		f := fixture(st)
		baseline := func() string {
			return f.mustRun(ctx, st, `:local s [/ip/service/get [find where name=api-ssl and !dynamic]]; :put ([:tostr ($s->"disabled")] . "|" . [:tostr ($s->"certificate")] . "|" . [:tostr ($s->"address")] . "|" . [:tostr ($s->"port")] . "|" . [:tostr [/certificate/find]] . "|" . [:tostr [/user/find]] . "|" . [:tostr [/user/group/find]] . "|" . [:tostr [/container/config/get tmpdir]] . "|" . [:tostr [/container/config/get registry-url]])`)
		}
		owner := baseline()
		f.mustRun(ctx, st, "/ip/dns/set allow-remote-requests=no")
		f.requireRefusal(ctx, st, "tikray: enable router DNS")
		if !f.installClean(ctx) || baseline() != owner {
			st.Fatal("DNS preflight wrote an owned object")
		}
		f.mustRun(ctx, st, "/ip/dns/set allow-remote-requests=yes")
		f.mustRun(ctx, st, "/interface/bridge/add name=tikray comment=owner:sentinel")
		f.requireRefusal(ctx, st, "tikray: object conflict")
		if (!f.installClean(ctx) || baseline() != owner) || f.mustRun(ctx, st, `:put [:len [/interface/bridge/find where name=tikray and comment="owner:sentinel"]]`) != "1" {
			st.Fatal("preflight changed a foreign bridge")
		}
		f.mustRun(ctx, st, `/interface/bridge/remove [find where name=tikray and comment="owner:sentinel"]`)
		f.mustRun(ctx, st, "/ip/address/add address=172.30.252.18/24 interface=ether2 comment=owner:overlap")
		f.requireRefusal(ctx, st, "tikray: bridge overlaps")
		if !f.installClean(ctx) || baseline() != owner {
			st.Fatal("overlap preflight wrote an owned object")
		}
		f.mustRun(ctx, st, `/ip/address/remove [find where comment="owner:overlap"]`)
		b, err := os.ReadFile(f.runnerTar)
		if err != nil || len(b) < 8192 {
			st.Fatal("bad archive witness unavailable")
		}
		b[len(b)/2] ^= 0x80
		tmp := filepath.Join(f.workDir, "corrupt.tar")
		if os.WriteFile(tmp, b, 0600) != nil || f.CHR.Push(ctx, tmp, "disk1/tikray/images/"+filepath.Base(f.runnerTar)) != nil {
			st.Fatal("could not stage corrupted archive")
		}
		if _, err := f.runInstaller(ctx); err == nil || (!f.installClean(ctx) || baseline() != owner) {
			st.Fatal("installer accepted altered archive bytes or wrote installation objects")
		}
		if f.CHR.Push(ctx, f.runnerTar, "disk1/tikray/images/"+filepath.Base(f.runnerTar)) != nil {
			st.Fatal("could not restore signed archive")
		}
		note("DNS, overlapping LAN, owner name collision and altered archive failed before any owned network, account or container row.")
	})
	check("clean_install", func(st *testing.T, note func(string, ...any)) {
		f := ensure(st)
		set := f.mustRun(ctx, st, `:put [/ip/service/get [find where name=api-ssl and !dynamic] certificate]`)
		if set == "" || set == "none" {
			st.Fatal("installer did not attach a certificate")
		}
		receipt := f.mustRun(ctx, st, `:put [/system/script/get [find name=tikray-api-receipt] comment]`)
		if !strings.HasPrefix(receipt, "tikray:api-receipt ") {
			st.Fatal("missing tagged certificate receipt")
		}
		if f.mustRun(ctx, st, `:put [/system/script/get [find name=tikray-api-receipt] source]`) != "" {
			st.Fatal("certificate receipt is executable")
		}
		checkEmergencySource(ctx, st, f)
		f.checkReceipt(ctx, st, receipt, set)
		f.ownerLogin(ctx, st)
		grants := strings.FieldsFunc(f.mustRun(ctx, st, `:put [:tostr [/user/group/get [find name=tikray] policy]]`), func(r rune) bool { return r == ',' || r == ';' || r == ' ' })
		grants = slices.DeleteFunc(grants, func(v string) bool { return strings.HasPrefix(v, "!") })
		slices.Sort(grants)
		address := f.mustRun(ctx, st, `:put [:tostr [/user/get [find name=tikray] address]]`)
		if !slices.Equal(grants, []string{"api", "read", "write"}) || (address != installControl+"/32" && address != installControl) {
			st.Fatal("installed control account exceeded the intended scope")
		}
		if f.probe(ctx, st, "account") != "verified" {
			st.Fatal("restricted API permission witness failed")
		}
		keptTmp := f.mustRun(ctx, st, `{:local p [:tostr [/container/config/get tmpdir]]; :put (($p = "/disk1/lab-container-tmp") or ($p = "disk1/lab-container-tmp"))}`)
		if keptTmp != "true" {
			st.Fatal("installer changed the owner's temporary directory")
		}
		if f.mustRun(ctx, st, `:put [:len [/system/scheduler/find where name=tikray-watchdog and interval=1m and disabled=no]]`) != "1" {
			st.Fatal("missing minute watchdog")
		}
		note("Private API-SSL login from the control container succeeded and a privileged write failed in that session. The initial signed core runs with direct policy.")
	})
	check("bridge_acl", func(st *testing.T, note func(string, ...any)) {
		f := ensure(st)
		f.checkBridge(ctx, st)
		checkBridgeIPFirewall(ctx, st, f)
		note("LAN used the pinned HTTPS service. Fresh WAN and direct LAN probes could not reach private runner services. The control and router probes succeeded.")
	})
	check("second_import", func(st *testing.T, note func(string, ...any)) {
		f := ensure(st)
		code := f.file(ctx, st, dataRoot+"/state/setup.code")
		if !setupPattern.MatchString(code) {
			st.Fatal("missing first-claim code")
		}
		api := f.pinned(ctx, st)
		anon := authLabClient{base: api.BaseURL, http: api.HTTPClient()}
		password := rand.Text()
		login := anon.call(st, ctx, "POST", "/v1/auth/setup", map[string]string{"username": "lab-admin", "password": password, "code": code}, 200)
		session := anon.withSession(st, login)
		prev := f.stability(ctx, st)
		out := f.requireSuccess(ctx, st)
		if strings.Contains(out, code) || f.stability(ctx, st) != prev {
			st.Fatal("repeat import exposed setup material or changed healthy state, object IDs or running processes")
		}
		session.wantState(st, ctx, false, true)
		// The cardinality is unchanged and the control grant still exists.
		// A name-and-count check would incorrectly accept the replacement.
		svc := "/ip/service/set [find where name=api-ssl and !dynamic] address="
		original := "192.168.88.0/24,198.51.100.3/32,2001:db8:4:1::2/128," + installControl + "/32"
		f.mustRun(ctx, st, svc+strings.Replace(original, "198.51.100.3/", "198.51.100.4/", 1))
		func() {
			defer f.mustRun(ctx, st, svc+original)
			want := "tikray: shared_reference_refuses; api-ssl was changed by its owner"
			f.requireRefusal(ctx, st, want)
			if f.stability(ctx, st) != prev {
				st.Fatal("conflicting owner edit changed installation state")
			}
			current := f.mustRun(ctx, st, `{:local s [/ip/service/get [find where name=api-ssl and !dynamic]]; :put [:tostr ($s->"address")]}`)
			if !strings.Contains(current, "198.51.100.4") || strings.Contains(current, "198.51.100.3") {
				st.Fatal("installer overwrote the owner's replacement grant")
			}
		}()
		beforeRunner := f.probe(ctx, st, "runner")
		f.mustRun(ctx, st, `/container/stop [find where name="tikray" and comment="tikray:tikray"]`)
		if f.waitForContainer(ctx, "tikray", "stopped") != nil {
			st.Fatal("could not stage stopped control for command repair")
		}
		f.mustRun(ctx, st, `/container/set [find where name="tikray" and comment="tikray:tikray"] cmd="status"`)
		f.mustRun(ctx, st, `/container/set [find where name="tikray" and comment="tikray:tikray"] cmd=""`)
		f.requireSuccess(ctx, st)
		f.checkReady(ctx, st)
		session.wantState(st, ctx, false, true)
		if f.probe(ctx, st, "runner") != beforeRunner {
			st.Fatal("repairing the control command restarted xray")
		}
		f.audit(ctx, st, code, password, api.Token, session.cookie.Value, session.csrf)
		note("Healthy reimport preserved object and process IDs. An owner grant edit refused safely. A stopped control with an empty command recovered serving the original session, with the same xray instance.")
	})
	check("basic_watchdog", func(st *testing.T, note func(string, ...any)) {
		f := ensure(st)
		f.checkWatchdog(ctx, st)
		note("Tick-level evidence distinguished control and runner failures, restart threshold, backoff, recovery and emergency suppression.")
	})
}

func (f *installLab) file(ctx context.Context, t *testing.T, path string) string {
	t.Helper()
	return f.mustRun(ctx, t, ":put ["+fileContents(path)+"]")
}
func (f *installLab) requireRefusal(ctx context.Context, t *testing.T, category string) {
	t.Helper()
	_, err := f.runInstaller(ctx)
	if err == nil || err.Error() != category {
		t.Fatalf("missing installer refusal for %s (got %v)", category, err)
	}

}
func (f *installLab) requireSuccess(ctx context.Context, t *testing.T) string {
	t.Helper()
	out, err := f.runInstaller(ctx)
	if err != nil {
		// Diagnostics from the container subsystem can repeat settings.
		// Report only native counts for the two exact fixture identities.
		for _, component := range []struct{ name, tag string }{{"tikray", "tikray:tikray"}, {"tikray-runner", "tikray:runner"}} {
			q := "name=" + component.name
			var counters []int
			for _, filter := range []string{q, "comment=" + component.tag, q + " and running", q + " and stopped"} {
				s, e := f.CHR.RunPrivate(ctx, ":put [:len [/container/find where "+filter+"]]")
				n, e2 := strconv.Atoi(strings.TrimSpace(s))
				if e != nil || e2 != nil {
					break
				}
				counters = append(counters, n)
			}
			t.Logf("container %s counts [name tag running stopped] %v", component.name, counters)
		}
		t.Fatalf("packaged installer import failed: %v", err)
	}
	pin, err := apiclient.FingerprintOfPEM([]byte(f.file(ctx, t, apiCert)))
	if err != nil || !strings.Contains(strings.ToLower(strings.ReplaceAll(out, ":", "")), strings.ToLower(strings.ReplaceAll(pin, ":", ""))) || !strings.Contains(out, installControl) {
		t.Fatal("installer omitted actual management address or TLS fingerprint")
	}
	f.checkOwnerRules(ctx, t)
	return out
}
func (f *installLab) pinned(ctx context.Context, t *testing.T) *apiclient.Client {
	t.Helper()
	api, err := apiClient(f.file(ctx, t, apiToken), f.file(ctx, t, apiCert))
	if err != nil {
		t.Fatal("private pinned management credentials unavailable")
	}
	api.BaseURL = "https://" + installControl
	return api
}
func (f *installLab) checkReady(ctx context.Context, t *testing.T) {
	t.Helper()
	api := f.pinned(ctx, t)
	_, ok := poll(ctx, 3*time.Minute, time.Second, func() bool {
		resp, err := api.Status(ctx)
		if err != nil {
			return false
		}
		var s struct {
			Applied bool
			Core    string
			Router  *struct {
				Pending  bool
				Degraded string
			} `json:"routeros"`
		}
		return json.Unmarshal(resp.Body, &s) == nil && s.Applied && s.Core == f.Newest && s.Router != nil && !s.Router.Pending && s.Router.Degraded == ""
	})
	if !ok {
		t.Fatal("daemon could not verify the committed core and router state")
	}
	for _, name := range []string{"tikray", "tikray-runner"} {
		if want := f.mustRun(ctx, t, fmt.Sprintf(`:put [/container/get [find name="%s"] dns]`, name)); want != "172.30.252.1" {
			t.Fatal("wrong bridge resolver")
		}
		if f.mustRun(ctx, t, fmt.Sprintf(`:put [/container/get [find name="%s"] start-on-boot]`, name)) != "true" {
			t.Fatal("missing boot recovery")
		}
		settings := fmt.Sprintf(`{:local c [/container/get [find name=%q]]; :put ((($c->"restart-policy") = "on-failure") and (($c->"memory-high") > 0) and (($c->"memory-max") >= ($c->"memory-high")) and ([:tostr ($c->"mountlists")] = %q))}`, name, name)
		if f.mustRun(ctx, t, settings) != "true" {
			t.Fatal("container restart, memory or mount settings are incomplete")
		}
	}
	for _, mount := range []struct{ list, dst, mode string }{
		{"tikray", "/data", "rw"}, {"tikray-runner", "/data/run", "rw"},
		{"tikray-runner", "/data/cores", "ro"}, {"tikray-runner", "/data/geo", "ro"},
	} {
		expr := fmt.Sprintf(`:put [:len [/container/mounts/find where list=%q and dst=%q and mode=%q and comment~"^tikray:"]]`, mount.list, mount.dst, mount.mode)
		if f.mustRun(ctx, t, expr) != "1" {
			t.Fatal("data sharing exceeds the intended component scope")
		}
	}
	cmd := f.mustRun(ctx, t, `:put [/container/get [find name=tikray] cmd]`)
	if cmd != "" && cmd != "serve" {
		t.Fatal("control container command is not serve")
	}
}
func (f *installLab) checkReceipt(ctx context.Context, t *testing.T, comment, cert string) {
	t.Helper()
	var receipt struct {
		Name, Fingerprint, Address, Certificate string
		Disabled                                bool
		Port                                    int
	}
	if json.Unmarshal([]byte(strings.TrimPrefix(comment, "tikray:api-receipt ")), &receipt) != nil || receipt.Name != cert || len(strings.ReplaceAll(receipt.Fingerprint, ":", "")) != 64 {
		t.Fatal("certificate receipt does not pin the created identity")
	}
	var original struct {
		Address, Certificate string
		Disabled             bool
		Port                 int
	}
	if json.Unmarshal([]byte(f.originalAPI), &original) != nil || original.Port != 9879 {
		t.Fatal("original API-SSL settings were not observable before install")
	}
	grants := func(raw string) []string {
		t.Helper()
		var out []string
		for _, s := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				a, e := netip.ParseAddr(s)
				if e != nil {
					t.Fatal("unrecognized API source prefix")
				}
				p = netip.PrefixFrom(a, a.BitLen())
			}
			out = append(out, p.Masked().String())
		}
		slices.Sort(out)
		return out
	}
	want := grants("192.168.88.0/24,198.51.100.3/32,2001:db8:4:1::2/128")
	if !slices.Equal(grants(original.Address), want) {
		t.Fatal("independent original service read did not see both families of the owner grants")
	}
	if receipt.Disabled != original.Disabled || receipt.Port != original.Port || receipt.Certificate != original.Certificate || !slices.Equal(grants(receipt.Address), want) {
		t.Fatal("receipt did not preserve the original enabled state, certificate, port and complete IPv4/IPv6 grants")
	}
	cur := f.mustRun(ctx, t, `{:local row [/ip/service/get [find where name=api-ssl and !dynamic]]; :put [:tostr ($row->"address")]}`)
	if !slices.Equal(grants(cur), grants(original.Address+";"+installControl+"/32")) || f.mustRun(ctx, t, `:put [/ip/service/get [find where name=api-ssl and !dynamic] port]`) != "9879" {
		t.Fatal("live API-SSL grants differ from the independent original plus control /32")
	}
	if f.v6Port(ctx, 9879) || !f.v6Port(ctx, 22) {
		t.Fatal("WAN API-SSL isolation or unrelated owner SSH failed over IPv6")
	}
	var cfg routeros.Installation
	if json.Unmarshal([]byte(f.file(ctx, t, dataRoot+"/state/routeros.json")), &cfg) != nil || !strings.EqualFold(strings.ReplaceAll(cfg.Fingerprint, ":", ""), strings.ReplaceAll(receipt.Fingerprint, ":", "")) || cfg.Scope.Subnet != netip.MustParsePrefix(installSubnet) {
		t.Fatal("private handoff does not match the receipt and installation scope")
	}
	// RouterOS can show SHA-1 in its fingerprint property; use the actual
	// DER certificate for an independent SHA-256 witness.
	f.mustRun(ctx, t, fmt.Sprintf(`/certificate/export-certificate [%s] type=pem file-name=m3-lab-cert`, "/certificate/find name="+strconv.Quote(cert)))
	fp, err := apiclient.FingerprintOfPEM([]byte(f.file(ctx, t, "m3-lab-cert.crt")))
	if err != nil || !strings.EqualFold(strings.ReplaceAll(fp, ":", ""), strings.ReplaceAll(receipt.Fingerprint, ":", "")) {
		t.Fatal("receipt did not match the actual public certificate")
	}
}
func (f *installLab) probe(ctx context.Context, t *testing.T, arg string) string {
	t.Helper()
	const remote = "/data/inbox/m3-lab-probe"
	p := filepath.Join(f.workDir, "m3-lab-probe")
	if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
		c := exec.CommandContext(ctx, "go", "build", "-trimpath", "-ldflags=-s -w", "-o", p, "./test/e2e/testdata/install-probe")
		c.Dir = repoRoot()
		c.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+f.Arch.GOARCH(), "CGO_ENABLED=0")
		if c.Run() != nil || f.CHR.Push(ctx, p, inboxDir+"/m3-lab-probe") != nil {
			t.Fatal("could not stage control-side witness")
		}
	}
	return f.mustRun(ctx, t, fmt.Sprintf(`/container/shell [find where name=tikray] cmd="chmod 700 %s && %s %s"`, remote, remote, arg))
}
func (f *installLab) stability(ctx context.Context, t *testing.T) [5]string {
	t.Helper()
	ids, err := f.owned(ctx)
	if err != nil {
		t.Fatal("could not read owned identities")
	}
	instance := f.probe(ctx, t, "runner")
	if !strings.HasPrefix(instance, f.Newest+"|") {
		t.Fatal("runner instance witness failed")
	}
	proc := f.probe(ctx, t, "control-start")
	if _, err := strconv.ParseUint(proc, 10, 64); err != nil {
		t.Fatal("control PID start time unavailable")
	}
	return [5]string{ids, instance, proc, f.file(ctx, t, dataRoot+"/state/routeros.json"), f.file(ctx, t, dataRoot+"/run/active.json")}
}
func (f *installLab) audit(ctx context.Context, t *testing.T, extra ...string) {
	t.Helper()
	var cfg routeros.Installation
	if json.Unmarshal([]byte(f.file(ctx, t, dataRoot+"/state/routeros.json")), &cfg) != nil {
		t.Fatal("could not identify privacy witnesses")
	}
	secrets := append(extra, cfg.Password, f.file(ctx, t, runnerToken))
	scan := func(data []byte) {
		t.Helper()
		for _, secret := range secrets {
			if len(secret) < 8 {
				t.Fatal("incomplete privacy witnesses")
			}
			for _, value := range []string{secret, base64.StdEncoding.EncodeToString([]byte(secret)), hex.EncodeToString([]byte(secret)), url.QueryEscape(secret)} {
				if bytes.Contains(data, []byte(value)) {
					t.Fatal("private material reached a diagnostic surface")
				}
			}
		}
	}
	events, err := f.pinned(ctx, t).Events(ctx, 0)
	if err != nil {
		t.Fatal("private event audit unavailable")
	}
	scan(events.Body)
	for _, menu := range []string{"/log", "/system/history", "/container/envs"} {
		wire := f.mustRun(ctx, t, fmt.Sprintf(`:foreach id in=[%s/find] do={ :put [:convert [:serialize to=json options=json.no-string-conversion value=[%s/get $id]] to=base64] }`, menu, menu))
		for _, line := range strings.Fields(wire) {
			row, err := base64.StdEncoding.DecodeString(line)
			if err != nil {
				t.Fatal("private diagnostic row unreadable")
			}
			scan(row)
		}
	}
	for _, name := range []string{"harness.log", "console.log", "console.log.timeline", "qemu.log"} {
		data, err := os.ReadFile(filepath.Join(f.workDir, "vm", name))
		if err != nil {
			t.Fatal("lab log audit unavailable")
		}
		scan(data)
	}
}

// Login as the original owner from the retained LAN grant. A success from
// the control account alone cannot establish that earlier grants survived.
func (f *installLab) ownerLogin(ctx context.Context, t *testing.T) {
	t.Helper()
	pw, err := os.ReadFile(filepath.Join(lab.CacheDir(), "ready", f.Version, string(f.Arch), "password"))
	if err != nil {
		t.Fatal("owner test identity unavailable")
	}
	sub, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	c, err := routeros.Dial(sub, routeros.ConnConfig{Address: "172.30.252.1:9879", Username: "admin", Password: string(pw), Fingerprint: f.routerPin(ctx, t)})
	if err != nil {
		t.Fatal("retained LAN owner grant did not allow a pinned API-SSL login")
	}
	defer c.Close()
	rows, err := c.CommandAt(sub, c.Generation(), []string{"/interface/bridge/print", "?name=tikray", "=.proplist=name,comment"})
	if err != nil || len(rows) != 1 || rows[0]["comment"] != "tikray:bridge" {
		t.Fatal("retained owner API session could not read its router")
	}
}
func (f *installLab) routerPin(ctx context.Context, t *testing.T) string {
	t.Helper()
	var cfg routeros.Installation
	if json.Unmarshal([]byte(f.file(ctx, t, dataRoot+"/state/routeros.json")), &cfg) != nil {
		t.Fatal("missing pinned router identity")
	}
	return cfg.Fingerprint
}
func (f *installLab) v6TLS(ctx context.Context, t *testing.T) bool {
	t.Helper()
	return f.Net.Inet(ctx, "python3", "-c", `import hashlib,hmac,socket,ssl,sys
s=socket.socket(socket.AF_INET6);s.settimeout(4);s.bind(("2001:db8:4:1::99",0));s.connect(("2001:db8:4:1::1",9879))
c=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);c.check_hostname=False;c.verify_mode=ssl.CERT_NONE
with c.wrap_socket(s,server_hostname="172.30.252.1") as ss:
 sys.exit(0 if hmac.compare_digest(hashlib.sha256(ss.getpeercert(binary_form=True)).hexdigest(),sys.argv[1].replace(":","").lower()) else 1)`, f.routerPin(ctx, t)).Run() == nil
}
