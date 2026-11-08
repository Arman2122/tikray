//go:build lab

package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/test/lab"
	"github.com/Arman2122/tikray/test/lab/fixtures/labinet"
)

// A fresh install uses a different /29 to catch listeners or API clients
// that assume the default bridge. The WAN namespace has an explicit route
// to it the same way a routed external network would.
const installSubnet = "172.30.252.0/29"
const installControl = "172.30.252.2"
const installRunner = "172.30.252.3"

type installLab struct {
	*Lab
	installer             string
	controlTar, runnerTar string
	publicKey             string
	ownerRules            []string
	originalAPI           string
}

func DeployM3(ctx context.Context, t *testing.T) *installLab { t.Helper(); return deployM3(ctx, t, t) }

func deployM3(ctx context.Context, t, owner *testing.T) *installLab {
	t.Helper()
	l, artifacts := newLab(ctx, t, owner)
	f := &installLab{Lab: l}
	goarch := l.Arch.GOARCH()
	var err error
	f.runnerTar, f.controlTar, err = buildImages(ctx, goarch)
	if err != nil {
		t.Fatal("installer archives unavailable")
	}
	f.installer = f.packInstaller(ctx, t)
	// Exercise the same offline signed-index path an isolated owner uses.
	// The pinned public key comes separately from the archive and its index.
	v, err := lab.ResolveXrayVersion(ctx, lab.LabXrayVersion())
	if err != nil {
		t.Fatal("could not resolve test core")
	}
	l.Newest, err = lab.XrayCoreVersion(v)
	if err != nil {
		t.Fatal("unsupported test core")
	}
	binary, err := lab.XrayBinaryVersion(ctx, lab.CacheDir(), v, goarch)
	if err != nil {
		t.Fatal("test core is unavailable")
	}
	l.Releases = filepath.Join(l.workDir, "releases")
	if os.MkdirAll(l.Releases, 0700) != nil {
		t.Fatal("could not create releases fixture")
	}
	zip := filepath.Join(l.Releases, l.Asset)
	sum, err := labinet.MakeReleaseZip(zip, binary)
	if err != nil {
		t.Fatal("could not create offline core")
	}
	l.Zips[l.Newest] = zip
	pub, err := signIndex(l.Releases, map[string]map[string]string{"v" + l.Newest: {l.Asset: sum}})
	if err != nil {
		t.Fatal("could not sign offline index")
	}
	f.publicKey = filepath.Join(l.workDir, "index.pub")
	if os.WriteFile(f.publicKey, pub, 0600) != nil {
		t.Fatal("could not stage trusted index key")
	}
	bootLab(ctx, t, l, artifacts)
	// Certificates are issued on the router. Set the fixture's clock before
	// any signing and confirm it independently; production leaves it alone.
	now := time.Now().UTC()
	f.mustRun(ctx, t, fmt.Sprintf("/system/clock/set time-zone-name=UTC time-zone-autodetect=no date=%s time=%s", now.Format("2006-01-02"), now.Format("15:04:05")))
	guest, e := l.routerClock(ctx)
	if e != nil || time.Since(guest).Abs() > 2*time.Minute {
		t.Fatal("CHR clock is outside the certificate test window")
	}
	f.cleanOverlay(ctx, t)
	if err := l.CHR.Import(ctx, filepath.Join(e2eDir(), "routeros", "lab.rsc")); err != nil {
		t.Fatal("could not establish owner network")
	}
	// CHR ready images have interfaces, not LAN/WAN lists. An intentionally
	// permissive owner forward rule exercises precedence of bridge isolation.
	for _, cmd := range []string{
		"/ip/service/set [find where name=api-ssl and !dynamic] disabled=yes address=192.168.88.0/24,198.51.100.3/32,2001:db8:4:1::2/128 port=9879",
		"/ipv6/address/add interface=ether1 address=2001:db8:4:1::1/64 advertise=no comment=lab:v6-wan",
		"/ipv6/firewall/filter/add chain=input in-interface=ether1 protocol=tcp dst-port=22,9879 action=accept comment=lab:v6-owner",
		"/interface/list/add name=LAN comment=lab:lan-list",
		"/interface/list/add name=WAN comment=lab:wan-list",
		"/interface/list/member/add list=LAN interface=ether2 comment=lab:ingress",
		"/interface/list/member/add list=WAN interface=ether1 comment=lab:egress",
		"/ip/firewall/filter/add chain=forward action=accept comment=lab:permit",
		"/ip/firewall/filter/add chain=input action=accept protocol=tcp dst-port=22 comment=lab:ssh",
		"/ip/firewall/nat/add chain=dstnat in-interface=ether1 dst-address=198.51.100.2 protocol=tcp dst-port=9879 action=dst-nat to-addresses=203.0.113.30 to-ports=80 comment=lab:owner-service",
		"/ip/firewall/nat/add chain=srcnat out-interface=ether1 src-address=198.51.100.1 dst-address=203.0.113.30 protocol=tcp dst-port=80 action=masquerade comment=lab:owner-return",
	} {
		f.mustRun(ctx, t, cmd)
	}
	if exec.CommandContext(ctx, "ip", "addr", "add", "192.168.88.201/24", "dev", "tklab-lan").Run() != nil ||
		exec.CommandContext(ctx, "ip", "route", "add", installSubnet, "via", "192.168.88.1", "dev", "tklab-lan").Run() != nil ||
		l.Net.Inet(ctx, "ip", "route", "add", installSubnet, "via", "198.51.100.2").Run() != nil {
		t.Fatal("could not route LAN and WAN probes")
	}
	if l.Net.Inet(ctx, "ip", "-6", "addr", "add", "2001:db8:4:1::2/64", "dev", "wan0", "nodad").Run() != nil {
		t.Fatal("could not attach IPv6 owner probe")
	}
	f.mustRun(ctx, t, "/ip/service/set [find where name=api-ssl and !dynamic] disabled=no")
	_, positive := poll(ctx, 25*time.Second, time.Second, func() bool { return f.v6Port(ctx, 22) && f.v6Port(ctx, 9879) })
	if !positive {
		t.Fatal("IPv6 SSH and positive API-SSL controls did not reach router before install")
	}
	f.mustRun(ctx, t, "/ip/service/set [find where name=api-ssl and !dynamic] disabled=yes")
	if f.v6Port(ctx, 9879) || !f.v6Port(ctx, 22) {
		t.Fatal("IPv6 owner service pre-install baseline failed")
	}
	f.ownerPortForward(ctx, t)
	f.ownerRules = f.readOwnerRules(ctx, t)
	f.originalAPI = f.mustRun(ctx, t, `{:local c [/ip/service/get [find where name="api-ssl" and !dynamic]]; :put [:serialize to=json options=json.no-string-conversion value={"disabled"=($c->"disabled");"certificate"=[:tostr ($c->"certificate")];"address"=[:tostr ($c->"address")];"port"=($c->"port")}]}`)
	return f
}

func (f *installLab) cleanOverlay(ctx context.Context, t *testing.T) {
	t.Helper()
	// BootReadyCHR caches this empty M1 fixture tree. The destructive
	// cleanup is confined to verified empty directories in this overlay.
	known := map[string]bool{}
	for _, s := range []string{"", "/tmp", "/images", "/containers", "/data", "/data/run", "/data/cores"} {
		known["disk1/tikray"+s] = true
	}
	got := f.mustRun(ctx, t, `:foreach id in=[/file/find where name="disk1/tikray" or name~"^disk1/tikray/"] do={ :put ([/file/get $id type] . "|" . [/file/get $id name]) }`)
	var paths []string
	for _, line := range strings.Fields(got) {
		kind, path, ok := strings.Cut(line, "|")
		if !ok || kind != "directory" || !known[path] {
			t.Fatal("unexpected content in ready-image installation area")
		}
		paths = append(paths, path)
	}
	f.mustRun(ctx, t, "/file/add type=directory name=disk1/lab-container-tmp")
	f.mustRun(ctx, t, "/container/config/set tmpdir=disk1/lab-container-tmp")
	sort.Slice(paths, func(i, j int) bool { return len(paths[i]) > len(paths[j]) })
	for _, path := range paths {
		f.mustRun(ctx, t, "/file/remove [find name="+path+"]")
	}
	if !f.installClean(ctx) {
		t.Fatal("ready image contains installation objects")
	}
}

var installMenus = []string{"/interface/bridge", "/interface/bridge/port", "/interface/veth", "/ip/address", "/ip/firewall/filter", "/ip/firewall/mangle", "/ip/firewall/raw", "/ip/firewall/nat", "/ipv6/firewall/filter", "/ip/firewall/address-list", "/routing/table", "/ip/route", "/tool/netwatch", "/system/script", "/system/scheduler", "/user", "/user/group", "/container", "/container/mounts", "/container/envs"}

func (f *installLab) owned(ctx context.Context) (string, error) {
	var s strings.Builder
	for _, m := range installMenus {
		fmt.Fprintf(&s, `:foreach i in=[%s/find where comment~"^tikray:"] do={ :put ("%s|" . $i . "|" . [%s/get $i comment]) }; `, m, m, m)
	}
	out, err := f.CHR.RunPrivate(ctx, s.String())
	if err != nil {
		return "", errors.New("could not observe installation ownership")
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	sort.Strings(lines)
	return strings.Join(lines, "\n"), nil
}
func (f *installLab) installClean(ctx context.Context) bool {
	owned, err := f.owned(ctx)
	return err == nil && owned == ""
}

func (f *installLab) waitForContainer(ctx context.Context, name, state string) error {
	ctx, cancel := context.WithTimeout(ctx, 75*time.Second)
	defer cancel()
	return waitContainer(ctx, f.CHR, name, state)
}

func (f *installLab) mustRun(ctx context.Context, t *testing.T, cmd string) string {
	t.Helper()
	out, err := f.CHR.RunPrivate(ctx, cmd)
	if err != nil {
		_, file, line, _ := runtime.Caller(1)
		t.Fatalf("private RouterOS fixture or observation failed at %s:%d", filepath.Base(file), line)
	}
	return strings.TrimSpace(out)
}

func (f *installLab) packInstaller(ctx context.Context, t *testing.T) string {
	t.Helper()
	dir := filepath.Join(f.workDir, "signed")
	if os.MkdirAll(dir, 0700) != nil {
		t.Fatal("could not stage archive signatures")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("could not create test signing identity")
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	keyFile := filepath.Join(dir, "cosign.pub")
	if err != nil || os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600) != nil {
		t.Fatal("could not stage public verification key")
	}
	for _, src := range []string{f.controlTar, f.runnerTar} {
		dst := filepath.Join(dir, filepath.Base(src))
		in, err := os.Open(src)
		if err != nil {
			t.Fatal("could not read archive")
		}
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			in.Close()
			t.Fatal("could not stage archive")
		}
		sum := sha256.New()
		_, err = io.Copy(io.MultiWriter(sum, out), in)
		in.Close()
		err = errors.Join(err, out.Close())
		if err != nil {
			t.Fatal("could not copy archive")
		}
		sig, err := ecdsa.SignASN1(rand.Reader, key, sum.Sum(nil))
		if err != nil || os.WriteFile(dst+".sig", []byte(base64.StdEncoding.EncodeToString(sig)), 0600) != nil {
			t.Fatal("could not sign archive")
		}
	}
	target := filepath.Join(dir, "install.rsc")
	cmd := exec.CommandContext(ctx, "go", "run", "./cmd/tikray-installer", "-arch", f.Arch.GOARCH(), "-version", f.Version, "-key", keyFile, "-images", dir, "-out", target)
	cmd.Dir = repoRoot()
	if cmd.Run() != nil {
		t.Fatal("real installer packager refused signed test inputs")
	}
	return target
}

func (f *installLab) stage(ctx context.Context, t *testing.T, core bool) {
	t.Helper()
	for _, dir := range []string{"disk1/tikray/images", inboxDir, dataRoot + "/state"} {
		f.mustRun(ctx, t, fmt.Sprintf(`:if ([:len [/file/find where name=%q]]=0) do={/file/add name=%q type=directory}`, dir, dir))
	}
	for _, file := range []string{f.controlTar, f.runnerTar} {
		if f.CHR.Push(ctx, file, "disk1/tikray/images/"+filepath.Base(file)) != nil {
			t.Fatal("could not upload signed test archives")
		}
	}
	if err := f.CHR.Push(ctx, f.publicKey, indexKey); err != nil {
		t.Fatal("could not provision trusted public key")
	}
	if core {
		f.stageCore(ctx, t)
	}
	if f.CHR.Push(ctx, f.installer, "m3-lab-install.rsc") != nil {
		t.Fatal("could not upload generated installer")
	}
}
func (f *installLab) stageCore(ctx context.Context, t *testing.T) {
	t.Helper()
	for _, file := range []string{f.Asset, "index.json", "index.json.sig"} {
		if f.CHR.Push(ctx, filepath.Join(f.Releases, file), inboxDir+"/"+file) != nil {
			t.Fatal("could not upload offline core inputs")
		}
	}
}

// Preserve successful terminal output privately for the URL and fingerprint
// assertions. A rejected import can contain partly expanded script input.
func (f *installLab) runInstaller(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	cmd := fmt.Sprintf(`:global tikraySubnet "%s"; :global tikrayCore "%s"; :global tikrayOffline true; :onerror r in={ /import file-name=m3-lab-install.rsc; :put "m3-import-ok" } do={ :put ("m3-import-error=" . [:convert [:tostr $r] to=base64]) }`, installSubnet, f.Newest)
	out, e := f.CHR.RunPrivate(ctx, cmd)
	if e != nil {
		return "", errors.New("private installer execution failed")
	}
	return installOutput(out)
}

var sourceError = regexp.MustCompile(`:error +"(tikray: [^"\\]+)"`)
var importPosition = regexp.MustCompile(`line ([0-9]{1,7}) column ([0-9]{1,7})`)

func installOutput(wire string) (string, error) {
	s := strings.TrimSpace(wire)
	i := strings.LastIndexByte(s, '\n')
	last := strings.TrimSpace(s[i+1:])
	if last == "m3-import-ok" {
		if i < 0 {
			return "", nil
		}
		return strings.TrimSpace(s[:i]), nil
	}
	raw, e := base64.StdEncoding.DecodeString(strings.TrimPrefix(last, "m3-import-error="))
	if !strings.HasPrefix(last, "m3-import-error=") || e != nil {
		return "", errors.New("installer acknowledgement missing")
	}
	msg := string(raw)
	for _, suffix := range []string{"restore service certificate", "api-ssl was changed by its owner", "inspect certificate lacking completed fingerprint proof", "certificate identity changed"} {
		known := "tikray: shared_reference_refuses; " + suffix
		if strings.Contains(msg, known) {
			return "", errors.New(known)
		}
	}
	for _, category := range []string{"enable router DNS", "bridge overlaps", "object conflict", "retry bootstrap", "shared_reference_refuses", "inspect api-ssl", "inspect selected disk", "inspect disk", "select", "inspect", "enable", "choose", "archive", "image archive", "pending", "multiple active", "obtain installer", "unsupported", "unexpected", "invalid", "insufficient", "private handoff"} {
		known := "tikray: " + category
		if strings.Contains(msg, known) {
			return "", errors.New(known)
		}
	}
	// Error literals come only from the reviewed installer sources. Dynamic
	// RouterOS diagnostics can contain router configuration or credentials.
	for _, p := range []string{"install.rsc", "certificate.rsc", "watchdog-preflight.rsc", "watchdog.rsc"} {
		src, e := os.ReadFile(filepath.Join(repoRoot(), "routeros", p))
		if e != nil {
			continue
		}
		for _, match := range sourceError.FindAllStringSubmatch(string(src), -1) {
			if strings.Contains(msg, match[1]) {
				return "", errors.New(match[1])
			}
		}
	}
	for _, category := range []string{"not enough permissions", "expected argument of type", "invalid internal item number", "no such item", "input does not match any value", "value of argument", "argument of", "not a valid", "cannot be used", "cannot add", "not enough", "cannot compare", "invalid value for", "expected end of command", "expected command name", "already have", "not a valid value", "not a number", "not allowed by device-mode", "script is too large"} {
		if strings.Contains(msg, category) {
			return "", errors.New("routeros: " + category)
		}
	}
	if at := importPosition.FindStringSubmatch(msg); at != nil {
		return "", fmt.Errorf("installer syntax at line %s column %s", at[1], at[2])
	}
	return "", errors.New("installer refused")
}

// This WAN port was in use by an ordinary owner DNAT before API-SSL was
// enabled on the same port. A blanket raw-port drop breaks the existing service.
func (f *installLab) ownerPortForward(ctx context.Context, t *testing.T) {
	t.Helper()
	_, ok := poll(ctx, 12*time.Second, time.Second, func() bool {
		out, err := exec.CommandContext(ctx, "curl", "--noproxy", "*", "--interface", "198.51.100.1", "--fail", "--silent", "--connect-timeout", "2", "--max-time", "3", "http://198.51.100.2:9879/whoami").Output()
		return err == nil && strings.TrimSpace(string(out)) == egressDirect
	})
	if !ok {
		dnat := f.mustRun(ctx, t, `:put [/ip/firewall/nat/get [find where comment="lab:owner-service"] packets]`)
		snat := f.mustRun(ctx, t, `:put [/ip/firewall/nat/get [find where comment="lab:owner-return"] packets]`)
		d, _ := strconv.ParseUint(dnat, 10, 64)
		s, _ := strconv.ParseUint(snat, 10, 64)
		t.Fatalf("owner WAN port forward failed its endpoint witness (DNAT hits %d, reply masquerade hits %d)", d, s)
	}
}

// Keep actual row IDs and order in memory. The harness fixture adds new
// witnesses later, so they may be interspersed with the original rows.
func (f *installLab) readOwnerRules(ctx context.Context, t *testing.T) []string {
	t.Helper()
	var result []string
	for _, menu := range []string{"/ip/firewall/filter", "/ip/firewall/nat", "/ipv6/firewall/filter"} {
		cmd := fmt.Sprintf(`:foreach id in=[%s/find where comment~"^lab:"] do={:local r [%s/get $id]; :put (%q . $id . "|" . ($r->"comment") . "|" . ($r->"chain") . "|" . ($r->"action") . "|" . [:tostr ($r->"disabled")])}`, menu, menu, menu+"|")
		result = append(result, strings.Split(f.mustRun(ctx, t, cmd), "\n")...)
	}
	return result
}

func (f *installLab) checkOwnerRules(ctx context.Context, t *testing.T) {
	t.Helper()
	remain := f.ownerRules
	for _, r := range f.readOwnerRules(ctx, t) {
		if len(remain) > 0 && remain[0] == r {
			remain = remain[1:]
		}
	}
	if len(remain) > 0 {
		t.Fatal("installation changed an owner's firewall rule or its order")
	}
}

func (f *installLab) v6Port(ctx context.Context, port int) bool {
	return f.Net.Inet(ctx, "python3", "-c", `import socket,sys
s=socket.socket(socket.AF_INET6);s.settimeout(2);s.bind(("2001:db8:4:1::2",0));s.connect(("2001:db8:4:1::1",int(sys.argv[1])));s.close()`, strconv.Itoa(port)).Run() == nil
}
