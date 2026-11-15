//go:build lab

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/routeros"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
)

// This archive is the delivered 7.25 x86_64 M3a kit used for the final
// branch review. Pin the manifest separately from the public key it covers.
func TestM3ImageKeepUpgrade(t *testing.T) {
	old := os.Getenv("TIKRAY_LAB_M3A_BUNDLE")
	if old == "" {
		t.Skip("supply the archived 7.25 x86_64 M3a release")
	}
	if os.Getenv("TIKRAY_LAB_CHANNEL") != "7.25" || labArch().GOARCH() != "amd64" {
		t.Skip("archived M3a release targets 7.25 x86_64")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Minute)
	defer cancel()
	checks, err := os.ReadFile(filepath.Join(old, "SHA256SUMS"))
	if err != nil {
		t.Fatal("old release verification manifest unavailable")
	}
	sum := sha256.Sum256(checks)
	if hex.EncodeToString(sum[:]) != "58bbb063a8e13f8e0ff7ef60a9c5faf7e52c52d25e321860fd7563f6d75bdbe3" {
		t.Fatal("wrong historical release manifest")
	}
	revision, e := os.ReadFile(filepath.Join(old, "SOURCE_COMMIT"))
	if e != nil || strings.TrimSpace(string(revision)) != "57d40cb565698a0ce865c408ee78c538384066a3" {
		t.Fatal("wrong M3a source revision")
	}
	run := func(program string, args ...string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, program, args...)
		cmd.Dir = old
		if cmd.Run() != nil {
			t.Fatal("historical release verification failed")
		}
	}
	run("sha256sum", "--strict", "--status", "--check", "SHA256SUMS")
	for _, file := range []string{"tikray-amd64.tar", "tikray-runner-amd64.tar"} {
		run("cosign", "verify-blob", "--key", "cosign.pub", "--signature", file+".sig", "--offline", "--insecure-ignore-tlog", file)
	}
	f := DeployM3(ctx, t)
	control, runner, installer := f.controlTar, f.runnerTar, f.installer
	state := func() runnerapi.Selection {
		t.Helper()
		var s runnerapi.Selection
		if json.Unmarshal(f.exactFile(ctx, t, dataRoot+"/run/active.json"), &s) != nil || s.Validate() != nil {
			t.Fatal("committed runner selection unavailable")
		}
		return s
	}
	native := func(component, archive string) {
		t.Helper()
		name := imageContainer(component)
		ref := identifyArchive(t, archive)
		actual := f.mustRun(ctx, t, `:put [/container/get [find where name="`+name+`" and comment="tikray:`+component+`"] image-id]`)
		if strings.TrimPrefix(strings.TrimSpace(actual), "sha256:") != ref.imageID {
			t.Fatal("native container differs from authenticated release archive")
		}
	}
	f.controlTar = filepath.Join(old, "tikray-amd64.tar")
	f.runnerTar = filepath.Join(old, "tikray-runner-amd64.tar")
	f.installer = filepath.Join(old, "install.rsc")
	baseline := observedService(ctx, t, f)
	f.stage(ctx, t, true)
	f.requireSuccess(ctx, t)
	f.checkReady(ctx, t)
	native("tikray", f.controlTar)
	native("runner", f.runnerTar)
	oldID := f.checkHealthIdentity(ctx, t)
	oldAPI := f.pinned(ctx, t)
	anon := authLabClient{base: oldAPI.BaseURL, http: oldAPI.HTTPClient()}
	authenticated := anon
	authenticated.bearer = oldAPI.Token
	authenticated.call(t, ctx, http.MethodGet, "/v1/images/tikray", nil, http.StatusNotFound)
	authenticated.call(t, ctx, http.MethodGet, "/v1/images/runner", nil, http.StatusNotFound)
	t.Log("Both authenticated image endpoints returned 404 on the historical control")
	password, code := rand.Text(), f.file(ctx, t, dataRoot+"/state/setup.code")
	session := anon.withSession(t, anon.call(t, ctx, http.MethodPost, "/v1/auth/setup", map[string]string{"username": "owner", "password": password, "code": code}, http.StatusOK))
	device := store.Device{Address: netip.MustParsePrefix("192.168.88.22/32"), MAC: "02:00:00:00:00:22", Policy: store.Policy{Mode: store.ModeFull, KillSwitch: true}}
	if _, err := oldAPI.SetDevice(ctx, device); err != nil {
		t.Fatal("could not save M3a closed client policy")
	}
	f.checkReady(ctx, t)
	prior, err := oldAPI.State(ctx)
	if err != nil {
		t.Fatal("could not read M3a owner policy")
	}
	selection := state()
	tls := f.exactFile(ctx, t, apiCert)
	var oldNative routeros.Installation
	if json.Unmarshal(f.exactFile(ctx, t, dataRoot+"/state/routeros.json"), &oldNative) != nil {
		t.Fatal("missing historic native credential audit witness")
	}
	private := []string{oldNative.Password, oldAPI.Token, f.file(ctx, t, runnerToken), password, code, session.csrf, session.cookie.Value}
	f.audit(ctx, t, private...)
	uninstaller := filepath.Join(old, "uninstall.rsc")
	script, err := os.ReadFile(uninstaller)
	if err != nil || f.CHR.Push(ctx, uninstaller, removalFile) != nil {
		t.Fatal("historical owner uninstaller unavailable")
	}
	remove := &removalLab{installLab: f, script: string(script)}
	f.mustRun(ctx, t, `/system/script/add name=m3-removal-observer source="" policy=read comment="owner:removal-observer"`)
	flow := remove.unchangedFlow(ctx, t)
	if err = remove.remove(ctx, removalFile, ""); err != nil {
		t.Fatal("historical default-keep uninstall refused", err)
	}
	after := observedService(ctx, t, f)
	if !f.installClean(ctx) || after.Disabled != baseline.Disabled || after.Certificate != baseline.Certificate || after.Port != baseline.Port || !slices.Equal(after.Grants, baseline.Grants) || f.whoami(ctx) != egressDirect {
		t.Fatal("historical default keep failed to restore the owner network")
	}
	flow()
	f.checkOwnerRules(ctx, t)
	f.ownerPortForward(ctx, t)
	if !strings.Contains(f.file(ctx, t, dataRoot+"/install.retained"), oldID) || state() != selection || !bytes.Equal(tls, f.exactFile(ctx, t, apiCert)) {
		t.Fatal("default keep lost the selected core, UI identity or retained volume")
	}
	f.controlTar, f.runnerTar, f.installer = control, runner, installer
	// A returning owner uploads the new signed pair and installer. The
	// historical installation must supply its own retained core and trust.
	for _, archive := range []string{control, runner} {
		if f.CHR.Push(ctx, archive, "disk1/tikray/images/"+filepath.Base(archive)) != nil {
			t.Fatal("could not deliver replacement image")
		}
	}
	if f.CHR.Push(ctx, installer, "m3-lab-install.rsc") != nil {
		t.Fatal("could not deliver replacement installer")
	}
	f.requireRefusal(ctx, t, "tikray: set tikrayReuseID")
	if !f.installClean(ctx) {
		t.Fatal("unselected retained volume was modified")
	}
	f.mustRun(ctx, t, `:global tikrayReuseID "`+oldID+`"`)
	f.requireSuccess(ctx, t)
	f.checkReady(ctx, t)
	native("tikray", control)
	native("runner", runner)
	for _, c := range []struct{ name, file string }{{"tikray", control}, {"runner", runner}} {
		var got artifacts.ImageStatus
		authenticated.call(t, ctx, http.MethodGet, "/v1/images/"+c.name, nil, http.StatusOK).decode(t, &got)
		if got.Component != c.name || got.Active != identifyArchive(t, c.file).digest || got.Previous != "" || got.Pending != nil {
			t.Fatal("new image endpoints do not report authenticated running archives")
		}
	}
	current, err := oldAPI.State(ctx)
	if err != nil || !bytes.Equal(current.Body, prior.Body) || state() != selection || !bytes.Equal(tls, f.exactFile(ctx, t, apiCert)) {
		t.Fatal("owner-selected reuse lost policy, selected core, or management TLS identity")
	}
	session.wantState(t, ctx, false, true)
	login := anon.withSession(t, anon.call(t, ctx, http.MethodPost, "/v1/auth/login", map[string]string{"username": "owner", "password": password}, http.StatusOK))
	login.wantState(t, ctx, false, true)
	f.ownerLogin(ctx, t)
	f.checkOwnerRules(ctx, t)
	f.ownerPortForward(ctx, t)
	flow()
	f.audit(ctx, t, append(private, login.csrf, login.cookie.Value)...)
}
