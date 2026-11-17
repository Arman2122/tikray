//go:build lab

package e2e

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/store"
)

// An exact older executable has a different native ownership catalogue. A
// current binary relabelled as a release cannot exercise this boundary.
func TestM3CrossVersionUDPRollback(t *testing.T) {
	old := os.Getenv("TIKRAY_LAB_PRE_UDP_BUNDLE")
	if old == "" {
		t.Skip("supply the signed pre-UDP control archive")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 26*time.Minute)
	defer cancel()
	current := os.Getenv("TIKRAY_LAB_IMAGES")
	if current == "" || filepath.Clean(current) == filepath.Clean(old) {
		t.Fatal("current signed image pair missing")
	}
	revision, err := os.ReadFile(filepath.Join(old, "SOURCE_COMMIT"))
	if err != nil || strings.TrimSpace(string(revision)) != "8b91d54bea691f744b1e022768f46a5f1459181d" {
		t.Fatal("historical controller revision is unverified")
	}
	arch := labArch().GOARCH()
	control, runner := "tikray-"+arch+".tar", "tikray-runner-"+arch+".tar"
	run := func(name string, args ...string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Dir = repoRoot()
		if cmd.Run() != nil {
			t.Fatal("could not prepare authenticated cross-version images", name)
		}
	}
	for _, pair := range []struct{ dir, image string }{{old, control}, {current, control}, {current, runner}} {
		file := filepath.Join(pair.dir, pair.image)
		run("cosign", "verify-blob", "--key", filepath.Join(pair.dir, "cosign.pub"), "--signature", file+".sig", "--offline", "--insecure-ignore-tlog", file)
	}
	// Sign copies with one lab publisher. The original archived binaries
	// and their independently verified archive digests stay intact.
	work := t.TempDir()
	key := filepath.Join(work, "private.pem")
	public := filepath.Join(work, "cosign.pub")
	run("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-out", key)
	run("openssl", "pkey", "-in", key, "-pubout", "-out", public)
	sign := func(src, dst string) {
		t.Helper()
		run("cp", src, dst)
		raw := filepath.Join(work, "signature")
		run("openssl", "dgst", "-sha256", "-sign", key, "-out", raw, dst)
		run("openssl", "base64", "-A", "-in", raw, "-out", dst+".sig")
	}
	sign(filepath.Join(old, control), filepath.Join(work, control))
	sign(filepath.Join(current, runner), filepath.Join(work, runner))
	candidate := identifyArchive(t, filepath.Join(current, control))
	version := "sha256-" + candidate.digest
	update := filepath.Join(work, "updates", version)
	if err := os.MkdirAll(update, 0700); err != nil {
		t.Fatal("could not stage pinned newer archive")
	}
	sign(filepath.Join(current, control), filepath.Join(update, control))
	installer := filepath.Join(work, "install.rsc")
	run("go", "run", "./cmd/tikray-installer", "-version", env("TIKRAY_LAB_CHANNEL", "7.25"), "-arch", arch, "-images", work, "-key", public, "-out", installer)
	t.Setenv("TIKRAY_LAB_IMAGES", work)
	t.Setenv("TIKRAY_LAB_INSTALLER", installer)

	f := deployOutage(ctx, t)
	original := identifyArchive(t, filepath.Join(work, control))
	baseline := f.requireImage(ctx, t, "tikray", original)
	runnerBaseline, present := f.containerImage(ctx, "runner")
	if !present || f.taggedID(ctx, t, "/tool/netwatch", "tikray:udp-watch") != "" {
		t.Fatal("historical baseline did not use its original RouterOS policy")
	}
	ssh := f.ownerLANSSH(ctx, t)
	newRef := f.stageImageFixture(ctx, t, "tikray", version, false)
	f.imageOperation(ctx, t, "tikray", "update", version, original.digest, candidate.digest, false)
	f.waitImageCompletion(ctx, t, "tikray", newRef, original.digest, baseline)
	if _, ok := poll(ctx, 70*time.Second, time.Second, func() bool {
		return f.taggedID(ctx, t, "/tool/netwatch", "tikray:udp-watch") != ""
	}); !ok {
		f.checkReady(ctx, t)
		t.Fatal("current control never armed open UDP recovery")
	}
	socket := f.keepImagePeerFlow(ctx, t)
	if f.retainedUDP(ctx, t) == "" {
		t.Fatal("current control never created a path-retained UDP connection")
	}
	newer := f.requireImage(ctx, t, "tikray", newRef)
	f.scheduler(ctx, t, false)
	// Keep the native worker stopped while the control process retires the
	// actual active UDP bindings and while its ordinary apply loop can tick.
	request, cancelRequest := context.WithTimeout(ctx, 4*time.Minute)
	response, err := f.api.ImageRollback(request, "tikray")
	cancelRequest()
	var rollback imageAcceptance
	if err != nil || response.Decode(&rollback) != nil || rollback.From != candidate.digest ||
		rollback.To != original.digest || !imageNonce.MatchString(rollback.OperationID) {
		t.Fatal("native UDP migration did not publish the requested rollback")
	}
	for range 6 {
		state := f.imageStatus(ctx, t, "tikray")
		if state.Pending == nil || *state.Pending != rollback || state.Active != candidate.digest ||
			f.taggedID(ctx, t, "/tool/netwatch", "tikray:udp-watch") != "" {
			t.Fatal("ordinary control pass changed compatible policy during the queued rollback")
		}
		if sleep(ctx, time.Second) != nil {
			t.Fatal("queued rollback observation cancelled")
		}
	}
	f.scheduler(ctx, t, true)
	f.waitImageCompletion(ctx, t, "tikray", original, candidate.digest, newer)
	f.checkReady(ctx, t)
	if f.taggedID(ctx, t, "/tool/netwatch", "tikray:udp-watch") != "" {
		t.Fatal("older control still has newer UDP routing rules")
	}
	requireOutageDatagram(ctx, t, socket, 'P')
	// A positive durable policy edit requires the old controller's
	// ownership verifier and data path, beyond its watchdog health reply.
	f.setClientPolicy(ctx, t, store.Policy{Mode: store.ModeSmart, KillSwitch: true})
	if f.egress(ctx, routingDomestic) != egressDirect {
		t.Fatal("older control could not apply an owner policy edit after rollback")
	}
	if row, ok := f.containerImage(ctx, "runner"); !ok || row.id != runnerBaseline.id || row.imageID != runnerBaseline.imageID {
		t.Fatal("control rollback recreated the unrelated runner")
	}
	if currentStatus := f.imageStatus(ctx, t, "tikray"); currentStatus.Active != original.digest || currentStatus.Pending != nil {
		t.Fatal("older control committed status unavailable")
	}
	f.requireNoLeak(t)
	f.requireDirectOwner(ctx, t)
	ssh()
}
