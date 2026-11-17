package service

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/store"
)

func TestImageReplacementFencesOtherMutations(t *testing.T) {
	e := newEnv(t)
	e.inSync()
	r := &testRouter{}
	e.s = e.newService(Config{Router: r})
	path := filepath.Join(e.data, "state", "image-update.request")
	if os.WriteFile(path, []byte("private-fixture"), 0600) != nil {
		t.Fatal("fixture setup")
	}
	_, rev := e.s.State()
	for _, do := range []func() error{
		func() error {
			_, err := e.s.SetDefaultPolicy(t.Context(), rev, store.Policy{Mode: store.ModeFull})
			return err
		},
		func() error { _, err := e.s.ApplyNow(t.Context()); return err },
		func() error { _, err := e.s.CoreUpdate(t.Context(), testCore, artifacts.UpdateOptions{}); return err },
		func() error { _, err := e.s.GeoRollback(t.Context()); return err },
		func() error { _, err := e.s.ImageUpdate(t.Context(), "runner", "v1.0.0"); return err },
	} {
		if err := do(); !errors.Is(err, artifacts.ErrImageBusy) {
			t.Fatal("pending image marker allowed an operation or was ignored")
		}
	}
	if _, after := e.s.State(); after != rev || len(e.runner.gotTrials()) != 0 {
		t.Fatal("marker failed to fence state and runner")
	}
}

// A failing refresh can return after the owner has already requested a swap.
func TestImagePendingPreservesConfigurationDuringRecovery(t *testing.T) {
	e, _ := newSubEnv(t)
	sub, _ := e.addSub("provider")
	r := &testRouter{}
	e.s = e.newService(Config{Router: r})
	_, rev := e.s.State()
	if err := os.WriteFile(filepath.Join(e.data, "state", "image-update.request"), []byte("{"), 0600); err != nil {
		t.Fatal("cannot stage interrupted image receipt")
	}
	e.s.refreshFailed(t.Context(), sub, "fixture failure")
	if _, current := e.s.State(); current != rev {
		t.Error("late subscription failure changed the state during image recovery")
	}
	if _, _, err := e.s.save(rev, func(*store.State) ([]note, error) {
		t.Error("retry modified desired state before image recovery")
		return nil, nil
	}); !errors.Is(err, artifacts.ErrImageBusy) {
		t.Error("metadata write bypassed the image fence")
	}
	if _, err := e.s.RefreshSubscription(t.Context(), sub.ID); !errors.Is(err, artifacts.ErrImageBusy) {
		t.Error("refresh started during an image replacement")
	}
	if !e.s.pass(t.Context(), 0) || len(r.prepared) != 0 || r.count() != 0 {
		t.Error("unreadable transition allowed the reconciler to change watchdog routing")
	}
}

func TestImageHealthRequiresSameLiveDataPath(t *testing.T) {
	e := newEnv(t)
	e.inSync()
	status, err := e.s.runner.Status(t.Context())
	if err != nil || status.Active == nil {
		t.Fatal("missing runner fixture")
	}
	digest := artifacts.ImageSelectionDigest(*status.Active)
	if e.s.verifyImageDataPath(t.Context(), digest) != nil {
		t.Fatal("healthy committed selection did not pass")
	}
	if e.s.verifyImageDataPath(t.Context(), strings.Repeat("0", 64)) == nil {
		t.Fatal("different selection accepted")
	}
	e.health.fail(errors.New("private-fixture"))
	if err := e.s.verifyImageDataPath(context.Background(), digest); err == nil || strings.Contains(err.Error(), "private-fixture") {
		t.Fatal("failed or private runner probe accepted")
	}
}

func TestPendingControlImageKeepsLegacyRouterTargets(t *testing.T) {
	e := newEnv(t)
	e.inSync()
	r := &testRouter{}
	e.s = e.newService(Config{Router: r})
	dir := filepath.Join(e.data, "state")
	id := strings.Repeat("1", 32)
	from := artifacts.ImageRef{Component: "tikray", Digest: strings.Repeat("a", 64), Chain: strings.Repeat("b", 128), ImageID: strings.Repeat("c", 64), Size: 1}
	to := from
	to.Digest, to.ImageID = strings.Repeat("d", 64), strings.Repeat("e", 64)
	wire, err := json.Marshal(map[string]any{
		"version": 1, "installation_id": id, "component": "tikray", "previous": from,
		"candidate": to, "selection_digest": strings.Repeat("f", 64), "phase": "requested",
		"nonce": strings.Repeat("2", 32), "started": 1, "deadline": 301,
	})
	pending := filepath.Join(dir, "image-update.request")
	if err != nil || os.WriteFile(filepath.Join(dir, "install.id"), []byte(id), 0600) != nil ||
		os.WriteFile(pending, wire, 0600) != nil || artifacts.HoldsRunnerPolicy(e.data) {
		t.Fatal("verified control-image request fixture unavailable")
	}
	if !e.s.pass(t.Context(), 0) {
		t.Fatal("compatibility pass did not schedule a normal retry after retirement")
	}
	if len(r.prepared) != 1 || len(r.verified) != 1 || !r.prepared[0].LegacyOpenUDP || !r.verified[0].LegacyOpenUDP {
		t.Fatal("a normal pass could re-arm the new UDP roles before the swap")
	}
	if os.Remove(pending) != nil {
		t.Fatal("could not retire test request")
	}
	e.s.pass(t.Context(), 0)
	if len(r.prepared) != 2 || len(r.verified) != 2 || r.prepared[1].LegacyOpenUDP || r.verified[1].LegacyOpenUDP {
		t.Fatal("normal mode did not resume after the image request retired")
	}
}
