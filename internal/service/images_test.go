package service

import (
	"context"
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
	path := filepath.Join(e.data, "state", "image-update.json")
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
