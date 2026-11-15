package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestImageCommandsUseAuthenticatedService(t *testing.T) {
	f := newFake()
	vars := startDaemon(t, f).env(t)
	for _, args := range [][]string{{"image", "status", "tikray"}, {"image", "update", "tikray-runner", "v1.2.3"}, {"image", "rollback", "runner"}} {
		code, out, _ := runAPI(t, vars, args...)
		var reply struct {
			Component string `json:"component"`
		}
		if code != 0 || json.Unmarshal([]byte(out), &reply) != nil || (reply.Component != "tikray" && reply.Component != "runner") {
			t.Fatal("image CLI lost the authenticated operation result")
		}
	}
	if !reflect.DeepEqual(f.called("ImageUpdate"), [][]any{{"runner", "v1.2.3"}}) || !reflect.DeepEqual(f.called("ImageRollback"), [][]any{{"runner"}}) {
		t.Fatal("CLI dispatched to the wrong component or release")
	}
	const private = "private-fixture-value"
	for _, args := range [][]string{{"image", "update", "runner", "../" + private}, {"image", "update", private, "v1.2.3"}, {"image", "rollback", "runner", private}} {
		code, out, diag := runAPI(t, vars, args...)
		if code != 2 || strings.Contains(out+diag, private) || len(f.called("ImageUpdate")) != 1 {
			t.Fatal("invalid image argument dispatched or echoed")
		}
	}
}

func TestOwnerImageSourceWithoutChangingRouterOSEnvironment(t *testing.T) {
	data := t.TempDir()
	dir := filepath.Join(data, "state")
	if os.Mkdir(dir, 0700) != nil {
		t.Fatal("fixture")
	}
	p := filepath.Join(dir, "image-source.json")
	cfg := Config{Data: data}
	if os.WriteFile(p, []byte(`{"version":1,"upstream":"https://release.example/tikray","mirrors":["https://mirror.example/{version}/{file}"],"runner_mode":"manual"}`), 0600) != nil {
		t.Fatal("fixture")
	}
	got, err := ownerImageSource(cfg)
	if err != nil || got.ImageUpstream != "https://release.example/tikray" || len(got.ImageMirrors) != 1 || got.ImageSchedules == nil {
		t.Fatal("installed owner source was not available")
	}
	if os.WriteFile(p, []byte(`{"version":1,"upstream":"http://private-fixture"}`), 0600) != nil {
		t.Fatal("fixture")
	}
	_, err = ownerImageSource(cfg)
	if err == nil || strings.Contains(err.Error(), "private-fixture") {
		t.Fatal("bad source accepted or echoed")
	}
	// Environment overrides are a complete configuration, never a blend of two roots.
	cfg.ImageUpstream = "https://override.example/"
	got, err = ownerImageSource(cfg)
	if err != nil || got.ImageUpstream != cfg.ImageUpstream || len(got.ImageMirrors) != 0 {
		t.Fatal("ambiguous image source precedence")
	}
}
