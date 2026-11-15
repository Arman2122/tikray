package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/artifacts"
)

func TestGeoCommandsUseService(t *testing.T) {
	f := newFake()
	vars := startDaemon(t, f).env(t)
	for _, args := range [][]string{{"geo", "update", "latest", "--profile", "iran"}, {"geo", "rollback"}, {"geo", "update", "latest"}} {
		code, out, _ := runAPI(t, vars, args...)
		var r artifacts.Result
		if code != 0 || json.Unmarshal([]byte(out), &r) != nil || r.Outcome != f.result.Outcome {
			t.Fatal("geo command lost service operation or result")
		}
	}
	if got := f.called("GeoUpdate"); !reflect.DeepEqual(got, [][]any{{"iran", "latest"}, {"", "latest"}}) || len(f.called("GeoRollback")) != 1 {
		t.Fatal("geo CLI dispatched wrong profile, version or operation")
	}
	const marker = "private-fixture-marker"
	for _, args := range [][]string{{"geo", "update", "../" + marker, "--profile", "custom"}, {"geo", "update", "latest", "--profile", marker}, {"geo", "rollback", marker}, {"geo", "--" + marker}} {
		code, out, errout := runAPI(t, vars, args...)
		if code != 2 || strings.Contains(out+errout, marker) || len(f.called("GeoUpdate")) != 2 || len(f.called("GeoRollback")) != 1 {
			t.Fatal("invalid geo CLI operation ran or echoed its input")
		}
	}
}
