package main

import (
	"encoding/json"
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
