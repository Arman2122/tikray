//go:build lab

package m3

import (
	"context"
	"os"
	"testing"
	"time"
)

// Several native setters change related fields as a side effect. Exercise
// each setting against a pristine running image to prove it alone refuses.
func TestNativeImagePreservesOwnerExecutionSettings(t *testing.T) {
	type property struct{ field, value string }
	cases := []property{
		{"file", ""}, {"hostname", "owner-image-host"}, {"user", "65532:65532"}, {"workdir", "/owner-dir"},
		{"cpu-list", "cpu0"}, {"shm-size", "33554432"}, {"restart-max-count", "3"}, {"restart-interval", "2s"},
		{"stop-time", "7s"}, {"stop-on-unhealthy", "yes"}, {"ignore-remote-image-change", "yes"}, {"check-certificate", "no"},
	}
	if os.Getenv("TIKRAY_LAB_CHANNEL") == "7.25" {
		cases = append(cases, property{"swap-max", "33554432"})
	}
	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			f := newNativeImageCase(t)
			const row = `[:pick [/container/find where name=tikray and comment="tikray:tikray"] 0]`
			id := f.run(`:put [:tostr ` + row + `]`)
			observe := func() string {
				return f.run(`{:local r [/container/get ` + row + `];:put [:tostr ($r->"` + tc.field + `")]}`)
			}
			before := observe()
			value := tc.value
			if tc.field == "file" {
				value = f.data + "/images/tikray-" + f.second["digest"].(string) + ".tar"
			}
			f.req(nativeImageNonce, f.first, f.second)
			ctx, cancel := context.WithTimeout(f.r.ctx, 15*time.Second)
			defer cancel()
			if _, err := f.r.admin.RunContext(ctx, "/container/set", "=.id="+id, "="+tc.field+"="+value); err != nil {
				t.Fatal("cannot stage supported owner override")
			}
			changed := observe()
			if changed == before {
				t.Fatal("owner change did not take effect")
			}
			if result := f.tick(); result != "image: owner execution settings differ" && result != "image: owner lifecycle settings differ" {
				t.Fatalf("owner override did not refuse before replacement (%s)", result)
			}
			if f.run(`:put [:tostr `+row+`]`) != id || !f.isLive(f.first) || observe() != changed {
				t.Fatal("owner's running executable, row or override changed")
			}
		})
	}
}
