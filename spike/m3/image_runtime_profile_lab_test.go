//go:build lab

package m3

import "testing"

// Docker's own default-user/default-workdir are distinct from these direct
// owner settings. Replacing the row would silently remove a restricted user.
func TestNativeImagePreservesOwnerExecutionSettings(t *testing.T) {
	f := newNativeImageCase(t)
	const row = `[:pick [/container/find where name=tikray and comment="tikray:tikray"] 0]`
	id := f.run(`:put [:tostr ` + row + `]`)
	f.req(nativeImageNonce, f.first, f.second)
	for _, tc := range []struct{ field, value string }{
		{"hostname", "owner-image-host"}, {"user", "65532:65532"}, {"workdir", "/owner-dir"}, {"cpu-list", "cpu0"},
		{"shm-size", "33554432"}, {"restart-max-count", "3"}, {"restart-interval", "2s"}, {"stop-time", "7s"},
		{"stop-on-unhealthy", "yes"}, {"ignore-remote-image-change", "yes"}, {"check-certificate", "no"},
	} {
		t.Run(tc.field, func(t *testing.T) {
			before := f.run(`{:local r [/container/get ` + row + `];:put [:tostr ($r->"` + tc.field + `")]}`)
			if _, e := f.r.admin.RunContext(f.r.ctx, "/container/set", "=.id="+id, "="+tc.field+"="+tc.value); e != nil {
				t.Fatal("cannot stage supported owner override")
			}
			observe := func() string {
				return f.run(`{:local r [/container/get ` + row + `];:put [:tostr ($r->"` + tc.field + `")]}`)
			}
			changed := observe()
			if changed == before {
				t.Fatal("owner change did not take effect")
			}
			if got := f.tick(); got != "image: owner execution settings differ" && got != "image: owner lifecycle settings differ" {
				t.Fatalf("owner override did not refuse before replacement (%s)", got)
			}
			if f.run(`:put [:tostr `+row+`]`) != id || !f.isLive(f.first) || observe() != changed {
				t.Fatal("owner's running executable, row or override changed")
			}
			if _, e := f.r.admin.RunContext(f.r.ctx, "/container/set", "=.id="+id, "="+tc.field+"="+before); e != nil {
				if _, e = f.r.admin.RunContext(f.r.ctx, "/container/unset", "=.id="+id, "=value-name="+tc.field); e != nil {
					t.Fatal("fixture reset failed")
				}
			}
			if _, e := f.r.admin.RunContext(f.r.ctx, "/container/set", "=.id="+id, "=restart-policy=on-failure"); e != nil {
				t.Fatal("could not restore the native restart policy")
			}
			if observe() != before {
				t.Fatal("fixture default was not restored")
			}

		})
	}
}
