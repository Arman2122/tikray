//go:build lab

package m3

import (
	"testing"
)

// Large domestic transitions use literal native address intervals for the
// temporary exclusions of a closed client. The owner script keeps its original
// negated-list selector. Exercise the real restricted account and both ends.
func TestGeoTemporaryIntervalOwnership(t *testing.T) {
	r := newRig(t)
	const menu = "/ip/firewall/address-list"
	const interval = "0.0.0.0-68.0.0.0"
	const tag = "tikray:hold:ec1ad0b274d44916e3e1574c8cc47231"
	const list = "tikray-h39865fe0819b5c793f67bb10f73ba817"
	add, err := r.api.RunContext(r.ctx, menu+"/add", "=list="+list, "=address="+interval, "=comment="+tag)
	if err != nil || add.Done.Map["ret"] == "" {
		t.Fatal("restricted account could not create an interval")
	}
	id := add.Done.Map["ret"]
	got, err := r.api.RunContext(r.ctx, menu+"/print", "?.id="+id, "?list="+list, "?comment="+tag, "=.proplist=.id,comment,address,list")
	if err != nil || len(got.Re) != 1 || got.Re[0].Map["address"] != interval {
		t.Fatal("native interval identity did not round-trip")
	}
	if _, err = r.api.RunContext(r.ctx, menu+"/remove", "=.id="+id); err != nil {
		t.Fatal("restricted interval removal failed")
	}
}
