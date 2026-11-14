package e2e

import "testing"

type wanSample struct {
	closedDirect, closedProxy, peerDirect, unknown int
	freshDirect, freshProxy                        int
}

// A quiet WAN receiver cannot certify a kill switch. Every interval needs a
// fresh direct-client packet while the closed client's bypass count stays put.
func (s wanSample) isolatedSince(previous wanSample) bool {
	return s.closedDirect == previous.closedDirect && s.peerDirect > previous.peerDirect && s.unknown == 0
}

func TestClosedRouteWindowNeedsContinuousControls(t *testing.T) {
	prev := wanSample{closedDirect: 2, peerDirect: 9}
	for _, tc := range []struct {
		name string
		next wanSample
		want bool
	}{
		{"guarded", wanSample{closedDirect: 2, peerDirect: 10}, true},
		{"closed packet escaped", wanSample{closedDirect: 3, peerDirect: 11}, false},
		{"receiver or peer went quiet", prev, false},
		{"unexpected egress", wanSample{closedDirect: 2, peerDirect: 11, unknown: 1}, false},
		{"trace lost", wanSample{closedDirect: 0, peerDirect: 11}, false},
	} {
		if got := tc.next.isolatedSince(prev); got != tc.want {
			t.Errorf("%s: got %t", tc.name, got)
		}
	}
}

func (s wanSample) sourcesPreservedSince(previous wanSample) bool {
	return s.isolatedSince(previous) && s.freshDirect == previous.freshDirect && s.freshProxy > previous.freshProxy
}

func TestSourceGuardNeedsFreshConnectionsOnTheWAN(t *testing.T) {
	prev := wanSample{freshDirect: 2, freshProxy: 5, peerDirect: 9}
	for _, tc := range []struct {
		sample wanSample
		pass   bool
	}{
		{wanSample{freshDirect: 2, freshProxy: 7, peerDirect: 11}, true},
		{wanSample{freshDirect: 3, freshProxy: 7, peerDirect: 11}, false},
		{wanSample{freshDirect: 2, freshProxy: 5, peerDirect: 11}, false},
		{wanSample{freshDirect: 2, freshProxy: 7, peerDirect: 9}, false},
	} {
		if tc.sample.sourcesPreservedSince(prev) != tc.pass {
			t.Fatal("source-NAT window accepted a leak or lost a positive witness")
		}
	}
}
