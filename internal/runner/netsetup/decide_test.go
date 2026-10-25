package netsetup

import "testing"

func TestGatewaySysctl(t *testing.T) {
	// The runner answers ping (icmp_echo_ignore_all=0) only while xray runs
	// and its routes are in place.
	tests := []struct {
		healthy, routesOK bool
		want              string
	}{
		{true, true, "0"},
		{true, false, "1"},
		{false, true, "1"},
		{false, false, "1"},
	}
	for _, tt := range tests {
		if got := GatewaySysctl(tt.healthy, tt.routesOK); got != tt.want {
			t.Errorf("GatewaySysctl(healthy=%v, routesOK=%v) = %q, want %q", tt.healthy, tt.routesOK, got, tt.want)
		}
	}
}

func TestConstants(t *testing.T) {
	if TunName != "xray0" || TunTable != 1001 || UnreachablePriority != 100 {
		t.Errorf("TunName, TunTable, UnreachablePriority = %q, %d, %d; want xray0, 1001, 100", TunName, TunTable, UnreachablePriority)
	}
}
