package routeros

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func setupLeaseEngine(t *testing.T, dynamic string) (*Engine, *diffRouter) {
	t.Helper()
	f := newDiffRouter()
	f.insert("/ip/dhcp-server", "", map[string]string{
		"name":      "dhcp-lan",
		"interface": "bridge",
	})
	leaseProps := map[string]string{
		"active-server":      "dhcp-lan",
		"status":             "bound",
		"active-address":     "192.168.88.25",
		"active-mac-address": "02:00:00:00:00:25",
		"host-name":          "workstation",
	}
	if dynamic != "" {
		leaseProps["dynamic"] = dynamic
	}
	id := f.insert("/ip/dhcp-server/lease", "", leaseProps)
	if dynamic == "true" || dynamic == "" {
		for i := range f.rows {
			if f.rows[i].ID == id {
				f.rows[i].Dynamic = true
			}
		}
	}
	scope := InstallScope{
		Subnet:  netip.MustParsePrefix("172.30.0.0/29"),
		LANList: "LAN",
		LANs:    []LAN{{Interface: "bridge", Prefix: netip.MustParsePrefix("192.168.88.0/24")}},
		WAN:     WANPath{Interface: "ether1", Gateway: netip.MustParseAddr("198.51.100.1"), Network: netip.MustParsePrefix("198.51.100.0/24")},
	}
	e := NewEngine(f, scope, t.TempDir())
	e.observe = func(_ context.Context, _ Native, _ InstallScope) (Actual, error) {
		a := Actual{
			Generation: f.gen,
			Topology: Topology{
				Subnet:     scope.Subnet,
				LANList:    scope.LANList,
				LANs:       scope.LANs,
				LANMembers: []string{"bridge"},
				RouterIPs:  []netip.Addr{netip.MustParseAddr("192.168.88.1")},
				WAN:        []WANPath{scope.WAN},
			},
		}
		o := observation{ctx: context.Background(), c: f, gen: f.gen}
		leases, err := o.lanLeases("bridge", a.Topology.LANs, a.Topology.RouterIPs)
		if err != nil {
			return Actual{}, err
		}
		a.Leases = leases
		return a, nil
	}
	return e, f
}

func TestMakeStaticLeaseConvertsDynamicLease(t *testing.T) {
	e, f := setupLeaseEngine(t, "true")
	addr := netip.MustParseAddr("192.168.88.25")

	before, err := e.Leases(t.Context())
	if err != nil || len(before) != 1 || before[0].Static {
		t.Fatalf("before = %+v, %v; want 1 dynamic lease", before, err)
	}

	got, err := e.MakeStaticLease(t.Context(), addr)
	if err != nil {
		t.Fatalf("MakeStaticLease: %v", err)
	}
	if got.Address != addr || got.MAC != "02:00:00:00:00:25" || got.Name != "workstation" || !got.Static {
		t.Fatalf("got = %+v, want static lease for %s", got, addr)
	}
	if len(f.writes) != 1 || f.writes[0][0] != "/ip/dhcp-server/lease/make-static" {
		t.Fatalf("writes = %v, want single make-static command", f.writes)
	}

	// Repeating on an already-static lease is a read-only no-op.
	got2, err := e.MakeStaticLease(t.Context(), addr)
	if err != nil || !got2.Static {
		t.Fatalf("second MakeStaticLease = %+v, %v", got2, err)
	}
	if len(f.writes) != 1 {
		t.Fatalf("writes after noop = %d, want 1", len(f.writes))
	}

	after, err := e.Leases(t.Context())
	if err != nil || len(after) != 1 || !after[0].Static {
		t.Fatalf("after = %+v, %v; want 1 static lease", after, err)
	}
}

func TestMakeStaticLeaseRejectsOutOfScopeAndMissing(t *testing.T) {
	e, f := setupLeaseEngine(t, "true")

	cases := []netip.Addr{
		{},
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("192.168.88.1"),  // router IP
		netip.MustParseAddr("192.168.88.99"), // no bound lease
		netip.MustParseAddr("10.0.0.5"),      // not in managed LAN
	}
	for _, addr := range cases {
		if _, err := e.MakeStaticLease(t.Context(), addr); !errors.Is(err, ErrLeaseNotFound) {
			t.Fatalf("MakeStaticLease(%v) err = %v, want ErrLeaseNotFound", addr, err)
		}
	}
	if len(f.writes) != 0 {
		t.Fatalf("rejected calls performed %d writes", len(f.writes))
	}
}

func TestMakeStaticLeaseDetectsFailedReadback(t *testing.T) {
	e, f := setupLeaseEngine(t, "true")
	f.afterWrite = func() {
		// Simulate a router that accepted the command without actually marking the lease static.
		for i := range f.rows {
			if f.rows[i].Menu == "/ip/dhcp-server/lease" {
				f.rows[i].Dynamic = true
				f.rows[i].Props["dynamic"] = "true"
			}
		}
	}
	_, err := e.MakeStaticLease(t.Context(), netip.MustParseAddr("192.168.88.25"))
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable when readback stays dynamic", err)
	}
}
