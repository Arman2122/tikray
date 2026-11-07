package api

import (
	"bytes"
	"context"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/routeros"
)

type leaseBackend struct {
	*fakeBackend
	reads int
	lease routeros.LeaseInfo
}

func (b *leaseBackend) Leases(context.Context) ([]routeros.LeaseInfo, error) {
	b.reads++
	return []routeros.LeaseInfo{b.lease}, nil
}

func TestLeaseDiscoveryIsReadOnly(t *testing.T) {
	b := &leaseBackend{fakeBackend: newFake(), lease: routeros.LeaseInfo{Address: netip.MustParseAddr("192.168.1.17"), MAC: "02:00:00:00:00:17", Name: "printer", Interface: "private-scope"}}
	srv := httptest.NewServer(newHandler(t, b))
	defer srv.Close()
	const path = "/v1/routeros/leases"
	if got := request(t, srv, "GET", path, "", nil); got.status != 401 || b.reads != 0 {
		t.Fatal("unauthenticated lease read")
	}
	if got := request(t, srv, "POST", path, "{}", authed()); got.status < 400 || b.reads != 0 || len(b.recorded()) != 0 {
		t.Fatal("lease discovery accepted a write")
	}
	got := request(t, srv, "GET", path, "", authed())
	if got.status != 200 || got.header.Get("ETag") != `"7"` {
		t.Fatal("lease response missing revision")
	}
	sameJSON(t, got.body, `[{"address":"192.168.1.17","mac":"02:00:00:00:00:17","name":"printer"}]`)
	b.lease.Address = netip.MustParseAddr("192.168.1.25")
	for _, host := range []string{"tkr_deadbeef_" + strings.Repeat("a", 43), testToken, "123e4567-e89b-12d3-a456-426614174000", "evil\nname"} {
		b.lease.Name = host
		got = request(t, srv, "GET", path, "", authed())
		if got.status != 200 || bytes.Contains(got.body, []byte(host)) || bytes.Contains(got.body, []byte("private-scope")) || !bytes.Contains(got.body, []byte("192.168.1.25")) {
			t.Fatal("unsafe or stale lease view")
		}
	}
}
