package xray

import (
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

// The tests build xray's answers with these, from the field numbers in
// xray-core's protos, and compare requests with hex written out by hand.

func vint(num protowire.Number, v uint64) []byte {
	return protowire.AppendVarint(protowire.AppendTag(nil, num, protowire.VarintType), v)
}

func str(num protowire.Number, s string) []byte {
	return protowire.AppendString(protowire.AppendTag(nil, num, protowire.BytesType), s)
}

func sub(num protowire.Number, parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return protowire.AppendBytes(protowire.AppendTag(nil, num, protowire.BytesType), b)
}

func fixed32(num protowire.Number, v uint32) []byte {
	return protowire.AppendFixed32(protowire.AppendTag(nil, num, protowire.Fixed32Type), v)
}

func fixed64(num protowire.Number, v uint64) []byte {
	return protowire.AppendFixed64(protowire.AppendTag(nil, num, protowire.Fixed64Type), v)
}

func cat(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

// rpc is what a test server saw of one call.
type rpc struct {
	path string
	msg  []byte // the request message, without its framing
}

// answering serves every call with answer, and records the call in *got.
func answering(t *testing.T, got *rpc, answer []byte) *Client {
	t.Helper()
	return grpcServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if len(body) < 5 {
			t.Errorf("request body is %d bytes, want a framed message", len(body))
			body = make([]byte, 5)
		}
		*got = rpc{path: r.URL.Path, msg: body[5:]}
		reply(w, answer, "0", "")
	})
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

func TestQueryStats(t *testing.T) {
	answer := cat(
		sub(1, str(1, "outbound>>>srv-a>>>traffic>>>uplink"), vint(2, 1234)),
		sub(1, str(1, "outbound>>>srv-a>>>traffic>>>downlink"), vint(2, 5678)),
		// A counter that is zero is sent as an empty message, and a negative
		// value is ten bytes of varint.
		sub(1, str(1, "outbound>>>srv-b>>>traffic>>>uplink")),
		sub(1, str(1, "outbound>>>srv-b>>>traffic>>>downlink"), vint(2, ^uint64(0))),
		// Fields the client does not know are skipped, whatever their type.
		fixed32(9, 1), fixed64(10, 2), str(11, "x"),
	)
	var got rpc
	c := answering(t, &got, answer)
	stats, err := c.QueryStats(t.Context(), "outbound>>>", false)
	if err != nil {
		t.Fatal(err)
	}
	if got.path != "/xray.app.stats.command.StatsService/QueryStats" {
		t.Errorf("path = %q", got.path)
	}
	// QueryStatsRequest{pattern: "outbound>>>"}; reset=false is left out.
	if want := "0a0b6f7574626f756e643e3e3e"; hexOf(got.msg) != want {
		t.Errorf("request = %s, want %s", hexOf(got.msg), want)
	}
	want := []Stat{
		{"outbound>>>srv-a>>>traffic>>>uplink", 1234},
		{"outbound>>>srv-a>>>traffic>>>downlink", 5678},
		{"outbound>>>srv-b>>>traffic>>>uplink", 0},
		{"outbound>>>srv-b>>>traffic>>>downlink", -1},
	}
	if !reflect.DeepEqual(stats, want) {
		t.Errorf("stats = %+v, want %+v", stats, want)
	}

	if _, err := c.QueryStats(t.Context(), "outbound>>>", true); err != nil {
		t.Fatal(err)
	}
	// ... and QueryStatsRequest{pattern, reset: true}.
	if want := "0a0b6f7574626f756e643e3e3e1001"; hexOf(got.msg) != want {
		t.Errorf("request with reset = %s, want %s", hexOf(got.msg), want)
	}
	if _, err := c.QueryStats(t.Context(), "", false); err != nil {
		t.Fatal(err)
	}
	if len(got.msg) != 0 {
		t.Errorf("request for every counter = %s, want empty", hexOf(got.msg))
	}
}

func TestQueryStatsNone(t *testing.T) {
	var got rpc
	c := answering(t, &got, nil)
	stats, err := c.QueryStats(t.Context(), "nothing", false)
	if err != nil || len(stats) != 0 {
		t.Errorf("QueryStats = %v, %v; want no stats", stats, err)
	}
}

func TestSysStats(t *testing.T) {
	answer := cat(
		vint(1, 42),       // NumGoroutine
		vint(2, 7),        // NumGC
		vint(3, 1<<33),    // Alloc, past 32 bits
		vint(4, 99),       // TotalAlloc
		vint(9, 5),        // PauseTotalNs
		vint(10, 3600),    // Uptime
		fixed32(20, 1234), // a field of a later release
	)
	var got rpc
	c := answering(t, &got, answer)
	st, err := c.SysStats(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got.path != "/xray.app.stats.command.StatsService/GetSysStats" {
		t.Errorf("path = %q", got.path)
	}
	if len(got.msg) != 0 {
		t.Errorf("request = %s, want empty", hexOf(got.msg))
	}
	if want := (SysStats{Uptime: 3600, NumGoroutine: 42, Alloc: 1 << 33}); st != want {
		t.Errorf("SysStats = %+v, want %+v", st, want)
	}
}

func TestOutboundStatus(t *testing.T) {
	// GetOutboundStatusResponse{status: ObservationResult{status: [...]}}.
	answer := sub(1, // GetOutboundStatusResponse.status
		sub(1, // ObservationResult.status
			vint(1, 1),                       // alive
			vint(2, 143),                     // delay, ms
			str(4, "srv-a"),                  // outbound_tag
			vint(5, 1_700_000_100),           // last_seen_time, Unix seconds
			vint(6, 1_700_000_110),           // last_try_time
			sub(7, vint(1, 5), vint(4, 140)), // health_ping, skipped
		),
		sub(1,
			str(3, "the outbound srv-b is dead: dial tcp: refused"), // last_error_reason
			str(4, "srv-b"),
			vint(2, 99999999),
			vint(6, 1_700_000_120),
			// alive is false, so it is not on the wire; last_seen_time is 0.
			fixed32(30, 5),
		),
		sub(1, str(4, "srv-c")), // never probed
	)
	var got rpc
	c := answering(t, &got, answer)
	st, err := c.OutboundStatus(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got.path != "/xray.core.app.observatory.command.ObservatoryService/GetOutboundStatus" {
		t.Errorf("path = %q", got.path)
	}
	if len(got.msg) != 0 {
		t.Errorf("request = %s, want empty", hexOf(got.msg))
	}
	want := []OutboundStatus{
		{Tag: "srv-a", Alive: true, Delay: 143 * time.Millisecond, LastSeen: time.Unix(1_700_000_100, 0), LastTry: time.Unix(1_700_000_110, 0)},
		{Tag: "srv-b", Delay: 99999999 * time.Millisecond, LastError: "the outbound srv-b is dead: dial tcp: refused", LastTry: time.Unix(1_700_000_120, 0)},
		{Tag: "srv-c"},
	}
	if len(st) != len(want) {
		t.Fatalf("OutboundStatus = %+v, want %d entries", st, len(want))
	}
	for i := range want {
		if st[i].Tag != want[i].Tag || st[i].Alive != want[i].Alive || st[i].Delay != want[i].Delay || st[i].LastError != want[i].LastError ||
			!st[i].LastSeen.Equal(want[i].LastSeen) || !st[i].LastTry.Equal(want[i].LastTry) {
			t.Errorf("entry %d = %+v, want %+v", i, st[i], want[i])
		}
	}
	// A time that was never set is the zero time, not 1970.
	if !st[1].LastSeen.IsZero() || !st[2].LastTry.IsZero() {
		t.Errorf("unset times are %v and %v, want the zero time", st[1].LastSeen, st[2].LastTry)
	}
}

// TestOutboundStatusEmpty: with no outbound observed yet, xray answers with an
// empty ObservationResult, or with none at all.
func TestOutboundStatusEmpty(t *testing.T) {
	for name, answer := range map[string][]byte{"no result": nil, "empty result": sub(1)} {
		t.Run(name, func(t *testing.T) {
			var got rpc
			c := answering(t, &got, answer)
			st, err := c.OutboundStatus(t.Context())
			if err != nil || len(st) != 0 {
				t.Errorf("OutboundStatus = %v, %v; want no entries", st, err)
			}
		})
	}
}

func TestBalancerTargets(t *testing.T) {
	// GetBalancerInfoResponse{balancer: BalancerMsg{override: {target: 2},
	// principle_target: {tag: 1}}}.
	answer := sub(1,
		sub(5, str(2, "srv-z")),
		sub(6, str(1, "srv-a"), str(1, "srv-b")),
	)
	var got rpc
	c := answering(t, &got, answer)
	override, targets, err := c.BalancerTargets(t.Context(), "proxy-open")
	if err != nil {
		t.Fatal(err)
	}
	if got.path != "/xray.app.router.command.RoutingService/GetBalancerInfo" {
		t.Errorf("path = %q", got.path)
	}
	// GetBalancerInfoRequest{tag: "proxy-open"}.
	if want := "0a0a70726f78792d6f70656e"; hexOf(got.msg) != want {
		t.Errorf("request = %s, want %s", hexOf(got.msg), want)
	}
	if override != "srv-z" || !reflect.DeepEqual(targets, []string{"srv-a", "srv-b"}) {
		t.Errorf("BalancerTargets = %q, %q; want srv-z, [srv-a srv-b]", override, targets)
	}
}

// TestBalancerTargetsNone: xray names no target while none is alive (leastPing
// puts an empty tag in the list), and has none to report without the
// override.
func TestBalancerTargetsNone(t *testing.T) {
	for name, answer := range map[string][]byte{
		"empty balancer":    sub(1),
		"empty response":    nil,
		"empty override":    sub(1, sub(5), sub(6)),
		"no alive outbound": sub(1, sub(5, str(2, "")), sub(6, str(1, ""))),
	} {
		t.Run(name, func(t *testing.T) {
			var got rpc
			c := answering(t, &got, answer)
			override, targets, err := c.BalancerTargets(t.Context(), "proxy-open")
			if err != nil || override != "" || len(targets) != 0 {
				t.Errorf("BalancerTargets = %q, %q, %v; want nothing", override, targets, err)
			}
		})
	}
}

// TestStatusErrorsSurface: each method returns the *StatusError that xray's
// grpc-status gives, such as 12 from a release without the service.
func TestStatusErrorsSurface(t *testing.T) {
	c := grpcServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Grpc-Status", "12")
		w.Header().Set("Grpc-Message", "unknown service "+r.URL.Path)
		w.WriteHeader(http.StatusOK)
	})
	ctx := t.Context()
	calls := map[string]func() error{
		"QueryStats":      func() error { _, err := c.QueryStats(ctx, "", false); return err },
		"SysStats":        func() error { _, err := c.SysStats(ctx); return err },
		"OutboundStatus":  func() error { _, err := c.OutboundStatus(ctx); return err },
		"BalancerTargets": func() error { _, _, err := c.BalancerTargets(ctx, "b"); return err },
	}
	for name, call := range calls {
		var se *StatusError
		if err := call(); !errors.As(err, &se) || se.Code != 12 {
			t.Errorf("%s: err = %v, want a *StatusError with code 12", name, err)
		}
	}
}

// TestDecodeErrors: a message that does not parse is an error naming the
// method, not a partial result.
func TestDecodeErrors(t *testing.T) {
	// Field 1, 127 bytes long, with one byte there.
	truncated := []byte{0x0a, 0x7f, 'a'}
	ctx := t.Context()
	for _, tc := range []struct {
		method  string // the RPC, as the error names it
		call    func(c *Client) error
		answers map[string][]byte
	}{
		{"QueryStats", func(c *Client) error { _, err := c.QueryStats(ctx, "", false); return err }, map[string][]byte{
			"top level": truncated,
			"stat":      sub(1, truncated),
		}},
		{"GetSysStats", func(c *Client) error { _, err := c.SysStats(ctx); return err }, map[string][]byte{
			"top level":          truncated,
			"varint":             {0x08, 0x80},
			"tag":                {0x80},
			"field number zero":  {0x00, 0x01},
			"unknown field cut":  {0x1d, 0x01},
			"bytes before first": append(str(30, "ok"), truncated...),
		}},
		{"GetOutboundStatus", func(c *Client) error { _, err := c.OutboundStatus(ctx); return err }, map[string][]byte{
			"top level":          truncated,
			"result":             sub(1, truncated),
			"outbound":           sub(1, sub(1, truncated)),
			"field number zero":  sub(1, sub(1, []byte{0x00, 0x01})),
			"unknown field cut":  sub(1, sub(1, []byte{0x3d, 0x01})),
			"varint in outbound": sub(1, sub(1, []byte{0x08, 0x80})),
		}},
		{"GetBalancerInfo", func(c *Client) error { _, _, err := c.BalancerTargets(ctx, "b"); return err }, map[string][]byte{
			"top level": truncated,
			"balancer":  sub(1, truncated),
			"override":  sub(1, sub(5, truncated)),
			"principle": sub(1, sub(6, truncated)),
		}},
	} {
		for name, answer := range tc.answers {
			t.Run(tc.method+"/"+name, func(t *testing.T) {
				var got rpc
				c := answering(t, &got, answer)
				err := tc.call(c)
				if err == nil {
					t.Fatal("call succeeded")
				}
				if want := "xray: " + tc.method + ": "; !strings.HasPrefix(err.Error(), want) {
					t.Errorf("err = %q, want the prefix %q", err, want)
				}
			})
		}
	}
}

// TestWrongWireType: a field that arrives with another wire type than the
// proto says is skipped, as protobuf parsers do.
func TestWrongWireType(t *testing.T) {
	// alive as a string, delay as a string, tag right.
	answer := sub(1, sub(1, str(1, "yes"), str(2, "fast"), str(4, "srv-a")))
	var got rpc
	c := answering(t, &got, answer)
	st, err := c.OutboundStatus(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(st) != 1 || st[0].Tag != "srv-a" || st[0].Alive || st[0].Delay != 0 {
		t.Errorf("OutboundStatus = %+v, want srv-a, dead, no delay", st)
	}
}
