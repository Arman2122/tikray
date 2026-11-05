//go:build lab

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/runnerapi"
)

func withCounterReplies(t *testing.T, replies ...runnerapi.XrayAPIResponse) {
	t.Helper()
	var calls atomic.Uint32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		i := min(int(calls.Add(1))-1, len(replies)-1)
		json.NewEncoder(w).Encode(replies[i])
	}))
	t.Cleanup(server.Close)
	before := runnerAPI
	runnerAPI = &runnerapi.Client{BaseURL: server.URL, Token: "fixture"}
	t.Cleanup(func() { runnerAPI = before })
}

func directCounterJSON(value string) string {
	return `{"stat":{"name":"outbound>>>direct>>>traffic>>>downlink"` + value + `}}`
}

func TestDirectBytesValidatesCounter(t *testing.T) {
	for _, tc := range []struct {
		name, stdout string
		want         int64
		fail         bool
	}{
		{"missing zero value", directCounterJSON(""), 0, false},
		{"numeric", directCounterJSON(`,"value":108`), 108, false},
		{"quoted", directCounterJSON(`,"value":"216"`), 216, false},
		{"empty", "", 0, true}, {"malformed", "{", 0, true},
		{"missing stat", "{}", 0, true},
		{"wrong counter", `{"stat":{"name":"outbound>>>block>>>traffic>>>downlink","value":"108"}}`, 0, true},
		{"invalid value", directCounterJSON(`,"value":"invalid"`), 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withCounterReplies(t, runnerapi.XrayAPIResponse{Stdout: tc.stdout})
			got, err := directBytes(t.Context())
			if got != tc.want || (err != nil) != tc.fail {
				t.Errorf("bytes=%d, error=%v; want %d, error=%v", got, err != nil, tc.want, tc.fail)
			}
		})
	}
	t.Run("explicit not found", func(t *testing.T) {
		withCounterReplies(t, runnerapi.XrayAPIResponse{ExitCode: 1, Stderr: "counter not found"})
		if got, err := directBytes(t.Context()); got != 0 || err != nil {
			t.Error("missing counter should count as zero")
		}
	})
}

func TestBootstrapWaitsForBothDirectSignals(t *testing.T) {
	var replies []runnerapi.XrayAPIResponse
	// First request uses RouterOS's fallback. The second request arrives on
	// the wrong egress. Only the third proves that xray sent the request direct.
	for _, n := range []int{0, 0, 0, 108, 108, 216} {
		replies = append(replies, runnerapi.XrayAPIResponse{Stdout: directCounterJSON(fmt.Sprintf(`,"value":%d`, n))})
	}
	withCounterReplies(t, replies...)
	calls := 0
	proof := waitDirect(t.Context(), 2*time.Second, time.Millisecond, func(context.Context) string {
		calls++
		if calls == 2 {
			return serverEgress["a"]
		}
		return egressDirect
	})
	if !proof.ok || proof.attempts != 3 || proof.bytes != 108 || !proof.wan {
		t.Errorf("direct proof = %v in %d attempts, WAN=%v delta=%d", proof.ok, proof.attempts, proof.wan, proof.bytes)
	}
}
