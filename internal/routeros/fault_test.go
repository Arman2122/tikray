package routeros

import (
	"bufio"
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func faultListenQuery() []string {
	return []string{"/ip/firewall/address-list/listen", "?comment=tikray:test", "=.proplist=.id,comment"}
}

func faultReceive[T any](t *testing.T, ch <-chan T, failure string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(3 * time.Second):
		t.Fatal(failure)
		var zero T
		return zero
	}
}

func TestCommandCancellationKeepsOtherRequestsHealthy(t *testing.T) {
	pending := make(chan struct{}, 1)
	cancelled := make(chan struct{}, 1)
	changes := make(chan Change, 4)
	p, cfg := testPeer(t, true, func(conn net.Conn, rd *bufio.Reader) {
		var listener, blocked string
		for {
			words, err := readSentence(rd)
			if err != nil {
				return
			}
			tag := tagWord(words)
			switch words[0] {
			case "/ip/firewall/address-list/listen":
				listener = tag
			case "/cancel":
				if len(words) != 3 || words[1] != "=tag="+strings.TrimPrefix(blocked, ".tag=") || tag == blocked || tag == listener {
					t.Error("command cancellation targeted another request")
					return
				}
				peerSend(conn, "!trap", "=category=2", blocked)
				peerSend(conn, "!done", blocked)
				peerSend(conn, "!done", tag)
				peerSend(conn, "!re", "=.id=*still-listening", listener)
				cancelled <- struct{}{}
			default:
				if words[1] == "?comment=tikray:pending" {
					blocked = tag
					pending <- struct{}{}
					continue
				}
				peerSend(conn, "!re", "=.id=*healthy", tag)
				peerSend(conn, "!done", tag)
			}
		}
	})
	c := connectTest(t, cfg)
	listenDone := make(chan error, 1)
	go func() {
		listenDone <- c.Listen(t.Context(), faultListenQuery(), func(ch Change) { changes <- ch })
	}()
	ready := faultReceive(t, changes, "listener did not become ready")
	if ready.Kind != ChangeReady {
		t.Fatal("listener did not start with readiness")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	commandDone := make(chan error, 1)
	go func() {
		query := readQuery()
		query[1] = "?comment=tikray:pending"
		_, err := c.Command(ctx, query)
		commandDone <- err
	}()
	faultReceive(t, pending, "peer did not receive cancellable command")
	cancel()
	rows, err := c.Command(t.Context(), readQuery())
	if err != nil || len(rows) != 1 || rows[0][".id"] != "*healthy" {
		t.Fatal("cancelling a command damaged a concurrent command")
	}
	if err := faultReceive(t, commandDone, "command cancellation did not finish"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled command lost cancellation result")
	}
	faultReceive(t, cancelled, "peer did not acknowledge targeted cancellation")
	row := faultReceive(t, changes, "listener stopped receiving after another command was cancelled")
	if row.Kind != ChangeRow || row.Generation != ready.Generation || row.Row[".id"] != "*still-listening" || p.logins.Load() != 1 {
		t.Fatal("command cancellation disturbed the shared listener session")
	}
	c.Close()
	faultReceive(t, listenDone, "listener did not stop on close")
}

func TestListenerCallbackCanReenterAndDoesNotBlockClose(t *testing.T) {
	_, cfg := testPeer(t, true, func(conn net.Conn, rd *bufio.Reader) {
		for {
			words, err := readSentence(rd)
			if err != nil {
				return
			}
			if strings.HasSuffix(words[0], "/listen") {
				continue
			}
			peerSend(conn, "!done", tagWord(words))
		}
	})
	c := connectTest(t, cfg)
	callbackCommand := make(chan error, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	listenDone := make(chan error, 1)
	go func() {
		listenDone <- c.Listen(t.Context(), faultListenQuery(), func(ch Change) {
			if ch.Kind == ChangeReady {
				_, err := c.Command(t.Context(), readQuery())
				callbackCommand <- err
				<-release
			}
		})
	}()
	if err := faultReceive(t, callbackCommand, "callback command blocked the reader"); err != nil {
		t.Fatal("callback could not issue a command on its own client")
	}
	if _, err := c.Command(t.Context(), readQuery()); err != nil {
		t.Fatal("blocked listener callback prevented unrelated command")
	}
	closed := make(chan struct{})
	go func() { c.Close(); close(closed) }()
	faultReceive(t, closed, "Close waited for blocked listener callback")
	unblock()
	if err := faultReceive(t, listenDone, "listener did not finish after callback returned"); !errors.Is(err, ErrClosed) {
		t.Fatal("listener did not report closed client")
	}
}

func TestListenerLostStreamRequiresFreshGeneration(t *testing.T) {
	for _, mode := range []string{"connection-loss", "unexpected-done", "callback-overflow"} {
		t.Run(mode, func(t *testing.T) {
			trigger := make(chan struct{})
			release := make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			var sessions atomic.Int32
			p, cfg := testPeer(t, true, func(conn net.Conn, rd *bufio.Reader) {
				n := sessions.Add(1)
				for {
					words, err := readSentence(rd)
					if err != nil {
						return
					}
					if strings.HasSuffix(words[0], "/listen") {
						if !reflect.DeepEqual(words[:len(words)-1], faultListenQuery()) {
							t.Error("reconnect changed the router-filtered subscription")
							return
						}
						if n != 1 {
							peerSend(conn, "!re", "=.id=*removed", "=.dead=yes", tagWord(words))
							continue
						}
						select {
						case <-trigger:
						case <-t.Context().Done():
							return
						}
						switch mode {
						case "connection-loss":
							return
						case "unexpected-done":
							peerSend(conn, "!done", tagWord(words))
						case "callback-overflow":
							// A stalled consumer cannot retain an unbounded stream;
							// overflow must force resynchronization, not drop rows.
							frame, err := encodeSentence([]string{"!re", "=comment=" + strings.Repeat("x", maxWordBytes-16), tagWord(words)})
							if err != nil {
								t.Error("could not build bounded fixture row")
								return
							}
							for range 256 {
								if writeAll(conn, frame) != nil {
									return
								}
							}
						}
						continue
					}
					peerSend(conn, "!done", tagWord(words))
				}
			})
			cfg.retryDelay = func(int) time.Duration { return time.Millisecond }
			c := connectTest(t, cfg)
			c.mu.Lock()
			firstSession := c.current
			c.mu.Unlock()
			changes := make(chan Change, 512)
			listenDone := make(chan error, 1)
			go func() {
				listenDone <- c.Listen(t.Context(), faultListenQuery(), func(ch Change) {
					changes <- ch
					if mode == "callback-overflow" && ch.Kind == ChangeReady && ch.Generation == firstSession.generation {
						<-release
					}
				})
			}()
			ready := faultReceive(t, changes, "listener did not become ready")
			if ready.Kind != ChangeReady || ready.Generation == 0 {
				t.Fatal("listener did not announce initial generation")
			}
			close(trigger)
			if mode == "callback-overflow" {
				faultReceive(t, firstSession.done, "slow callback overflow did not invalidate its session")
				unblock()
			}
			disconnected := faultReceive(t, changes, "lost stream did not announce disconnection")
			if disconnected.Kind != ChangeDisconnected || disconnected.Generation != ready.Generation {
				t.Fatal("lost stream did not invalidate its generation before recovery")
			}
			reconnected := faultReceive(t, changes, "lost stream was not resubscribed")
			if reconnected.Kind != ChangeReady || reconnected.Generation <= ready.Generation {
				t.Fatal("recovered listener did not require a fresh snapshot generation")
			}
			row := faultReceive(t, changes, "resubscribed listener did not receive removed row")
			if row.Kind != ChangeRow || row.Generation != reconnected.Generation || row.Row[".dead"] != "yes" || p.logins.Load() != 2 {
				t.Fatal("resubscribed listener lost tombstone or authenticated more than once per session")
			}
			c.Close()
			faultReceive(t, listenDone, "recovered listener did not stop on close")
		})
	}
}

func TestClientRejectsMaliciousRepliesWithoutPeerText(t *testing.T) {
	for _, mode := range []string{"duplicate-tag", "duplicate-property", "oversized-word"} {
		t.Run(mode, func(t *testing.T) {
			_, cfg := testPeer(t, true, func(conn net.Conn, rd *bufio.Reader) {
				words, err := readSentence(rd)
				if err != nil {
					return
				}
				switch mode {
				case "duplicate-tag":
					peerSend(conn, "!trap", "=message=private-fixture-value", tagWord(words), tagWord(words))
				case "duplicate-property":
					peerSend(conn, "!re", "=comment=private-fixture-value", "=comment=private-fixture-value", tagWord(words))
				case "oversized-word":
					// An oversized declared length must fail before waiting for a payload.
					_, _ = conn.Write([]byte{0xc1, 0x00, 0x01})
				}
				_, _ = readSentence(rd)
			})
			cfg.retryDelay = func(int) time.Duration { return time.Hour }
			c := connectTest(t, cfg)
			_, err := c.Command(t.Context(), readQuery())
			want := ErrProtocol
			if mode == "oversized-word" {
				want = ErrLimit
			}
			if !errors.Is(err, want) {
				t.Fatal("malicious response did not produce its fixed safe error")
			}
			if strings.Contains(err.Error(), cfg.Password) || !strings.HasPrefix(err.Error(), "routeros:") {
				t.Fatal("malicious response exposed peer text or lost package prefix")
			}
		})
	}
}

type faultWriteConn struct {
	net.Conn
	prefix int
	writes atomic.Int32
	bytes  atomic.Int32
}

func (c *faultWriteConn) Write(data []byte) (int, error) {
	c.writes.Add(1)
	n := 0
	if c.prefix > 0 {
		n, _ = c.Conn.Write(data[:min(c.prefix, len(data))])
	}
	c.bytes.Add(int32(n))
	return n, errors.New("private-fixture-value")
}

func faultInstallWriteFailure(t *testing.T, c *Client, prefix int) (*faultWriteConn, uint64) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.current
	if s == nil {
		t.Fatal("fixture has no active session")
	}
	// No request has started and the peer is waiting for one. The reader
	// retains the original connection and cannot fail until this wrapper closes it.
	fault := &faultWriteConn{Conn: s.conn, prefix: prefix}
	s.conn = fault
	return fault, s.generation
}

func TestListenerFailedWriteResubscribes(t *testing.T) {
	for _, prefix := range []int{0, 12} {
		name := "before-frame"
		if prefix > 0 {
			name = "partial-frame"
		}
		t.Run(name, func(t *testing.T) {
			var subscriptions atomic.Int32
			p, cfg := testPeer(t, true, func(conn net.Conn, rd *bufio.Reader) {
				for {
					words, err := readSentence(rd)
					if err != nil {
						return
					}
					if !reflect.DeepEqual(words[:len(words)-1], faultListenQuery()) {
						t.Error("failed listener send changed its subscription on reconnect")
						return
					}
					subscriptions.Add(1)
					peerSend(conn, "!re", "=.id=*recovered", tagWord(words))
				}
			})
			cfg.retryDelay = func(int) time.Duration { return time.Millisecond }
			c := connectTest(t, cfg)
			fault, generation := faultInstallWriteFailure(t, c, prefix)
			changes := make(chan Change, 4)
			listenDone := make(chan error, 1)
			go func() {
				listenDone <- c.Listen(t.Context(), faultListenQuery(), func(ch Change) { changes <- ch })
			}()
			disconnected := faultReceive(t, changes, "failed subscription write ended listening without recovery")
			if disconnected.Kind != ChangeDisconnected || disconnected.Generation != generation {
				t.Fatal("failed subscription write did not invalidate its generation")
			}
			ready := faultReceive(t, changes, "failed subscription write was not retried on a new session")
			if ready.Kind != ChangeReady || ready.Generation <= generation {
				t.Fatal("failed subscription write reused its old generation")
			}
			row := faultReceive(t, changes, "recovered subscription did not receive rows")
			if row.Kind != ChangeRow || row.Generation != ready.Generation || row.Row[".id"] != "*recovered" {
				t.Fatal("recovered subscription delivered the wrong generation")
			}
			if fault.writes.Load() != 1 || fault.bytes.Load() != int32(prefix) || subscriptions.Load() != 1 || p.logins.Load() != 2 {
				t.Fatal("failed subscription send retried its broken socket or duplicated recovery")
			}
			c.Close()
			faultReceive(t, listenDone, "recovered listener did not close")
		})
	}
}

func TestPartialMutationWriteIsUncertainAndNeverReplayed(t *testing.T) {
	var mutations atomic.Int32
	p, cfg := testPeer(t, true, func(conn net.Conn, rd *bufio.Reader) {
		for {
			words, err := readSentence(rd)
			if err != nil {
				return
			}
			if strings.HasSuffix(words[0], "/add") {
				mutations.Add(1)
			}
			peerSend(conn, "!done", tagWord(words))
		}
	})
	cfg.retryDelay = func(int) time.Duration { return time.Millisecond }
	c := connectTest(t, cfg)
	fault, generation := faultInstallWriteFailure(t, c, 12)
	_, err := c.Command(t.Context(), []string{"/ip/firewall/address-list/add", "=comment=tikray:test", "=list=tikray-test", "=address=192.0.2.1"})
	if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, ErrDisconnected) {
		t.Fatal("partial mutation write did not report uncertain outcome")
	}
	if strings.Contains(err.Error(), cfg.Password) {
		t.Fatal("partial write exposed transport error text")
	}
	if _, err := c.Command(t.Context(), readQuery()); err != nil {
		t.Fatal("partial mutation write prevented recovery")
	}
	if fault.writes.Load() != 1 || fault.bytes.Load() != 12 || mutations.Load() != 0 || p.logins.Load() != 2 || c.Generation() <= generation {
		t.Fatal("partial mutation write was replayed or recovery did not replace its session")
	}
}
