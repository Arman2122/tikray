package routeros

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type peer struct {
	logins atomic.Int32
	ln     net.Listener
	mu     sync.Mutex
	conns  []net.Conn
	wg     sync.WaitGroup
}

func testPeer(t *testing.T, authenticated bool, serve func(net.Conn, *bufio.Reader), versions ...string) (*peer, ConnConfig) {
	t.Helper()
	if len(versions) == 0 {
		versions = []string{"7.25"}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("fixture key")
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal("fixture certificate")
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal("fixture listener")
	}
	p := &peer{ln: ln}
	cfg := ConnConfig{Address: ln.Addr().String(), Username: "fixture", Password: "private-fixture-value", Fingerprint: hex.EncodeToString(sha256Sum(der)), CommandTimeout: 3 * time.Second}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			conn, e := ln.Accept()
			if e != nil {
				return
			}
			p.mu.Lock()
			p.conns = append(p.conns, conn)
			p.mu.Unlock()
			p.wg.Add(1)
			go func() {
				defer p.wg.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
				rd := bufio.NewReader(conn)
				login, e := readSentence(rd)
				if e != nil {
					return
				}
				if len(login) == 0 || login[0] != "/login" {
					t.Error("login missing")
					return
				}
				p.logins.Add(1)
				if !authenticated {
					peerSend(conn, "!trap", "=message=private-fixture-value", tagWord(login))
					peerSend(conn, "!done", tagWord(login))
					return
				}
				peerSend(conn, "!done", tagWord(login))
				{
					words, e := readSentence(rd)
					if e != nil {
						return
					}
					if words[0] != "/system/resource/print" {
						t.Error("metadata probe sent a mutation")
						return
					}
					peerSend(conn, "!re", "=version="+versions[0], "=architecture-name=x86_64", "=board-name=CHR", tagWord(words))
					peerSend(conn, "!done", tagWord(words))

				}
				serve(conn, rd)
			}()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		p.mu.Lock()
		for _, c := range p.conns {
			c.Close()
		}
		p.mu.Unlock()
		p.wg.Wait()
	})
	return p, cfg
}

func TestUnknownProfileNeverBecomesWritable(t *testing.T) {
	var calls atomic.Int32
	_, cfg := testPeer(t, true, func(_ net.Conn, r *bufio.Reader) {
		if _, err := readSentence(r); err == nil {
			calls.Add(1)
		}
	}, "7.99")
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	c, err := Dial(ctx, cfg)
	if c != nil {
		c.Close()
	}
	if !errors.Is(err, ErrUnsupported) || calls.Load() != 0 {
		t.Fatal("unsupported profile became usable")
	}
}

func sha256Sum(b []byte) []byte { s := sha256.Sum256(b); return s[:] }
func tagWord(words []string) string {
	for _, w := range words {
		if strings.HasPrefix(w, ".tag=") {
			return w
		}
	}
	return ".tag=missing"
}
func peerSend(c net.Conn, words ...string) {
	b, e := encodeSentence(words)
	if e == nil {
		_, _ = c.Write(b)
	}
}
func readQuery() []string {
	return []string{"/ip/firewall/address-list/print", "?comment=tikray:test", "=.proplist=.id,comment"}
}
func connectTest(t *testing.T, cfg ConnConfig) *Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, e := Dial(ctx, cfg)
	if e != nil {
		t.Fatal("could not connect test peer")
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestClientPinsBeforeLogin(t *testing.T) {
	p, cfg := testPeer(t, true, func(net.Conn, *bufio.Reader) {})
	cfg.Fingerprint = strings.Repeat("00", 32)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := Dial(ctx, cfg)
	if !errors.Is(err, ErrPin) || p.logins.Load() != 0 {
		t.Fatal("bad pin allowed login or wrong error")
	}
	if strings.Contains(fmt.Sprintf("%+v %#v", cfg, cfg), cfg.Password) {
		t.Fatal("config formatting exposed credential")
	}
	data, _ := json.Marshal(cfg)
	if strings.Contains(string(data), cfg.Password) {
		t.Fatal("config JSON exposed credential")
	}
}

func TestListenAndCommandsShareOneLogin(t *testing.T) {
	received := make(chan struct{}, 1)
	p, cfg := testPeer(t, true, func(c net.Conn, r *bufio.Reader) {
		var listening string
		for {
			w, e := readSentence(r)
			if e != nil {
				return
			}
			tag := tagWord(w)
			switch w[0] {
			case "/ip/firewall/address-list/listen":
				listening = tag
				peerSend(c, "!re", "=.id=*7", "=comment=tikray:test", tag)
			case "/cancel":
				if tag == listening || len(w) < 3 || w[1] != "=tag="+strings.TrimPrefix(listening, ".tag=") {
					t.Error("cancel did not target one listener")
					return
				}
				peerSend(c, "!trap", "=category=2", listening)
				peerSend(c, "!done", listening)
				peerSend(c, "!done", tag)
			default:
				peerSend(c, "!empty", tag)
				peerSend(c, "!re", "=.id=*8", tag)
				peerSend(c, "!done", tag)
			}
		}
	})
	c := connectTest(t, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- c.Listen(ctx, []string{"/ip/firewall/address-list/listen", "?comment=tikray:test", "=.proplist=.id,comment"}, func(ch Change) {
			if ch.Kind == ChangeRow && ch.Row[".id"] == "*7" {
				select {
				case received <- struct{}{}:
				default:
				}
			}
		})
	}()
	select {
	case <-received:
	case <-time.After(3 * time.Second):
		t.Fatal("listener received no row")
	}
	rows, e := c.Command(t.Context(), readQuery())
	if e != nil || len(rows) != 1 || rows[0][".id"] != "*8" {
		t.Fatal("command interleaving failed")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("listener cancellation hung")
	}
	if _, e = c.Command(t.Context(), readQuery()); e != nil || p.logins.Load() != 1 {
		t.Fatal("cancelling listener broke shared session")
	}
}

func TestLostAckIsNotReplayed(t *testing.T) {
	var mutations atomic.Int32
	p, cfg := testPeer(t, true, func(c net.Conn, r *bufio.Reader) {
		for {
			w, e := readSentence(r)
			if e != nil {
				return
			}
			if strings.HasSuffix(w[0], "/add") {
				mutations.Add(1)
				return
			}
			peerSend(c, "!done", tagWord(w))
		}
	})
	cfg.retryDelay = func(int) time.Duration { return time.Millisecond }
	c := connectTest(t, cfg)
	_, e := c.Command(t.Context(), []string{"/ip/firewall/address-list/add", "=comment=tikray:test", "=list=tikray-test", "=address=192.0.2.1"})
	if !errors.Is(e, ErrOutcomeUnknown) {
		t.Fatal("lost acknowledgement did not report uncertain outcome")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if _, e = c.Command(ctx, readQuery()); e != nil {
		t.Fatal("reconnect failed")
	}
	if mutations.Load() != 1 || p.logins.Load() != 2 {
		t.Fatal("mutation replayed or reconnect duplicated login")
	}
}

func TestLoginBackoffAndCancel(t *testing.T) {
	p, cfg := testPeer(t, false, func(net.Conn, *bufio.Reader) {})
	var waits atomic.Int32
	cfg.retryDelay = func(int) time.Duration { waits.Add(1); return time.Hour }
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	_, err := Dial(ctx, cfg)
	if !errors.Is(err, context.DeadlineExceeded) || p.logins.Load() != 1 || waits.Load() != 1 {
		t.Fatal("refused login spun or cancellation did not interrupt backoff")
	}
}

func TestClientErrorsArePrivate(t *testing.T) {
	_, cfg := testPeer(t, true, func(c net.Conn, r *bufio.Reader) {
		for {
			w, e := readSentence(r)
			if e != nil {
				return
			}
			peerSend(c, "!trap", "=message=private-fixture-value", tagWord(w))
			peerSend(c, "!done", tagWord(w))
		}
	})
	c := connectTest(t, cfg)
	_, e := c.Command(t.Context(), readQuery())
	if !errors.Is(e, ErrRejected) || strings.Contains(fmt.Sprint(e), cfg.Password) {
		t.Fatal("trap did not return fixed safe error")
	}
}

func TestCommandPreservesAddIDAndRefusesUnscopedReads(t *testing.T) {
	var calls atomic.Int32
	_, cfg := testPeer(t, true, func(c net.Conn, r *bufio.Reader) {
		for {
			w, e := readSentence(r)
			if e != nil {
				return
			}
			calls.Add(1)
			peerSend(c, "!done", "=ret=*9", tagWord(w))
		}
	})
	c := connectTest(t, cfg)
	if _, e := c.Command(t.Context(), []string{"/ip/route/print", "=.proplist=.id"}); !errors.Is(e, ErrRequest) {
		t.Fatal("unfiltered table read accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("unscoped read reached router")
	}
	if _, e := c.Command(t.Context(), []string{"/ip/route/getall", "=.proplist=.id"}); !errors.Is(e, ErrRequest) {
		t.Fatal("unfiltered print alias accepted")
	}
	rows, e := c.Command(t.Context(), []string{"/routing/table/add", "=name=tikray-closed", "=comment=tikray:table-closed"})
	if e != nil || len(rows) != 1 || rows[0]["ret"] != "*9" {
		t.Fatal("lost RouterOS add ID")
	}
}

func TestLargeScopedReplyWithinBudget(t *testing.T) {
	_, cfg := testPeer(t, true, func(c net.Conn, r *bufio.Reader) {
		w, e := readSentence(r)
		if e != nil {
			return
		}
		var batch []byte
		for range 2048 {
			row, _ := encodeSentence([]string{"!re", "=.id=*8", "=comment=tikray:test", tagWord(w)})
			batch = append(batch, row...)
		}
		last, _ := encodeSentence([]string{"!done", tagWord(w)})
		batch = append(batch, last...)
		_, _ = c.Write(batch)
		// Keep the peer up after the complete response.
		_, _ = readSentence(r)
	})
	c := connectTest(t, cfg)
	rows, err := c.Command(t.Context(), readQuery())
	if err != nil || len(rows) != 2048 {
		t.Fatal("a bounded address-list response was lost")
	}
}

func TestClosedClientCannotInstallAnotherSession(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	c := &Client{terminal: ErrClosed, changed: make(chan struct{})}
	s := newSession(left, bufio.NewReader(left))
	if c.install(s) || c.current != nil || c.generation != 0 {
		t.Fatal("closed client accepted a replacement session")
	}
	_ = right.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := right.Read(b[:]); !errors.Is(err, io.EOF) {
		t.Fatal("replacement socket was not closed")
	}
}

func TestListenerLimitCountsBacklogNotLifetime(t *testing.T) {
	left, right := net.Pipe()
	s := newSession(left, bufio.NewReader(left))
	r := &request{tag: "stream", stream: true, notify: make(chan struct{}, 1)}
	s.pending[r.tag] = r
	go s.readLoop()
	t.Cleanup(func() { s.fail(ErrClosed); right.Close(); <-s.stopped })
	done := make(chan struct{})
	ack := make(chan struct{})
	go func() {
		defer close(done)
		for range maxReplyRows + 1 {
			peerSend(right, "!re", "=.id=*7", ".tag=stream")
			select {
			case <-ack:
			case <-s.done:
				return
			}
		}
	}()
	for range maxReplyRows + 1 {
		select {
		case <-r.notify:
			m, ok := s.take(r)
			if !ok {
				t.Fatal("missing streamed row")
			}
			s.release(r, m.weight)
			select {
			case ack <- struct{}{}:
			case <-s.done:
				t.Fatal("stream killed despite drained backlog")
			}
		case <-s.done:
			t.Fatal("stream lifetime incorrectly counted as retained response")
		case <-time.After(3 * time.Second):
			t.Fatal("stream fixture stalled")
		}
	}
	<-done
}

func TestStaleGenerationCannotMutateReplacementSession(t *testing.T) {
	var reads, writes atomic.Int32
	_, cfg := testPeer(t, true, func(c net.Conn, r *bufio.Reader) {
		for {
			w, e := readSentence(r)
			if e != nil {
				return
			}
			if strings.HasSuffix(w[0], "/add") {
				writes.Add(1)
			}
			if reads.Add(1) == 1 {
				return
			}
			peerSend(c, "!done", tagWord(w))
		}
	})
	cfg.retryDelay = func(int) time.Duration { return time.Millisecond }
	client := connectTest(t, cfg)
	generation := client.Generation()
	_, _ = client.Command(t.Context(), readQuery())
	if _, err := client.Command(t.Context(), readQuery()); err != nil {
		t.Fatal("replacement session did not become ready")
	}
	_, err := client.CommandAt(t.Context(), generation, []string{"/routing/table/add", "=name=tikray-stale", "=comment=tikray:stale"})
	if !errors.Is(err, ErrStaleGeneration) || writes.Load() != 0 {
		t.Fatal("stale plan reached replacement session")
	}
}
