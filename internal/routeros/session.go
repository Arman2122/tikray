package routeros

import (
	"bufio"
	"context"
	"github.com/Arman2122/tikray/internal/routeros/adapters"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxBufferedBytes = 8 << 20
const maxReplyRows = 32768

type message struct {
	kind   string
	row    Row
	weight int
}
type request struct {
	tag        string
	queue      []message
	notify     chan struct{}
	stream     bool
	used, rows int  // protected by session.mu
	sent       bool // assigned before open returns
}
type session struct {
	profile       adapters.Profile
	conn          net.Conn
	reader        *bufio.Reader
	generation    uint64
	done, stopped chan struct{}
	once          sync.Once
	err           error // published by closing done
	writer        chan struct{}
	mu            sync.Mutex
	next          uint64
	pending       map[string]*request
	buffered      int
}

func newSession(conn net.Conn, r *bufio.Reader) *session {
	return &session{conn: conn, reader: r, done: make(chan struct{}), stopped: make(chan struct{}), writer: make(chan struct{}, 1), pending: make(map[string]*request)}
}
func (s *session) fail(err error) { s.once.Do(func() { s.err = err; close(s.done); s.conn.Close() }) }
func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, e := w.Write(data)
		if n < 0 || n > len(data) {
			return ErrProtocol
		}
		data = data[n:]
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
func (s *session) open(ctx context.Context, words []string) (*request, error) {
	// Reserve tag capacity separately from callbacks and user response data.
	s.mu.Lock()
	if len(s.pending) >= 32 {
		s.mu.Unlock()
		return nil, ErrLimit
	}
	s.next++
	r := &request{tag: strconv.FormatUint(s.next, 10), notify: make(chan struct{}, 1), stream: strings.HasSuffix(words[0], "/listen")}
	tagged := append(append([]string(nil), words...), ".tag="+r.tag)
	data, e := encodeSentence(tagged)
	if e != nil {
		s.mu.Unlock()
		return nil, e
	}
	select {
	case <-s.done:
		s.mu.Unlock()
		return nil, s.err
	default:
	}
	s.pending[r.tag] = r
	s.mu.Unlock()
	select {
	case s.writer <- struct{}{}:
	case <-ctx.Done():
		return r, contextError(ctx)
	case <-s.done:
		return r, s.err
	}
	defer func() { <-s.writer }()
	if ctx.Err() != nil {
		return r, contextError(ctx)
	}
	deadline := time.Now().Add(10 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if s.conn.SetWriteDeadline(deadline) != nil {
		s.fail(ErrDisconnected)
		return r, ErrDisconnected
	}
	// Interrupt a blocked write without closing a fully delivered frame.
	// Join the callback before clearing its deadline or releasing the writer.
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		if s.conn.SetWriteDeadline(time.Now()) != nil {
			s.fail(ErrDisconnected)
		}
		close(interrupted)
	})
	r.sent = true
	e = writeAll(s.conn, data)
	if !stop() {
		<-interrupted
	}
	// A failed Write on TLS may have sent part of a record even when it
	// reports zero plaintext bytes. Retire the connection on any such error.
	if e != nil || s.conn.SetWriteDeadline(time.Time{}) != nil {
		s.fail(ErrDisconnected)
		return r, ErrDisconnected
	}
	return r, nil
}
func (s *session) remove(r *request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending[r.tag] != r {
		return
	}
	delete(s.pending, r.tag)
	s.buffered -= r.used
	r.used = 0
}
func (s *session) take(r *request) (message, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(r.queue) == 0 {
		return message{}, false
	}
	m := r.queue[0]
	r.queue[0] = message{}
	r.queue = r.queue[1:]
	if len(r.queue) > 0 {
		select {
		case r.notify <- struct{}{}:
		default:
		}
	}
	return m, true
}
func (s *session) release(r *request, weight int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending[r.tag] == r {
		s.buffered -= weight
		r.used -= weight
	}
}
func parseMessage(words []string) (string, message, error) {
	m := message{kind: words[0], row: make(Row)}
	switch m.kind {
	case "!re", "!done", "!trap", "!empty", "!fatal":
	default:
		return "", m, ErrProtocol
	}
	tag := ""
	for _, w := range words[1:] {
		m.weight += len(w) + 64
		if strings.HasPrefix(w, ".tag=") {
			if tag != "" || len(w) == 5 {
				return "", m, ErrProtocol
			}
			tag = w[5:]
			continue
		}
		if !strings.HasPrefix(w, "=") {
			return "", m, ErrProtocol
		}
		key, value, ok := strings.Cut(w[1:], "=")
		if !ok || key == "" {
			return "", m, ErrProtocol
		}
		if _, duplicate := m.row[key]; duplicate {
			return "", m, ErrProtocol
		}
		m.row[key] = value
	}
	if m.kind == "!trap" || m.kind == "!fatal" {
		m.row = nil
	}
	m.weight += 128
	if m.kind != "!fatal" && tag == "" {
		return "", m, ErrProtocol
	}
	return tag, m, nil
}
func (s *session) readLoop() {
	defer close(s.stopped)
	empty := 0
	for {
		words, e := readSentence(s.reader)
		if e != nil {
			s.fail(safeReadError(e))
			return
		}
		if len(words) == 0 {
			empty++
			if empty > 32 {
				s.fail(ErrProtocol)
				return
			}
			continue
		}
		empty = 0
		tag, m, e := parseMessage(words)
		if e != nil {
			s.fail(e)
			return
		}
		if m.kind == "!fatal" {
			s.fail(ErrDisconnected)
			return
		}
		if m.kind == "!empty" {
			continue
		}
		s.mu.Lock()
		r := s.pending[tag]
		if r == nil {
			s.mu.Unlock()
			continue
		}
		if m.kind == "!re" && !r.stream {
			r.rows++
		}
		// Streamed listeners release bytes as they consume. A command retains
		// its total until return, so concurrent accumulated replies are bounded.
		if s.buffered+m.weight > maxBufferedBytes || r.rows > maxReplyRows {
			s.mu.Unlock()
			s.fail(ErrLimit)
			return
		}
		r.used += m.weight
		s.buffered += m.weight
		if r.stream && len(r.queue) >= 32 {
			s.mu.Unlock()
			s.fail(ErrLimit)
			return
		}
		r.queue = append(r.queue, m)
		select {
		case r.notify <- struct{}{}:
		default:
		}
		s.mu.Unlock()
	}
}

// Both acknowledgements must drain. Otherwise a stale stream could fill a
// pending slot indefinitely, so retire the session and let scoped reads heal.
func (s *session) cancelRequest(target *request) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	control, e := s.open(ctx, []string{"/cancel", "=tag=" + target.tag})
	if control != nil {
		defer s.remove(control)
	}
	if e != nil {
		s.fail(ErrDisconnected)
		return
	}
	targetDone, controlDone := false, false
	for !targetDone || !controlDone {
		select {
		case <-s.done:
			return
		case <-ctx.Done():
			s.fail(ErrDisconnected)
			return
		case <-target.notify:
			m, ok := s.take(target)
			if !ok {
				continue
			}
			if m.kind == "!done" {
				targetDone = true
			}
		case <-control.notify:
			m, ok := s.take(control)
			if !ok {
				continue
			}
			if m.kind == "!done" {
				controlDone = true
			}
			if m.kind == "!trap" {
				s.fail(ErrDisconnected)
				return
			}
		}
	}
}
