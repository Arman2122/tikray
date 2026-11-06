// Package routeros talks to the router over one pinned native API-SSL session.
// Commands are never replayed: after an uncertain mutation the caller must
// read its scoped state again before deciding what to change.
package routeros

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Arman2122/tikray/internal/routeros/adapters"
)

var (
	ErrStaleGeneration = errors.New("routeros: connection changed; read scoped state before writing")
	ErrUnsupported     = errors.New("routeros: unsupported router profile")
	ErrProtocol        = errors.New("routeros: invalid protocol")
	ErrLimit           = errors.New("routeros: response or resource limit")
	ErrPin             = errors.New("routeros: certificate pin mismatch")
	ErrRequest         = errors.New("routeros: invalid or unscoped request")
	ErrAuth            = errors.New("routeros: login refused")
	ErrClosed          = errors.New("routeros: client closed")
	ErrDisconnected    = errors.New("routeros: connection lost")
	ErrRejected        = errors.New("routeros: command refused")
	ErrOutcomeUnknown  = errors.New("routeros: mutation outcome unknown; read scoped state before retrying")
)

// ConnConfig is private installation data. Formatting and marshaling it
// intentionally provide no connection details.
type ConnConfig struct {
	Address, Username, Password, Fingerprint string
	DialTimeout, CommandTimeout              time.Duration
	retryDelay                               func(int) time.Duration // deterministic backoff in tests
}

func (ConnConfig) String() string               { return "routeros: private connection configuration" }
func (c ConnConfig) GoString() string           { return c.String() }
func (ConnConfig) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }

type Row map[string]string
type ChangeKind string

const (
	ChangeReady        ChangeKind = "ready"
	ChangeDisconnected ChangeKind = "disconnected"
	ChangeRow          ChangeKind = "row"
)

// Ready marks a new session. Before acting on observations from it the
// reconciler must repeat its router-filtered snapshot. A Row can be a
// tombstone (.dead=yes) with only the router's ID.
type Change struct {
	Kind       ChangeKind
	Generation uint64
	Row        Row
}

type Client struct {
	cfg        ConnConfig
	pin        [32]byte
	ctx        context.Context
	stop       context.CancelFunc
	finished   chan struct{}
	slots      chan struct{}
	mu         sync.Mutex
	current    *session
	generation uint64
	changed    chan struct{}
	terminal   error
}

func (*Client) String() string     { return "routeros: private client" }
func (c *Client) GoString() string { return c.String() }

// Dial waits for the first authenticated session. Failed logins use the same
// bounded backoff as reconnections. ctx controls initial dialing only; Close
// ends the successfully opened client's lifetime.
func Dial(ctx context.Context, cfg ConnConfig) (*Client, error) {
	if cfg.Username == "" || cfg.Password == "" || len(cfg.Username) > 256 || len(cfg.Password) > 4096 {
		return nil, ErrRequest
	}
	if _, _, err := net.SplitHostPort(cfg.Address); err != nil {
		return nil, ErrRequest
	}
	pin, err := hex.DecodeString(strings.ReplaceAll(cfg.Fingerprint, ":", ""))
	if err != nil || len(pin) != 32 {
		return nil, ErrPin
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if cfg.CommandTimeout <= 0 {
		cfg.CommandTimeout = 30 * time.Second
	}
	life, stop := context.WithCancel(context.Background())
	c := &Client{cfg: cfg, ctx: life, stop: stop, finished: make(chan struct{}), slots: make(chan struct{}, 16), changed: make(chan struct{})}
	copy(c.pin[:], pin)
	for attempt := 0; ; attempt++ {
		s, e := c.connect(ctx)
		if e == nil {
			c.install(s)
			go c.supervise(s)
			return c, nil
		}
		if errors.Is(e, ErrUnsupported) || errors.Is(e, ErrPin) || errors.Is(e, ErrProtocol) || errors.Is(e, ErrLimit) {
			stop()
			return nil, e
		}
		if e = c.waitRetry(ctx, attempt); e != nil {
			stop()
			return nil, e
		}
	}
}

func (c *Client) connect(ctx context.Context) (*session, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.DialTimeout)
	defer cancel()
	pinFailed := false
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12,
		// The installer authenticates this exact leaf. A local self-signed
		// certificate need not have public DNS names or a public CA.
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				pinFailed = true
				return ErrPin
			}
			sum := sha256.Sum256(state.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(sum[:], c.pin[:]) != 1 {
				pinFailed = true
				return ErrPin
			}
			return nil
		},
	}
	conn, e := (&tls.Dialer{NetDialer: &net.Dialer{}, Config: tlsCfg}).DialContext(ctx, "tcp", c.cfg.Address)
	if e != nil {
		if pinFailed {
			return nil, ErrPin
		}
		return nil, ErrDisconnected
	}
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()
	// This is the only synchronous phase, before the multiplexed reader exists.
	dl, _ := ctx.Deadline()
	_ = conn.SetDeadline(dl)
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	data, e := encodeSentence([]string{"/login", "=name=" + c.cfg.Username, "=password=" + c.cfg.Password, ".tag=login"})
	if e != nil {
		return nil, e
	}
	if e = writeAll(conn, data); e != nil {
		return nil, ErrDisconnected
	}
	reader := bufio.NewReader(conn)
	rejected := false
	for range 32 {
		words, e := readSentence(reader)
		if e != nil {
			return nil, safeReadError(e)
		}
		if len(words) == 0 {
			continue
		}
		switch words[0] {
		case "!trap":
			rejected = true
		case "!empty":
		case "!done":
			// The supported v7 versions use the password login. Never answer
			// a peer-supplied legacy challenge.
			for _, w := range words[1:] {
				if strings.HasPrefix(w, "=ret=") {
					return nil, ErrAuth
				}
			}
			if rejected {
				return nil, ErrAuth
			}
			profile, e := detectProfile(conn, reader)
			if e != nil {
				return nil, e
			}
			if !stop() {
				return nil, ErrDisconnected
			}
			_ = conn.SetDeadline(time.Time{})
			ok = true
			s := newSession(conn, reader)
			s.profile = profile
			return s, nil
		case "!fatal":
			return nil, ErrAuth
		default:
			return nil, ErrProtocol
		}
	}
	return nil, ErrLimit
}
func safeReadError(e error) error {
	if errors.Is(e, ErrProtocol) || errors.Is(e, ErrLimit) {
		return e
	}
	return ErrDisconnected
}
func contextError(ctx context.Context) error {
	return fmt.Errorf("routeros: request ended: %w", ctx.Err())
}
func (c *Client) waitRetry(ctx context.Context, attempt int) error {
	d := time.Second * time.Duration(1<<min(attempt, 8))
	d = min(5*time.Minute, d+time.Duration(rand.Int64N(int64(d/4)+1)))
	if c.cfg.retryDelay != nil {
		d = c.cfg.retryDelay(attempt)
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return contextError(ctx)
	case <-timer.C:
		return nil
	}
}
func (c *Client) install(s *session) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.terminal != nil {
		s.conn.Close()
		return false
	}
	c.generation++
	s.generation = c.generation
	c.current = s
	close(c.changed)
	c.changed = make(chan struct{})
	go s.readLoop()
	return true
}
func (c *Client) supervise(s *session) {
	defer close(c.finished)
	for {
		<-s.done
		<-s.stopped
		c.mu.Lock()
		if c.terminal != nil {
			c.mu.Unlock()
			return
		}
		c.current = nil
		close(c.changed)
		c.changed = make(chan struct{})
		c.mu.Unlock()
		for attempt := 0; ; attempt++ {
			if c.waitRetry(c.ctx, attempt) != nil {
				return
			}
			next, err := c.connect(c.ctx)
			if err == nil {
				c.mu.Lock()
				closed := c.terminal != nil
				c.mu.Unlock()
				if closed {
					next.conn.Close()
					return
				}
				if !c.install(next) {
					return
				}
				s = next
				break
			}
			if errors.Is(err, ErrPin) || errors.Is(err, ErrUnsupported) {
				c.mu.Lock()
				c.terminal = err
				close(c.changed)
				c.changed = make(chan struct{})
				c.mu.Unlock()
				c.stop()
				return
			}
		}
	}
}
func (c *Client) ready(ctx context.Context) (*session, error) {
	for {
		c.mu.Lock()
		s, changed, err := c.current, c.changed, c.terminal
		c.mu.Unlock()
		if err != nil {
			return nil, err
		}
		if s != nil {
			select {
			case <-s.done:
			default:
				return s, nil
			}
		}
		select {
		case <-ctx.Done():
			return nil, contextError(ctx)
		case <-changed:
		case <-c.ctx.Done():
			return nil, ErrClosed
		}
	}
}

// Generation returns a token for CommandAt, which binds a plan to the session
// it observed. It returns zero while disconnected.
func (c *Client) Generation() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current == nil {
		return 0
	}
	select {
	case <-c.current.done:
		return 0
	default:
		return c.current.generation
	}
}
func (c *Client) Profile() adapters.Profile {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current == nil {
		return adapters.Profile{}
	}
	select {
	case <-c.current.done:
		return adapters.Profile{}
	default:
		return c.current.profile
	}
}
func (c *Client) Close() error {
	c.mu.Lock()
	if c.terminal == nil {
		c.terminal = ErrClosed
		close(c.changed)
		c.changed = make(chan struct{})
	}
	s := c.current
	c.mu.Unlock()
	c.stop()
	if s != nil {
		s.fail(ErrClosed)
	}
	<-c.finished
	return nil
}

// validateRequest rejects hidden tags and full table reads before any bytes
// leave the client. Domain-specific query predicates belong to the reconciler.
func validateRequest(words []string, listen bool) error {
	if len(words) == 0 || !strings.HasPrefix(words[0], "/") || strings.ContainsAny(words[0], " \r\n\x00") {
		return ErrRequest
	}
	op := words[0]
	if op == "/login" || op == "/cancel" || strings.HasSuffix(op, "/listen") != listen {
		return ErrRequest
	}
	scoped, projected := false, false
	for _, w := range words[1:] {
		if strings.HasPrefix(w, "?") {
			scoped = true
		} else if strings.HasPrefix(w, "=.proplist=") && len(w) > len("=.proplist=") {
			projected = true
		} else if !strings.HasPrefix(w, "=") || strings.HasPrefix(w, "=.tag=") {
			return ErrRequest
		}
	}
	if listen || strings.HasSuffix(op, "/print") || strings.HasSuffix(op, "/getall") {
		// The system resource is a singleton used for version detection.
		if !projected || (!scoped && op != "/system/resource/print") {
			return ErrRequest
		}
	}
	return nil
}
func isRead(words []string) bool {
	return strings.HasSuffix(words[0], "/print") || strings.HasSuffix(words[0], "/getall") || strings.HasSuffix(words[0], "/get")
}
func (c *Client) acquire(ctx context.Context) error {
	select {
	case c.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return contextError(ctx)
	case <-c.ctx.Done():
		return ErrClosed
	}
}

// Command returns !re rows and, when present, the final !done properties
// (for example ret, the ID of an added object) as a last row. It never retries.
func (c *Client) Command(ctx context.Context, words []string) ([]Row, error) {
	return c.command(ctx, 0, words)
}

// CommandAt refuses to send on another generation. If this session fails
// during the write, the normal uncertain-outcome rules apply.
func (c *Client) CommandAt(ctx context.Context, generation uint64, words []string) ([]Row, error) {
	if generation == 0 {
		return nil, ErrStaleGeneration
	}
	return c.command(ctx, generation, words)
}
func (c *Client) command(ctx context.Context, generation uint64, words []string) ([]Row, error) {
	words = append([]string(nil), words...)
	if e := validateRequest(words, false); e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(ctx, c.cfg.CommandTimeout)
	defer cancel()
	if e := c.acquire(ctx); e != nil {
		return nil, e
	}
	defer func() { <-c.slots }()
	s, e := c.ready(ctx)
	if e != nil {
		return nil, e
	}
	if generation != 0 && s.generation != generation {
		return nil, ErrStaleGeneration
	}
	r, e := s.open(ctx, words)
	if r != nil {
		defer s.remove(r)
	}
	uncertain := func(e error) error {
		if r != nil && r.sent && !isRead(words) {
			return errors.Join(ErrOutcomeUnknown, e)
		}
		return e
	}
	if e != nil {
		return nil, uncertain(e)
	}
	var rows []Row
	rejected := false
	for {
		select {
		case <-ctx.Done():
			s.cancelRequest(r)
			return nil, uncertain(contextError(ctx))
		case <-s.done:
			return nil, uncertain(s.err)
		case <-r.notify:
			m, ok := s.take(r)
			if !ok {
				continue
			}
			switch m.kind {
			case "!re":
				rows = append(rows, m.row)
			case "!trap":
				rejected = true
			case "!done":
				if rejected {
					return nil, ErrRejected
				}
				if len(m.row) > 0 {
					rows = append(rows, m.row)
				}
				return rows, nil
			}
		}
	}
}

// Listen reinstalls its filtered subscription after reconnect and reports
// Ready before delivering that generation's rows. notify runs in this caller,
// outside reader locks, and should return promptly. Close never waits on it.
func (c *Client) Listen(ctx context.Context, words []string, notify func(Change)) error {
	words = append([]string(nil), words...)
	if notify == nil {
		return ErrRequest
	}
	if e := validateRequest(words, true); e != nil {
		return e
	}
	if e := c.acquire(ctx); e != nil {
		return e
	}
	defer func() { <-c.slots }()
	for {
		s, e := c.ready(ctx)
		if e != nil {
			return e
		}
		r, e := s.open(ctx, words)
		if e != nil {
			if r != nil {
				s.remove(r)
			}
			if ctx.Err() != nil {
				return contextError(ctx)
			}
			if errors.Is(e, ErrProtocol) || errors.Is(e, ErrLimit) || errors.Is(e, ErrRequest) {
				return e
			}
			s.fail(ErrDisconnected)
			notify(Change{Kind: ChangeDisconnected, Generation: s.generation})
			continue
		}
		notify(Change{Kind: ChangeReady, Generation: s.generation})
		e = c.listenSession(ctx, s, r, notify)
		s.remove(r)
		if e == nil || errors.Is(e, ErrRejected) || ctx.Err() != nil {
			return e
		}
		notify(Change{Kind: ChangeDisconnected, Generation: s.generation})
	}
}
func (c *Client) listenSession(ctx context.Context, s *session, r *request, notify func(Change)) error {
	rejected := false
	for {
		select {
		case <-s.done:
			return s.err
		default:
		}
		select {
		case <-ctx.Done():
			s.cancelRequest(r)
			return contextError(ctx)
		case <-s.done:
			return s.err
		case <-r.notify:
			m, ok := s.take(r)
			if !ok {
				continue
			}
			s.release(r, m.weight)
			select {
			case <-s.done:
				return s.err
			default:
			}
			switch m.kind {
			case "!re":
				notify(Change{Kind: ChangeRow, Generation: s.generation, Row: m.row})
			case "!trap":
				rejected = true
			case "!done":
				if rejected {
					return ErrRejected
				}
				s.fail(ErrDisconnected)
				return ErrDisconnected
			}
		}
	}
}
