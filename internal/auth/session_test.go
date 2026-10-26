package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// clock is the fake clock of the tests: the store and the limiter read it
// through Now, and the test moves it.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock {
	return &clock{t: time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)}
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func (c *clock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// newSessionT starts a session as SignIn does after its password check, with
// no hash: the tests that need many sessions would otherwise spend a second
// of argon2 on each ten.
func newSessionT(t *testing.T, s *Store) Session {
	t.Helper()
	sess, err := startSession(s)
	if err != nil {
		t.Fatalf("starting a session: %v", err)
	}
	return sess
}

// startSession is newSessionT for a goroutine that is not the test's.
func startSession(s *Store) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.startSessionLocked(s.clock())
}

// sessionCount is the number of sessions the store holds.
func sessionCount(s *Store) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.d.Sessions)
}

// fileView is the part of auth.json the tests read back, through its own
// types and not the store's.
type fileView struct {
	Tokens []struct {
		ID       string    `json:"id"`
		Name     string    `json:"name"`
		Hash     string    `json:"hash"`
		Created  time.Time `json:"created"`
		Expires  time.Time `json:"expires"`
		LastUsed time.Time `json:"last_used"`
	} `json:"tokens"`
	Sessions []struct {
		Hash     string    `json:"hash"`
		Created  time.Time `json:"created"`
		LastUsed time.Time `json:"last_used"`
	} `json:"sessions"`
}

func readView(t *testing.T, dir string) fileView {
	t.Helper()
	var v fileView
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(dir, "auth.json"))), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// sha256Hex is the hash of a session id or of the secret part of a token, as
// auth.json holds it.
func sumHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

var sessionIDForm = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

func TestSignInSameAnswerAndTime(t *testing.T) {
	ctx := context.Background()
	s, dir := openTest(t)

	// The argon2 runs are counted through the hook, not timed.
	var runs atomic.Int32
	argonHook = func() { runs.Add(1) }
	t.Cleanup(func() { argonHook = nil })

	// With no admin yet, a sign-in is a wrong pair like any other, and costs
	// a check like any other.
	runs.Store(0)
	if _, err := s.SignIn(ctx, "alice", testPassword); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("a sign-in with no admin: %v, want ErrBadCredentials", err)
	}
	if n := runs.Load(); n != 1 {
		t.Errorf("a sign-in with no admin ran argon2 %d times, want 1", n)
	}

	claim(t, s, dir, "alice", testPassword)

	pairs := map[string][2]string{
		"wrong username": {"mallory", testPassword},
		"wrong password": {"alice", testPassword + "x"},
		"both wrong":     {"mallory", "not the password"},
		"the right password, a name that is another case": {"Alice", testPassword},
		"a name with the admin's as its prefix":           {"alice2", testPassword},
		"an empty pair":                                   {"", ""},
		"an empty password":                               {"alice", ""},
		"a long name":                                     {strings.Repeat("a", 5000), testPassword},
		"a long password":                                 {"alice", strings.Repeat("p", 5000)},
	}
	var first error
	for name, p := range pairs {
		runs.Store(0)
		sess, err := s.SignIn(ctx, p[0], p[1])
		if !errors.Is(err, ErrBadCredentials) {
			t.Errorf("%s: SignIn = %v, want ErrBadCredentials", name, err)
			continue
		}
		if sess != (Session{}) {
			t.Errorf("%s: SignIn gave a session with its error", name)
		}
		if n := runs.Load(); n != 1 {
			t.Errorf("%s: SignIn ran argon2 %d times, want 1", name, n)
		}
		// The same answer: the same error, the same words.
		if first == nil {
			first = err
		} else if err != first || err.Error() != first.Error() {
			t.Errorf("%s: the answer differs from the others", name)
		}
		noSecrets(t, name, err, p[0], p[1], testPassword)
	}

	// The right pair is one check too, and gets a session.
	runs.Store(0)
	sess, err := s.SignIn(ctx, "alice", testPassword)
	if err != nil {
		t.Fatalf("the right pair: %v", err)
	}
	if n := runs.Load(); n != 1 {
		t.Errorf("the right pair ran argon2 %d times, want 1", n)
	}
	if !sessionIDForm.MatchString(sess.ID) {
		t.Errorf("the session id is not 43 base64url characters (%d long)", len(sess.ID))
	}
	if raw, err := base64.RawURLEncoding.DecodeString(sess.ID); err != nil || len(raw) != 32 {
		t.Errorf("the session id is not 32 bytes in base64url (%d bytes, %v)", len(raw), err)
	}
	if sess.CSRF == "" || sess.CSRF == sess.ID {
		t.Error("the session has no CSRF token of its own")
	}
	if got, ok := s.Session(sess.ID); !ok || got.CSRF != sess.CSRF {
		t.Error("the session that SignIn made is not found with its CSRF token")
	}
}

func TestSignInRefusesTheDummyHashPassword(t *testing.T) {
	// The password the dummy hash was made from is in the source history, so
	// what decides is the name: a name that is not the admin's never signs in,
	// even with a password that matches the dummy hash.
	ctx := context.Background()
	s, dir := openTest(t)
	claim(t, s, dir, "alice", testPassword)

	const dummyPassword = "the password of the dummy hash"
	made, err := HashPassword(ctx, dummyPassword)
	if err != nil {
		t.Fatal(err)
	}
	old := DummyHash
	DummyHash = made
	t.Cleanup(func() { DummyHash = old })

	var runs atomic.Int32
	argonHook = func() { runs.Add(1) }
	t.Cleanup(func() { argonHook = nil })

	for _, name := range []string{"mallory", "", "Alice"} {
		runs.Store(0)
		sess, err := s.SignIn(ctx, name, dummyPassword)
		if !errors.Is(err, ErrBadCredentials) || sess != (Session{}) {
			t.Errorf("SignIn(%q, the dummy's password) = (%v), want ErrBadCredentials", name, err)
		}
		if n := runs.Load(); n != 1 {
			t.Errorf("SignIn(%q, ...) ran argon2 %d times, want 1", name, n)
		}
	}
	if n := sessionCount(s); n != 0 {
		t.Errorf("%d sessions were made for names that are not the admin's", n)
	}
	// And the same with no admin at all.
	s2, _ := openTest(t)
	if _, err := s2.SignIn(ctx, "alice", dummyPassword); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("a sign-in with no admin and the dummy's password: %v, want ErrBadCredentials", err)
	}
}

func TestSignInGivesUpWithItsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s, dir := openTest(t)
	claim(t, s, dir, "alice", testPassword)
	for _, name := range []string{"alice", "mallory"} {
		_, err := s.SignIn(ctx, name, testPassword)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("SignIn(%q) with a cancelled context: %v, want context.Canceled", name, err)
		}
		if errors.Is(err, ErrBadCredentials) {
			t.Errorf("SignIn(%q): a context that ended was told as a wrong pair", name)
		}
	}
	if n := sessionCount(s); n != 0 {
		t.Error("a sign-in that gave up made a session")
	}
}

func TestSignInDoesNotOutliveAPasswordChange(t *testing.T) {
	// A sign-in that is waiting in its hash while the password is changed was
	// checked against the old one: it must not make a session.
	ctx := context.Background()
	s, dir := openTest(t)
	claim(t, s, dir, "alice", testPassword)

	entered := make(chan struct{})
	release := make(chan struct{})
	var once, openOnce sync.Once
	open := func() { openOnce.Do(func() { close(release) }) }
	argonHook = func() {
		first := false
		once.Do(func() { first = true })
		if first {
			close(entered)
			<-release
		}
	}
	t.Cleanup(func() { open(); argonHook = nil })

	done := make(chan error, 1)
	go func() {
		_, err := s.SignIn(ctx, "alice", testPassword)
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the sign-in did not reach its hash")
	}
	if err := s.ChangePassword(ctx, "", testPassword, "a new password for alice"); err != nil {
		t.Fatal(err)
	}
	open()
	select {
	case err := <-done:
		if !errors.Is(err, ErrBadCredentials) {
			t.Errorf("a sign-in with the old password, finished after the change: %v, want ErrBadCredentials", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the sign-in did not finish")
	}
	if n := sessionCount(s); n != 0 {
		t.Errorf("%d sessions after a sign-in with the old password", n)
	}
}

func TestSessionLimits(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) (*Store, string, *clock) {
		s, dir := openTest(t)
		clk := newClock()
		s.now = clk.Now
		return s, dir, clk
	}

	t.Run("idle", func(t *testing.T) {
		s, dir, clk := setup(t)
		claim(t, s, dir, "alice", testPassword)
		sess, err := s.SignIn(ctx, "alice", testPassword)
		if err != nil {
			t.Fatal(err)
		}
		t0 := clk.Now()
		if !sess.Expires.Equal(t0.Add(12 * time.Hour)) {
			t.Errorf("a new session expires at %v, want 12 h after its start", sess.Expires)
		}

		// Each use slides the idle limit, so a session in use outlives 12 h.
		for i := range 3 {
			clk.Advance(12*time.Hour - time.Minute)
			got, ok := s.Session(sess.ID)
			if !ok {
				t.Fatalf("use %d: the session ended while it was in use", i)
			}
			if !got.Expires.Equal(clk.Now().Add(12 * time.Hour)) {
				t.Errorf("use %d: expires at %v, want 12 h after this use", i, got.Expires)
			}
			if got.ID != sess.ID || got.CSRF != sess.CSRF {
				t.Errorf("use %d: the session has another id or CSRF token", i)
			}
		}

		// Another session, left alone: valid a nanosecond short of 12 h, not
		// at 12 h.
		other := newSessionT(t, s)
		clk.Advance(12*time.Hour - time.Nanosecond)
		if _, ok := s.Session(other.ID); !ok {
			t.Error("a session idle for 12 h less a nanosecond has ended")
		}
		again := newSessionT(t, s)
		clk.Advance(12 * time.Hour)
		if _, ok := s.Session(again.ID); ok {
			t.Error("a session idle for 12 h is still valid")
		}
		// Once ended, ended: moving the clock back does not bring it back.
		clk.Advance(-12 * time.Hour)
		if _, ok := s.Session(again.ID); ok {
			t.Error("a session that ended came back")
		}
	})

	t.Run("absolute", func(t *testing.T) {
		s, dir, clk := setup(t)
		claim(t, s, dir, "alice", testPassword)
		sess, err := s.SignIn(ctx, "alice", testPassword)
		if err != nil {
			t.Fatal(err)
		}
		t0 := clk.Now()
		end := t0.Add(7 * 24 * time.Hour)
		// In use every 11 h, the session still ends 7 days after it started.
		for clk.Now().Add(11 * time.Hour).Before(end.Add(-time.Second)) {
			clk.Advance(11 * time.Hour)
			if _, ok := s.Session(sess.ID); !ok {
				t.Fatalf("the session ended %v after its start, before 7 days", clk.Now().Sub(t0))
			}
		}
		clk.Set(end.Add(-time.Second))
		got, ok := s.Session(sess.ID)
		if !ok {
			t.Fatal("the session ended a second before 7 days")
		}
		if !got.Expires.Equal(end) {
			t.Errorf("near the end the session expires at %v, want %v (the 7 day limit)", got.Expires, end)
		}
		clk.Advance(time.Second)
		if _, ok := s.Session(sess.ID); ok {
			t.Error("the session is valid 7 days after its start, though it was used a second before")
		}
	})

	t.Run("cap", func(t *testing.T) {
		s, dir, clk := setup(t)
		var ids []string
		for range 21 {
			clk.Advance(time.Minute)
			ids = append(ids, newSessionT(t, s).ID)
		}
		if n := sessionCount(s); n != 20 {
			t.Errorf("%d sessions are kept, want at most 20", n)
		}
		if _, ok := s.Session(ids[0]); ok {
			t.Error("the oldest session survived the 21st")
		}
		for i, id := range ids[1:] {
			if _, ok := s.Session(id); !ok {
				t.Errorf("session %d (not the oldest) was dropped", i+1)
			}
		}
		if n := len(readView(t, dir).Sessions); n != 20 {
			t.Errorf("auth.json holds %d sessions, want 20", n)
		}

		// It is the oldest to start that goes, not the one used least
		// recently: the second one is in use all along.
		clk.Advance(time.Minute)
		newSessionT(t, s)
		if _, ok := s.Session(ids[1]); ok {
			t.Error("the oldest session left was kept because it was in use")
		}
	})

	t.Run("sign-out", func(t *testing.T) {
		s, dir, _ := setup(t)
		a, b := newSessionT(t, s), newSessionT(t, s)
		s.SignOut(a.ID)
		if _, ok := s.Session(a.ID); ok {
			t.Error("a session is valid after SignOut")
		}
		if _, ok := s.Session(b.ID); !ok {
			t.Error("SignOut ended another session")
		}
		if n := len(readView(t, dir).Sessions); n != 1 {
			t.Errorf("auth.json holds %d sessions after a sign-out, want 1", n)
		}
		// Signing out what isn't there, or twice, does nothing.
		before := readFile(t, filepath.Join(dir, "auth.json"))
		s.SignOut(a.ID)
		s.SignOut("")
		s.SignOut("not a session")
		if _, ok := s.Session(b.ID); !ok || readFile(t, filepath.Join(dir, "auth.json")) != before {
			t.Error("a sign-out of nothing changed the state")
		}
		// It outlives the process.
		s2, err := OpenStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := s2.Session(a.ID); ok {
			t.Error("a signed-out session came back after a restart")
		}
	})

	t.Run("sign-out holds when the file can't be written", func(t *testing.T) {
		// A sign-out that can't be saved still ends the session here.
		s, dir, _ := setup(t)
		a := newSessionT(t, s)
		breakAuthFile(t, dir)
		s.SignOut(a.ID)
		if _, ok := s.Session(a.ID); ok {
			t.Error("a session is valid after a SignOut that could not be saved")
		}
	})

	t.Run("ended ones are dropped from the file by the next sign-in", func(t *testing.T) {
		s, dir, clk := setup(t)
		claim(t, s, dir, "alice", testPassword)
		for range 3 {
			newSessionT(t, s)
		}
		clk.Advance(13 * time.Hour)
		sess, err := s.SignIn(ctx, "alice", testPassword)
		if err != nil {
			t.Fatal(err)
		}
		v := readView(t, dir)
		if len(v.Sessions) != 1 || v.Sessions[0].Hash != sumHex(sess.ID) {
			t.Errorf("auth.json holds %d sessions after a sign-in 13 h on, want just the new one", len(v.Sessions))
		}
	})

	t.Run("a slide is saved when the saved one is an hour stale", func(t *testing.T) {
		s, dir, clk := setup(t)
		sess := newSessionT(t, s)
		t0 := clk.Now()
		path := filepath.Join(dir, "auth.json")
		start := readFile(t, path)

		clk.Advance(59 * time.Minute)
		got, ok := s.Session(sess.ID)
		if !ok || !got.Expires.Equal(clk.Now().Add(12*time.Hour)) {
			t.Fatalf("the slide is not applied in memory (%v)", ok)
		}
		if readFile(t, path) != start {
			t.Error("a slide of 59 minutes rewrote auth.json")
		}
		clk.Advance(time.Minute) // exactly an hour: not yet "more than"
		s.Session(sess.ID)
		if readFile(t, path) != start {
			t.Error("a slide of exactly an hour rewrote auth.json")
		}
		clk.Advance(time.Second)
		s.Session(sess.ID)
		want := t0.Add(time.Hour + time.Second)
		if v := readView(t, dir); len(v.Sessions) != 1 || !v.Sessions[0].LastUsed.Equal(want) {
			t.Errorf("auth.json holds last_used %v after a slide of more than an hour, want %v", v.Sessions[0].LastUsed, want)
		}
		saved := readFile(t, path)
		clk.Advance(30 * time.Minute)
		s.Session(sess.ID)
		if readFile(t, path) != saved {
			t.Error("the next use rewrote auth.json again")
		}

		// A write for another reason takes the slide along.
		if _, _, err := s.CreateToken("any", time.Time{}); err != nil {
			t.Fatal(err)
		}
		if v := readView(t, dir); !v.Sessions[0].LastUsed.Equal(clk.Now()) {
			t.Errorf("a write for another reason left last_used at %v, want %v", v.Sessions[0].LastUsed, clk.Now())
		}

		// What was saved is what a restart sees: 12 h from the saved use.
		clk.Advance(11*time.Hour + 30*time.Minute)
		s2, err := OpenStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		s2.now = clk.Now
		if _, ok := s2.Session(sess.ID); !ok {
			t.Error("a session was lost in a restart")
		}
	})
}

func TestSessionIDsNotStored(t *testing.T) {
	ctx := context.Background()
	s, dir := openTest(t)
	claim(t, s, dir, "alice", testPassword)
	a, err := s.SignIn(ctx, "alice", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	b := newSessionT(t, s)
	info, secret, err := s.CreateToken("ci", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	s.SignOut(b.ID)
	c := newSessionT(t, s)

	file := readFile(t, filepath.Join(dir, "auth.json"))
	secretPart := secret[len("tkr_")+8+1:]
	for what, clear := range map[string]string{
		"a session id":    a.ID,
		"the second id":   b.ID,
		"the third id":    c.ID,
		"a CSRF token":    a.CSRF,
		"the third CSRF":  c.CSRF,
		"an API token":    secret,
		"its secret part": secretPart,
		"the password":    testPassword,
	} {
		if strings.Contains(file, clear) {
			t.Errorf("auth.json holds %s", what)
		}
	}
	// What it holds instead: the SHA-256 of each id, and of the token's secret
	// part.
	for what, want := range map[string]string{
		"the hash of the first session": sumHex(a.ID),
		"the hash of the third session": sumHex(c.ID),
		"the hash of the token":         sumHex(secretPart),
		"the id of the token":           info.ID,
	} {
		if !strings.Contains(file, want) {
			t.Errorf("auth.json lacks %s", what)
		}
	}
	if strings.Contains(file, sumHex(b.ID)) {
		t.Error("auth.json still holds the hash of a session that signed out")
	}
	v := readView(t, dir)
	if len(v.Sessions) != 2 {
		t.Errorf("auth.json holds %d sessions, want 2", len(v.Sessions))
	}
	// The ids don't show in the errors either.
	for _, err := range []error{ErrBadCredentials, ErrTokenLimit, ErrNoToken} {
		noSecrets(t, "a session error", err, a.ID, a.CSRF, secret)
	}
}

func TestCSRF(t *testing.T) {
	ctx := context.Background()
	s, dir := openTest(t)
	claim(t, s, dir, "alice", testPassword)
	a, err := s.SignIn(ctx, "alice", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.SignIn(ctx, "alice", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if a.ID == b.ID || a.CSRF == b.CSRF {
		t.Fatal("two sessions share an id or a CSRF token")
	}

	// The token is base64url(HMAC-SHA256(csrf_key, session id)).
	m := hmac.New(sha256.New, s.d.CSRFKey)
	m.Write([]byte(a.ID))
	if want := base64.RawURLEncoding.EncodeToString(m.Sum(nil)); a.CSRF != want || s.CSRFFor(a.ID) != want {
		t.Error("the CSRF token is not the HMAC-SHA256 of the session id under the CSRF key")
	}
	if !s.CheckCSRF(a.ID, a.CSRF) || !s.CheckCSRF(b.ID, b.CSRF) {
		t.Error("a session's own CSRF token fails")
	}

	// The token of one session is no good for another, and nothing else is.
	bad := map[string][2]string{
		"A's token for B":        {b.ID, a.CSRF},
		"B's token for A":        {a.ID, b.CSRF},
		"an empty token":         {a.ID, ""},
		"an empty session id":    {"", a.CSRF},
		"both empty":             {"", ""},
		"the session id":         {a.ID, a.ID},
		"a prefix":               {a.ID, a.CSRF[:len(a.CSRF)-1]},
		"a suffix":               {a.ID, a.CSRF + "A"},
		"a space":                {a.ID, a.CSRF + " "},
		"one character changed":  {a.ID, flip(a.CSRF)},
		"padded":                 {a.ID, a.CSRF + "="},
		"another session's id":   {a.ID + "x", a.CSRF},
		"a session that is none": {"not-a-session", a.CSRF},
	}
	for name, c := range bad {
		if s.CheckCSRF(c[0], c[1]) {
			t.Errorf("CheckCSRF passes %s", name)
		}
	}
	if got := s.CSRFFor(""); got != "" {
		t.Error("CSRFFor of no session gives a token")
	}

	// Another store has another key: a token from it is no good here, and a
	// restart of this one keeps its key.
	other, otherDir := openTest(t)
	claim(t, other, otherDir, "alice", testPassword)
	if other.CSRFFor(a.ID) == a.CSRF || other.CheckCSRF(a.ID, a.CSRF) {
		t.Error("two stores make the same CSRF token: the key is not their own")
	}
	s2, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !s2.CheckCSRF(a.ID, a.CSRF) {
		t.Error("a CSRF token did not survive a restart")
	}
}

// flip changes one character of a token, to another that is valid base64url.
func flip(tok string) string {
	b := []byte(tok)
	if b[0] == 'A' {
		b[0] = 'B'
	} else {
		b[0] = 'A'
	}
	return string(b)
}

// breakAuthFile makes the store unable to save: auth.json becomes a directory,
// which a rename over it can't replace.
func breakAuthFile(t *testing.T, dir string) {
	t.Helper()
	p := filepath.Join(dir, "auth.json")
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestChangePasswordEndsOtherSessions(t *testing.T) {
	ctx := context.Background()
	s, dir := openTest(t)
	claim(t, s, dir, "alice", testPassword)
	mk := func() (Session, Session, Session) {
		a, err := s.SignIn(ctx, "alice", testPassword)
		if err != nil {
			t.Fatal(err)
		}
		return a, newSessionT(t, s), newSessionT(t, s)
	}
	valid := func(sess ...Session) []bool {
		var out []bool
		for _, x := range sess {
			_, ok := s.Session(x.ID)
			out = append(out, ok)
		}
		return out
	}
	eq := func(got []bool, want ...bool) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	}

	a, b, c := mk()
	// A change that fails ends nothing.
	if err := s.ChangePassword(ctx, a.ID, "wrong current", "a brand new password"); !errors.Is(err, ErrBadPassword) {
		t.Fatalf("a wrong current password: %v", err)
	}
	if err := s.ChangePassword(ctx, a.ID, testPassword, "short"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a short new password: %v", err)
	}
	if got := valid(a, b, c); !eq(got, true, true, true) {
		t.Errorf("a change that failed ended sessions: %v", got)
	}

	// One that works keeps the session it came from, and ends the others.
	const second = "a brand new password"
	if err := s.ChangePassword(ctx, b.ID, testPassword, second); err != nil {
		t.Fatal(err)
	}
	if got := valid(a, b, c); !eq(got, false, true, false) {
		t.Errorf("after a change that keeps B, sessions A, B, C are valid: %v, want [false true false]", got)
	}
	if n := len(readView(t, dir).Sessions); n != 1 {
		t.Errorf("auth.json holds %d sessions after the change, want 1", n)
	}
	// The old password no longer signs in, the new one does.
	if _, err := s.SignIn(ctx, "alice", testPassword); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("the old password after a change: %v, want ErrBadCredentials", err)
	}

	// An empty keep ends all of them, and so does a keep that is no session.
	d, err := s.SignIn(ctx, "alice", second)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ChangePassword(ctx, "", second, "another brand new password"); err != nil {
		t.Fatal(err)
	}
	if got := valid(b, d); !eq(got, false, false) {
		t.Errorf("after a change with no session to keep, sessions are valid: %v", got)
	}
	e := newSessionT(t, s)
	if err := s.ChangePassword(ctx, "not-a-session", "another brand new password", "yet another brand new one"); err != nil {
		t.Fatal(err)
	}
	if got := valid(e); !eq(got, false) {
		t.Error("a change that kept a session that does not exist left another")
	}

	// The tokens are not sessions: they stay.
	_, secret, err := s.CreateToken("ci", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ChangePassword(ctx, "", "yet another brand new one", "and one more brand new one"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.CheckToken(secret); !ok {
		t.Error("a change of password ended an API token")
	}
}

func TestEndOtherSessions(t *testing.T) {
	s, dir := openTest(t)
	a, b, c := newSessionT(t, s), newSessionT(t, s), newSessionT(t, s)
	s.EndOtherSessions(b.ID)
	if _, ok := s.Session(b.ID); !ok {
		t.Error("EndOtherSessions ended the session it was to keep")
	}
	for _, x := range []Session{a, c} {
		if _, ok := s.Session(x.ID); ok {
			t.Error("EndOtherSessions left another session")
		}
	}
	if n := len(readView(t, dir).Sessions); n != 1 {
		t.Errorf("auth.json holds %d sessions, want 1", n)
	}
	s.EndOtherSessions("")
	if _, ok := s.Session(b.ID); ok {
		t.Error("EndOtherSessions with no session to keep left one")
	}
	if n := len(readView(t, dir).Sessions); n != 0 {
		t.Errorf("auth.json holds %d sessions, want 0", n)
	}
	// With none to end it writes nothing.
	before := readFile(t, filepath.Join(dir, "auth.json"))
	s.EndOtherSessions("")
	if readFile(t, filepath.Join(dir, "auth.json")) != before {
		t.Error("ending no session rewrote auth.json")
	}
}

func TestRestartKeepsSessionsAndTokens(t *testing.T) {
	ctx := context.Background()
	s, dir := openTest(t)
	clk := newClock()
	s.now = clk.Now
	claim(t, s, dir, "alice", testPassword)
	sess, err := s.SignIn(ctx, "alice", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	info, secret, err := s.CreateToken("ci", clk.Now().Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	clk.Advance(time.Hour)
	s2, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	s2.now = clk.Now
	got, ok := s2.Session(sess.ID)
	if !ok {
		t.Fatal("the session did not survive a restart")
	}
	if got.CSRF != sess.CSRF {
		t.Error("the session has another CSRF token after a restart")
	}
	if !s2.CheckCSRF(sess.ID, sess.CSRF) {
		t.Error("the CSRF token of a session fails after a restart")
	}
	tok, ok := s2.CheckToken(secret)
	if !ok {
		t.Fatal("the API token did not survive a restart")
	}
	if tok.ID != info.ID || tok.Name != "ci" || !tok.Expires.Equal(info.Expires) || !tok.Created.Equal(info.Created) {
		t.Error("the API token changed in a restart")
	}
	if list := s2.Tokens(); len(list) != 1 || list[0].ID != info.ID {
		t.Errorf("Tokens() after a restart lists %d tokens", len(list))
	}

	// And the limits still hold after it: 12 h idle from the last saved use.
	clk.Advance(13 * time.Hour)
	s3, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	s3.now = clk.Now
	if _, ok := s3.Session(sess.ID); ok {
		t.Error("a session that was idle for more than 12 h came back from a restart")
	}
	if _, ok := s3.CheckToken(secret); !ok {
		t.Error("the API token (valid 48 h) was lost 14 h in")
	}
}

func TestSessionStoreConcurrentUse(t *testing.T) {
	s, dir := openTest(t)
	claim(t, s, dir, "alice", testPassword)
	_, secret, err := s.CreateToken("ci", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	base := newSessionT(t, s)

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(4)
		go func() {
			defer wg.Done()
			for range 30 {
				if _, ok := s.Session(base.ID); !ok {
					t.Error("a session that is in use ended")
					return
				}
				s.CheckCSRF(base.ID, base.CSRF)
			}
		}()
		go func() {
			defer wg.Done()
			for range 10 {
				sess, err := startSession(s)
				if err != nil {
					t.Error(err)
					return
				}
				s.SignOut(sess.ID)
			}
		}()
		go func() {
			defer wg.Done()
			for range 20 {
				if _, ok := s.CheckToken(secret); !ok {
					t.Error("a token that is in use stopped checking")
					return
				}
				s.Tokens()
			}
		}()
		go func() {
			defer wg.Done()
			for range 5 {
				info, _, err := s.CreateToken("tmp", time.Time{})
				if err != nil {
					t.Error(err)
					return
				}
				if err := s.RevokeToken(info.ID); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	// Whatever the order, the file is whole and holds what it should.
	s2, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.Session(base.ID); !ok {
		t.Error("the session was lost in the race")
	}
	if _, ok := s2.CheckToken(secret); !ok {
		t.Error("the token was lost in the race")
	}
	if n := len(s2.Tokens()); n != 1 {
		t.Errorf("%d tokens after the race, want 1", n)
	}
}
