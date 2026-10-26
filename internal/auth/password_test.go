package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testPassword is a password that passes ValidPassword.
const testPassword = "correct horse battery staple"

// noSecrets fails the test unless err carries the auth prefix and none of the
// secrets. It never prints a secret.
func noSecrets(t *testing.T, what string, err error, secrets ...string) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: no error", what)
		return
	}
	msg := err.Error()
	if !strings.HasPrefix(msg, "auth:") {
		t.Errorf("%s: the error %q does not start with %q", what, msg, "auth:")
	}
	for i, s := range secrets {
		if s != "" && strings.Contains(msg, s) {
			t.Errorf("%s: the error holds secret #%d", what, i)
		}
	}
}

func TestHashRoundTrip(t *testing.T) {
	ctx := context.Background()
	phc, err := HashPassword(ctx, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" || parts[3] != "m=19456,t=2,p=1" {
		t.Fatalf("the PHC string has the wrong shape or parameters: %q", strings.Join(parts[:min(len(parts), 4)], "$"))
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) != 16 {
		t.Errorf("the salt is %d bytes (err %v), want 16 in unpadded base64", len(salt), err)
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) != 32 {
		t.Errorf("the key is %d bytes (err %v), want 32 in unpadded base64", len(key), err)
	}
	if strings.Contains(phc, testPassword) {
		t.Error("the PHC string holds the password")
	}

	ok, err := CheckPassword(ctx, phc, testPassword)
	if err != nil || !ok {
		t.Errorf("the right password checks (%v, %v), want (true, nil)", ok, err)
	}
	ok, err = CheckPassword(ctx, phc, testPassword+"!")
	if err != nil || ok {
		t.Errorf("a wrong password checks (%v, %v), want (false, nil)", ok, err)
	}
	ok, err = CheckPassword(ctx, phc, "")
	if err != nil || ok {
		t.Errorf("an empty password checks (%v, %v), want (false, nil)", ok, err)
	}

	// The salt is fresh each time.
	again, err := HashPassword(ctx, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if again == phc {
		t.Error("two hashes of one password are the same: the salt is not random")
	}
}

func TestDummyHash(t *testing.T) {
	// It has the parameters a real hash has, so that checking it costs the
	// same, and no password the tests can think of opens it.
	if _, _, err := parsePHC(DummyHash); err != nil {
		t.Fatalf("DummyHash is not a PHC string this package reads: %v", err)
	}
	for _, pw := range []string{"", "password", testPassword, DummyHash} {
		ok, err := CheckPassword(context.Background(), DummyHash, pw)
		if err != nil || ok {
			t.Errorf("DummyHash checks a guess (%v, %v), want (false, nil)", ok, err)
		}
	}
}

func TestCheckRefusesOtherParams(t *testing.T) {
	ctx := context.Background()
	phc, err := HashPassword(ctx, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	base := strings.Split(phc, "$") // "", argon2id, v=19, params, salt, key
	with := func(i int, v string) string {
		p := slices.Clone(base)
		p[i] = v
		return strings.Join(p, "$")
	}
	std := base64.StdEncoding // with padding
	raw := base64.RawStdEncoding

	cases := map[string]string{
		"argon2i":         with(1, "argon2i"),
		"argon2d":         with(1, "argon2d"),
		"old version":     with(2, "v=16"),
		"new version":     with(2, "v=20"),
		"more memory":     with(3, "m=65536,t=2,p=1"),
		"less memory":     with(3, "m=4096,t=2,p=1"),
		"more passes":     with(3, "m=19456,t=3,p=1"),
		"more threads":    with(3, "m=19456,t=2,p=2"),
		"reordered":       with(3, "t=2,m=19456,p=1"),
		"padded numbers":  with(3, "m=019456,t=2,p=1"),
		"no params":       with(3, ""),
		"short salt":      with(4, raw.EncodeToString(make([]byte, 8))),
		"long salt":       with(4, raw.EncodeToString(make([]byte, 32))),
		"empty salt":      with(4, ""),
		"short key":       with(5, raw.EncodeToString(make([]byte, 16))),
		"long key":        with(5, raw.EncodeToString(make([]byte, 64))),
		"salt not base64": with(4, "!!!!!!!!!!!!!!!!!!!!!!"),
		"padded salt":     with(4, std.EncodeToString(make([]byte, 16))),
		"missing hash":    strings.Join(base[:5], "$"),
		"extra part":      phc + "$x",
		"no leading $":    strings.TrimPrefix(phc, "$"),
		"empty":           "",
		"plain text":      "not a hash",
		"bcrypt":          "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
	}
	var hashes atomic.Int32
	argonHook = func() { hashes.Add(1) }
	t.Cleanup(func() { argonHook = nil })

	for name, bad := range cases {
		ok, err := CheckPassword(ctx, bad, testPassword)
		if ok || !errors.Is(err, errBadHash) {
			t.Errorf("%s: CheckPassword = (%v, %v), want (false, errBadHash)", name, ok, err)
			continue
		}
		noSecrets(t, name, err, testPassword, bad)
	}
	if n := hashes.Load(); n != 0 {
		t.Errorf("a hash string with other parameters cost %d argon2 runs, want 0", n)
	}
}

func TestHashConcurrencyBounded(t *testing.T) {
	phc, err := HashPassword(context.Background(), testPassword)
	if err != nil {
		t.Fatal(err)
	}

	// Two hashes get their slot and wait at the gate. The channel has room
	// for more, so that a third one that gets a slot it should not have fails
	// the test below, and doesn't hang it.
	var calls atomic.Int32
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	var once sync.Once
	open := func() { once.Do(func() { close(release) }) }
	argonHook = func() {
		calls.Add(1)
		entered <- struct{}{}
		<-release
	}
	t.Cleanup(func() { open(); argonHook = nil })

	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := HashPassword(context.Background(), testPassword)
			results <- err
		}()
	}
	for range 2 {
		select {
		case <-entered:
		case <-time.After(10 * time.Second):
			t.Fatal("two hashes did not start")
		}
	}

	// A third hash and a check wait for a slot, and give up with their
	// context: they never start.
	for name, run := range map[string]func(context.Context) error{
		"hash":  func(ctx context.Context) error { _, err := HashPassword(ctx, testPassword); return err },
		"check": func(ctx context.Context) error { _, err := CheckPassword(ctx, phc, testPassword); return err },
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		done := make(chan error, 1)
		go func() { done <- run(ctx) }()
		select {
		case err := <-done:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("a third %s while two run: %v, want context.DeadlineExceeded", name, err)
			}
			noSecrets(t, name, err, testPassword, phc)
		case <-time.After(10 * time.Second):
			open()
			t.Fatalf("a third %s while two run did not give up with its context", name)
		}
		cancel()
	}
	// A hash string it won't read is refused before a slot is needed.
	if _, err := CheckPassword(context.Background(), "$argon2i$v=19$m=1,t=1,p=1$AAAA$AAAA", "x"); !errors.Is(err, errBadHash) {
		t.Errorf("a bad hash string while two run: %v, want errBadHash", err)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("%d argon2 runs started, want 2", n)
	}

	open()
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Errorf("a held hash failed: %v", err)
		}
	}

	// The slots came back: two more run at once and finish (the gate is open).
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if ok, err := CheckPassword(ctx, phc, testPassword); err != nil || !ok {
				t.Errorf("a check after the others finished = (%v, %v), want (true, nil)", ok, err)
			}
		}()
	}
	wg.Wait()

	// A context that is done takes no slot, a free one included: nothing runs.
	before := calls.Load()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := HashPassword(ctx, testPassword); !errors.Is(err, context.Canceled) {
		t.Errorf("a hash with a cancelled context: %v, want context.Canceled", err)
	}
	if _, err := CheckPassword(ctx, phc, testPassword); !errors.Is(err, context.Canceled) {
		t.Errorf("a check with a cancelled context: %v, want context.Canceled", err)
	}
	if n := calls.Load(); n != before {
		t.Errorf("a cancelled context started %d argon2 runs, want 0", n-before)
	}
}

func TestValidPassword(t *testing.T) {
	cases := []struct {
		name, user, pass string
		ok               bool
	}{
		{"nine bytes", "alice", strings.Repeat("a", 9), false},
		{"ten bytes", "alice", strings.Repeat("a", 10), true},
		{"256 bytes", "alice", strings.Repeat("a", 256), true},
		{"257 bytes", "alice", strings.Repeat("a", 257), false},
		{"empty", "alice", "", false},
		// The bounds are in bytes: five runes of two bytes are ten.
		{"ten bytes in five runes", "alice", strings.Repeat("é", 5), true},
		{"nine bytes in four runes", "alice", strings.Repeat("é", 4) + "a", false},
		{"equal to the username", "administrator", "administrator", false},
		{"holds the username", "administrator", "administrator1", true},
		{"spaces", "alice", "          ", true},
	}
	for _, c := range cases {
		err := ValidPassword(c.user, c.pass)
		if (err == nil) != c.ok {
			t.Errorf("%s: ValidPassword(%q, ...) = %v, ok want %v", c.name, c.user, err, c.ok)
			continue
		}
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("%s: %v is not ErrInvalid", c.name, err)
			}
			noSecrets(t, c.name, err, c.pass)
		}
	}
}

func TestValidUsername(t *testing.T) {
	cases := []struct {
		name, user string
		ok         bool
	}{
		{"empty", "", false},
		{"one rune", "a", true},
		{"ordinary", "alice.admin", true},
		{"64 runes", strings.Repeat("é", 64), true},
		{"65 runes", strings.Repeat("é", 65), false},
		{"64 ASCII", strings.Repeat("a", 64), true},
		{"65 ASCII", strings.Repeat("a", 65), false},
		{"non-Latin", "管理者", true},
		{"newline", "al\nice", false},
		{"tab", "al\tice", false},
		{"NUL", "al\x00ice", false},
		{"DEL", "al\x7fice", false},
		{"C1 control", "al\u0085ice", false},
		{"line separator", "al\u2028ice", false},
		{"paragraph separator", "al\u2029ice", false},
		{"bidi override", "al\u202eice", false},
		{"bidi isolate", "al\u2066ice", false},
		{"invalid UTF-8", "al\xffice", false},
	}
	for _, c := range cases {
		err := ValidUsername(c.user)
		if (err == nil) != c.ok {
			t.Errorf("%s: ValidUsername = %v, ok want %v", c.name, err, c.ok)
			continue
		}
		if err != nil && !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v is not ErrInvalid", c.name, err)
		}
		if err != nil {
			noSecrets(t, c.name, err)
		}
	}
}
