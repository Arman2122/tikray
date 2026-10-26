package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// openTest opens a store in a state directory that doesn't exist yet.
func openTest(t *testing.T) (*Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// claim claims the admin of s with the code in its setup.code, as the CLI
// would show it.
func claim(t *testing.T, s *Store, dir, user, pass string) {
	t.Helper()
	code := readFile(t, filepath.Join(dir, "setup.code"))
	if err := s.Claim(context.Background(), code, user, pass); err != nil {
		t.Fatalf("Claim: %v", err)
	}
}

// adminOf is the admin the store holds, for the tests that look inside.
func adminOf(t *testing.T, s *Store) admin {
	t.Helper()
	a, ok := s.admin()
	if !ok {
		t.Fatal("the store has no admin")
	}
	return a
}

func TestOpenCreatesSetupCode(t *testing.T) {
	s, dir := openTest(t)
	if !s.NeedsSetup() {
		t.Error("a new store with no admin does not need setup")
	}
	if got := mode(t, dir); got != 0o700 {
		t.Errorf("the state directory has mode %o, want 700", got)
	}
	for _, f := range []string{"auth.json", "setup.code"} {
		if got := mode(t, filepath.Join(dir, f)); got != 0o600 {
			t.Errorf("%s has mode %o, want 600", f, got)
		}
	}
	// Nothing else is left in the directory, not even a temporary file.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if !slices.Equal(names, []string{"auth.json", "setup.code"}) {
		t.Errorf("the state directory holds %v", names)
	}

	code := readFile(t, filepath.Join(dir, "setup.code"))
	if !codeForm.MatchString(code) {
		t.Errorf("setup.code does not hold a code in the shown form (%d bytes)", len(code))
	}
	got, err := s.SetupCode()
	if err != nil || got != code {
		t.Errorf("SetupCode = (%v), want the file's code", err)
	}

	// Opening it again keeps the code and the CSRF key.
	key := slices.Clone(s.d.CSRFKey)
	if len(key) != 32 {
		t.Errorf("the CSRF key is %d bytes, want 32", len(key))
	}
	s2, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(dir, "setup.code")); got != code {
		t.Error("opening the store again made a new setup code")
	}
	if !bytes.Equal(s2.d.CSRFKey, key) {
		t.Error("opening the store again made a new CSRF key")
	}
	if !s2.NeedsSetup() {
		t.Error("the reopened store does not need setup")
	}
}

func TestOpenRepairsWhatACrashLeaves(t *testing.T) {
	ctx := context.Background()

	// An admin and a setup code: a claim that died before it removed the code.
	s, dir := openTest(t)
	code := readFile(t, filepath.Join(dir, "setup.code"))
	claim(t, s, dir, "alice", testPassword)
	if err := os.WriteFile(filepath.Join(dir, "setup.code"), []byte(code), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if exists(filepath.Join(dir, "setup.code")) {
		t.Error("a setup code survived next to an admin")
	}
	if s.NeedsSetup() {
		t.Error("the admin is gone")
	}
	if ok, err := CheckPassword(ctx, adminOf(t, s).Hash, testPassword); err != nil || !ok {
		t.Errorf("the admin's password no longer checks (%v, %v)", ok, err)
	}

	// No admin and no code: a reset that died between its two writes.
	s, err = OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir2 := s.dir
	if err := os.Remove(filepath.Join(dir2, "setup.code")); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(dir2); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(dir2, "setup.code")); !codeForm.MatchString(got) {
		t.Error("no setup code was made for a store with no admin and no code")
	}
}

func TestClaim(t *testing.T) {
	ctx := context.Background()
	s, dir := openTest(t)
	codePath := filepath.Join(dir, "setup.code")
	code := readFile(t, codePath)

	// A wrong code changes nothing.
	for _, bad := range []string{"", "0000-0000-0000", "ZZZZ-ZZZZ-ZZZZ", code + "0", code[:len(code)-1], code[:4]} {
		err := s.Claim(ctx, bad, "alice", testPassword)
		if !errors.Is(err, ErrBadCode) {
			t.Errorf("Claim with a wrong code %q: %v, want ErrBadCode", bad, err)
		}
	}
	if !s.NeedsSetup() || !exists(codePath) || readFile(t, codePath) != code {
		t.Error("a wrong code changed the state")
	}

	// A right code with a username or a password that breaks the rules is a
	// validation error, and the code stays good.
	for name, c := range map[string]struct{ user, pass string }{
		"empty username":    {"", testPassword},
		"newline username":  {"al\nice", testPassword},
		"long username":     {strings.Repeat("a", 65), testPassword},
		"short password":    {"alice", "short"},
		"password is name":  {"administrator", "administrator"},
		"long password":     {"alice", strings.Repeat("a", 257)},
		"empty both":        {"", ""},
		"bad name, bad one": {"\x00", "x"},
	} {
		err := s.Claim(ctx, code, c.user, c.pass)
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want a validation error", name, err)
		}
	}
	if !s.NeedsSetup() || readFile(t, codePath) != code {
		t.Error("a validation error changed the state")
	}

	// The code as a person may type it: lower case, with spaces, and a letter
	// that looks like a digit.
	typed := strings.NewReplacer("0", "o", "1", "i", "-", "  ").Replace(strings.ToLower(code))
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	if err := s.Claim(ctx, typed, "alice", testPassword); err != nil {
		t.Fatalf("Claim with the right code: %v", err)
	}
	if s.NeedsSetup() {
		t.Error("the admin was claimed but the store still needs setup")
	}
	if exists(codePath) {
		t.Error("setup.code is still there after the claim")
	}
	a := adminOf(t, s)
	if a.Username != "alice" || !a.ChangedAt.Equal(now) {
		t.Errorf("the admin is %q changed at %v", a.Username, a.ChangedAt)
	}
	if ok, err := CheckPassword(ctx, a.Hash, testPassword); err != nil || !ok {
		t.Errorf("the stored hash does not check the password (%v, %v)", ok, err)
	}
	if got := mode(t, filepath.Join(dir, "auth.json")); got != 0o600 {
		t.Errorf("auth.json has mode %o, want 600", got)
	}

	// A second claim, with the code that was, or any other, is refused.
	for _, c := range []string{code, "", "ZZZZ-ZZZZ-ZZZZ"} {
		if err := s.Claim(ctx, c, "mallory", testPassword); !errors.Is(err, ErrAlreadyClaimed) {
			t.Errorf("a second claim: %v, want ErrAlreadyClaimed", err)
		}
	}
	if adminOf(t, s).Username != "alice" {
		t.Error("a second claim replaced the admin")
	}
	if _, err := s.SetupCode(); !errors.Is(err, ErrAlreadyClaimed) {
		t.Errorf("SetupCode after the claim: %v, want ErrAlreadyClaimed", err)
	}

	// The admin outlives the process, and no new code is made for it.
	s2, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s2.NeedsSetup() || exists(codePath) {
		t.Error("the reopened store needs setup or made a code")
	}
	if got := adminOf(t, s2); got.Username != "alice" || got.Hash != a.Hash || !got.ChangedAt.Equal(now) {
		t.Error("the reopened store has another admin")
	}
}

func TestClaimGivesUpWithItsContext(t *testing.T) {
	s, dir := openTest(t)
	code := readFile(t, filepath.Join(dir, "setup.code"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := s.Claim(ctx, code, "alice", testPassword)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Claim with a cancelled context: %v, want context.Canceled", err)
	}
	if !s.NeedsSetup() || readFile(t, filepath.Join(dir, "setup.code")) != code {
		t.Error("a claim that gave up changed the state")
	}
	// A wrong code is a wrong code before it is anything else.
	if err := s.Claim(ctx, "ZZZZ-ZZZZ-ZZZZ", "alice", testPassword); !errors.Is(err, ErrBadCode) {
		t.Errorf("a wrong code with a cancelled context: %v, want ErrBadCode", err)
	}
}

func TestClaimOnlyOnceWhenRacing(t *testing.T) {
	s, dir := openTest(t)
	code := readFile(t, filepath.Join(dir, "setup.code"))

	const n = 4
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = s.Claim(context.Background(), code, "user"+string(rune('a'+i)), testPassword)
		}()
	}
	wg.Wait()
	wins := 0
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case !errors.Is(err, ErrAlreadyClaimed):
			t.Errorf("a racing claim: %v, want nil or ErrAlreadyClaimed", err)
		}
	}
	if wins != 1 {
		t.Errorf("%d claims won, want 1", wins)
	}
	if s.NeedsSetup() || exists(filepath.Join(dir, "setup.code")) {
		t.Error("the state after the race is not a claimed one")
	}
}

func TestResetMakesNewCode(t *testing.T) {
	ctx := context.Background()
	s, dir := openTest(t)
	oldCode := readFile(t, filepath.Join(dir, "setup.code"))
	claim(t, s, dir, "alice", testPassword)
	key := slices.Clone(s.d.CSRFKey)

	// A reset ends the sessions and leaves the API tokens alone.
	sess1, sess2 := newSessionT(t, s), newSessionT(t, s)
	info, secret, err := s.CreateToken("kept", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	s, err = OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Reset(); err != nil {
		t.Fatal(err)
	}
	if !s.NeedsSetup() {
		t.Error("after a reset the store has an admin")
	}
	newCode := readFile(t, filepath.Join(dir, "setup.code"))
	if !codeForm.MatchString(newCode) || newCode == oldCode {
		t.Error("a reset did not write a new setup code")
	}
	if got := mode(t, filepath.Join(dir, "setup.code")); got != 0o600 {
		t.Errorf("setup.code has mode %o, want 600", got)
	}
	if got, err := s.SetupCode(); err != nil || got != newCode {
		t.Errorf("SetupCode after a reset = (%v), want the new code", err)
	}

	var file struct {
		Version  int              `json:"version"`
		Admin    *json.RawMessage `json:"admin"`
		CSRFKey  []byte           `json:"csrf_key"`
		Tokens   []struct{ ID, Name string }
		Sessions json.RawMessage `json:"sessions"`
	}
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(dir, "auth.json"))), &file); err != nil {
		t.Fatal(err)
	}
	if file.Version != 1 || file.Admin != nil {
		t.Errorf("auth.json after a reset: version %d, admin %v", file.Version, file.Admin != nil)
	}
	if !bytes.Equal(file.CSRFKey, key) {
		t.Error("a reset changed the CSRF key")
	}
	if len(file.Tokens) != 1 || file.Tokens[0].ID != info.ID || file.Tokens[0].Name != "kept" {
		t.Errorf("a reset changed the tokens: %v", file.Tokens)
	}
	if _, ok := s.CheckToken(secret); !ok {
		t.Error("a reset ended an API token")
	}
	if got := string(bytes.TrimSpace(file.Sessions)); got != "[]" {
		t.Errorf("a reset left the sessions as %s, want []", got)
	}
	for _, sess := range []Session{sess1, sess2} {
		if _, ok := s.Session(sess.ID); ok {
			t.Error("a reset left a session")
		}
	}

	// The old code is dead, the new one makes an admin, and it all survives
	// a restart.
	if err := s.Claim(ctx, oldCode, "bob", testPassword); !errors.Is(err, ErrBadCode) {
		t.Errorf("the old code after a reset: %v, want ErrBadCode", err)
	}
	s, err = OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !s.NeedsSetup() || readFile(t, filepath.Join(dir, "setup.code")) != newCode {
		t.Error("a restart after a reset lost the reset")
	}
	if err := s.Claim(ctx, newCode, "bob", testPassword); err != nil {
		t.Fatalf("claiming with the code a reset made: %v", err)
	}
	if adminOf(t, s).Username != "bob" {
		t.Error("the new admin is not bob")
	}

	// A reset with no admin makes a new code too.
	s, dir = openTest(t)
	before := readFile(t, filepath.Join(dir, "setup.code"))
	if err := s.Reset(); err != nil {
		t.Fatal(err)
	}
	if after := readFile(t, filepath.Join(dir, "setup.code")); after == before || !codeForm.MatchString(after) {
		t.Error("a reset with no admin did not make a new code")
	}
}

func TestFileHasNoSecretsInClear(t *testing.T) {
	ctx := context.Background()
	s, dir := openTest(t)
	code := readFile(t, filepath.Join(dir, "setup.code"))
	norm := NormalizeSetupCode(code)
	// Before the claim the file holds neither the code nor anything else
	// secret but the CSRF key.
	if auth := readFile(t, filepath.Join(dir, "auth.json")); strings.Contains(auth, code) || strings.Contains(auth, norm) {
		t.Error("auth.json holds the setup code before the claim")
	}

	const pass, next = "the first password", "the second password"
	claim(t, s, dir, "alice", pass)
	if err := s.ChangePassword(ctx, "", pass, next); err != nil {
		t.Fatal(err)
	}
	auth := readFile(t, filepath.Join(dir, "auth.json"))
	for what, secret := range map[string]string{"the first password": pass, "the second password": next, "the setup code": code, "the normalised setup code": norm} {
		if strings.Contains(auth, secret) {
			t.Errorf("auth.json holds %s", what)
		}
	}
	// The file is not empty of what it should hold.
	for _, want := range []string{`"version": 1`, `"username": "alice"`, `"hash": "$argon2id$v=19$m=19456,t=2,p=1$`, `"csrf_key"`, `"changed_at"`, `"tokens": []`, `"sessions": []`} {
		if !strings.Contains(auth, want) {
			t.Errorf("auth.json lacks %s", want)
		}
	}
}

func TestUnknownVersionRefused(t *testing.T) {
	cases := map[string]string{
		"version 2":         `{"version":2,"admin":{"username":"alice","hash":"x"},"csrf_key":"","tokens":[],"sessions":[]}`,
		"version 2 shape":   `{"version":2,"admins":[{"name":"SECRETMARKER"}],"csrf_key":42}`,
		"no version":        `{"admin":null,"csrf_key":"","tokens":[],"sessions":[]}`,
		"version 0":         `{"version":0}`,
		"negative version":  `{"version":-1}`,
		"version as string": `{"version":"1"}`,
		"empty object":      `{}`,
		"empty file":        ``,
		"not JSON":          `SECRETMARKER`,
		"truncated":         `{"version":1,"admin":{"username":"SECRETMARKER`,
		"an array":          `[1]`,
		"null":              `null`,
	}
	for name, content := range cases {
		dir := t.TempDir()
		path := filepath.Join(dir, "auth.json")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := OpenStore(dir)
		if err == nil || s != nil {
			t.Errorf("%s: OpenStore = (%v, %v), want an error", name, s != nil, err)
			continue
		}
		noSecrets(t, name, err, "SECRETMARKER")
		// The file is not touched, and nothing else is made beside it.
		if got := readFile(t, path); got != content {
			t.Errorf("%s: OpenStore changed the file it refused", name)
		}
		if exists(filepath.Join(dir, "setup.code")) {
			t.Errorf("%s: OpenStore made a setup code beside a file it refused", name)
		}
	}
}

func TestOpenRefusesAFileItCannotUse(t *testing.T) {
	good, err := HashPassword(context.Background(), testPassword)
	if err != nil {
		t.Fatal(err)
	}
	key := `"csrf_key":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="`
	cases := map[string]string{
		"hash of another kind":  `{"version":1,"admin":{"username":"alice","hash":"$argon2i$v=19$m=19456,t=2,p=1$AAAA$AAAA"},` + key + `}`,
		"hash that is no hash":  `{"version":1,"admin":{"username":"alice","hash":"SECRETMARKER"},` + key + `}`,
		"admin with no name":    `{"version":1,"admin":{"username":"","hash":"` + good + `"},` + key + `}`,
		"short CSRF key":        `{"version":1,"csrf_key":"AAEC"}`,
		"CSRF key not base64":   `{"version":1,"csrf_key":"SECRETMARKER!"}`,
		"CSRF key of a number":  `{"version":1,"csrf_key":7}`,
		"tokens of another typ": `{"version":1,"tokens":"SECRETMARKER"}`,
		// A username that was edited in by hand is held to the rules of
		// ValidUsername, so that it is never shown with a control character or a
		// bidi mark in it.
		"username with a control": `{"version":1,"admin":{"username":"SECRETMARKER\u0007","hash":"` + good + `"},` + key + `}`,
		"username with a newline": `{"version":1,"admin":{"username":"SECRETMARKER\n","hash":"` + good + `"},` + key + `}`,
		"username with a bidi":    `{"version":1,"admin":{"username":"SECRETMARKER‮","hash":"` + good + `"},` + key + `}`,
		"username with a C1":      `{"version":1,"admin":{"username":"SECRETMARKER\u0085","hash":"` + good + `"},` + key + `}`,
		"username too long":       `{"version":1,"admin":{"username":"` + strings.Repeat("a", 65) + `","hash":"` + good + `"},` + key + `}`,
	}
	for name, content := range cases {
		dir := t.TempDir()
		path := filepath.Join(dir, "auth.json")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenStore(dir); err == nil {
			t.Errorf("%s: OpenStore took the file", name)
		} else {
			noSecrets(t, name, err, "SECRETMARKER", good)
		}
		if got := readFile(t, path); got != content {
			t.Errorf("%s: OpenStore changed the file it refused", name)
		}
	}

	// A directory where the file should be is an error, not a new file.
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "auth.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(dir); err == nil {
		t.Error("OpenStore took a directory for auth.json")
	}

	// A name that passes the rules, in any script, is taken.
	dir = t.TempDir()
	ok := `{"version":1,"admin":{"username":"管理者","hash":"` + good + `"},` + key + `}`
	if err := os.WriteFile(filepath.Join(dir, "auth.json"), []byte(ok), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore refused a file with a username that passes the rules: %v", err)
	}
	if got := adminOf(t, s).Username; got != "管理者" {
		t.Error("the admin's username was not read as it was written")
	}
}

func TestResetRemovesTheOldCodeBeforeItCommits(t *testing.T) {
	// A crash between the commit of "no admin" and the new code must not leave
	// the old code beside no admin, where it would claim the admin again. So
	// the old file goes first: a Reset whose commit fails (auth.json here is a
	// directory) has already removed it, and no crash point has it.
	s, dir := openTest(t)
	old := readFile(t, filepath.Join(dir, "setup.code"))
	authPath := filepath.Join(dir, "auth.json")
	if err := os.Remove(authPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(authPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.Reset(); err == nil {
		t.Fatal("Reset saved to a directory")
	}
	if exists(filepath.Join(dir, "setup.code")) {
		t.Error("the old setup code was still on disk when the commit of the reset was made")
	}
	// What is left is what OpenStore and SetupCode already mend: no admin, no
	// code, and a new one on the next ask, never the old one.
	got, err := s.SetupCode()
	if err != nil || got == old || !codeForm.MatchString(got) {
		t.Errorf("SetupCode after a failed reset: (%v), want a new code", err)
	}
}

func TestChangePassword(t *testing.T) {
	ctx := context.Background()
	s, dir := openTest(t)
	t0 := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	t1 := t0.Add(48 * time.Hour)
	s.now = func() time.Time { return t0 }
	claim(t, s, dir, "alice", testPassword)
	before := adminOf(t, s)

	const next = "a different long password"
	s.now = func() time.Time { return t1 }

	// Nothing that fails changes the admin.
	if err := s.ChangePassword(ctx, "", testPassword+"x", next); !errors.Is(err, ErrBadPassword) {
		t.Errorf("a wrong current password: %v, want ErrBadPassword", err)
	}
	for name, bad := range map[string]string{"short": "short", "the username": "alice", "long": strings.Repeat("a", 257)} {
		if err := s.ChangePassword(ctx, "", testPassword, bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("a new password that is %s: %v, want a validation error", name, err)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.ChangePassword(cancelled, "", testPassword, next); !errors.Is(err, context.Canceled) {
		t.Errorf("a change with a cancelled context: %v, want context.Canceled", err)
	}
	if got := adminOf(t, s); got != before {
		t.Error("a change that failed altered the admin")
	}

	if err := s.ChangePassword(ctx, "", testPassword, next); err != nil {
		t.Fatal(err)
	}
	after := adminOf(t, s)
	if after.Username != "alice" || after.Hash == before.Hash || !after.ChangedAt.Equal(t1) {
		t.Errorf("the admin after a change: %q, new hash %v, changed at %v", after.Username, after.Hash != before.Hash, after.ChangedAt)
	}
	if ok, err := CheckPassword(ctx, after.Hash, next); err != nil || !ok {
		t.Errorf("the new password does not check (%v, %v)", ok, err)
	}
	if ok, err := CheckPassword(ctx, after.Hash, testPassword); err != nil || ok {
		t.Errorf("the old password still checks (%v, %v)", ok, err)
	}
	// The old one is not the current one any more.
	if err := s.ChangePassword(ctx, "", testPassword, "yet another long password"); !errors.Is(err, ErrBadPassword) {
		t.Errorf("the old password as the current one: %v, want ErrBadPassword", err)
	}

	// It is saved.
	s2, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := adminOf(t, s2); got.Hash != after.Hash || !got.ChangedAt.Equal(t1) {
		t.Error("a change was not saved")
	}
	if got := mode(t, filepath.Join(dir, "auth.json")); got != 0o600 {
		t.Errorf("auth.json has mode %o, want 600", got)
	}

	// With no admin there is nothing to change.
	if err := s2.Reset(); err != nil {
		t.Fatal(err)
	}
	if err := s2.ChangePassword(ctx, "", next, "yet another long password"); err == nil {
		t.Error("a password was changed with no admin")
	} else {
		if !errors.Is(err, ErrNoAdmin) {
			t.Errorf("a change with no admin: %v, want ErrNoAdmin", err)
		}
		noSecrets(t, "no admin", err, next, "yet another long password")
	}
}

func TestChangePasswordRacing(t *testing.T) {
	ctx := context.Background()
	s, dir := openTest(t)
	claim(t, s, dir, "alice", testPassword)

	// Two changes from the same current password: one wins, and the other is
	// told the current password is wrong, as it is by then.
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, pw := range []string{"the first new password", "the second new password"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = s.ChangePassword(ctx, "", testPassword, pw)
		}()
	}
	wg.Wait()
	wins := 0
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case !errors.Is(err, ErrBadPassword):
			t.Errorf("a racing change: %v, want nil or ErrBadPassword", err)
		}
	}
	if wins != 1 {
		t.Errorf("%d changes won, want 1", wins)
	}
}

func TestErrorsCarryNoSecrets(t *testing.T) {
	ctx := context.Background()
	s, dir := openTest(t)
	code := readFile(t, filepath.Join(dir, "setup.code"))
	norm := NormalizeSetupCode(code)
	const pw = "secret-pw"           // too short, so that it is refused
	const long = "a-secret-password" // fine
	const wrong = "wrong-secret-password"

	secrets := []string{code, norm, pw, long, wrong, "ZZZZ-ZZZZ-ZZZZ"}
	noSecrets(t, "bad code", s.Claim(ctx, "ZZZZ-ZZZZ-ZZZZ", "alice", long), secrets...)
	noSecrets(t, "short password", s.Claim(ctx, code, "alice", pw), secrets...)
	noSecrets(t, "password is the name", s.Claim(ctx, code, long, long), secrets...)
	claim(t, s, dir, "alice", long)
	hash := adminOf(t, s).Hash
	secrets = append(secrets, hash)
	noSecrets(t, "claimed", s.Claim(ctx, code, "alice", long), secrets...)
	noSecrets(t, "wrong current", s.ChangePassword(ctx, "", wrong, long+"!"), secrets...)
	noSecrets(t, "short new", s.ChangePassword(ctx, "", long, pw), secrets...)
	_, err := s.SetupCode()
	noSecrets(t, "setup code of a claimed store", err, secrets...)
	_, err = CheckPassword(ctx, "$argon2id$v=19$m=1,t=2,p=1$"+hash, long)
	noSecrets(t, "bad hash", err, secrets...)

	// A setup.code that holds no code is named, not shown.
	if err := s.Reset(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "setup.code"), []byte("SECRET-MARKER!"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = s.SetupCode()
	noSecrets(t, "garbled setup.code", err, "SECRET-MARKER!", "SECRET")
	// Claiming with the very text of the file, which normalises to something
	// that is no code, is no claim.
	noSecrets(t, "claim with a garbled setup.code", s.Claim(ctx, "SECRET-MARKER!", "alice", long), "SECRET-MARKER!", "SECRET", long)
	// ... and it cannot be opened with the same text as the "code".
	if err := s.Claim(ctx, "", "alice", long); err == nil {
		t.Error("an empty code claimed the admin over an unusable setup.code")
	}
	if !s.NeedsSetup() {
		t.Error("a garbled setup.code let a claim through")
	}
	// A reset repairs it.
	if err := s.Reset(); err != nil {
		t.Fatal(err)
	}
	if got, err := s.SetupCode(); err != nil || !codeForm.MatchString(got) {
		t.Errorf("SetupCode after a reset over a garbled file: (%v)", err)
	}
}

func TestEmptySetupCodeFileOpensNothing(t *testing.T) {
	// Two empty strings are equal to a constant-time compare: an empty file
	// and an empty code must not be a claim.
	ctx := context.Background()
	s, dir := openTest(t)
	if err := os.WriteFile(filepath.Join(dir, "setup.code"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"", " ", "-", "\n"} {
		if err := s.Claim(ctx, code, "alice", testPassword); err == nil {
			t.Errorf("Claim(%q) over an empty setup.code succeeded", code)
		}
	}
	if !s.NeedsSetup() {
		t.Error("an empty setup.code let a claim through")
	}
}

func TestSetupCodeFileMade(t *testing.T) {
	// A setup.code a person removed while serve runs (no admin yet) is made
	// again by the next read, rather than leaving the store with no way in.
	s, dir := openTest(t)
	old := readFile(t, filepath.Join(dir, "setup.code"))
	if err := os.Remove(filepath.Join(dir, "setup.code")); err != nil {
		t.Fatal(err)
	}
	got, err := s.SetupCode()
	if err != nil || !codeForm.MatchString(got) || got == old {
		t.Fatalf("SetupCode after the file was removed = (%v)", err)
	}
	if readFile(t, filepath.Join(dir, "setup.code")) != got || mode(t, filepath.Join(dir, "setup.code")) != 0o600 {
		t.Error("the code SetupCode returned is not in a 0600 setup.code")
	}
	// The old code, which nobody can read any more, is no claim.
	if err := s.Claim(context.Background(), old, "alice", testPassword); !errors.Is(err, ErrBadCode) {
		t.Errorf("the removed code: %v, want ErrBadCode", err)
	}
}

func TestStoreConcurrentUse(t *testing.T) {
	s, dir := openTest(t)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(3)
		go func() {
			defer wg.Done()
			for range 20 {
				s.NeedsSetup()
			}
		}()
		go func() {
			defer wg.Done()
			for range 20 {
				if _, err := s.SetupCode(); err != nil {
					t.Error(err)
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for range 10 {
				if err := s.Reset(); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	// Whatever the order, the files are whole.
	if _, err := OpenStore(dir); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(dir, "setup.code")); !codeForm.MatchString(got) {
		t.Error("setup.code is not a code after the race")
	}
}

func TestUsername(t *testing.T) {
	s, dir := openTest(t)
	if got := s.Username(); got != "" {
		t.Errorf("Username with no admin = %q, want empty", got)
	}
	claim(t, s, dir, "alice", "correct horse battery")
	if got := s.Username(); got != "alice" {
		t.Errorf("Username = %q, want alice", got)
	}
	if err := s.Reset(); err != nil {
		t.Fatal(err)
	}
	if got := s.Username(); got != "" {
		t.Errorf("Username after a reset = %q, want empty", got)
	}
	if SessionLife != 7*24*time.Hour {
		t.Errorf("SessionLife = %v, want 7 days", SessionLife)
	}
}

// stateFiles is what the files of a state directory hold and when they were
// written, for a test that a read changed none of them and made none.
func stateFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range ents {
		fi, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		got[e.Name()] = fi.Mode().String() + " " + fi.ModTime().String() + " " + readFile(t, filepath.Join(dir, e.Name()))
	}
	return got
}

// ReadSetupCode is the CLI's way to the code while serve owns the directory:
// it reads, and it never writes or makes anything.
func TestReadSetupCode(t *testing.T) {
	t.Run("nothing yet", func(t *testing.T) {
		// serve has never run here: no directory, no files. It says so, which
		// is not "claimed", and it makes nothing.
		dir := filepath.Join(t.TempDir(), "state")
		code, claimed, err := ReadSetupCode(dir)
		if !errors.Is(err, ErrNoSetupCode) || code != "" || claimed {
			t.Errorf("ReadSetupCode = (%q, %v, %v), want no code, not claimed, ErrNoSetupCode", code, claimed, err)
		}
		if exists(dir) {
			t.Error("ReadSetupCode made the state directory")
		}
	})

	t.Run("a code", func(t *testing.T) {
		_, dir := openTest(t)
		before := stateFiles(t, dir)
		code, claimed, err := ReadSetupCode(dir)
		if err != nil || claimed || code != readFile(t, filepath.Join(dir, "setup.code")) || !codeForm.MatchString(code) {
			t.Errorf("ReadSetupCode = (%v, %v, %v), want the code in setup.code, not claimed", codeForm.MatchString(code), claimed, err)
		}
		if after := stateFiles(t, dir); !reflect.DeepEqual(before, after) {
			t.Errorf("ReadSetupCode changed the directory:\nbefore %v\nafter  %v", before, after)
		}
	})

	t.Run("the file as a person left it", func(t *testing.T) {
		// Lower case, spaces and a newline, as an editor leaves a pasted code:
		// it is shown in the form claims take.
		_, dir := openTest(t)
		if err := os.WriteFile(filepath.Join(dir, "setup.code"), []byte(" 7f3k-9q2m xx4t \n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if code, claimed, err := ReadSetupCode(dir); err != nil || claimed || code != "7F3K-9Q2M-XX4T" {
			t.Errorf("ReadSetupCode = (%v, %v, %v), want 7F3K-9Q2M-XX4T", code == "7F3K-9Q2M-XX4T", claimed, err)
		}
	})

	t.Run("claimed", func(t *testing.T) {
		s, dir := openTest(t)
		claim(t, s, dir, "alice", testPassword)
		before := stateFiles(t, dir)
		code, claimed, err := ReadSetupCode(dir)
		if err != nil || !claimed || code != "" {
			t.Errorf("ReadSetupCode = (%q, %v, %v), want no code, claimed", code, claimed, err)
		}
		if exists(filepath.Join(dir, "setup.code")) {
			t.Error("ReadSetupCode made a setup.code beside the admin")
		}
		if after := stateFiles(t, dir); !reflect.DeepEqual(before, after) {
			t.Errorf("ReadSetupCode changed the directory:\nbefore %v\nafter  %v", before, after)
		}
	})

	t.Run("a code left beside an admin is no code", func(t *testing.T) {
		// A claim that died between saving the admin and removing the file:
		// the admin is what counts, and the stale code is not shown.
		s, dir := openTest(t)
		stale := readFile(t, filepath.Join(dir, "setup.code"))
		claim(t, s, dir, "alice", testPassword)
		if err := os.WriteFile(filepath.Join(dir, "setup.code"), []byte(stale), 0o600); err != nil {
			t.Fatal(err)
		}
		code, claimed, err := ReadSetupCode(dir)
		if err != nil || !claimed || code != "" {
			t.Errorf("ReadSetupCode = (%q, %v, %v), want no code, claimed", code, claimed, err)
		}
		if !exists(filepath.Join(dir, "setup.code")) {
			t.Error("ReadSetupCode removed a file: it only reads")
		}
	})

	t.Run("no admin and no file", func(t *testing.T) {
		// The file was removed by hand: there is no admin, so it is not
		// "claimed", and the read does not make a new code (the store's
		// SetupCode does).
		_, dir := openTest(t)
		if err := os.Remove(filepath.Join(dir, "setup.code")); err != nil {
			t.Fatal(err)
		}
		code, claimed, err := ReadSetupCode(dir)
		if !errors.Is(err, ErrNoSetupCode) || code != "" || claimed {
			t.Errorf("ReadSetupCode = (%q, %v, %v), want no code, not claimed, ErrNoSetupCode", code, claimed, err)
		}
		if exists(filepath.Join(dir, "setup.code")) {
			t.Error("ReadSetupCode made a setup.code")
		}
	})

	t.Run("after a reset", func(t *testing.T) {
		s, dir := openTest(t)
		claim(t, s, dir, "alice", testPassword)
		if err := s.Reset(); err != nil {
			t.Fatal(err)
		}
		if code, claimed, err := ReadSetupCode(dir); err != nil || claimed || code != readFile(t, filepath.Join(dir, "setup.code")) {
			t.Errorf("ReadSetupCode = (%v, %v, %v), want the new code, not claimed", code != "", claimed, err)
		}
	})

	t.Run("what it can't use", func(t *testing.T) {
		// None of these is "claimed", none shows what the file held, and a
		// code that can't be told to be the right one is not shown.
		const junk = "SECRETJUNK-not-a-code"
		for name, tc := range map[string]struct {
			file, content string
		}{
			"a setup.code that holds no code":       {"setup.code", junk},
			"an empty setup.code":                   {"setup.code", ""},
			"an auth.json that is not JSON":         {"auth.json", "{" + junk},
			"an auth.json of another version":       {"auth.json", `{"version": 99}`},
			"an auth.json with a hash it can't use": {"auth.json", `{"version":1,"admin":{"username":"alice","hash":"` + junk + `"}}`},
		} {
			t.Run(name, func(t *testing.T) {
				_, dir := openTest(t)
				if err := os.WriteFile(filepath.Join(dir, tc.file), []byte(tc.content), 0o600); err != nil {
					t.Fatal(err)
				}
				code, claimed, err := ReadSetupCode(dir)
				if err == nil || errors.Is(err, ErrNoSetupCode) || claimed || code != "" {
					t.Fatalf("ReadSetupCode = (%q, %v, %v), want an error and nothing else", code, claimed, err)
				}
				if strings.Contains(err.Error(), "SECRETJUNK") || !strings.HasPrefix(err.Error(), "auth: ") {
					t.Errorf("the error %q shows the file's content or lacks the package prefix", err)
				}
			})
		}
	})
}
