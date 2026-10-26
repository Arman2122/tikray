package auth

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

var tokenForm = regexp.MustCompile(`^tkr_[0-9a-f]{8}_[A-Za-z0-9_-]{43}$`)

// secretOf is the secret part of a token: what its hash is made of.
func secretOf(tok string) string { return tok[len("tkr_")+8+1:] }

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestParseToken(t *testing.T) {
	const secret = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG" // 43 characters
	if len(secret) != 43 {
		t.Fatal("the test secret is not 43 characters")
	}
	const id = "0a1b2c3d"
	if gotID, gotSecret, ok := parseToken("tkr_" + id + "_" + secret); !ok || gotID != id || gotSecret != secret {
		t.Errorf("parseToken of a well-formed token = (%q, %q, %v)", gotID, gotSecret, ok)
	}
	// The whole base64url alphabet is allowed in the secret.
	if _, _, ok := parseToken("tkr_" + id + "_" + "-_" + secret[2:]); !ok {
		t.Error("parseToken refuses - and _ in the secret")
	}
	bad := map[string]string{
		"empty":                  "",
		"upper-case id":          "tkr_0A1B2C3D_" + secret,
		"mixed-case id":          "tkr_0a1b2c3D_" + secret,
		"id of 7":                "tkr_0a1b2c3_" + secret,
		"id of 9":                "tkr_0a1b2c3d4_" + secret,
		"id not hex":             "tkr_0a1b2c3g_" + secret,
		"secret of 42":           "tkr_" + id + "_" + secret[1:],
		"secret of 44":           "tkr_" + id + "_" + secret + "A",
		"secret with +":          "tkr_" + id + "_" + secret[:42] + "+",
		"secret with /":          "tkr_" + id + "_" + secret[:42] + "/",
		"secret with =":          "tkr_" + id + "_" + secret[:42] + "=",
		"secret with a space":    "tkr_" + id + "_" + secret[:42] + " ",
		"another prefix":         "tok_" + id + "_" + secret,
		"upper-case prefix":      "TKR_" + id + "_" + secret,
		"no prefix":              id + "_" + secret,
		"a dash for the _":       "tkr_" + id + "-" + secret,
		"a trailing newline":     "tkr_" + id + "_" + secret + "\n",
		"a leading newline":      "\ntkr_" + id + "_" + secret,
		"a NUL in the id":        "tkr_0a1b2c\x00d_" + secret,
		"a multi-byte in the id": "tkr_0a1b2cé_" + secret,
	}
	for name, v := range bad {
		if _, _, ok := parseToken(v); ok {
			t.Errorf("parseToken accepts %s", name)
		}
	}
}

// TestTokens is the life of an API token: made, checked, listed, revoked,
// expired, capped, and named by the rules.
func TestTokens(t *testing.T) {
	t.Run("create, check, revoke", testTokenBasics)
	t.Run("expiry", testTokenExpiry)
	t.Run("the cap of 50", testTokenCap)
	t.Run("names", testTokenNames)
}

func testTokenBasics(t *testing.T) {
	s, dir := openTest(t)
	clk := newClock()
	s.now = clk.Now
	t0 := clk.Now()

	info, tok, err := s.CreateToken("backup script", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if !tokenForm.MatchString(tok) {
		t.Fatalf("the token is not tkr_<8 hex>_<43 base64url> (%d characters)", len(tok))
	}
	if info.ID != tok[4:12] || info.Name != "backup script" || !info.Created.Equal(t0) || !info.Expires.IsZero() || !info.LastUsed.IsZero() {
		t.Errorf("the info of a new token is %+v", info)
	}

	// Checking it finds it, and notes its use.
	clk.Advance(time.Minute)
	got, ok := s.CheckToken(tok)
	if !ok {
		t.Fatal("a new token does not check")
	}
	if got.ID != info.ID || got.Name != info.Name || !got.LastUsed.Equal(clk.Now()) {
		t.Errorf("CheckToken gave %+v", got)
	}

	// The list shows the token and never its secret, in any form.
	list := s.Tokens()
	if len(list) != 1 || list[0].ID != info.ID || list[0].Name != "backup script" || !list[0].LastUsed.Equal(clk.Now()) {
		t.Fatalf("Tokens() = %+v", list)
	}
	shown := fmt.Sprintf("%+v %#v %v", list, list, got)
	if strings.Contains(shown, secretOf(tok)) || strings.Contains(shown, tok) || strings.Contains(shown, sumHex(secretOf(tok))) {
		t.Error("Tokens() shows the secret of a token, or its hash")
	}

	// Two tokens are two secrets.
	info2, tok2, err := s.CreateToken("backup script", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if info2.ID == info.ID || secretOf(tok2) == secretOf(tok) {
		t.Error("two tokens share an id or a secret")
	}
	if got, ok := s.CheckToken(tok2); !ok || got.ID != info2.ID {
		t.Error("the second token does not check as itself")
	}

	// What is wrong with a token is never an error that says more than no.
	bad := map[string]string{
		"empty":                     "",
		"the prefix":                "tkr_",
		"no prefix":                 tok[4:],
		"another prefix":            "tkx_" + tok[4:],
		"upper-case prefix":         "TKR_" + tok[4:],
		"only the secret":           secretOf(tok),
		"too short":                 tok[:len(tok)-1],
		"too long":                  tok + "A",
		"a trailing newline":        tok + "\n",
		"a leading space":           " " + tok,
		"two tokens":                tok + tok,
		"id too short":              "tkr_" + info.ID[:7] + tok[12:],
		"id not hex":                "tkr_zzzzzzzz" + tok[12:],
		"no separator":              tok[:12] + "-" + tok[13:],
		"separator moved":           tok[:11] + "_" + tok[11:12] + tok[13:],
		"a wrong secret":            tok[:13] + flip(secretOf(tok)),
		"another token's secret":    tok[:13] + secretOf(tok2),
		"another token's id":        tok2[:13] + secretOf(tok),
		"a character off the set":   tok[:len(tok)-1] + "+",
		"a padding":                 tok[:len(tok)-1] + "=",
		"a NUL":                     tok[:len(tok)-1] + "\x00",
		"a multi-byte character":    tok[:len(tok)-2] + "é",
		"the secret of the hash":    tok[:13] + sumHex(secretOf(tok))[:43],
		"an unknown id, any secret": "tkr_00000000_" + secretOf(tok),
	}
	for name, v := range bad {
		if _, ok := s.CheckToken(v); ok {
			t.Errorf("CheckToken accepts %s", name)
		}
	}

	// Revoking: it stops checking at once, and is gone from the list.
	if err := s.RevokeToken(info.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.CheckToken(tok); ok {
		t.Error("a revoked token still checks")
	}
	if _, ok := s.CheckToken(tok2); !ok {
		t.Error("revoking one token ended another")
	}
	if list := s.Tokens(); len(list) != 1 || list[0].ID != info2.ID {
		t.Errorf("Tokens() after a revoke = %+v", list)
	}
	for _, id := range []string{info.ID, "", "00000000", "not an id", tok} {
		if err := s.RevokeToken(id); !errors.Is(err, ErrNoToken) {
			t.Errorf("RevokeToken(%q) of a token that is not there: %v, want ErrNoToken", id, err)
		} else {
			noSecrets(t, "revoke", err, tok, tok2)
		}
	}
	// And it is gone for good.
	s2, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.CheckToken(tok); ok {
		t.Error("a revoked token checks after a restart")
	}
	if _, ok := s2.CheckToken(tok2); !ok {
		t.Error("the token that was not revoked is lost after a restart")
	}
}

func testTokenExpiry(t *testing.T) {
	s, _ := openTest(t)
	clk := newClock()
	s.now = clk.Now
	start := clk.Now()

	info, tok, err := s.CreateToken("short", start.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !info.Expires.Equal(start.Add(time.Hour)) {
		t.Errorf("the token expires at %v, want an hour on", info.Expires)
	}
	clk.Advance(time.Hour - time.Nanosecond)
	if _, ok := s.CheckToken(tok); !ok {
		t.Error("a token a nanosecond before its expiry does not check")
	}
	clk.Advance(time.Nanosecond)
	if _, ok := s.CheckToken(tok); ok {
		t.Error("a token at its expiry still checks")
	}
	clk.Advance(24 * time.Hour)
	if _, ok := s.CheckToken(tok); ok {
		t.Error("an expired token checks later")
	}
	// An expired token is still listed, so that it can be seen and revoked.
	if list := s.Tokens(); len(list) != 1 || list[0].ID != info.ID || !list[0].Expires.Equal(start.Add(time.Hour)) {
		t.Errorf("Tokens() = %+v, want the expired token", list)
	}
	if err := s.RevokeToken(info.ID); err != nil {
		t.Errorf("revoking an expired token: %v", err)
	}

	// An expiry that is not in the future is refused, and nothing is made.
	for name, at := range map[string]time.Time{"now": clk.Now(), "the past": clk.Now().Add(-time.Hour)} {
		_, tok, err := s.CreateToken("late", at)
		if !errors.Is(err, ErrInvalid) || tok != "" {
			t.Errorf("an expiry of %s: (%q, %v), want ErrInvalid and no token", name, tok, err)
		}
	}
	if n := len(s.Tokens()); n != 0 {
		t.Errorf("%d tokens after refused ones", n)
	}
	// A time zone is the same instant.
	zone := time.FixedZone("x", 5*3600)
	_, tok, err = s.CreateToken("zoned", clk.Now().Add(time.Hour).In(zone))
	if err != nil {
		t.Fatal(err)
	}
	clk.Advance(30 * time.Minute)
	if _, ok := s.CheckToken(tok); !ok {
		t.Error("a token with an expiry in another time zone does not check")
	}
}

func testTokenCap(t *testing.T) {
	s, _ := openTest(t)
	clk := newClock()
	s.now = clk.Now
	// The first token expires in an hour; the other 49 never do.
	var first TokenInfo
	var firstTok string
	for i := range 50 {
		var expires time.Time
		if i == 0 {
			expires = clk.Now().Add(time.Hour)
		}
		info, tok, err := s.CreateToken(fmt.Sprintf("token %d", i), expires)
		if err != nil {
			t.Fatalf("token %d: %v", i, err)
		}
		if i == 0 {
			first, firstTok = info, tok
		}
	}
	_, tok, err := s.CreateToken("one too many", time.Time{})
	if !errors.Is(err, ErrTokenLimit) || tok != "" {
		t.Errorf("the 51st token: (%q, %v), want ErrTokenLimit and no token", tok, err)
	}
	noSecrets(t, "limit", err)
	if n := len(s.Tokens()); n != 50 {
		t.Errorf("%d tokens, want 50", n)
	}

	// An expired token counts toward the 50 until it is revoked: it is still
	// listed, so that it can be seen and removed.
	clk.Advance(2 * time.Hour)
	if _, ok := s.CheckToken(firstTok); ok {
		t.Fatal("the token that was to expire in an hour still checks after two")
	}
	_, tok, err = s.CreateToken("one more", time.Time{})
	if !errors.Is(err, ErrTokenLimit) || tok != "" {
		t.Errorf("a token with one of the 50 expired: (%q, %v), want ErrTokenLimit and no token", tok, err)
	}
	if list := s.Tokens(); len(list) != 50 || list[0].ID != first.ID {
		t.Errorf("Tokens() lists %d tokens with an expired one, want 50 with it first", len(list))
	}

	// A revoke (of the expired one, say) makes room.
	if err := s.RevokeToken(first.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateToken("room again", time.Time{}); err != nil {
		t.Errorf("a token after a revoke at the cap: %v", err)
	}
	if n := len(s.Tokens()); n != 50 {
		t.Errorf("%d tokens, want 50", n)
	}
}

func testTokenNames(t *testing.T) {
	s, _ := openTest(t)
	cases := []struct {
		name, in string
		ok       bool
	}{
		{"empty", "", false},
		{"one rune", "a", true},
		{"64 ASCII", strings.Repeat("a", 64), true},
		{"65 ASCII", strings.Repeat("a", 65), false},
		{"64 runes of 2 bytes", strings.Repeat("é", 64), true},
		{"65 runes of 2 bytes", strings.Repeat("é", 65), false},
		{"non-Latin", "管理者のトークン", true},
		{"spaces inside", "my backup script", true},
		{"newline", "my\nscript", false},
		{"tab", "my\tscript", false},
		{"NUL", "my\x00script", false},
		{"DEL", "my\x7fscript", false},
		{"C1 control", "my\u0085script", false},
		{"line separator", "my script", false},
		{"bidi override", "my‮script", false},
		{"bidi isolate", "my⁦script", false},
		{"invalid UTF-8", "my\xffscript", false},
	}
	for _, c := range cases {
		info, tok, err := s.CreateToken(c.in, time.Time{})
		if (err == nil) != c.ok {
			t.Errorf("%s: CreateToken = %v, ok want %v", c.name, err, c.ok)
			continue
		}
		if err != nil {
			if !errors.Is(err, ErrInvalid) || tok != "" {
				t.Errorf("%s: (%q, %v), want ErrInvalid and no token", c.name, tok, err)
			}
			noSecrets(t, c.name, err)
			continue
		}
		if info.Name != c.in {
			t.Errorf("%s: the name was changed", c.name)
		}
		if err := s.RevokeToken(info.ID); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTokenHashOnDisk(t *testing.T) {
	s, dir := openTest(t)
	info, tok, err := s.CreateToken("ci", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	file := readFile(t, filepath.Join(dir, "auth.json"))
	if strings.Contains(file, tok) || strings.Contains(file, secretOf(tok)) {
		t.Error("auth.json holds an API token or its secret")
	}
	v := readView(t, dir)
	if len(v.Tokens) != 1 {
		t.Fatalf("auth.json holds %d tokens, want 1", len(v.Tokens))
	}
	rec := v.Tokens[0]
	// The hash is of the secret part, not of the whole token.
	if rec.ID != info.ID || rec.Name != "ci" || rec.Hash != sumHex(secretOf(tok)) {
		t.Error("auth.json holds a token record other than the id, the name and the SHA-256 of the secret part")
	}
	if rec.Hash == sumHex(tok) {
		t.Error("the stored hash is of the whole token")
	}
	// The hash is no credential: it does not check as a secret.
	if _, ok := s.CheckToken("tkr_" + info.ID + "_" + rec.Hash[:43]); ok {
		t.Error("the stored hash checks as a token")
	}
}

func TestTokenLastUsedSavedLazily(t *testing.T) {
	s, dir := openTest(t)
	clk := newClock()
	s.now = clk.Now
	_, tok, err := s.CreateToken("ci", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "auth.json")

	// The first use is saved (nothing was saved before it): a token is seen to
	// have been used.
	clk.Advance(time.Minute)
	use1 := clk.Now()
	if _, ok := s.CheckToken(tok); !ok {
		t.Fatal("the token does not check")
	}
	if v := readView(t, dir); !v.Tokens[0].LastUsed.Equal(use1) {
		t.Errorf("the first use was saved as %v, want %v", v.Tokens[0].LastUsed, use1)
	}
	saved := readFile(t, path)

	// Uses less than 10 minutes on are in memory only.
	clk.Advance(5 * time.Minute)
	use2 := clk.Now()
	got, ok := s.CheckToken(tok)
	if !ok || !got.LastUsed.Equal(use2) {
		t.Fatalf("the use is not noted in memory (%v, %v)", ok, got.LastUsed)
	}
	if readFile(t, path) != saved {
		t.Error("a use 5 minutes after the saved one rewrote auth.json")
	}
	if list := s.Tokens(); !list[0].LastUsed.Equal(use2) {
		t.Error("Tokens() does not show the use that is not saved yet")
	}
	clk.Advance(5 * time.Minute) // 10 minutes from the saved one: not yet more
	s.CheckToken(tok)
	if readFile(t, path) != saved {
		t.Error("a use exactly 10 minutes after the saved one rewrote auth.json")
	}

	// More than 10 minutes on, it is saved.
	clk.Advance(time.Second)
	use3 := clk.Now()
	s.CheckToken(tok)
	if v := readView(t, dir); !v.Tokens[0].LastUsed.Equal(use3) {
		t.Errorf("auth.json holds last_used %v, want %v", v.Tokens[0].LastUsed, use3)
	}

	// A write for another reason takes the pending use along.
	saved = readFile(t, path)
	clk.Advance(2 * time.Minute)
	use4 := clk.Now()
	s.CheckToken(tok)
	if readFile(t, path) != saved {
		t.Fatal("a use 2 minutes after the saved one rewrote auth.json")
	}
	if _, _, err := s.CreateToken("other", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if v := readView(t, dir); !v.Tokens[0].LastUsed.Equal(use4) {
		t.Errorf("a write for another reason left last_used at %v, want %v", v.Tokens[0].LastUsed, use4)
	}

	// And a restart reads what was saved.
	s2, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	s2.now = clk.Now
	if list := s2.Tokens(); !list[0].LastUsed.Equal(use4) {
		t.Errorf("a restart reads last_used %v, want %v", list[0].LastUsed, use4)
	}

	// A use that can't be saved is still a use: the token checks.
	breakAuthFile(t, dir)
	clk.Advance(time.Hour)
	if _, ok := s2.CheckToken(tok); !ok {
		t.Error("a token stopped checking because its use could not be saved")
	}
}

func TestTokenWritesThatFailChangeNothing(t *testing.T) {
	s, dir := openTest(t)
	info, tok, err := s.CreateToken("ci", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	breakAuthFile(t, dir)

	_, tok2, err := s.CreateToken("new", time.Time{})
	if err == nil || tok2 != "" {
		t.Errorf("CreateToken with no way to save: (%q, %v), want an error and no token", tok2, err)
	} else {
		noSecrets(t, "create", err, tok)
	}
	if n := len(s.Tokens()); n != 1 {
		t.Errorf("%d tokens after a create that failed, want 1", n)
	}
	if err := s.RevokeToken(info.ID); err == nil {
		t.Error("RevokeToken with no way to save was a success")
	} else {
		noSecrets(t, "revoke", err, tok)
	}
	if _, ok := s.CheckToken(tok); !ok {
		t.Error("a revoke that failed ended the token")
	}
}

func TestOpenRefusesBadTokensAndSessions(t *testing.T) {
	good := sumHex("x")
	key := `"csrf_key":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="`
	tok := func(id, name, hash string) string {
		return `{"id":"` + id + `","name":"` + name + `","hash":"` + hash + `","created":"2026-10-26T12:00:00Z"}`
	}
	file := func(tokens, sessions string) string {
		return `{"version":1,` + key + `,"tokens":[` + tokens + `],"sessions":[` + sessions + `]}`
	}
	cases := map[string]string{
		"token with a short id":     file(tok("abcdef0", "ci", good), ""),
		"token with an id not hex":  file(tok("abcdefgh", "ci", good), ""),
		"token with an upper id":    file(tok("ABCDEF01", "ci", good), ""),
		"token with no hash":        file(tok("abcdef01", "ci", ""), ""),
		"token with a short hash":   file(tok("abcdef01", "ci", good[:63]), ""),
		"token with a hash not hex": file(tok("abcdef01", "ci", strings.Repeat("z", 64)), ""),
		"token with no name":        file(tok("abcdef01", "", good), ""),
		"token with a bidi name":    file(tok("abcdef01", `SECRETMARKER‮`, good), ""),
		"token with a long name":    file(tok("abcdef01", strings.Repeat("a", 65), good), ""),
		"two tokens with one id":    file(tok("abcdef01", "a", good)+","+tok("abcdef01", "b", good), ""),
		"session with no hash":      file("", `{"hash":"","created":"2026-10-26T12:00:00Z","last_used":"2026-10-26T12:00:00Z"}`),
		"session with a short hash": file("", `{"hash":"`+good[:10]+`","created":"2026-10-26T12:00:00Z","last_used":"2026-10-26T12:00:00Z"}`),
		"session of another type":   file("", `"SECRETMARKER"`),
		"time of another type":      file("", `{"hash":"`+good+`","created":"SECRETMARKER","last_used":"2026-10-26T12:00:00Z"}`),
		"two sessions with one id":  file("", `{"hash":"`+good+`","created":"2026-10-26T12:00:00Z","last_used":"2026-10-26T12:00:00Z"},{"hash":"`+good+`","created":"2026-10-26T12:00:00Z","last_used":"2026-10-26T12:00:00Z"}`),
	}
	for name, content := range cases {
		dir := t.TempDir()
		path := filepath.Join(dir, "auth.json")
		writeFile(t, path, content)
		_, err := OpenStore(dir)
		if err == nil {
			t.Errorf("%s: OpenStore took the file", name)
			continue
		}
		noSecrets(t, name, err, "SECRETMARKER", good)
		if got := readFile(t, path); got != content {
			t.Errorf("%s: OpenStore changed the file it refused", name)
		}
	}

	// The same shapes, right, open.
	dir := t.TempDir()
	ok := file(tok("abcdef01", "ci", good), `{"hash":"`+good+`","created":"2026-10-26T12:00:00Z","last_used":"2026-10-26T12:00:00Z"}`)
	writeFile(t, filepath.Join(dir, "auth.json"), ok)
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore refused a file with a token and a session: %v", err)
	}
	if list := s.Tokens(); len(list) != 1 || list[0].ID != "abcdef01" || list[0].Name != "ci" {
		t.Errorf("Tokens() = %+v", list)
	}
}
