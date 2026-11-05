package auth

import (
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

var codeForm = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$`)

func TestSetupCodeFormatAndNormalize(t *testing.T) {
	seen := map[string]bool{}
	for range 50 {
		code, err := NewSetupCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(code) != 14 || code[4] != '-' || code[9] != '-' {
			t.Fatalf("a code has the wrong shape: len %d", len(code))
		}
		if !codeForm.MatchString(code) {
			t.Fatal("a code has a symbol outside the alphabet")
		}
		if seen[code] {
			t.Fatal("the same code came twice in 50 draws")
		}
		seen[code] = true
		// A code is its own canonical form once the dashes are gone.
		if got := NormalizeSetupCode(code); got != strings.ReplaceAll(code, "-", "") {
			t.Fatal("a code does not normalise to itself without its dashes")
		}
	}

	norm := map[string]string{
		"abcd efgh-ijkl":    "ABCDEFGH1JK1", // I and L are 1
		"ABCD-EFGH-IJKL":    "ABCDEFGH1JK1",
		" 0o1i-lL ":         "001111", // O is 0, I and L are 1
		"o0O0-1I1l-LiIl":    "000011111111",
		"abcdefgh1jk1":      "ABCDEFGH1JK1",
		"  ab\tcd\nef-gh ":  "ABCDEFGH", // any white space goes
		"":                  "",
		"----  ":            "",
		"u-v":               "UV",           // U is not in the alphabet: it stays, and never matches
		"\u0131-\u017f":     "\u0131\u017f", // only ASCII is upper-cased: no look-alike becomes I or S
		"0123-4567-89AB":    "0123456789AB",
		"x\u202ey":          "X\u202eY",
		"zzzz-zzzz-zzzz-zz": "ZZZZZZZZZZZZZZ",
	}
	for in, want := range norm {
		if got := NormalizeSetupCode(in); got != want {
			t.Errorf("NormalizeSetupCode(%q) = %q, want %q", in, got, want)
		}
	}

	// Typing a code the way a person might, with the O, I and L they see in
	// place of the 0 and 1, in lower case and with spaces, finds the same code.
	code, err := NewSetupCode()
	if err != nil {
		t.Fatal(err)
	}
	typed := strings.NewReplacer("0", "o", "1", "l", "-", " ").Replace(strings.ToLower(code))
	if NormalizeSetupCode(typed) != NormalizeSetupCode(code) {
		t.Error("a sloppy copy of the code did not normalize to the original")
	}
}

func TestSetupCodeAlphabetHasNoLookAlikes(t *testing.T) {
	if len(codeAlphabet) != 32 {
		t.Fatalf("the alphabet has %d symbols, want 32", len(codeAlphabet))
	}
	if codeAlphabet != "0123456789ABCDEFGHJKMNPQRSTVWXYZ" {
		t.Errorf("the alphabet is not Crockford's base32")
	}
	for _, r := range "ILOU" {
		if strings.ContainsRune(codeAlphabet, r) {
			t.Errorf("the alphabet holds %q", r)
		}
	}
}

// HoldsSecret finds what the store issued, wherever it sits in a text, and
// nothing that only looks like a credential: it is for values of the state,
// such as a server's name, which no label rule applies to.
func TestHoldsSecretFindsOnlyRealSecrets(t *testing.T) {
	s, dir := openTest(t)
	claim(t, s, dir, "alice", "correct horse battery")
	sess, err := s.SignIn(t.Context(), "alice", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	_, tok, err := s.CreateToken("ci", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	// Found by their hashes, with no caller to compare with.
	for name, text := range map[string]string{
		"a token":               "ci " + tok,
		"a token's secret":      "ci-" + secretOf(tok) + ".example",
		"a session's ID":        "regexp:" + sess.ID,
		"the CSRF key, as text": "key " + base64.StdEncoding.EncodeToString(s.csrfKey),
	} {
		if !s.HoldsSecret(text, Session{}) {
			t.Errorf("%s was not found", name)
		}
	}
	if !s.HoldsSecret("x"+sess.CSRF, sess) || s.HoldsSecret("x"+sess.CSRF, Session{}) {
		t.Error("the caller's CSRF token is found only with the caller's session")
	}
	for _, text := range []string{
		"VMESS-HTTP-WS01", "test-test-test", "ABCD-EFGH-JKMN", "https://provider.example",
		strings.Repeat("a", 64), "tkr_00000000_" + strings.Repeat("A", 43), strings.Repeat("b", 10000),
	} {
		if s.HoldsSecret(text, sess) {
			t.Errorf("%q is taken for a secret", text)
		}
	}
}

// The label rule hides a setup code only as a standalone token of 14
// characters, XXXX-XXXX-XXXX, in either case: dashed groups inside a longer
// name, such as a server's "VMESS-HTTP-WS01" or a UUID, are no setup code.
func TestPublicNameMatchesStandaloneSetupCodes(t *testing.T) {
	for _, name := range []string{
		"ABCD-EFGH-JKMN",
		"abcd-efgh-jkmn",
		"code: ABCD-EFGH-JKMN.",
		"admin (0123-4567-89AB)",
	} {
		if got := PublicName(name); got != hiddenName {
			t.Errorf("PublicName(%q) = %q, want it hidden", name, got)
		}
	}
	for _, name := range []string{
		"VMESS-HTTP-WS01",
		"node 5fdc6e8a-4a2b-4a3c",
		"ABCD-EFGH-JKMN-PQRS",
		"xABCD-EFGH-JKMN",
		"ABCD-EFGH-JKMN_2",
		"backup script",
	} {
		if got := PublicName(name); got != name {
			t.Errorf("PublicName(%q) = %q, want it shown", name, got)
		}
	}
	s, _ := openTest(t)
	if info, _, err := s.CreateToken("VMESS-HTTP-WS01 deploy", time.Time{}); err != nil || info.Name != "VMESS-HTTP-WS01 deploy" {
		t.Errorf("CreateToken of an ordinary name = %+v, %v", info, err)
	}
	if _, _, err := s.CreateToken("ci ABCD-EFGH-JKMN", time.Time{}); !errors.Is(err, ErrInvalid) {
		t.Errorf("CreateToken with a setup code in its name = %v, want ErrInvalid", err)
	}
}
