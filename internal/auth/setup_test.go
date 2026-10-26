package auth

import (
	"regexp"
	"strings"
	"testing"
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
			t.Fatalf("a code has a symbol outside the alphabet: %q", code)
		}
		if seen[code] {
			t.Fatalf("the same code came twice in 50 draws: %q", code)
		}
		seen[code] = true
		// A code is its own canonical form once the dashes are gone.
		if got := NormalizeSetupCode(code); got != strings.ReplaceAll(code, "-", "") {
			t.Fatalf("a code does not normalise to itself without its dashes: %q", code)
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
		t.Errorf("a sloppy copy of %q (%q) does not normalise to it", code, typed)
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
