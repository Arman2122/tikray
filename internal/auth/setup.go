package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Arman2122/tikray/internal/store"
)

// codeAlphabet is Crockford's base32: the digits and the letters but I, L, O
// and U. Of the 32 symbols each takes 5 bits, so 12 of them are 60 bits.
const codeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// codeLen is the number of symbols in a setup code, and codeGroup how many of
// them are shown together, with a dash between the groups.
const (
	codeLen   = 12
	codeGroup = 4
)

// NewSetupCode returns a new random setup code of 12 symbols, shown in three
// groups of four: XXXX-XXXX-XXXX.
func NewSetupCode() (string, error) {
	b := make([]byte, codeLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: making a setup code: %w", err)
	}
	for i, v := range b {
		// 256 is a multiple of 32, so the low five bits are uniform.
		b[i] = codeAlphabet[v&31]
	}
	return formatSetupCode(string(b)), nil
}

// formatSetupCode shows the 12 symbols of a normalised code in groups.
func formatSetupCode(norm string) string {
	var sb strings.Builder
	for i := 0; i < len(norm); i += codeGroup {
		if i > 0 {
			sb.WriteByte('-')
		}
		sb.WriteString(norm[i:min(i+codeGroup, len(norm))])
	}
	return sb.String()
}

// NormalizeSetupCode returns s in the form two codes are compared in: ASCII
// letters in upper case, dashes and white space dropped, and the letters
// people read for a digit mapped to it (O to 0, I and L to 1). Anything else
// stays as it was, and so never matches a code. Only ASCII is upper-cased: a
// letter of another script that Unicode upper-cases to an I or an S is not one.
func NormalizeSetupCode(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '-' || unicode.IsSpace(r):
			return -1
		case r >= 'a' && r <= 'z':
			r -= 'a' - 'A'
		}
		switch r {
		case 'O':
			return '0'
		case 'I', 'L':
			return '1'
		}
		return r
	}, s)
}

// validSetupCode reports whether norm, a normalised string, is a setup code:
// 12 symbols of the alphabet. A file that holds anything else is no code, and
// is never compared with one (two empty strings are equal).
func validSetupCode(norm string) bool {
	if len(norm) != codeLen {
		return false
	}
	for i := 0; i < len(norm); i++ {
		if strings.IndexByte(codeAlphabet, norm[i]) < 0 {
			return false
		}
	}
	return true
}

// Public names appear in logs, token listings and session responses. A name
// containing a bearer, a session/CSRF value, a setup code in its display
// form, or a link must never be used to publish that credential. Match wire
// formats, without trying passwords or confirming guesses against the store.
const hiddenName = store.Masked

var credentialLabel = regexp.MustCompile(
	`(?i:(?:https?|vless|vmess|trojan|ss)://|[0-9A-HJKMNP-TV-Z]{4}(?:-[0-9A-HJKMNP-TV-Z]{4}){2})` +
		`|[0-9a-f]{64}|tkr_[0-9a-f]{8}_[A-Za-z0-9_-]{43}` +
		// A standalone, canonical base64url encoding of 32 bytes.
		`|(?:^|[^A-Za-z0-9_-])[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048](?:$|[^A-Za-z0-9_-])`)

// PublicName returns the label safe to display, including for older auth.json
// files that already contain a credential as an admin or token name.
func PublicName(name string) string {
	if credentialLabel.MatchString(name) {
		return hiddenName
	}
	return name
}

// PublicName applies the label rule of the package's PublicName, which is for
// the admin's username and the names of tokens, and also hides a name that
// holds a credential this store knows (see HoldsSecret).
func (s *Store) PublicName(name string, sess Session) string {
	// The longest supported display name is 128 runes (a store server).
	// Bound the work even when the caller has not yet validated its input.
	if len(name) > 128*utf8.UTFMax {
		return hiddenName
	}
	if sess.holds(name) {
		return hiddenName
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.publicNameLocked(name)
}

func (s *Store) publicNameLocked(name string) string {
	if PublicName(name) == hiddenName || s.holdsSecretLocked(name) {
		return hiddenName
	}
	return name
}

// HoldsSecret reports whether text holds a credential this store knows: the
// caller's session ID or CSRF token, the key of the CSRF tokens, or the ID of
// a session or the secret of a token it issued, found by its hash. Unlike
// PublicName it applies no label rule, so that text that merely looks like a
// credential, such as a server named "VMESS-HTTP-WS01", is no secret. It is
// for what the desired state holds: the names and routing values the API's
// views show.
func (s *Store) HoldsSecret(text string, sess Session) bool {
	if sess.holds(text) {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.holdsSecretLocked(text)
}

// holds reports whether text holds the session's own ID or CSRF token.
func (sess Session) holds(text string) bool {
	return (sess.ID != "" && strings.Contains(text, sess.ID)) || (sess.CSRF != "" && strings.Contains(text, sess.CSRF))
}

func (s *Store) holdsSecretLocked(text string) bool {
	if len(text) >= tokenSecretLen && strings.Contains(text, base64.StdEncoding.EncodeToString(s.csrfKey)) {
		return true
	}
	// The IDs and secrets share the same encoded length. Recording a new
	// plaintext copy to redact names would defeat their hashed storage. Both
	// are base64url, so only a window of those characters can be one: text
	// of other characters, however long, costs no hash.
	run := 0 // the base64url characters that end at text[i]
	for i := 0; i < len(text); i++ {
		if !base64URLChar(text[i]) {
			run = 0
			continue
		}
		if run++; run < tokenSecretLen {
			continue
		}
		h := sha256Hex(text[i+1-tokenSecretLen : i+1])
		if indexOfSession(s.d.Sessions, h) >= 0 {
			return true
		}
		for _, tok := range s.d.Tokens {
			if sameHash(tok.Hash, h) {
				return true
			}
		}
	}
	return false
}

// base64URLChar reports whether c is in the alphabet of base64url.
func base64URLChar(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_'
}
