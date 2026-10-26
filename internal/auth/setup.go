package auth

import (
	"crypto/rand"
	"fmt"
	"strings"
	"unicode"
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
