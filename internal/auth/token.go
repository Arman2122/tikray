package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Arman2122/tikray/internal/store"
)

// The API tokens: named credentials for scripts, each
// tkr_<8 hex digits of its id>_<43 base64url characters of its secret>. The
// id is for listing and revoking, and is not secret. Only the SHA-256 of the
// secret part is kept.
const (
	tokenPrefix      = "tkr_"
	tokenIDLen       = 8  // hex digits: 4 random bytes
	tokenSecretBytes = 32 // 43 characters in unpadded base64url
	tokenSecretLen   = 43
	tokenLen         = len(tokenPrefix) + tokenIDLen + 1 + tokenSecretLen

	maxTokens         = 50
	maxTokenNameRunes = 64

	// The use of a token is noted in memory and saved when the saved one is
	// more than this stale (CheckToken), or with the next write.
	tokenSaveEvery = 10 * time.Minute
)

var (
	// ErrTokenLimit is the answer to a new token when there are already 50.
	ErrTokenLimit = errors.New("auth: there are already 50 API tokens: revoke one first")
	// ErrNoToken is the answer to the revoke of a token that does not exist.
	ErrNoToken = errors.New("auth: there is no such API token")
)

// TokenInfo is what is known of a token apart from its secret, which is shown
// once, when the token is made.
type TokenInfo struct {
	ID      string
	Name    string
	Created time.Time
	// Expires is when the token stops working; zero is never.
	Expires time.Time
	// LastUsed is the last time it was used; zero is never. It is noted in
	// memory at each use, and saved at most every 10 minutes.
	LastUsed time.Time
}

// tokenRecord is a token as auth.json holds it: its id, its name, the SHA-256
// of its secret part (in hex) and its times.
type tokenRecord struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Hash     string    `json:"hash"`
	Created  time.Time `json:"created"`
	Expires  time.Time `json:"expires,omitzero"`
	LastUsed time.Time `json:"last_used,omitzero"`

	saved time.Time // the LastUsed that auth.json holds
}

func (r *tokenRecord) info() TokenInfo {
	return TokenInfo{ID: r.ID, Name: r.Name, Created: r.Created, Expires: r.Expires, LastUsed: r.LastUsed}
}

// validTokenName checks the rules for the name of a token: 1 to 64 runes of
// valid UTF-8, none of them one that a name may not hold
// (store.ForbiddenInName). The error is an ErrInvalid.
func validTokenName(name string) error {
	switch n := utf8.RuneCountInString(name); {
	case !utf8.ValidString(name):
		return invalidError("the name of a token must be valid UTF-8")
	case n < 1:
		return invalidError("the name of a token must not be empty")
	case n > maxTokenNameRunes:
		return invalidError(fmt.Sprintf("the name of a token must be at most %d characters", maxTokenNameRunes))
	case strings.ContainsFunc(name, store.ForbiddenInName):
		return invalidError("the name of a token must not hold a control character or a character that changes the direction of text")
	}
	return nil
}

// validTokenID reports whether id is 8 lower-case hex digits.
func validTokenID(id string) bool {
	if len(id) != tokenIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		if c := id[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// validTokenRecords reports whether auth.json's tokens are usable.
func validTokenRecords(list []tokenRecord) bool {
	seen := make(map[string]bool, len(list))
	for _, r := range list {
		if !validTokenID(r.ID) || seen[r.ID] || !validHash(r.Hash) || validTokenName(r.Name) != nil {
			return false
		}
		seen[r.ID] = true
	}
	return true
}

// parseToken splits a token into its id and its secret part. It is false for
// anything that is not exactly tkr_<8 lower-case hex digits>_<43 characters of
// base64url>.
func parseToken(tok string) (id, secret string, ok bool) {
	if len(tok) != tokenLen || !strings.HasPrefix(tok, tokenPrefix) || tok[len(tokenPrefix)+tokenIDLen] != '_' {
		return "", "", false
	}
	id = tok[len(tokenPrefix) : len(tokenPrefix)+tokenIDLen]
	secret = tok[len(tokenPrefix)+tokenIDLen+1:]
	if !validTokenID(id) {
		return "", "", false
	}
	for i := 0; i < len(secret); i++ {
		c := secret[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && c != '-' && c != '_' {
			return "", "", false
		}
	}
	return id, secret, true
}

// CreateToken makes an API token with the name name, which stops working at
// expires (the zero time is never; a time that is not in the future is an
// ErrInvalid). It returns what is known of the token and the token itself:
// that is the only time anyone can see it, since only a hash of its secret is
// kept. A name that breaks the rules is an ErrInvalid, and a 51st token is
// ErrTokenLimit.
func (s *Store) CreateToken(name string, expires time.Time) (TokenInfo, string, error) {
	if err := validTokenName(name); err != nil {
		return TokenInfo{}, "", err
	}
	now := s.clock()
	if !expires.IsZero() {
		expires = expires.UTC().Round(0)
		if !expires.After(now) {
			return TokenInfo{}, "", invalidError("the expiry of a token must be in the future")
		}
	}
	secretRaw := make([]byte, tokenSecretBytes)
	if _, err := rand.Read(secretRaw); err != nil {
		return TokenInfo{}, "", fmt.Errorf("auth: making a token: %w", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(secretRaw)

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.d.Tokens) >= maxTokens {
		return TokenInfo{}, "", ErrTokenLimit
	}
	var id string
	for {
		idRaw := make([]byte, tokenIDLen/2)
		if _, err := rand.Read(idRaw); err != nil {
			return TokenInfo{}, "", fmt.Errorf("auth: making a token: %w", err)
		}
		id = hex.EncodeToString(idRaw)
		if !slices.ContainsFunc(s.d.Tokens, func(r tokenRecord) bool { return r.ID == id }) {
			break
		}
	}
	rec := tokenRecord{ID: id, Name: name, Hash: sha256Hex(secret), Created: now, Expires: expires}
	next := s.d
	next.Tokens = append(slices.Clone(s.d.Tokens), rec)
	if err := s.commit(next); err != nil {
		return TokenInfo{}, "", err
	}
	return rec.info(), tokenPrefix + id + "_" + secret, nil
}

// Tokens lists the API tokens, the oldest first, with no secret: a token that
// has expired is listed until it is revoked.
func (s *Store) Tokens() []TokenInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]TokenInfo, len(s.d.Tokens))
	for i := range s.d.Tokens {
		out[i] = s.d.Tokens[i].info()
	}
	return out
}

// RevokeToken removes the token with the id id: from then on it doesn't check.
// An id that is no token is ErrNoToken. A removal that can't be saved is an
// error, and changes nothing.
func (s *Store) RevokeToken(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := slices.IndexFunc(s.d.Tokens, func(r tokenRecord) bool { return r.ID == id })
	if i < 0 {
		return ErrNoToken
	}
	next := s.d
	next.Tokens = slices.Delete(slices.Clone(s.d.Tokens), i, i+1)
	return s.commit(next)
}

// CheckToken reports whether tok is a token that works: of the exact format,
// with an id that is known, a secret whose SHA-256 is the one kept (compared in
// constant time) and an expiry that has not come. Its use is noted in memory,
// and saved when the saved one is more than 10 minutes stale (and with any
// other write, whenever it comes). A use that can't be saved is still a use.
func (s *Store) CheckToken(tok string) (TokenInfo, bool) {
	id, secret, ok := parseToken(tok)
	if !ok {
		return TokenInfo{}, false
	}
	h := sha256Hex(secret)
	now := s.clock()
	s.mu.Lock()
	defer s.mu.Unlock()
	i := slices.IndexFunc(s.d.Tokens, func(r tokenRecord) bool { return r.ID == id })
	if i < 0 {
		return TokenInfo{}, false
	}
	rec := &s.d.Tokens[i]
	if !sameHash(rec.Hash, h) {
		return TokenInfo{}, false
	}
	if !rec.Expires.IsZero() && !now.Before(rec.Expires) {
		return TokenInfo{}, false
	}
	if now.After(rec.LastUsed) {
		rec.LastUsed = now
	}
	if rec.LastUsed.Sub(rec.saved) > tokenSaveEvery {
		// A failure is not the token's: it stays valid, and the use is saved
		// by the next write.
		_ = s.commit(s.d)
	}
	return rec.info(), true
}
