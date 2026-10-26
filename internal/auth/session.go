package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"
)

// The limits of a session.
const (
	sessionIdle = 12 * time.Hour     // since the last use
	sessionLife = 7 * 24 * time.Hour // since the sign-in, however much it is used
	maxSessions = 20                 // the oldest to start is dropped for a 21st

	// A slide of the idle limit (the use of a session) is noted in memory at
	// once, and saved when the saved one is more than this stale, so that a
	// busy page does not rewrite auth.json with every request. A restart
	// then loses at most this much of a slide.
	sessionSaveEvery = time.Hour

	sessionIDBytes = 32
)

// sessionIDLen is the length of a session id: sessionIDBytes in unpadded
// base64url.
var sessionIDLen = base64.RawURLEncoding.EncodedLen(sessionIDBytes)

// ErrBadCredentials is the answer to every sign-in that fails for the pair it
// was given: a username that is not the admin's, a password that is not right,
// or no admin yet. It is one error with one message, so that the answer
// doesn't say which.
var ErrBadCredentials = errors.New("auth: the username or the password is not right")

// Session is a signed-in session, as SignIn and Session return it.
type Session struct {
	// ID is the secret of the session, for its cookie. The store keeps only its
	// SHA-256, so it is the caller's to hold and never to log.
	ID string
	// CSRF is the token that goes with the session (CSRFFor).
	CSRF string
	// Expires is when the session ends if it is not used again: 12 hours after
	// its last use, and never later than 7 days after its sign-in.
	Expires time.Time
}

// sessionRecord is a session as auth.json holds it: the SHA-256 of its id
// (in hex) and its times. The id is not in the file, and neither is the CSRF
// token, which is made from the id when it is asked for.
type sessionRecord struct {
	Hash    string    `json:"hash"`
	Created time.Time `json:"created"`
	// LastUsed is the last use that the store knows. In the file it is the
	// last one that was saved, which can be up to sessionSaveEvery behind.
	LastUsed time.Time `json:"last_used"`

	saved time.Time // the LastUsed that auth.json holds
}

// expires is when the session ends if it is not used again.
func (r *sessionRecord) expires() time.Time {
	idle, life := r.LastUsed.Add(sessionIdle), r.Created.Add(sessionLife)
	if life.Before(idle) {
		return life
	}
	return idle
}

// liveAt reports whether the session is still valid at now.
func (r *sessionRecord) liveAt(now time.Time) bool { return now.Before(r.expires()) }

// sha256Hex is the hash of a secret as auth.json holds it: SHA-256 in
// lower-case hex.
func sha256Hex(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// validHash reports whether h is what sha256Hex returns.
func validHash(h string) bool {
	if len(h) != 2*sha256.Size {
		return false
	}
	for i := 0; i < len(h); i++ {
		if c := h[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// sameHash compares two hashes in constant time.
func sameHash(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// sameText compares two strings in constant time, whatever their lengths: it
// compares their hashes.
func sameText(a, b string) bool {
	x, y := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(x[:], y[:]) == 1
}

// validSessionRecords reports whether auth.json's sessions are usable: each
// has a hash, and no two have the same.
func validSessionRecords(list []sessionRecord) bool {
	seen := make(map[string]bool, len(list))
	for _, r := range list {
		if !validHash(r.Hash) || seen[r.Hash] {
			return false
		}
		seen[r.Hash] = true
	}
	return true
}

// indexOfSession is the index of the session whose id has the hash h, or -1.
// It compares with every record, so that the time does not tell where in the
// list a hash is.
func indexOfSession(list []sessionRecord, h string) int {
	idx := -1
	for i := range list {
		if sameHash(list[i].Hash, h) {
			idx = i
		}
	}
	return idx
}

// onlySession returns the sessions of list that have the id keep: none for an
// empty keep.
func onlySession(list []sessionRecord, keep string) []sessionRecord {
	if keep == "" {
		return nil
	}
	h := sha256Hex(keep)
	var out []sessionRecord
	for _, r := range list {
		if sameHash(r.Hash, h) {
			out = append(out, r)
		}
	}
	return out
}

// csrfToken is the CSRF token of a session: base64url(HMAC-SHA256(key, id)).
func csrfToken(key []byte, id string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(id))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// SignIn starts a session when username and password are the admin's, and is
// ErrBadCredentials for any pair that is not, however it is wrong. It always
// runs one argon2 check, so that no answer is quicker than another: against
// the admin's hash when the username is the admin's, and against DummyHash
// when it is not (or when there is no admin). Which it is is decided by the
// usernames alone, compared in constant time; the dummy check is for its time
// only, and its result is never read, so no password opens a sign-in for a name
// that is not the admin's. The error of ctx is returned when the check had to
// wait too long for its turn (the same for every pair).
//
// The caller limits sign-ins by client (Limiter) before it calls this: it is
// the one that knows who is asking.
func (s *Store) SignIn(ctx context.Context, username, password string) (Session, error) {
	a, haveAdmin := s.admin()
	isAdmin := haveAdmin && sameText(a.Username, username)
	hash := DummyHash
	if isAdmin {
		hash = a.Hash
	}
	match, err := CheckPassword(ctx, hash, password)
	if err != nil {
		return Session{}, err
	}
	if !isAdmin || !match {
		return Session{}, ErrBadCredentials
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// The check took its time. If the password was changed (which ended the
	// sessions) or the admin reset while it ran, it was a check against what
	// is no longer the admin's password.
	if s.d.Admin == nil || s.d.Admin.Hash != a.Hash {
		return Session{}, ErrBadCredentials
	}
	return s.startSessionLocked(s.clock())
}

// startSessionLocked makes a session that is valid from now, drops the ones
// that have ended and, to stay within maxSessions, the oldest to start of the
// others, and saves. A write that fails makes no session. Callers hold s.mu.
func (s *Store) startSessionLocked(now time.Time) (Session, error) {
	raw := make([]byte, sessionIDBytes)
	if _, err := rand.Read(raw); err != nil {
		return Session{}, fmt.Errorf("auth: making a session id: %w", err)
	}
	id := base64.RawURLEncoding.EncodeToString(raw)

	rec := sessionRecord{Hash: sha256Hex(id), Created: now, LastUsed: now}
	kept := make([]sessionRecord, 0, len(s.d.Sessions)+1)
	for _, r := range s.d.Sessions {
		if r.liveAt(now) {
			kept = append(kept, r)
		}
	}
	// The oldest of the others goes to make room, and never the new session: a
	// clock that stepped back can make it older than all of them.
	for len(kept) >= maxSessions {
		oldest := 0
		for i := range kept {
			if kept[i].Created.Before(kept[oldest].Created) {
				oldest = i
			}
		}
		kept = slices.Delete(kept, oldest, oldest+1)
	}
	kept = append(kept, rec)
	next := s.d
	next.Sessions = kept
	if err := s.commit(next); err != nil {
		return Session{}, err
	}
	return Session{ID: id, CSRF: csrfToken(s.csrfKey, id), Expires: rec.expires()}, nil
}

// Session finds the session with the id id (the cookie's value). It is false
// for an id that is unknown, or that has ended: 12 hours after its last use, or
// 7 days after its sign-in. A valid session's idle limit slides: its last use is
// now. That is saved when the saved one is more than an hour stale, and with the
// next write otherwise. The Session returned has the id it was asked for.
func (s *Store) Session(id string) (Session, bool) {
	if len(id) != sessionIDLen {
		return Session{}, false
	}
	h := sha256Hex(id)
	now := s.clock()
	s.mu.Lock()
	defer s.mu.Unlock()
	i := indexOfSession(s.d.Sessions, h)
	if i < 0 {
		return Session{}, false
	}
	rec := &s.d.Sessions[i]
	if !rec.liveAt(now) {
		// Dropped here, and from the file with the next write.
		s.d.Sessions = slices.Delete(slices.Clone(s.d.Sessions), i, i+1)
		return Session{}, false
	}
	if now.After(rec.LastUsed) {
		rec.LastUsed = now
	}
	if rec.LastUsed.Sub(rec.saved) > sessionSaveEvery {
		// A failure is not the session's: it stays valid, the use is saved by
		// the next write, and the next use tries again.
		_ = s.commit(s.d)
	}
	return Session{ID: id, CSRF: csrfToken(s.csrfKey, id), Expires: rec.expires()}, true
}

// SignOut ends the session with the id id. An id that is no session is
// nothing to do. The session is gone here even when auth.json can't be written
// (an end that is not saved would be a sign-out that fails silently): the next
// write that works saves it.
func (s *Store) SignOut(id string) {
	if id == "" {
		return
	}
	h := sha256Hex(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropSessionsLocked(func(r sessionRecord) bool { return sameHash(r.Hash, h) })
}

// EndOtherSessions ends every session but the one with the id keep; an empty
// keep ends them all. As SignOut, it holds even when it can't be saved.
func (s *Store) EndOtherSessions(keep string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if keep == "" {
		s.dropSessionsLocked(func(sessionRecord) bool { return true })
		return
	}
	h := sha256Hex(keep)
	s.dropSessionsLocked(func(r sessionRecord) bool { return !sameHash(r.Hash, h) })
}

// dropSessionsLocked ends the sessions for which drop is true, and saves
// when there were any. Callers hold s.mu.
func (s *Store) dropSessionsLocked(drop func(sessionRecord) bool) {
	kept := make([]sessionRecord, 0, len(s.d.Sessions))
	for _, r := range s.d.Sessions {
		if !drop(r) {
			kept = append(kept, r)
		}
	}
	if len(kept) == len(s.d.Sessions) {
		return
	}
	s.d.Sessions = kept
	// The error is dropped on purpose: what ended stays ended in memory, and
	// the next write saves it.
	_ = s.commit(s.d)
}

// CSRFFor returns the CSRF token of the session with the id sessionID:
// base64url(HMAC-SHA256(csrf_key, id)). The key is in auth.json and never
// changes, so a token is good for as long as its session is, across restarts.
// It is made, not looked up: whether the session exists is for Session to say.
// For no session id it is "".
func (s *Store) CSRFFor(sessionID string) string {
	if sessionID == "" {
		return ""
	}
	return csrfToken(s.csrfKey, sessionID)
}

// CheckCSRF reports whether token is the CSRF token of the session with the id
// sessionID. The compare takes the same time for any token. An empty token, or
// an empty session id, is no match.
func (s *Store) CheckCSRF(sessionID, token string) bool {
	if sessionID == "" || token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(csrfToken(s.csrfKey, sessionID)), []byte(token)) == 1
}
