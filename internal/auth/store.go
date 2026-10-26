// Package auth keeps who may use the API: the admin account and its argon2id
// password, the one-time setup code that claims it and the file they are
// saved in (auth.json, beside setup.code, in the state directory). Sessions,
// API tokens, CSRF and the limit on failed sign-ins are built on its Store.
//
// No error of this package shows anything secret: not a password, not a hash
// string, not a setup code, not a piece of auth.json. The setup code is in
// setup.code, and shown by `tikray setup-code`; no password is in any file,
// only its hash.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Arman2122/tikray/internal/atomicfile"
)

// The files in the state directory. Both are 0600.
const (
	authFile = "auth.json"
	codeFile = "setup.code"
)

// fileVersion is the version of auth.json that this package reads and writes.
// A file of another version is an error.
const fileVersion = 1

// csrfKeyLen is the length of the key the CSRF tokens are made with.
const csrfKeyLen = 32

var (
	// ErrBadCode is the answer to a setup code that is not the code in
	// setup.code.
	ErrBadCode = errors.New("auth: the setup code is not right")
	// ErrAlreadyClaimed is the answer to a claim, or a request for the setup
	// code, when there is an admin.
	ErrAlreadyClaimed = errors.New("auth: the admin has already been claimed")
	// ErrBadPassword is the answer to a change of password that gives a
	// current password that is not the admin's.
	ErrBadPassword = errors.New("auth: the current password is not right")

	// errNoAdmin is what an operation that needs the admin gets when there is
	// none.
	errNoAdmin = errors.New("auth: there is no admin")
)

// admin is the one account. The password is kept only as its PHC hash.
type admin struct {
	Username  string    `json:"username"`
	Hash      string    `json:"hash"`
	ChangedAt time.Time `json:"changed_at"`
}

// fileData is auth.json. Tokens and Sessions are kept as they are read until
// the code that owns them takes them over.
type fileData struct {
	Version  int               `json:"version"`
	Admin    *admin            `json:"admin,omitempty"`
	CSRFKey  []byte            `json:"csrf_key"`
	Tokens   []json.RawMessage `json:"tokens"`
	Sessions []json.RawMessage `json:"sessions"`
}

// Store holds the admin and the secrets kept with it, and saves them to
// auth.json. Its methods are safe for concurrent use. Hashing a password
// takes about 100 ms on a router, so none of them holds the lock for it.
//
// One process owns a state directory (tikray serve holds state/serve.lock):
// two Stores on one directory would overwrite each other's writes.
type Store struct {
	dir string
	now func() time.Time

	mu sync.Mutex // guards d, and orders the writes of the two files
	d  fileData
}

// OpenStore opens the store in dir, which is made (mode 0700) when it is
// missing. A missing auth.json is no admin. A key for CSRF tokens is made when
// there is none, and auth.json is written when it is new or the key was just
// made. When there is no admin it makes setup.code, unless there is one; when
// there is an admin it removes a setup.code that a crash left behind. A file
// it can't use (another version, bad JSON, a hash it doesn't read) is an
// error, and is never replaced.
func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	s := &Store{dir: dir, now: time.Now}

	d, found, err := loadFile(s.path(authFile))
	if err != nil {
		return nil, err
	}
	dirty := !found
	if len(d.CSRFKey) == 0 {
		d.CSRFKey = make([]byte, csrfKeyLen)
		if _, err := rand.Read(d.CSRFKey); err != nil {
			return nil, fmt.Errorf("auth: making a key: %w", err)
		}
		dirty = true
	}
	if dirty {
		if err := s.save(d); err != nil {
			return nil, err
		}
	}
	s.d = d

	if d.Admin != nil {
		if err := s.removeCode(); err != nil {
			return nil, err
		}
	} else if _, err := os.Stat(s.path(codeFile)); errors.Is(err, fs.ErrNotExist) {
		if _, err := s.newCode(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) path(name string) string { return filepath.Join(s.dir, name) }

// loadFile reads auth.json. found is false when it doesn't exist.
func loadFile(path string) (d fileData, found bool, err error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return fileData{Version: fileVersion}, false, nil
	}
	if err != nil {
		return d, false, fmt.Errorf("auth: reading %s: %w", authFile, err)
	}
	// The version first, so that a file of another version is not read as
	// this one's shape.
	var head struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		return d, false, fmt.Errorf("auth: %s is not valid: %s", path, describeJSONError(err))
	}
	if head.Version != fileVersion {
		return d, false, fmt.Errorf("auth: %s is version %d, and this tikray reads version %d", path, head.Version, fileVersion)
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return d, false, fmt.Errorf("auth: %s is not valid: %s", path, describeJSONError(err))
	}
	if n := len(d.CSRFKey); n != 0 && n != csrfKeyLen {
		return d, false, fmt.Errorf("auth: %s holds a CSRF key of %d bytes, want %d", path, n, csrfKeyLen)
	}
	if d.Admin != nil {
		if d.Admin.Username == "" {
			return d, false, fmt.Errorf("auth: %s holds an admin with no username", path)
		}
		if _, _, err := parsePHC(d.Admin.Hash); err != nil {
			return d, false, fmt.Errorf("auth: %s holds a password hash this tikray can't use", path)
		}
	}
	return d, true, nil
}

// describeJSONError says what is wrong with a file without quoting any of it:
// a decoder's own message may show a piece of the text.
func describeJSONError(err error) string {
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syn):
		return fmt.Sprintf("a syntax error at byte %d", syn.Offset)
	case errors.As(err, &typ) && typ.Field == "":
		return "it is not a JSON object"
	case errors.As(err, &typ):
		return fmt.Sprintf("the field %q has the wrong type", typ.Field)
	}
	return "it can't be decoded"
}

// save writes d to auth.json, with lists (and not null) for tokens and
// sessions. Callers hold s.mu, or have the store to themselves.
func (s *Store) save(d fileData) error {
	if d.Tokens == nil {
		d.Tokens = []json.RawMessage{}
	}
	if d.Sessions == nil {
		d.Sessions = []json.RawMessage{}
	}
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return fmt.Errorf("auth: encoding %s: %w", authFile, err)
	}
	if err := atomicfile.WriteFile(s.path(authFile), append(b, '\n'), 0o600); err != nil {
		return fmt.Errorf("auth: writing %s: %w", authFile, err)
	}
	return nil
}

// commit saves next and, only when that worked, makes it the state. Callers
// hold s.mu. They build next without changing s.d, so that a write that fails
// leaves the state as it was.
func (s *Store) commit(next fileData) error {
	if err := s.save(next); err != nil {
		return err
	}
	s.d = next
	return nil
}

// admin returns the admin, if there is one.
func (s *Store) admin() (admin, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.d.Admin == nil {
		return admin{}, false
	}
	return *s.d.Admin, true
}

// NeedsSetup reports whether there is no admin yet: the first one is to be
// claimed with the setup code.
func (s *Store) NeedsSetup() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.d.Admin == nil
}

// newCode makes a setup code and writes it to setup.code (mode 0600, no
// newline, like api.token). It returns the code as 12 normalised symbols.
func (s *Store) newCode() (norm string, err error) {
	code, err := NewSetupCode()
	if err != nil {
		return "", err
	}
	if err := atomicfile.WriteFile(s.path(codeFile), []byte(code), 0o600); err != nil {
		return "", fmt.Errorf("auth: writing %s: %w", codeFile, err)
	}
	return NormalizeSetupCode(code), nil
}

// removeCode removes setup.code, if it is there.
func (s *Store) removeCode() error {
	path := s.path(codeFile)
	if err := os.Remove(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("auth: removing %s: %w", codeFile, err)
	}
	if err := atomicfile.SyncDir(s.dir); err != nil {
		return fmt.Errorf("auth: removing %s: %w", codeFile, err)
	}
	return nil
}

// codeLocked returns the code in setup.code, as 12 normalised symbols. A file
// that isn't there (it was removed by hand while there is no admin) is made
// again, with a new code. A file that holds no code is an error that names it
// and does not show it; a reset replaces it. Callers hold s.mu.
func (s *Store) codeLocked() (string, error) {
	b, err := os.ReadFile(s.path(codeFile))
	if errors.Is(err, fs.ErrNotExist) {
		return s.newCode()
	}
	if err != nil {
		return "", fmt.Errorf("auth: reading %s: %w", codeFile, err)
	}
	norm := NormalizeSetupCode(string(b))
	if !validSetupCode(norm) {
		return "", fmt.Errorf("auth: %s does not hold a setup code; reset the admin to make a new one", s.path(codeFile))
	}
	return norm, nil
}

// SetupCode returns the setup code in setup.code, as it is shown. It is for
// the CLI. With an admin there is no code: ErrAlreadyClaimed.
func (s *Store) SetupCode() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.d.Admin != nil {
		return "", ErrAlreadyClaimed
	}
	norm, err := s.codeLocked()
	if err != nil {
		return "", err
	}
	return formatSetupCode(norm), nil
}

// checkClaimLocked is the part of a claim that is about the state and the
// code: ErrAlreadyClaimed when there is an admin, ErrBadCode when code is not
// the one in setup.code. The compare is in constant time, over the normalised
// forms, and is of a file that holds a code, so that an empty code is no
// match. Callers hold s.mu.
func (s *Store) checkClaimLocked(code string) error {
	if s.d.Admin != nil {
		return ErrAlreadyClaimed
	}
	want, err := s.codeLocked()
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(want), []byte(NormalizeSetupCode(code))) != 1 {
		return ErrBadCode
	}
	return nil
}

// Claim makes the first admin, when code is the setup code (in any of the
// forms NormalizeSetupCode reads) and username and password pass the rules.
// It writes the admin to auth.json and then removes setup.code (a removal that
// fails is an error, with the admin saved all the same: the next OpenStore
// removes the file). The errors are
// ErrAlreadyClaimed, ErrBadCode (checked before anything costly: a wrong code
// never makes a hash), an ErrInvalid for the username or the password, or the
// error of ctx when the hash had to wait too long for its turn. Claims that
// race for the admin: one wins and the others get ErrAlreadyClaimed.
func (s *Store) Claim(ctx context.Context, code, username, password string) error {
	s.mu.Lock()
	err := s.checkClaimLocked(code)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if err := ValidUsername(username); err != nil {
		return err
	}
	if err := ValidPassword(username, password); err != nil {
		return err
	}
	// The hash takes its time and a lot of memory: not under the lock.
	hash, err := HashPassword(ctx, password)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// What was true before the hash may not be now: another claim, or a reset.
	if err := s.checkClaimLocked(code); err != nil {
		return err
	}
	next := s.d
	next.Admin = &admin{Username: username, Hash: hash, ChangedAt: s.now().UTC()}
	if err := s.commit(next); err != nil {
		return err
	}
	return s.removeCode()
}

// Reset removes the admin and every session, keeps the API tokens, and writes
// a new setup code, so that the admin can be claimed again. It is the answer
// to a lost password. The old setup code, if there was one, is gone with it.
func (s *Store) Reset() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.d
	next.Admin = nil
	next.Sessions = nil
	if err := s.commit(next); err != nil {
		return err
	}
	// In this order, so that a crash between the two leaves no admin and no
	// code, which OpenStore mends, and not a code beside an admin.
	_, err := s.newCode()
	return err
}

// ChangePassword sets the admin's password to next when current is the
// password now: ErrBadPassword when it is not. A next that breaks the rules
// is an ErrInvalid. Both passwords are checked and hashed outside the lock;
// when the admin's password changed in between (another change), current is
// no longer the current password, and it is ErrBadPassword too.
func (s *Store) ChangePassword(ctx context.Context, current, next string) error {
	a, ok := s.admin()
	if !ok {
		return errNoAdmin
	}
	if err := ValidPassword(a.Username, next); err != nil {
		return err
	}
	match, err := CheckPassword(ctx, a.Hash, current)
	if err != nil {
		return err
	}
	if !match {
		return ErrBadPassword
	}
	hash, err := HashPassword(ctx, next)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.d.Admin == nil || s.d.Admin.Hash != a.Hash {
		return ErrBadPassword
	}
	d := s.d
	d.Admin = &admin{Username: a.Username, Hash: hash, ChangedAt: s.now().UTC()}
	return s.commit(d)
}
