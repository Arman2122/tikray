package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	"github.com/Arman2122/tikray/internal/store"
)

// The argon2id parameters. They are fixed: a hash with any other is refused
// (CheckPassword), so that nothing stored in auth.json can make a check cost
// more memory or time than the router has to spare. Each hash holds
// argonMemory KiB, which is why at most hashSlots run at once.
const (
	argonMemory  = 19456 // KiB
	argonTime    = 2
	argonThreads = 1
	saltLen      = 16
	keyLen       = 32

	hashSlots = 2
)

// phcParams is the parameter part of every PHC string this package makes and
// reads.
var phcParams = fmt.Sprintf("m=%d,t=%d,p=%d", argonMemory, argonTime, argonThreads)

// The limits on a password and a username.
const (
	minPasswordBytes = 10
	maxPasswordBytes = 256
	maxUsernameRunes = 64
)

// b64 is how the salt and the key are written in a PHC string: standard
// base64 without padding.
var b64 = base64.RawStdEncoding

// hashSem is the semaphore that bounds the argon2 runs: a run takes a slot for
// its whole time, and one that finds them all taken waits, as long as its
// context lets it.
var hashSem = make(chan struct{}, hashSlots)

// argonHook, when it is set (tests only), runs in each argon2 run that holds
// a slot, just before the work starts.
var argonHook func()

// ErrInvalid is what a username or a password that breaks the rules wraps
// (ValidUsername, ValidPassword). The message says which rule, and never what
// was given.
var ErrInvalid = errors.New("auth: invalid")

// invalidError is a broken rule: ErrInvalid to errors.Is, and a message of
// its own.
type invalidError string

func (e invalidError) Error() string        { return "auth: " + string(e) }
func (e invalidError) Is(target error) bool { return target == ErrInvalid }

// errBadHash is what a hash string that this package won't read gets, whatever
// is wrong with it. It names nothing of the string.
var errBadHash = errors.New("auth: the password hash is not argon2id with the parameters this version uses")

// DummyHash is a valid hash of a random password that nobody knows. A sign-in
// for a user that doesn't exist checks the password against it, so that it
// costs the time of a check against a real hash.
//
// It was made once, with the parameters above and a password that was
// discarded, and is not made at start-up: that would cost a hash's time and
// memory in every command that imports this package, on a router.
var DummyHash = "$argon2id$v=19$m=19456,t=2,p=1$rpbWPaMfmQsMnDLEE0LuhQ$E39iPcLSzhm8M6IPjMJbGQRH1TLGkfichf5atXm55Ns"

// acquire takes a slot, waiting for one as long as ctx allows. The error of a
// context that ended wraps its own.
func acquire(ctx context.Context) (release func(), err error) {
	// A select with a free slot and a done context picks either at random;
	// a context that is done already takes none.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("auth: waiting to check a password: %w", err)
	}
	select {
	case hashSem <- struct{}{}:
		return func() { <-hashSem }, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("auth: waiting to check a password: %w", ctx.Err())
	}
}

// derive runs argon2id with the fixed parameters, in a slot.
func derive(ctx context.Context, password string, salt []byte) ([]byte, error) {
	release, err := acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if argonHook != nil {
		argonHook()
	}
	return argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, keyLen), nil
}

// HashPassword returns the argon2id hash of password as a PHC string
// ($argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>), with a salt of its own. It
// does not check the rules for a password (ValidPassword). At most two hashes
// and checks run at once, and a call that has to wait for its turn gives up
// with ctx.
func HashPassword(ctx context.Context, password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: making a salt: %w", err)
	}
	key, err := derive(ctx, password, salt)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("$argon2id$v=%d$%s$%s$%s", argon2.Version, phcParams, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// CheckPassword reports whether password is the one phc is the hash of, in
// constant time. A phc that is not argon2id with exactly the parameters above
// (any other version, cost, or lengths of salt and key) is an error, and is
// refused before any work: it is never a "wrong password". Like HashPassword
// it waits for one of two slots, and gives up with ctx.
func CheckPassword(ctx context.Context, phc, password string) (bool, error) {
	salt, want, err := parsePHC(phc)
	if err != nil {
		return false, err
	}
	got, err := derive(ctx, password, salt)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(want, got) == 1, nil
}

// parsePHC reads a PHC string of exactly the form HashPassword makes, and
// returns its salt and key. The base64 must be the canonical unpadded kind,
// so that a string is read one way only.
func parsePHC(phc string) (salt, key []byte, err error) {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" ||
		parts[2] != fmt.Sprintf("v=%d", argon2.Version) || parts[3] != phcParams {
		return nil, nil, errBadHash
	}
	if salt, err = b64.DecodeString(parts[4]); err != nil || len(salt) != saltLen || b64.EncodeToString(salt) != parts[4] {
		return nil, nil, errBadHash
	}
	if key, err = b64.DecodeString(parts[5]); err != nil || len(key) != keyLen || b64.EncodeToString(key) != parts[5] {
		return nil, nil, errBadHash
	}
	return salt, key, nil
}

// ValidPassword checks the rules for a password: 10 to 256 bytes, and not the
// username. The error is an ErrInvalid and does not show the password.
func ValidPassword(username, password string) error {
	switch {
	case len(password) < minPasswordBytes:
		return invalidError(fmt.Sprintf("the password must be at least %d bytes", minPasswordBytes))
	case len(password) > maxPasswordBytes:
		return invalidError(fmt.Sprintf("the password must be at most %d bytes", maxPasswordBytes))
	case password == username:
		return invalidError("the password must not be the username")
	}
	return nil
}

// ValidUsername checks the rules for a username: 1 to 64 runes of valid
// UTF-8, none of them one that a name may not hold (store.ForbiddenInName).
// The error is an ErrInvalid.
func ValidUsername(name string) error {
	switch n := utf8.RuneCountInString(name); {
	case !utf8.ValidString(name):
		return invalidError("the username must be valid UTF-8")
	case n < 1:
		return invalidError("the username must not be empty")
	case n > maxUsernameRunes:
		return invalidError(fmt.Sprintf("the username must be at most %d characters", maxUsernameRunes))
	case strings.ContainsFunc(name, store.ForbiddenInName):
		return invalidError("the username must not hold a control character or a character that changes the direction of text")
	}
	return nil
}
