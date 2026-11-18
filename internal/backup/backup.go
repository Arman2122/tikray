// Package backup seals and opens passphrase-encrypted tikray state backups.
//
// Because API views omit server credentials and subscription URLs (spec §7),
// backup exports encrypt the full desired store.State with AES-256-GCM using
// a key derived from a user passphrase via Argon2id. No secret or passphrase
// ever appears in returned errors.
package backup

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/Arman2122/tikray/internal/store"
	"golang.org/x/crypto/argon2"
)

const (
	// FormatV1 identifies the v1 encrypted backup envelope and acts as GCM AAD.
	FormatV1 = "tikray-backup-v1"
	// KDFArgon2id names the only accepted key derivation function.
	KDFArgon2id = "argon2id"

	// MinPassLen and MaxPassLen match internal/auth's passphrase bounds.
	MinPassLen = 10
	MaxPassLen = 256

	// MaxBundleBytes bounds an encoded backup envelope accepted by Open.
	MaxBundleBytes = 4 << 20

	saltLen   = 16
	nonceLen  = 12
	keyLen    = 32
	payloadV1 = 1

	// Default Argon2id cost parameters match internal/auth for MikroTik RAM safety.
	defaultMemoryKiB   uint32 = 19456
	defaultIterations  uint32 = 2
	defaultParallelism uint8  = 1

	// Bounds on untrusted KDF parameters in imported backup envelopes prevent
	// memory or CPU exhaustion on constrained routers.
	minMemoryKiB   uint32 = 8192
	maxMemoryKiB   uint32 = 65536
	minIterations  uint32 = 1
	maxIterations  uint32 = 10
	minParallelism uint8  = 1
	maxParallelism uint8  = 4
)

var (
	// ErrInvalid indicates a malformed backup envelope, invalid state, or
	// passphrase that does not meet length requirements.
	ErrInvalid = errors.New("backup: invalid backup or passphrase")
	// ErrDecrypt indicates wrong passphrase or tampered ciphertext.
	ErrDecrypt = errors.New("backup: wrong passphrase or corrupted backup")
)

// kdfSem limits concurrent Argon2id derivations to two, matching internal/auth
// so simultaneous backup requests cannot exhaust router memory.
var kdfSem = make(chan struct{}, 2)

// KDFParams records the Argon2id work factors stored in a backup envelope.
type KDFParams struct {
	Memory      uint32 `json:"memory_kib"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
}

// Bundle is the authenticated, passphrase-encrypted state export envelope.
type Bundle struct {
	Format     string    `json:"format"`
	CreatedAt  time.Time `json:"created_at"`
	KDF        string    `json:"kdf"`
	KDFParams  KDFParams `json:"kdf_params"`
	Salt       string    `json:"salt"`
	Nonce      string    `json:"nonce"`
	Ciphertext string    `json:"ciphertext"`
}

type payload struct {
	Version int         `json:"version"`
	State   store.State `json:"state"`
}

// Seal encrypts st with passphrase and returns an authenticated Bundle.
func Seal(ctx context.Context, st store.State, passphrase string) (Bundle, error) {
	if err := checkPassphrase(passphrase); err != nil {
		return Bundle{}, err
	}
	if err := st.Validate(); err != nil {
		return Bundle{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := ctx.Err(); err != nil {
		return Bundle{}, fmt.Errorf("backup: %w", err)
	}
	plain, err := json.Marshal(payload{Version: payloadV1, State: st})
	if err != nil {
		return Bundle{}, fmt.Errorf("backup: encoding state: %w", err)
	}
	defer zeroBytes(plain)

	salt := make([]byte, saltLen)
	nonce := make([]byte, nonceLen)
	rand.Read(salt)
	rand.Read(nonce)

	params := KDFParams{
		Memory:      defaultMemoryKiB,
		Iterations:  defaultIterations,
		Parallelism: defaultParallelism,
	}
	key, err := deriveKey(ctx, passphrase, salt, params)
	if err != nil {
		return Bundle{}, err
	}
	defer zeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return Bundle{}, fmt.Errorf("backup: cipher init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Bundle{}, fmt.Errorf("backup: aead init: %w", err)
	}
	ct := gcm.Seal(nil, nonce, plain, []byte(FormatV1))
	return Bundle{
		Format:     FormatV1,
		CreatedAt:  time.Now().UTC(),
		KDF:        KDFArgon2id,
		KDFParams:  params,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}, nil
}

// Open decrypts and validates b using passphrase, returning the recovered state.
func Open(ctx context.Context, b Bundle, passphrase string) (store.State, error) {
	if err := checkPassphrase(passphrase); err != nil {
		return store.State{}, err
	}
	if b.Format != FormatV1 || b.KDF != KDFArgon2id {
		return store.State{}, fmt.Errorf("%w: unsupported backup format", ErrInvalid)
	}
	if b.KDFParams.Memory < minMemoryKiB || b.KDFParams.Memory > maxMemoryKiB ||
		b.KDFParams.Iterations < minIterations || b.KDFParams.Iterations > maxIterations ||
		b.KDFParams.Parallelism < minParallelism || b.KDFParams.Parallelism > maxParallelism {
		return store.State{}, fmt.Errorf("%w: KDF parameters out of safe bounds", ErrInvalid)
	}
	if len(b.Ciphertext) == 0 || len(b.Ciphertext) > MaxBundleBytes {
		return store.State{}, fmt.Errorf("%w: invalid ciphertext size", ErrInvalid)
	}
	salt, err := base64.StdEncoding.Strict().DecodeString(b.Salt)
	if err != nil || len(salt) != saltLen {
		return store.State{}, fmt.Errorf("%w: invalid salt", ErrInvalid)
	}
	nonce, err := base64.StdEncoding.Strict().DecodeString(b.Nonce)
	if err != nil || len(nonce) != nonceLen {
		return store.State{}, fmt.Errorf("%w: invalid nonce", ErrInvalid)
	}
	ct, err := base64.StdEncoding.Strict().DecodeString(b.Ciphertext)
	if err != nil || len(ct) < 16 {
		return store.State{}, fmt.Errorf("%w: invalid ciphertext encoding", ErrInvalid)
	}

	key, err := deriveKey(ctx, passphrase, salt, b.KDFParams)
	if err != nil {
		return store.State{}, err
	}
	defer zeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return store.State{}, fmt.Errorf("backup: cipher init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return store.State{}, fmt.Errorf("backup: aead init: %w", err)
	}
	plain, err := gcm.Open(nil, nonce, ct, []byte(FormatV1))
	if err != nil {
		return store.State{}, ErrDecrypt
	}
	defer zeroBytes(plain)

	var p payload
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return store.State{}, fmt.Errorf("%w: decrypted payload is not a valid state", ErrInvalid)
	}
	if _, err := dec.Token(); err != io.EOF {
		return store.State{}, fmt.Errorf("%w: trailing payload data", ErrInvalid)
	}
	if p.Version != payloadV1 {
		return store.State{}, fmt.Errorf("%w: unsupported payload version", ErrInvalid)
	}
	if p.State.Servers == nil {
		p.State.Servers = []store.Server{}
	}
	if p.State.Subscriptions == nil {
		p.State.Subscriptions = []store.Subscription{}
	}
	if p.State.Devices == nil {
		p.State.Devices = []store.Device{}
	}
	if err := p.State.Validate(); err != nil {
		return store.State{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return p.State, nil
}

func checkPassphrase(pass string) error {
	if len(pass) < MinPassLen {
		return fmt.Errorf("%w: passphrase must be at least %d bytes", ErrInvalid, MinPassLen)
	}
	if len(pass) > MaxPassLen {
		return fmt.Errorf("%w: passphrase must be at most %d bytes", ErrInvalid, MaxPassLen)
	}
	return nil
}

func deriveKey(ctx context.Context, pass string, salt []byte, p KDFParams) ([]byte, error) {
	select {
	case kdfSem <- struct{}{}:
		defer func() { <-kdfSem }()
	case <-ctx.Done():
		return nil, fmt.Errorf("backup: %w", ctx.Err())
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("backup: %w", err)
	}
	return argon2.IDKey([]byte(pass), salt, p.Iterations, p.Memory, p.Parallelism, keyLen), nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
