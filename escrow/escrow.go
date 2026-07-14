// Package escrow provides key escrow backends for vault-git.
// It defines the KeyEscrow interface and two implementations:
//   - LocalEscrow: in-memory (testing/ephemeral use)
//   - FileEscrow:  encrypted YAML on disk
package escrow

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"golang.org/x/crypto/argon2"
	"gopkg.in/yaml.v3"
)

// KeyEscrow is the interface for key deposit/retrieval/rotation.
type KeyEscrow interface {
	// Deposit stores an encrypted key under keyID.
	Deposit(keyID string, encryptedKey []byte) error
	// Retrieve returns the encrypted key for keyID, authenticated by proof.
	// proof is the SHA-256 of the escrow master password (caller responsibility).
	Retrieve(keyID string, proof []byte) ([]byte, error)
	// Rotate replaces the key for keyID after verifying oldProof.
	Rotate(keyID string, oldProof, newKey []byte) error
}

// ── LocalEscrow ──────────────────────────────────────────────────────────────

// LocalEscrow is an in-memory escrow backend for testing and ephemeral use.
// It has no authentication — Retrieve and Rotate accept any proof.
type LocalEscrow struct {
	mu   sync.RWMutex
	keys map[string][]byte
}

// NewLocalEscrow returns an initialised LocalEscrow.
func NewLocalEscrow() *LocalEscrow {
	return &LocalEscrow{keys: make(map[string][]byte)}
}

func (e *LocalEscrow) Deposit(keyID string, encryptedKey []byte) error {
	if keyID == "" {
		return errors.New("keyID must not be empty")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	cp := make([]byte, len(encryptedKey))
	copy(cp, encryptedKey)
	e.keys[keyID] = cp
	return nil
}

func (e *LocalEscrow) Retrieve(keyID string, _ []byte) ([]byte, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	k, ok := e.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("escrow: key %q not found", keyID)
	}
	cp := make([]byte, len(k))
	copy(cp, k)
	return cp, nil
}

func (e *LocalEscrow) Rotate(keyID string, _ []byte, newKey []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.keys[keyID]; !ok {
		return fmt.Errorf("escrow: key %q not found", keyID)
	}
	cp := make([]byte, len(newKey))
	copy(cp, newKey)
	e.keys[keyID] = cp
	return nil
}

// ── FileEscrow ───────────────────────────────────────────────────────────────

// Escrow KDF scheme identifier persisted per entry. This is the on-disk format
// version; bump it if the KDF parameters or wrapping change in a way that makes
// old entries unreadable.
//
// schemeArgon2idV1 wraps each entry with AES-256-GCM whose key is derived from
// the master password via Argon2id (RFC 9106) over a per-entry random 16-byte
// salt, using the parameters below.
const schemeArgon2idV1 = "argon2id-v1"

// Argon2id key-derivation parameters. Chosen for interactive escrow use.
// keyLen is 32 bytes to produce an AES-256 key.
const (
	argonTime    uint32 = 1
	argonMemory  uint32 = 64 * 1024 // 64 MiB
	argonThreads uint8  = 4
	argonKeyLen  uint32 = 32
	argonSaltLen        = 16
)

// fileEscrowRecord is what gets persisted per key entry.
type fileEscrowRecord struct {
	// Scheme identifies the KDF/wrapping format used for this entry.
	// An empty Scheme marks a legacy pre-Argon2id entry (unsalted
	// SHA-256(masterPassword) key); such entries are rejected on read.
	Scheme string `yaml:"scheme"`
	// Salt is the per-entry random Argon2id salt, hex-encoded.
	Salt string `yaml:"salt"`
	// EncryptedKey is AES-256-GCM( Argon2id(masterPassword, Salt), payload )
	// stored as hex.
	EncryptedKey string `yaml:"encrypted_key"`
	// Nonce used for the outer AES-GCM layer, hex.
	Nonce string `yaml:"nonce"`
}

// fileEscrowStore is the on-disk YAML structure.
type fileEscrowStore struct {
	Keys map[string]fileEscrowRecord `yaml:"keys"`
}

// FileEscrow is an on-disk escrow backend. Each key entry is wrapped with
// AES-256-GCM whose key is derived from the master password via Argon2id over a
// per-entry random salt (see schemeArgon2idV1). The proof passed to
// Retrieve/Rotate must equal SHA-256(masterPassword).
//
// SECURITY / BREAKING CHANGE: earlier versions derived the AES key from a
// single UNSALTED SHA-256(masterPassword). That is intentionally no longer
// supported. Entries written by that format carry no "scheme" field and are
// rejected on Retrieve/Rotate with a clear error — the on-disk format has
// changed and any pre-existing entries must be re-Deposited under the new
// scheme. This is deliberate: an unsalted single-round hash offers no work
// factor against a stolen escrow file, so silently accepting it would defeat
// the point of this fix.
type FileEscrow struct {
	path string
	// masterPassword is retained to re-derive per-entry Argon2id keys from the
	// stored salt. It is a private copy and must never be logged.
	masterPassword []byte
	// pwVerifier is SHA-256(masterPassword); the Retrieve/Rotate proof is
	// checked against it in constant time. This preserves the historical proof
	// contract (proof == SHA-256(masterPassword)) without exposing any key.
	pwVerifier []byte
	mu         sync.Mutex
}

// NewFileEscrow creates a FileEscrow backed by the given file path.
// masterPassword is used with Argon2id (per-entry salt) to derive each entry's
// AES-256 key. masterPassword must never be logged by callers.
func NewFileEscrow(path string, masterPassword []byte) (*FileEscrow, error) {
	if len(masterPassword) == 0 {
		return nil, errors.New("escrow: master password must not be empty")
	}
	pw := make([]byte, len(masterPassword))
	copy(pw, masterPassword)
	verifier := sha256.Sum256(masterPassword)
	return &FileEscrow{path: path, masterPassword: pw, pwVerifier: verifier[:]}, nil
}

func (e *FileEscrow) load() (*fileEscrowStore, error) {
	data, err := os.ReadFile(e.path)
	if err != nil {
		if os.IsNotExist(err) {
			return &fileEscrowStore{Keys: make(map[string]fileEscrowRecord)}, nil
		}
		return nil, fmt.Errorf("escrow: read file: %w", err)
	}
	var store fileEscrowStore
	if err := yaml.Unmarshal(data, &store); err != nil {
		return nil, fmt.Errorf("escrow: parse yaml: %w", err)
	}
	if store.Keys == nil {
		store.Keys = make(map[string]fileEscrowRecord)
	}
	return &store, nil
}

func (e *FileEscrow) save(store *fileEscrowStore) error {
	data, err := yaml.Marshal(store)
	if err != nil {
		return fmt.Errorf("escrow: marshal yaml: %w", err)
	}
	return os.WriteFile(e.path, data, 0600)
}

// deriveKey derives the per-entry AES-256 key from the master password and the
// entry's salt using Argon2id.
func (e *FileEscrow) deriveKey(salt []byte) []byte {
	return argon2.IDKey(e.masterPassword, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
}

// wrap generates a fresh random salt, derives the entry key with Argon2id, and
// AES-256-GCM-seals plainKey. It returns (scheme, saltHex, ciphertextHex,
// nonceHex).
func (e *FileEscrow) wrap(plainKey []byte) (scheme, saltHex, encHex, nonceHex string, err error) {
	salt := make([]byte, argonSaltLen)
	if _, err = io.ReadFull(rand.Reader, salt); err != nil {
		return "", "", "", "", err
	}
	aesKey := e.deriveKey(salt)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", "", "", "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", "", "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", "", "", err
	}
	ct := gcm.Seal(nil, nonce, plainKey, nil)
	return schemeArgon2idV1, hex.EncodeToString(salt), hex.EncodeToString(ct), hex.EncodeToString(nonce), nil
}

// unwrap verifies the proof and the entry scheme, re-derives the entry key from
// the stored salt via Argon2id, and AES-256-GCM-opens the ciphertext.
func (e *FileEscrow) unwrap(scheme, saltHex, encHex, nonceHex string, proof []byte) ([]byte, error) {
	// Reject legacy, unsalted entries. An empty scheme means the record predates
	// the Argon2id format (unsalted SHA-256(masterPassword) key). This is an
	// intentional breaking change: such entries cannot be read and must be
	// re-Deposited.
	if scheme == "" {
		return nil, errors.New("escrow: legacy unsalted entry rejected; the on-disk format changed (Argon2id) and this key must be re-deposited")
	}
	if scheme != schemeArgon2idV1 {
		return nil, fmt.Errorf("escrow: unsupported entry scheme %q", scheme)
	}

	// Verify proof == SHA-256(masterPassword) in constant time. This preserves
	// the historical proof contract while no longer exposing a single derived
	// AES key (the AES key is now per-entry).
	if len(proof) != 32 {
		return nil, errors.New("escrow: proof must be 32 bytes (SHA-256)")
	}
	if subtle.ConstantTimeCompare(proof, e.pwVerifier) != 1 {
		return nil, errors.New("escrow: invalid proof")
	}

	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return nil, fmt.Errorf("escrow: decode salt: %w", err)
	}
	if len(salt) == 0 {
		return nil, errors.New("escrow: entry missing salt")
	}
	ct, err := hex.DecodeString(encHex)
	if err != nil {
		return nil, fmt.Errorf("escrow: decode ciphertext: %w", err)
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return nil, fmt.Errorf("escrow: decode nonce: %w", err)
	}

	aesKey := e.deriveKey(salt)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ct, nil)
}

func (e *FileEscrow) Deposit(keyID string, encryptedKey []byte) error {
	if keyID == "" {
		return errors.New("escrow: keyID must not be empty")
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	store, err := e.load()
	if err != nil {
		return err
	}

	scheme, saltHex, encHex, nonceHex, err := e.wrap(encryptedKey)
	if err != nil {
		return fmt.Errorf("escrow: wrap key: %w", err)
	}
	store.Keys[keyID] = fileEscrowRecord{
		Scheme:       scheme,
		Salt:         saltHex,
		EncryptedKey: encHex,
		Nonce:        nonceHex,
	}
	return e.save(store)
}

func (e *FileEscrow) Retrieve(keyID string, proof []byte) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	store, err := e.load()
	if err != nil {
		return nil, err
	}
	rec, ok := store.Keys[keyID]
	if !ok {
		return nil, fmt.Errorf("escrow: key %q not found", keyID)
	}
	return e.unwrap(rec.Scheme, rec.Salt, rec.EncryptedKey, rec.Nonce, proof)
}

func (e *FileEscrow) Rotate(keyID string, oldProof, newKey []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	store, err := e.load()
	if err != nil {
		return err
	}
	rec, ok := store.Keys[keyID]
	if !ok {
		return fmt.Errorf("escrow: key %q not found", keyID)
	}
	// Verify old proof (and that the existing entry is a supported scheme)
	// before replacing.
	if _, err := e.unwrap(rec.Scheme, rec.Salt, rec.EncryptedKey, rec.Nonce, oldProof); err != nil {
		return fmt.Errorf("escrow: rotate auth failed: %w", err)
	}

	// Re-wrap under a fresh salt.
	scheme, saltHex, encHex, nonceHex, err := e.wrap(newKey)
	if err != nil {
		return fmt.Errorf("escrow: wrap new key: %w", err)
	}
	store.Keys[keyID] = fileEscrowRecord{
		Scheme:       scheme,
		Salt:         saltHex,
		EncryptedKey: encHex,
		Nonce:        nonceHex,
	}
	return e.save(store)
}

// New returns the correct KeyEscrow implementation for the given backend name.
// Valid values: "local", "file". path and masterPassword are only used for "file".
func New(backend, path string, masterPassword []byte) (KeyEscrow, error) {
	switch backend {
	case "local":
		return NewLocalEscrow(), nil
	case "file":
		return NewFileEscrow(path, masterPassword)
	default:
		return nil, fmt.Errorf("escrow: unknown backend %q (use 'local' or 'file')", backend)
	}
}
