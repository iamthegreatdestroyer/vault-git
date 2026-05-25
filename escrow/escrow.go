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
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

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

// fileEscrowRecord is what gets persisted per key entry.
type fileEscrowRecord struct {
	// EncryptedKey is AES-GCM( masterKey-derived, encryptedKey payload )
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
// AES-256-GCM keyed by SHA-256(masterPassword). The proof passed to
// Retrieve/Rotate must equal SHA-256(masterPassword).
type FileEscrow struct {
	path     string
	aesKey   []byte // sha256(masterPassword)
	mu       sync.Mutex
}

// NewFileEscrow creates a FileEscrow backed by the given file path.
// masterPassword is hashed with SHA-256 to derive the AES-256 key.
// masterPassword must never be logged by callers.
func NewFileEscrow(path string, masterPassword []byte) (*FileEscrow, error) {
	if len(masterPassword) == 0 {
		return nil, errors.New("escrow: master password must not be empty")
	}
	h := sha256.Sum256(masterPassword)
	return &FileEscrow{path: path, aesKey: h[:]}, nil
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

func (e *FileEscrow) wrap(plainKey []byte) (string, string, error) {
	block, err := aes.NewCipher(e.aesKey)
	if err != nil {
		return "", "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", err
	}
	ct := gcm.Seal(nil, nonce, plainKey, nil)
	return hex.EncodeToString(ct), hex.EncodeToString(nonce), nil
}

func (e *FileEscrow) unwrap(encHex, nonceHex string, proof []byte) ([]byte, error) {
	// Verify proof == e.aesKey (caller passes sha256(masterPassword))
	if len(proof) != 32 {
		return nil, errors.New("escrow: proof must be 32 bytes (SHA-256)")
	}
	proofHash := sha256.Sum256(proof)
	keyHash := sha256.Sum256(e.aesKey)
	if proofHash != keyHash {
		return nil, errors.New("escrow: invalid proof")
	}

	ct, err := hex.DecodeString(encHex)
	if err != nil {
		return nil, fmt.Errorf("escrow: decode ciphertext: %w", err)
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return nil, fmt.Errorf("escrow: decode nonce: %w", err)
	}

	block, err := aes.NewCipher(e.aesKey)
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

	encHex, nonceHex, err := e.wrap(encryptedKey)
	if err != nil {
		return fmt.Errorf("escrow: wrap key: %w", err)
	}
	store.Keys[keyID] = fileEscrowRecord{EncryptedKey: encHex, Nonce: nonceHex}
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
	return e.unwrap(rec.EncryptedKey, rec.Nonce, proof)
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
	// Verify old proof before replacing
	if _, err := e.unwrap(rec.EncryptedKey, rec.Nonce, oldProof); err != nil {
		return fmt.Errorf("escrow: rotate auth failed: %w", err)
	}

	encHex, nonceHex, err := e.wrap(newKey)
	if err != nil {
		return fmt.Errorf("escrow: wrap new key: %w", err)
	}
	store.Keys[keyID] = fileEscrowRecord{EncryptedKey: encHex, Nonce: nonceHex}
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
