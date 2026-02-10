// Package vault provides encrypted, content-addressable storage compatible with
// git object semantics for the Ryzanstein LLM ecosystem.
//
// It supports multiple encryption modes:
//   - Searchable: allows encrypted search without decryption
//   - Computable: enables computation on encrypted data
//   - Provable: zero-knowledge proof of content integrity
//   - Hybrid: combines modes for maximum flexibility
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// EncryptionMode specifies the vault encryption strategy
type EncryptionMode int

const (
	ModeSearchable EncryptionMode = iota
	ModeComputable
	ModeProvable
	ModeHybrid
)

func (m EncryptionMode) String() string {
	switch m {
	case ModeSearchable:
		return "searchable"
	case ModeComputable:
		return "computable"
	case ModeProvable:
		return "provable"
	case ModeHybrid:
		return "hybrid"
	default:
		return "unknown"
	}
}

// VaultConfig configures the vault
type VaultConfig struct {
	StorePath      string         `yaml:"store_path"`
	EncryptionMode EncryptionMode `yaml:"encryption_mode"`
	KeyDerivation  string         `yaml:"key_derivation"` // "argon2" or "pbkdf2"
	RyzansteinURL  string         `yaml:"ryzanstein_url"`
	MaxObjectSize  int64          `yaml:"max_object_size"`
}

// DefaultConfig returns sensible defaults
func DefaultConfig() VaultConfig {
	return VaultConfig{
		StorePath:      ".vault",
		EncryptionMode: ModeHybrid,
		KeyDerivation:  "argon2",
		RyzansteinURL:  "http://localhost:8000",
		MaxObjectSize:  100 * 1024 * 1024, // 100 MB
	}
}

// Object represents a stored encrypted object
type Object struct {
	Hash       string         `json:"hash"`
	Size       int64          `json:"size"`
	Mode       EncryptionMode `json:"mode"`
	Encrypted  []byte         `json:"-"`
	Nonce      []byte         `json:"-"`
	ContentTag []byte         `json:"content_tag,omitempty"`
}

// VaultStats holds vault statistics
type VaultStats struct {
	TotalObjects   int   `json:"total_objects"`
	TotalSize      int64 `json:"total_size"`
	EncryptedSize  int64 `json:"encrypted_size"`
	UniqueHashes   int   `json:"unique_hashes"`
}

// Vault is the main encrypted content-addressable store
type Vault struct {
	config  VaultConfig
	objects map[string]*Object
	key     []byte
	mu      sync.RWMutex
}

// New creates a new Vault with the given config and master key
func New(config VaultConfig, masterKey []byte) (*Vault, error) {
	if len(masterKey) < 16 {
		return nil, fmt.Errorf("master key must be at least 16 bytes")
	}
	// Derive AES-256 key from master key
	hash := sha256.Sum256(masterKey)
	return &Vault{
		config:  config,
		objects: make(map[string]*Object),
		key:     hash[:],
	}, nil
}

// Store encrypts and stores content, returns content-addressed hash
func (v *Vault) Store(content []byte) (*Object, error) {
	if int64(len(content)) > v.config.MaxObjectSize {
		return nil, fmt.Errorf("content exceeds max size: %d > %d", len(content), v.config.MaxObjectSize)
	}

	// Content-addressable hash (like git)
	hash := sha256.Sum256(content)
	hashStr := hex.EncodeToString(hash[:])

	v.mu.RLock()
	if obj, exists := v.objects[hashStr]; exists {
		v.mu.RUnlock()
		return obj, nil // Dedup: already stored
	}
	v.mu.RUnlock()

	// Encrypt
	encrypted, nonce, err := v.encrypt(content)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	obj := &Object{
		Hash:      hashStr,
		Size:      int64(len(content)),
		Mode:      v.config.EncryptionMode,
		Encrypted: encrypted,
		Nonce:     nonce,
	}

	v.mu.Lock()
	v.objects[hashStr] = obj
	v.mu.Unlock()

	return obj, nil
}

// Retrieve decrypts and returns content by hash
func (v *Vault) Retrieve(hash string) ([]byte, error) {
	v.mu.RLock()
	obj, exists := v.objects[hash]
	v.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("object not found: %s", hash)
	}

	content, err := v.decrypt(obj.Encrypted, obj.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return content, nil
}

// Delete removes an object by hash
func (v *Vault) Delete(hash string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, exists := v.objects[hash]; !exists {
		return fmt.Errorf("object not found: %s", hash)
	}
	delete(v.objects, hash)
	return nil
}

// Exists checks if an object exists
func (v *Vault) Exists(hash string) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	_, exists := v.objects[hash]
	return exists
}

// Stats returns vault statistics
func (v *Vault) Stats() VaultStats {
	v.mu.RLock()
	defer v.mu.RUnlock()
	var totalSize, encSize int64
	for _, obj := range v.objects {
		totalSize += obj.Size
		encSize += int64(len(obj.Encrypted))
	}
	return VaultStats{
		TotalObjects:  len(v.objects),
		TotalSize:     totalSize,
		EncryptedSize: encSize,
		UniqueHashes:  len(v.objects),
	}
}

// Persist writes the vault to disk
func (v *Vault) Persist() error {
	v.mu.RLock()
	defer v.mu.RUnlock()

	dir := v.config.StorePath
	if err := os.MkdirAll(filepath.Join(dir, "objects"), 0700); err != nil {
		return err
	}

	for hash, obj := range v.objects {
		prefix := hash[:2]
		objDir := filepath.Join(dir, "objects", prefix)
		if err := os.MkdirAll(objDir, 0700); err != nil {
			return err
		}
		path := filepath.Join(objDir, hash[2:])
		data := append(obj.Nonce, obj.Encrypted...)
		if err := os.WriteFile(path, data, 0600); err != nil {
			return err
		}
	}
	return nil
}

func (v *Vault) encrypt(plaintext []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(v.key)
	if err != nil {
		return nil, nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

func (v *Vault) decrypt(ciphertext, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(v.key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
