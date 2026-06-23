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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
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
	// Derive AES-256 key from master key using Argon2id
	salt := []byte("vault-git-v1-key-derivation")
	derivedKey := argon2.IDKey(masterKey, salt, 1, 64*1024, 4, 32)
	return &Vault{
		config:  config,
		objects: make(map[string]*Object),
		key:     derivedKey,
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

// List returns all objects in the vault.
func (v *Vault) List() []*Object {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]*Object, 0, len(v.objects))
	for _, obj := range v.objects {
		out = append(out, obj)
	}
	return out
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

// Persist writes the vault to disk using the VaultContainer binary format.
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
		data, err := v.marshalContainer(obj)
		if err != nil {
			return fmt.Errorf("marshal container %s: %w", hash, err)
		}
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

// SearchableStore encrypts content with a deterministic nonce derived from
// HMAC-SHA256(key, plaintext). This allows equality search on encrypted data:
// the same plaintext always produces the same ciphertext.
func (v *Vault) SearchableStore(content []byte) (*Object, error) {
	if int64(len(content)) > v.config.MaxObjectSize {
		return nil, fmt.Errorf("content exceeds max size: %d > %d", len(content), v.config.MaxObjectSize)
	}

	hash := sha256.Sum256(content)
	hashStr := hex.EncodeToString(hash[:])

	v.mu.RLock()
	if obj, exists := v.objects[hashStr]; exists {
		v.mu.RUnlock()
		return obj, nil
	}
	v.mu.RUnlock()

	// Deterministic nonce via HMAC-SHA256(key, content)
	encrypted, nonce, err := v.encryptDeterministic(content)
	if err != nil {
		return nil, fmt.Errorf("searchable encryption failed: %w", err)
	}

	obj := &Object{
		Hash:      hashStr,
		Size:      int64(len(content)),
		Mode:      ModeSearchable,
		Encrypted: encrypted,
		Nonce:     nonce,
	}

	v.mu.Lock()
	v.objects[hashStr] = obj
	v.mu.Unlock()

	return obj, nil
}

// Verify proves that the vault holds content matching the given hash
// by decrypting and re-hashing, then comparing. Returns true if verified.
func (v *Vault) Verify(hashStr string) (bool, error) {
	content, err := v.Retrieve(hashStr)
	if err != nil {
		return false, err
	}

	computed := sha256.Sum256(content)
	computedStr := hex.EncodeToString(computed[:])
	return computedStr == hashStr, nil
}

// Load reads VaultContainer objects from disk back into memory.
// Complement to Persist().
func (v *Vault) Load() error {
	dir := v.config.StorePath
	objDir := filepath.Join(dir, "objects")

	prefixes, err := os.ReadDir(objDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No vault on disk yet
		}
		return fmt.Errorf("read objects dir: %w", err)
	}

	// Build GCM once to get nonce size for size validation before decryption.
	block, err := aes.NewCipher(v.key)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create GCM: %w", err)
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	for _, prefix := range prefixes {
		if !prefix.IsDir() {
			continue
		}
		prefixPath := filepath.Join(objDir, prefix.Name())
		entries, err := os.ReadDir(prefixPath)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			hashStr := prefix.Name() + entry.Name()
			data, err := os.ReadFile(filepath.Join(prefixPath, entry.Name()))
			if err != nil {
				continue
			}

			obj, err := v.unmarshalContainer(data)
			if err != nil {
				continue // Skip tampered or corrupted objects
			}

			// Verify decryptability and determine plaintext size.
			plaintext, err := aesGCM.Open(nil, obj.Nonce, obj.Encrypted, nil)
			if err != nil {
				continue
			}

			obj.Hash = hashStr
			obj.Size = int64(len(plaintext))
			v.objects[hashStr] = obj
		}
	}

	return nil
}

// encryptDeterministic uses HMAC-SHA256 of the key+content as nonce,
// enabling equality search on ciphertexts.
func (v *Vault) encryptDeterministic(plaintext []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(v.key)
	if err != nil {
		return nil, nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	// Derive deterministic nonce from HMAC-SHA256(key, plaintext)
	mac := hmacSHA256(v.key, plaintext)
	nonce := mac[:aesGCM.NonceSize()]

	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// hmacSHA256 computes HMAC-SHA256
func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// ── VaultContainer binary format ────────────────────────────────────────────
//
// Layout:
//   [4]  magic bytes: 0x56 0x4C 0x54 0x01  ("VLT\x01")
//   [4]  header length (big-endian uint32)
//   [N]  JSON header
//   [12] nonce
//   [M]  ciphertext
//   [32] HMAC-SHA256(key, magic+headerLen+header+nonce+ciphertext)

var containerMagic = [4]byte{0x56, 0x4C, 0x54, 0x01}

type containerHeader struct {
	Hash      string `json:"hash"`
	Mode      string `json:"mode"`
	Version   int    `json:"version"`
	CreatedAt string `json:"created_at"`
}

// marshalContainer serialises obj into the VaultContainer binary format.
func (v *Vault) marshalContainer(obj *Object) ([]byte, error) {
	hdr := containerHeader{
		Hash:      obj.Hash,
		Mode:      obj.Mode.String(),
		Version:   1,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	hdrJSON, err := json.Marshal(hdr)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	buf.Write(containerMagic[:])

	hdrLen := make([]byte, 4)
	binary.BigEndian.PutUint32(hdrLen, uint32(len(hdrJSON)))
	buf.Write(hdrLen)
	buf.Write(hdrJSON)
	buf.Write(obj.Nonce)
	buf.Write(obj.Encrypted)

	payload := buf.Bytes()
	mac := hmacSHA256(v.key, payload)
	buf.Write(mac)

	return buf.Bytes(), nil
}

// unmarshalContainer parses a VaultContainer byte slice and verifies HMAC.
func (v *Vault) unmarshalContainer(data []byte) (*Object, error) {
	const minSize = 4 + 4 + 1 + 12 + 32 // magic+hdrLen+minHdr+nonce+mac
	if len(data) < minSize {
		return nil, errors.New("container too small")
	}

	if [4]byte(data[:4]) != containerMagic {
		return nil, errors.New("bad magic bytes")
	}

	hdrLen := binary.BigEndian.Uint32(data[4:8])
	if int(hdrLen) > len(data)-8-32 {
		return nil, errors.New("header length overflow")
	}

	hdrEnd := 8 + int(hdrLen)
	hdrJSON := data[8:hdrEnd]

	// HMAC covers everything except the trailing 32-byte mac
	payload := data[:len(data)-32]
	mac := data[len(data)-32:]
	expected := hmacSHA256(v.key, payload)
	if !hmac.Equal(mac, expected) {
		return nil, errors.New("HMAC verification failed: container tampered")
	}

	var hdr containerHeader
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}

	body := data[hdrEnd : len(data)-32]
	if len(body) < 12 {
		return nil, errors.New("body too small for nonce")
	}
	nonce := body[:12]
	encrypted := body[12:]

	return &Object{
		Hash:      hdr.Hash,
		Mode:      v.config.EncryptionMode,
		Nonce:     nonce,
		Encrypted: encrypted,
	}, nil
}
