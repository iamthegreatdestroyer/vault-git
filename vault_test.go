package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestVault(t *testing.T) *Vault {
	t.Helper()
	v, err := New(DefaultConfig(), []byte("test-master-key-1234567890"))
	require.NoError(t, err)
	return v
}

func TestNewVault(t *testing.T) {
	v := newTestVault(t)
	assert.NotNil(t, v)
	assert.Equal(t, ModeHybrid, v.config.EncryptionMode)
}

func TestNewVaultShortKey(t *testing.T) {
	_, err := New(DefaultConfig(), []byte("short"))
	assert.Error(t, err)
}

func TestStoreAndRetrieve(t *testing.T) {
	v := newTestVault(t)
	content := []byte("hello vault world")

	obj, err := v.Store(content)
	require.NoError(t, err)
	assert.NotEmpty(t, obj.Hash)
	assert.Equal(t, int64(len(content)), obj.Size)

	retrieved, err := v.Retrieve(obj.Hash)
	require.NoError(t, err)
	assert.Equal(t, content, retrieved)
}

func TestStoreDedup(t *testing.T) {
	v := newTestVault(t)
	content := []byte("duplicate content")

	obj1, _ := v.Store(content)
	obj2, _ := v.Store(content)
	assert.Equal(t, obj1.Hash, obj2.Hash)

	stats := v.Stats()
	assert.Equal(t, 1, stats.TotalObjects)
}

func TestRetrieveNotFound(t *testing.T) {
	v := newTestVault(t)
	_, err := v.Retrieve("nonexistent-hash")
	assert.Error(t, err)
}

func TestDelete(t *testing.T) {
	v := newTestVault(t)
	obj, _ := v.Store([]byte("to be deleted"))
	assert.True(t, v.Exists(obj.Hash))

	err := v.Delete(obj.Hash)
	require.NoError(t, err)
	assert.False(t, v.Exists(obj.Hash))
}

func TestDeleteNotFound(t *testing.T) {
	v := newTestVault(t)
	err := v.Delete("nonexistent")
	assert.Error(t, err)
}

func TestExists(t *testing.T) {
	v := newTestVault(t)
	assert.False(t, v.Exists("nothing"))

	obj, _ := v.Store([]byte("exists test"))
	assert.True(t, v.Exists(obj.Hash))
}

func TestStats(t *testing.T) {
	v := newTestVault(t)
	v.Store([]byte("first object"))
	v.Store([]byte("second object"))

	stats := v.Stats()
	assert.Equal(t, 2, stats.TotalObjects)
	assert.Equal(t, 2, stats.UniqueHashes)
	assert.True(t, stats.TotalSize > 0)
	assert.True(t, stats.EncryptedSize > 0)
}

func TestEncryptionModeString(t *testing.T) {
	assert.Equal(t, "searchable", ModeSearchable.String())
	assert.Equal(t, "computable", ModeComputable.String())
	assert.Equal(t, "provable", ModeProvable.String())
	assert.Equal(t, "hybrid", ModeHybrid.String())
	assert.Equal(t, "unknown", EncryptionMode(99).String())
}

func TestMaxObjectSize(t *testing.T) {
	config := DefaultConfig()
	config.MaxObjectSize = 10
	v, _ := New(config, []byte("test-master-key-1234567890"))

	_, err := v.Store([]byte("this exceeds limit"))
	assert.Error(t, err)
}

func TestConcurrentAccess(t *testing.T) {
	v := newTestVault(t)
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			content := []byte(fmt.Sprintf("concurrent-%d", id))
			v.Store(content)
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	stats := v.Stats()
	assert.Equal(t, 10, stats.TotalObjects)
}

// TestContainerRoundTrip verifies that marshalContainer → unmarshalContainer
// preserves the object and that Persist/Load round-trips correctly.
func TestContainerRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.StorePath = filepath.Join(dir, ".vault")
	v, err := New(cfg, []byte("container-roundtrip-key-0000000"))
	require.NoError(t, err)

	content := []byte("container round-trip test content")
	obj, err := v.Store(content)
	require.NoError(t, err)

	raw, err := v.marshalContainer(obj)
	require.NoError(t, err)

	got, err := v.unmarshalContainer(raw)
	require.NoError(t, err)
	assert.Equal(t, obj.Hash, got.Hash)
	assert.Equal(t, obj.Nonce, got.Nonce)
	assert.Equal(t, obj.Encrypted, got.Encrypted)

	// Full Persist → Load round-trip
	require.NoError(t, v.Persist())

	v2, err := New(cfg, []byte("container-roundtrip-key-0000000"))
	require.NoError(t, err)
	require.NoError(t, v2.Load())

	restored, err := v2.Retrieve(obj.Hash)
	require.NoError(t, err)
	assert.Equal(t, content, restored)
}

// TestContainerTampering verifies that any bit-flip in the container body
// is detected by the HMAC check.
func TestContainerTampering(t *testing.T) {
	t.Parallel()

	v, err := New(DefaultConfig(), []byte("tamper-test-key-000000000000000"))
	require.NoError(t, err)

	obj, err := v.Store([]byte("tamper me"))
	require.NoError(t, err)

	raw, err := v.marshalContainer(obj)
	require.NoError(t, err)

	// Flip one byte in the middle of the payload (skip magic+hdrLen = 8 bytes)
	tampered := make([]byte, len(raw))
	copy(tampered, raw)
	tampered[len(tampered)/2] ^= 0xFF

	_, err = v.unmarshalContainer(tampered)
	assert.Error(t, err, "expected HMAC failure on tampered container")
}

// TestGitHookWorkflow simulates the pre-commit + post-checkout lifecycle:
//  1. Encrypt a "sensitive" file and write a .vault pointer (pre-commit analog).
//  2. Remove the plaintext; restore it from the pointer (post-checkout analog).
//  3. Assert restored content equals original.
func TestGitHookWorkflow(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.StorePath = filepath.Join(dir, ".vault")
	v, err := New(cfg, []byte("hook-workflow-test-key-000000"))
	require.NoError(t, err)

	// ── pre-commit: encrypt a secrets file ──────────────────────────────────
	secretContent := []byte("DATABASE_URL=postgres://user:p@ssw0rd@host/db")
	secretFile := filepath.Join(dir, ".env")
	require.NoError(t, os.WriteFile(secretFile, secretContent, 0600))

	data, err := os.ReadFile(secretFile)
	require.NoError(t, err)

	obj, err := v.Store(data)
	require.NoError(t, err)

	// Write pointer file (what the pre-commit hook does)
	vaultPointer := secretFile + ".vault"
	require.NoError(t, os.WriteFile(vaultPointer, []byte(obj.Hash), 0600))

	// Unstage plaintext (simulate git rm --cached)
	require.NoError(t, os.Remove(secretFile))
	assert.NoFileExists(t, secretFile)

	// Persist vault to disk
	require.NoError(t, v.Persist())

	// ── post-checkout: decrypt from pointer ─────────────────────────────────
	// Simulate fresh vault load (new process)
	v2, err := New(cfg, []byte("hook-workflow-test-key-000000"))
	require.NoError(t, err)
	require.NoError(t, v2.Load())

	hash, err := os.ReadFile(vaultPointer)
	require.NoError(t, err)

	restored, err := v2.Retrieve(string(hash))
	require.NoError(t, err)

	// Write restored plaintext and remove pointer
	require.NoError(t, os.WriteFile(secretFile, restored, 0600))
	require.NoError(t, os.Remove(vaultPointer))

	// Assert content matches original
	got, err := os.ReadFile(secretFile)
	require.NoError(t, err)
	assert.Equal(t, secretContent, got)
}
