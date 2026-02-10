package vault

import (
	"fmt"
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
