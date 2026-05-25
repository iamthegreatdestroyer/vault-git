package escrow

import (
	"crypto/sha256"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// proof computes the expected proof value (sha256 of the escrow aesKey itself)
// matching what unwrap verifies.
func makeProof(masterPassword []byte) []byte {
	aesKey := sha256.Sum256(masterPassword)
	// unwrap checks: sha256(proof) == sha256(aesKey)
	// so proof = aesKey
	return aesKey[:]
}

func TestLocalEscrow_DepositRetrieve(t *testing.T) {
	t.Parallel()
	e := NewLocalEscrow()

	key := []byte("super-secret-key-material")
	require.NoError(t, e.Deposit("k1", key))

	got, err := e.Retrieve("k1", nil)
	require.NoError(t, err)
	assert.Equal(t, key, got)
}

func TestLocalEscrow_DepositDedup(t *testing.T) {
	t.Parallel()
	e := NewLocalEscrow()

	require.NoError(t, e.Deposit("k1", []byte("first")))
	require.NoError(t, e.Deposit("k1", []byte("second")))

	got, err := e.Retrieve("k1", nil)
	require.NoError(t, err)
	assert.Equal(t, []byte("second"), got)
}

func TestLocalEscrow_Rotate(t *testing.T) {
	t.Parallel()
	e := NewLocalEscrow()

	require.NoError(t, e.Deposit("k1", []byte("old-key")))
	require.NoError(t, e.Rotate("k1", nil, []byte("new-key")))

	got, err := e.Retrieve("k1", nil)
	require.NoError(t, err)
	assert.Equal(t, []byte("new-key"), got)
}

func TestLocalEscrow_NotFound(t *testing.T) {
	t.Parallel()
	e := NewLocalEscrow()
	_, err := e.Retrieve("missing", nil)
	assert.Error(t, err)

	err = e.Rotate("missing", nil, []byte("x"))
	assert.Error(t, err)
}

func TestLocalEscrow_EmptyKeyID(t *testing.T) {
	t.Parallel()
	e := NewLocalEscrow()
	assert.Error(t, e.Deposit("", []byte("key")))
}

func TestFileEscrow_DepositRetrieve(t *testing.T) {
	t.Parallel()

	password := []byte("file-escrow-master-pass")
	path := filepath.Join(t.TempDir(), "escrow.yaml")

	e, err := NewFileEscrow(path, password)
	require.NoError(t, err)

	keyMaterial := []byte("my-encrypted-vault-key")
	require.NoError(t, e.Deposit("vault-key-1", keyMaterial))

	proof := makeProof(password)
	got, err := e.Retrieve("vault-key-1", proof)
	require.NoError(t, err)
	assert.Equal(t, keyMaterial, got)
}

func TestFileEscrow_Rotate(t *testing.T) {
	t.Parallel()

	password := []byte("rotate-test-pass")
	path := filepath.Join(t.TempDir(), "escrow.yaml")

	e, err := NewFileEscrow(path, password)
	require.NoError(t, err)

	require.NoError(t, e.Deposit("k1", []byte("old")))
	proof := makeProof(password)
	require.NoError(t, e.Rotate("k1", proof, []byte("new")))

	got, err := e.Retrieve("k1", proof)
	require.NoError(t, err)
	assert.Equal(t, []byte("new"), got)
}

func TestFileEscrow_WrongProof(t *testing.T) {
	t.Parallel()

	password := []byte("correct-pass")
	path := filepath.Join(t.TempDir(), "escrow.yaml")

	e, err := NewFileEscrow(path, password)
	require.NoError(t, err)

	require.NoError(t, e.Deposit("k1", []byte("secret")))

	wrongProof := make([]byte, 32) // all zeros
	_, err = e.Retrieve("k1", wrongProof)
	assert.Error(t, err)
}

func TestFileEscrow_Persistence(t *testing.T) {
	t.Parallel()

	password := []byte("persistence-test")
	path := filepath.Join(t.TempDir(), "escrow.yaml")

	e1, err := NewFileEscrow(path, password)
	require.NoError(t, err)
	require.NoError(t, e1.Deposit("pk1", []byte("persisted-key")))

	// Open a fresh FileEscrow on the same file — simulates process restart
	e2, err := NewFileEscrow(path, password)
	require.NoError(t, err)

	proof := makeProof(password)
	got, err := e2.Retrieve("pk1", proof)
	require.NoError(t, err)
	assert.Equal(t, []byte("persisted-key"), got)
}

func TestNew_Backends(t *testing.T) {
	t.Parallel()

	e, err := New("local", "", nil)
	require.NoError(t, err)
	assert.NotNil(t, e)

	path := filepath.Join(t.TempDir(), "escrow.yaml")
	e2, err := New("file", path, []byte("pass"))
	require.NoError(t, err)
	assert.NotNil(t, e2)

	_, err = New("unknown", "", nil)
	assert.Error(t, err)
}
