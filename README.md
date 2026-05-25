# vault-git

Encrypted, content-addressable storage for the Ryzanstein LLM ecosystem.

## Overview

vault-git provides git-compatible encrypted object storage with multiple encryption modes:

| Mode           | Description                         | Use Case          |
| -------------- | ----------------------------------- | ----------------- |
| **Searchable** | Encrypted search without decryption | Audit logs        |
| **Computable** | Computation on encrypted data       | Secure processing |
| **Provable**   | Zero-knowledge proof of integrity   | Compliance        |
| **Hybrid**     | All modes combined                  | Default           |

## CLI Usage

Build the binary:

```bash
go build -o vault-git ./cmd/vault-git
```

Master key is read from `--key-file` or the `VAULT_MASTER_KEY` environment variable.
The key is **never** written to logs or stdout.

### store

Encrypt and store a file; prints its SHA-256 content hash.

```bash
export VAULT_MASTER_KEY="my-secret-key"

vault-git store secrets/.env
# 3f4a1b...

echo "inline data" | vault-git store -
# a9c3e2...
```

### retrieve

Decrypt content by hash and write to stdout.

```bash
vault-git retrieve 3f4a1b... > restored.env
```

### verify

Zero-knowledge proof: decrypt, re-hash, compare.

```bash
vault-git verify 3f4a1b...
# OK 3f4a1b...
```

### list

List all stored objects with their sizes and encryption modes.

```bash
vault-git list
# 3f4a1b...  1024 bytes  [hybrid]
# a9c3e2...   512 bytes  [searchable]
```

### stats

Print aggregate vault statistics.

```bash
vault-git stats
# Objects:        2
# Unique hashes:  2
# Plaintext size: 1536 bytes
# Encrypted size: 1584 bytes
```

### persist / load

Flush the in-memory vault to disk and reload it.

```bash
vault-git persist   # writes .vault/objects/...
vault-git load      # reloads and reports object count
```

### Flags

| Flag               | Default  | Description                                      |
| ------------------ | -------- | ------------------------------------------------ |
| `--vault-path`     | `.vault` | Directory for on-disk object store               |
| `--mode`           | `hybrid` | searchable, computable, provable, or hybrid      |
| `--key-file`       | *(none)* | Path to file containing the master key           |
| `--escrow-backend` | `file`   | Key escrow backend: file or local                |

## Key Escrow

Deposit, retrieve, and rotate wrapped keys:

```bash
vault-git escrow deposit  vault-key-1 "$(cat wrapped-key.bin)"
vault-git escrow retrieve vault-key-1
vault-git escrow rotate   vault-key-1 "$(cat new-wrapped-key.bin)"

# Use in-memory escrow (testing only)
vault-git --escrow-backend=local escrow deposit vault-key-1 "test-material"
```

## Git Hooks Integration

Install transparent encryption hooks into a git repo:

```bash
# Copy .vault-config to your repo root first
cp .vault-config /path/to/repo/

# Install hooks
bash scripts/install-hooks.sh /path/to/repo
```

`.vault-config` controls which files are encrypted on commit:

```yaml
encrypt:
  - "*.key"
  - "secrets/**"
  - ".env*"
```

**pre-commit**: matched files are encrypted, replaced with `<file>.vault` pointer, and the plaintext is unstaged.  
**post-checkout / post-merge**: `*.vault` pointer files are decrypted back to plaintext.

## Container Format

On-disk objects use the `VLT\x01` binary container format:

```
[4]  magic bytes  0x56 0x4C 0x54 0x01
[4]  header length (big-endian uint32)
[N]  JSON header  {"hash":"...","mode":"hybrid","version":1,"created_at":"..."}
[12] nonce
[M]  AES-256-GCM ciphertext
[32] HMAC-SHA256(key, all preceding bytes)
```

Any tampering is detected by the HMAC check on load.

## Library Usage

```go
import vault "github.com/ryzanstein/vault-git"

v, err := vault.New(vault.DefaultConfig(), masterKey)

obj, _ := v.Store([]byte("secret data"))
fmt.Println(obj.Hash) // SHA-256 hash

data, _ := v.Retrieve(obj.Hash)

ok, _ := v.Verify(obj.Hash) // ZK proof of integrity

v.Persist() // flush to .vault/objects/
v.Load()    // reload from disk
```

## Architecture

```
Content → SHA-256 Hash → AES-256-GCM Encrypt → VaultContainer → .vault/objects/ab/cdef...
                ↓
        Content Dedup (same hash = same object)
```

## Security

- AES-256-GCM authenticated encryption (256-bit key derived via SHA-256)
- SHA-256 content addressing with automatic deduplication
- Random nonce per object (no nonce reuse)
- HMAC-SHA256 integrity footer on every on-disk container
- Master key never appears in logs or diagnostic output

## Ryzanstein Integration

Integrates with Ryzanstein for:

- Encrypted model weight storage
- Secure checkpoint management
- Audit trail for model versions

## License

AGPL-3.0
