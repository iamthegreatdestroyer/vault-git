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

## Quick Start

```go
import vault "github.com/ryzanstein/vault-git"

v, err := vault.New(vault.DefaultConfig(), masterKey)

// Store (content-addressable, automatic dedup)
obj, _ := v.Store([]byte("secret data"))
fmt.Println(obj.Hash) // SHA-256 hash

// Retrieve
data, _ := v.Retrieve(obj.Hash)

// Persist to disk (git-like .vault/objects/ structure)
v.Persist()
```

## Architecture

```
Content → SHA-256 Hash → AES-256-GCM Encrypt → .vault/objects/ab/cdef...
                ↓
        Content Dedup (same hash = same object)
```

## Security

- AES-256-GCM authenticated encryption
- SHA-256 content addressing (deduplication)
- Key derivation from master key
- All objects encrypted at rest
- Nonce per object (no nonce reuse)

## Ryzanstein Integration

Integrates with Ryzanstein for:

- Encrypted model weight storage
- Secure checkpoint management
- Audit trail for model versions

## License

AGPL-3.0
