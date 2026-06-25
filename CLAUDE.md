# vault-git — Autonomous Completion Brief

## Project Identity
- **Repo:** `iamthegreatdestroyer/vault-git`
- **Local path:** `S:\vault-git`
- **Language:** Go
- **Castle Layer:** Layer 3 — Security & Cryptography (Git Integration)
- **Current completion:** ~70%
- **Mission:** Encrypted, content-addressable git-compatible storage with polymorphic encryption modes (Searchable, Computable, Provable, Hybrid) — AES-256-GCM core

## Current State (verified 2026-05-25)
| Component | Status |
|-----------|--------|
| AES-256-GCM encryption core | ✅ Done (`vault.go`) |
| Content-addressing (SHA256) | ✅ Done |
| Searchable encryption (HMAC deterministic nonce) | ✅ Done |
| ZK proof of content integrity (`Verify`) | ✅ Done |
| Disk persistence (`Persist`/`Load`) | ✅ Done |
| Unit tests | ✅ Done (`vault_test.go`) |
| CLI interface | ❌ Missing |
| Git hooks integration | ❌ Missing |
| FHE key escrow | ❌ Missing |
| Polymorphic container serialization | ❌ Missing |

## Key File Map
```
vault-git/
├── vault.go          # Core encrypted vault (AES-GCM, content-addressing, all modes)
├── vault_test.go     # Unit tests
├── go.mod            # Module: vault-git
├── go.sum
└── README.md
```

## What Remains (Final 30%)

### Sprint 1 — CLI Interface (Day 1)
**Goal:** `vault-git` binary with store/retrieve/verify/list commands.

```
@APEX create cmd/vault-git/main.go with cobra CLI:
  vault-git store <file>        # Encrypt and store file, print hash
  vault-git retrieve <hash>     # Decrypt and print content
  vault-git verify <hash>       # Verify content integrity (ZK proof)
  vault-git list                # List all stored object hashes and sizes
  vault-git stats               # Print vault statistics
  vault-git persist             # Flush in-memory vault to disk
  vault-git load                # Load vault from disk

Flags: --vault-path (default: .vault), --mode (searchable|computable|provable|hybrid),
       --key-file (path to master key file, required)

Wire: read master key from --key-file OR VAULT_MASTER_KEY env var.
Run: go build ./cmd/vault-git && echo "test data" | ./vault-git store /dev/stdin
```

### Sprint 2 — Git Hooks Integration (Day 2)
**Goal:** Transparent encryption of git objects via hooks.

```
@APEX create scripts/install-hooks.sh that installs two git hooks into .git/hooks/:

  pre-commit hook:
    - Walk git index for files matching patterns in .vault-config
    - For each matched file: vault-git store <file> → replace with encrypted version + .vault extension
    - Stage the encrypted file, unstage the plaintext

  post-checkout / post-merge hook:
    - Walk checkout tree for *.vault files
    - vault-git retrieve <hash-from-vault-file> → restore plaintext at original path

Create .vault-config format (YAML):
  encrypt:
    - "*.key"
    - "secrets/**"
    - ".env*"

Write a test in vault_test.go: TestGitHookWorkflow that simulates the pre-commit + checkout cycle.
```

### Sprint 3 — Polymorphic Container Serialization (Day 2–3)
**Goal:** Portable on-disk format for vault objects that includes metadata.

```
@APEX design and implement VaultContainer format in vault.go:
  - Magic bytes: [0x56, 0x4C, 0x54, 0x01] ("VLT\x01")
  - Header (JSON): { "hash": "...", "mode": "hybrid", "version": 1, "created_at": "..." }
  - Body: nonce (12 bytes) + ciphertext
  - Footer: HMAC-SHA256(key, header+body) for integrity

Update Persist() and Load() to use VaultContainer format.
Update vault_test.go: TestContainerRoundTrip, TestContainerTampering (should fail HMAC).
```

### Sprint 4 — FHE Key Escrow Stub (Day 3)
**Goal:** Framework for FHE key escrow (full FHE is complex; implement the interface + mock).

```
@APEX create escrow/escrow.go defining the KeyEscrow interface:
  type KeyEscrow interface {
    Deposit(keyID string, encryptedKey []byte) error  
    Retrieve(keyID string, proof []byte) ([]byte, error)
    Rotate(keyID string, oldProof, newKey []byte) error
  }

Implement LocalEscrow (in-memory mock) and FileEscrow (encrypted YAML on disk).
Add --escrow-backend flag to CLI (default: file).
Write tests for both backends.
```

### Sprint 5 — Final Tests + Tag (Day 4)
```
@GENESIS run: go test ./... -v -race
All tests must pass. Then:
  go vet ./...
  go build -o vault-git-linux-amd64 ./cmd/vault-git

Update README.md with CLI usage examples.
git tag v0.3.0 && git push origin v0.3.0
```

## Done Criteria (all must pass)
- [x] `go test ./... -race` passes — zero failures
- [x] `vault-git store / retrieve / verify / list / stats` commands work
- [x] Git pre-commit and post-checkout hooks install and work
- [x] VaultContainer binary format with HMAC integrity check
- [x] `KeyEscrow` interface with LocalEscrow + FileEscrow implementations
- [x] `go vet ./...` clean
- [x] `v0.3.0` tag pushed

## Completion Signal
```bash
git tag v0.3.0 && git push origin v0.3.0
```

## Critical Rules
1. **Master key never logs** — `VAULT_MASTER_KEY` and key file contents must never appear in logs
2. **HMAC integrity on all containers** — tampering must be detectable
3. **Persist before exit** — the CLI must always Persist() on graceful shutdown
4. **Tests in parallel** — `go test ./... -parallel 4` must pass; no shared mutable state in tests
