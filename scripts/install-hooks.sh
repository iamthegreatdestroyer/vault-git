#!/usr/bin/env bash
# Installs vault-git pre-commit and post-checkout git hooks.
# Usage: bash scripts/install-hooks.sh [git-repo-path]
set -euo pipefail

REPO="${1:-.}"
HOOKS_DIR="$REPO/.git/hooks"

if [[ ! -d "$REPO/.git" ]]; then
  echo "ERROR: $REPO is not a git repository" >&2
  exit 1
fi

VAULT_GIT_BIN="${VAULT_GIT_BIN:-vault-git}"

mkdir -p "$HOOKS_DIR"

# ── pre-commit ──────────────────────────────────────────────────────────────
cat > "$HOOKS_DIR/pre-commit" << 'HOOK'
#!/usr/bin/env bash
# vault-git pre-commit hook: encrypts files matching .vault-config patterns.
set -euo pipefail

VAULT_GIT_BIN="${VAULT_GIT_BIN:-vault-git}"
CONFIG=".vault-config"

if [[ ! -f "$CONFIG" ]]; then
  exit 0  # Nothing to do
fi

# Read encrypt patterns from YAML (lines under `encrypt:` that start with `  - `)
mapfile -t PATTERNS < <(grep -E '^\s+-\s+"' "$CONFIG" | sed 's/.*"\(.*\)".*/\1/')

if [[ ${#PATTERNS[@]} -eq 0 ]]; then
  exit 0
fi

# Get staged files
mapfile -t STAGED < <(git diff --cached --name-only --diff-filter=ACM)

for FILE in "${STAGED[@]}"; do
  for PATTERN in "${PATTERNS[@]}"; do
    # Use bash glob matching
    if [[ "$FILE" == $PATTERN ]]; then
      if [[ ! -f "$FILE" ]]; then
        continue
      fi
      echo "[vault-git] encrypting $FILE"

      # Store encrypted copy
      HASH=$("$VAULT_GIT_BIN" store "$FILE")
      VAULT_FILE="${FILE}.vault"

      # Write a pointer file: just the hash
      echo "$HASH" > "$VAULT_FILE"

      # Stage encrypted pointer, unstage original
      git add "$VAULT_FILE"
      git rm --cached "$FILE" 2>/dev/null || true
      break
    fi
  done
done
HOOK

chmod +x "$HOOKS_DIR/pre-commit"

# ── post-checkout / post-merge ───────────────────────────────────────────────
cat > "$HOOKS_DIR/post-checkout" << 'HOOK'
#!/usr/bin/env bash
# vault-git post-checkout hook: decrypts *.vault pointer files.
set -euo pipefail

VAULT_GIT_BIN="${VAULT_GIT_BIN:-vault-git}"

# Find all .vault pointer files in the working tree
while IFS= read -r -d '' VAULT_FILE; do
  HASH=$(cat "$VAULT_FILE")
  ORIGINAL="${VAULT_FILE%.vault}"

  if [[ -z "$HASH" ]]; then
    continue
  fi

  echo "[vault-git] decrypting $VAULT_FILE → $ORIGINAL"
  "$VAULT_GIT_BIN" retrieve "$HASH" > "$ORIGINAL" && rm "$VAULT_FILE" || true
done < <(find . -name "*.vault" -not -path "./.vault/*" -print0)
HOOK

chmod +x "$HOOKS_DIR/post-checkout"

# post-merge reuses post-checkout
cp "$HOOKS_DIR/post-checkout" "$HOOKS_DIR/post-merge"
chmod +x "$HOOKS_DIR/post-merge"

echo "vault-git hooks installed in $HOOKS_DIR"
echo "  pre-commit   → encrypts files matching .vault-config patterns"
echo "  post-checkout → decrypts *.vault pointer files on checkout/merge"
