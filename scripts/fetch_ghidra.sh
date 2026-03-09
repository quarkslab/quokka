#!/usr/bin/env bash
# Fetch the Ghidra release matching the third_party/ghidra submodule tag.
# Prints the resolved install path on the last line of stdout.
#
# Usage:
#   scripts/fetch_ghidra.sh [--dest DIR] [--force] [--update-submodule [TAG]]
#
# Dependencies: git, curl, unzip, jq

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST=""
FORCE=0
UPDATE_TAG=""
UPDATE_SUBMODULE=0

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  --dest DIR               Install directory (default: third_party/)
  --force                  Re-download even if directory exists
  --update-submodule [TAG] Checkout TAG in the ghidra submodule before fetching
                           (if TAG is omitted, fetches the latest remote tag)
  -h, --help               Show this help
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dest)       DEST="$2"; shift 2 ;;
    --force)      FORCE=1; shift ;;
    --update-submodule)
      UPDATE_SUBMODULE=1
      # TAG is optional: consume next arg only if it doesn't look like a flag
      if [[ $# -ge 2 && "$2" != --* ]]; then
        UPDATE_TAG="$2"; shift 2
      else
        shift
      fi
      ;;
    -h|--help)    usage ;;
    *)            echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

# --- Update submodule if requested ---
SUBMODULE_DIR="$REPO_ROOT/third_party/ghidra"

if [[ "$UPDATE_SUBMODULE" -eq 1 ]]; then
  git -C "$SUBMODULE_DIR" fetch --tags
  if [[ -z "$UPDATE_TAG" ]]; then
    # Resolve the latest Ghidra_X.Y.Z_build tag by version sort (three-part versions only)
    UPDATE_TAG="$(git -C "$SUBMODULE_DIR" tag -l 'Ghidra_*_build' | grep -E '^Ghidra_[0-9]+\.[0-9]+\.[0-9]+_build$' | sort -V | tail -n1)"
    if [[ -z "$UPDATE_TAG" ]]; then
      echo "Error: No Ghidra_*_build tags found in submodule remote" >&2
      exit 1
    fi
    echo "Resolved latest tag: $UPDATE_TAG" >&2
  fi
  echo "Updating submodule to tag $UPDATE_TAG ..." >&2
  git -C "$SUBMODULE_DIR" checkout "$UPDATE_TAG"
fi

# --- Read tag from submodule ---
if [[ ! -d "$SUBMODULE_DIR/.git" && ! -f "$SUBMODULE_DIR/.git" ]]; then
  echo "Error: Ghidra submodule not checked out at $SUBMODULE_DIR" >&2
  echo "Run: git submodule update --init third_party/ghidra" >&2
  exit 1
fi

TAG="$(git -C "$SUBMODULE_DIR" describe --tags --exact-match 2>/dev/null)" || {
  echo "Error: Cannot determine exact tag for third_party/ghidra" >&2
  echo "The submodule HEAD must point to a tag like Ghidra_X.Y.Z_build" >&2
  exit 1
}

# Parse version from tag (e.g. Ghidra_12.0.3_build -> 12.0.3)
if [[ "$TAG" =~ ^Ghidra_([0-9]+\.[0-9]+\.[0-9]+)_build$ ]]; then
  VERSION="${BASH_REMATCH[1]}"
else
  echo "Error: Tag '$TAG' does not match expected pattern Ghidra_X.Y.Z_build" >&2
  exit 1
fi

echo "Ghidra version from submodule: $VERSION (tag: $TAG)" >&2

# --- Resolve destination ---
if [[ -z "$DEST" ]]; then
  DEST="$REPO_ROOT/third_party"
fi

# --- Query GitHub API for the release asset ---
API_URL="https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/tags/$TAG"
echo "Querying GitHub releases API ..." >&2

RELEASE_JSON="$(curl -fsSL "$API_URL")" || {
  echo "Error: Failed to query GitHub releases for tag $TAG" >&2
  exit 1
}

# Find the asset matching ghidra_<version>_PUBLIC_*.zip
ASSET_URL="$(echo "$RELEASE_JSON" | jq -r \
  --arg pat "ghidra_${VERSION}_PUBLIC_" \
  '.assets[] | select(.name | startswith($pat)) | select(.name | endswith(".zip")) | .browser_download_url' \
  | head -n1)"

ASSET_NAME="$(echo "$RELEASE_JSON" | jq -r \
  --arg pat "ghidra_${VERSION}_PUBLIC_" \
  '.assets[] | select(.name | startswith($pat)) | select(.name | endswith(".zip")) | .name' \
  | head -n1)"

if [[ -z "$ASSET_URL" || "$ASSET_URL" == "null" ]]; then
  echo "Error: No asset matching ghidra_${VERSION}_PUBLIC_*.zip in release $TAG" >&2
  exit 1
fi

# Derive install dir name from asset (e.g. ghidra_12.0.3_PUBLIC_20260210.zip -> ghidra_12.0.3_PUBLIC)
INSTALL_DIR_NAME="${ASSET_NAME%.zip}"
# Strip the date suffix: ghidra_12.0.3_PUBLIC_20260210 -> ghidra_12.0.3_PUBLIC
INSTALL_DIR_NAME="$(echo "$INSTALL_DIR_NAME" | sed 's/_[0-9]\{8\}$//')"
INSTALL_PATH="$DEST/$INSTALL_DIR_NAME"

# --- Skip if already present ---
if [[ -d "$INSTALL_PATH" && "$FORCE" -eq 0 ]]; then
  echo "Already installed at $INSTALL_PATH (use --force to re-download)" >&2
  echo "$INSTALL_PATH"
  exit 0
fi

# --- Download and extract ---
TMPZIP="$(mktemp)"
trap 'rm -f "$TMPZIP"' EXIT

echo "Downloading $ASSET_NAME ..." >&2
curl -fsSL -o "$TMPZIP" "$ASSET_URL"

if [[ "$FORCE" -eq 1 && -d "$INSTALL_PATH" ]]; then
  echo "Removing existing $INSTALL_PATH (--force) ..." >&2
  rm -rf "$INSTALL_PATH"
fi

echo "Extracting to $DEST/ ..." >&2
unzip -q "$TMPZIP" -d "$DEST"

if [[ ! -d "$INSTALL_PATH" ]]; then
  echo "Error: Expected directory $INSTALL_PATH not found after extraction" >&2
  echo "Contents of $DEST:" >&2
  ls "$DEST" >&2
  exit 1
fi

echo "Ghidra $VERSION installed at $INSTALL_PATH" >&2
echo "$INSTALL_PATH"
