#!/usr/bin/env bash
# Re-export all .quokka files tracked by Git LFS.
#
# For each .quokka file in LFS, determines the source binary and
# disassembler backend (IDA or Ghidra) from the filename convention:
#   <name>.quokka         -> IDA export of binary <name>
#   <name>_ghidra.quokka  -> Ghidra export of binary <name>
#
# Usage:
#   scripts/refresh_quokka_lfs.sh [OPTIONS]
#
# Options:
#   --ida-only      Only refresh IDA exports
#   --ghidra-only   Only refresh Ghidra exports
#   --dry-run       Show what would be done without executing
#   -h, --help      Show this help
#
# Prerequisites:
#   - quokka-cli must be installed (pip install -e '.[dev]')
#   - For IDA exports: IDA Pro accessible via IDA_PATH or on PATH
#   - For Ghidra exports: GHIDRA_INSTALL_DIR set or Ghidra on PATH

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

IDA_ONLY=0
GHIDRA_ONLY=0
DRY_RUN=0

usage() {
  sed -n '2,/^$/{ s/^# \?//; p }' "$0"
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ida-only)    IDA_ONLY=1; shift ;;
    --ghidra-only) GHIDRA_ONLY=1; shift ;;
    --dry-run)     DRY_RUN=1; shift ;;
    -h|--help)     usage ;;
    *)             echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

if [[ "$IDA_ONLY" -eq 1 && "$GHIDRA_ONLY" -eq 1 ]]; then
  echo "Error: --ida-only and --ghidra-only are mutually exclusive" >&2
  exit 1
fi

# Collect all .quokka files from LFS
mapfile -t quokka_files < <(
  git -C "$REPO_ROOT" lfs ls-files --name-only | grep '\.quokka$'
)

if [[ ${#quokka_files[@]} -eq 0 ]]; then
  echo "No .quokka files found in Git LFS"
  exit 0
fi

FAILED=0

for qfile in "${quokka_files[@]}"; do
  name="$(basename "$qfile")"
  dir="$(dirname "$qfile")"

  # Determine backend and source binary from naming convention
  if [[ "$name" == *_ghidra.quokka ]]; then
    backend=ghidra
    # <stem>_ghidra.quokka -> binary is <stem> (look for exact match or with extension)
    stem="${name%_ghidra.quokka}"
  else
    backend=ida
    stem="${name%.quokka}"
  fi

  # Apply filter
  if [[ "$IDA_ONLY" -eq 1 && "$backend" != "ida" ]]; then
    continue
  fi
  if [[ "$GHIDRA_ONLY" -eq 1 && "$backend" != "ghidra" ]]; then
    continue
  fi

  # Find the source binary: check for exact stem match first, then
  # look for files starting with stem (handles extensions like .ko)
  binary=""
  if [[ -f "$REPO_ROOT/$dir/$stem" ]]; then
    binary="$REPO_ROOT/$dir/$stem"
  else
    # Try common binary extensions
    for ext in .ko .so .exe .elf .o; do
      if [[ -f "$REPO_ROOT/$dir/$stem$ext" ]]; then
        binary="$REPO_ROOT/$dir/$stem$ext"
        break
      fi
    done
  fi

  if [[ -z "$binary" ]]; then
    echo "SKIP $qfile: source binary not found for stem '$stem' in $dir/" >&2
    continue
  fi

  output="$REPO_ROOT/$qfile"

  echo "[$backend] $(basename "$binary") -> $qfile"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    continue
  fi

  # Remove stale export and any leftover IDA database to ensure a clean re-export
  rm -f "$output"

  if ! quokka-cli --override -b "$backend" -o "$name" "$binary"; then
    echo "  FAILED" >&2
    FAILED=$((FAILED + 1))
  fi
done

if [[ "$FAILED" -gt 0 ]]; then
  echo "$FAILED export(s) failed" >&2
  exit 1
fi
