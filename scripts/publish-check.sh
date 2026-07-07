#!/usr/bin/env bash
# Pre-publish scrub check for a skill folder in this repo. Codifies the checks
# done by hand before the first publish: no personal/local-machine leakage, no
# stray metadata in attached PDFs, and a reminder about licensing.
#
# Usage: scripts/publish-check.sh <skill-folder-name>
set -uo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <skill-folder-name>" >&2
  exit 1
fi

NAME="$1"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="$ROOT/$NAME"

if [ ! -d "$DIR" ]; then
  echo "Error: $DIR does not exist" >&2
  exit 1
fi

FAIL=0

echo "== Scanning $NAME for personal/local-machine references =="
if grep -rniE "/Users/|/home/[a-z]+|first student" "$DIR" 2>/dev/null; then
  echo "!! Found local paths or flagged phrases above — review before publishing." >&2
  FAIL=1
else
  echo "OK: no local paths or flagged phrases found."
fi

echo
echo "== Checking for __pycache__ / .DS_Store / other junk =="
JUNK=$(find "$DIR" -name '__pycache__' -o -name '*.pyc' -o -name '.DS_Store')
if [ -n "$JUNK" ]; then
  echo "!! Found junk files, remove before publishing:" >&2
  echo "$JUNK"
  FAIL=1
else
  echo "OK: no junk files found."
fi

echo
echo "== Checking any PDFs for embedded author/producer metadata =="
if command -v pdfinfo >/dev/null 2>&1; then
  find "$DIR" -iname '*.pdf' -print0 | while IFS= read -r -d '' pdf; do
    echo "--- $pdf ---"
    pdfinfo "$pdf" 2>/dev/null | grep -E "^(Author|Creator|Producer):"
  done
  echo "Review the names above — confirm they're who you intend to credit."
else
  echo "pdfinfo not installed, skipping (brew install poppler to enable)."
fi

echo
echo "== Reminders =="
echo "- Does $NAME/README.md exist with install steps for Claude Code + Desktop?"
echo "- Does $NAME/README.md link to ../LICENSE if it uses non-default terms?"
echo "- Is $NAME listed under ## Skills in the root README.md?"

if [ "$FAIL" -ne 0 ]; then
  echo
  echo "FAILED: resolve the issues above before publishing." >&2
  exit 1
fi

echo
echo "All automated checks passed. Do a final manual skim before pushing."
