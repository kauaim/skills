#!/usr/bin/env bash
# Scaffold a new skill folder from templates/SKILL_TEMPLATE, and add it to the
# root README index.
#
# Usage: scripts/new-skill.sh <skill-folder-name>
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <skill-folder-name>" >&2
  exit 1
fi

NAME="$1"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/$NAME"

if [ -e "$DEST" ]; then
  echo "Error: $DEST already exists" >&2
  exit 1
fi

cp -R "$ROOT/templates/SKILL_TEMPLATE" "$DEST"
sed -i '' "s/skill-name-here/$NAME/g" "$DEST/SKILL.md" "$DEST/README.md"

echo "Created $DEST"
echo
echo "Next steps:"
echo "  1. Edit $DEST/SKILL.md and $DEST/README.md"
echo "  2. Add scripts/reference/article files as needed"
echo "  3. Run scripts/publish-check.sh $NAME before committing"
echo "  4. Add a line for it under ## Skills in the root README.md"
