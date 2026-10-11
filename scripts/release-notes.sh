#!/bin/bash
#
# Prints the CHANGELOG.md section for one version, without its heading.
# Those lines become the release's description on GitHub, which is what SGC
# shows before an update. Fails if the version has no section, so a release
# can never go out without notes.
#
# Usage: scripts/release-notes.sh [version]      (default: the VERSION file)

set -euo pipefail

cd "$(dirname "$0")/.."
version="${1:-$(tr -d '[:space:]' <VERSION)}"

# The sed drops blank lines before the first line of text; "$(...)" itself
# drops the ones at the end.
notes="$(awk -v heading="## $version" '
    $0 == heading { printing = 1; next }
    /^## /        { printing = 0 }
    printing      { print }
' CHANGELOG.md | sed '/./,$!d')"

if [ -z "$notes" ]; then
    echo "CHANGELOG.md has no section '## $version'. Describe the release there first." >&2
    exit 1
fi
printf '%s\n' "$notes"
