#!/bin/bash
#
# Runs inside the WSL build box, called by Test-UpgradeFromPrevious.ps1.
#
# Builds what is needed to test updating from the previous published release
# to the source as it is now:
#
#   good/              the previous release, built from its tag
#   updates/v<new>/    the current source
#
# Both are signed with one throwaway key made on the spot, and each trusts
# that key instead of the real one. Apart from that the previous release is
# exactly what was published. That matters because an update is carried out
# by the version that is already installed: this is the only test in which a
# release meets the updater it will really be installed by.
#
# The real release key is never involved, and nothing built here is ever
# published.
#
# Usage: make-upgrade-release.sh <previous tag> <output folder>
# Prints the two version numbers on its last line: "<previous> <new>".

exec 2>&1
set -euo pipefail

previous_tag="${1:?usage: make-upgrade-release.sh <previous tag> <output folder>}"
out="${2:?usage: make-upgrade-release.sh <previous tag> <output folder>}"
cd "$(dirname "$0")/../../.."
repo="$(pwd)"

keys="$(mktemp -d /dev/shm/sgc-test-key.XXXXXX)"
sources="$(mktemp -d)"
trap 'rm -rf "$keys" "$sources"' EXIT
openssl genpkey -algorithm ed25519 -out "$keys/test.pem"
openssl pkey -in "$keys/test.pem" -pubout -out "$keys/test.pub.pem"

sign() { # sign <folder>
    openssl pkeyutl -sign -inkey "$keys/test.pem" -rawin -in "$1/SHA256SUMS" -out "$1/SHA256SUMS.sig"
}

rm -rf "$out"
mkdir -p "$out/updates"

# --- The previous release, from its tag -----------------------------------------
old="$sources/old"
mkdir -p "$old"
git archive "$previous_tag" | tar -C "$old" -xf -
previous="$(tr -d '[:space:]' <"$old/VERSION")"
cp "$keys/test.pub.pem" "$old/installer/release-key.pem"
# With its own build script, and its own interface built from its own sources.
(cd "$old" && bash scripts/dist.sh "$out/good" >/dev/null)
sign "$out/good"

# --- The current source -------------------------------------------------------
# Under its own version number if that is newer than the previous release;
# otherwise (the version has not been raised yet) as the next patch version,
# because an update has to be to something newer.
current="$(tr -d '[:space:]' <VERSION)"
new="$current"
if [ "$(printf '%s\n%s\n' "$previous" "$current" | sort -V | tail -n 1)" = "$previous" ]; then
    IFS=. read -r major minor patch <<<"$previous"
    new="$major.$minor.$((patch + 1))"
fi
tree="$sources/new"
mkdir -p "$tree"
tar -C "$repo" --exclude=./.git --exclude=./dist --exclude=./bin --exclude=./docs \
    --exclude=./web/node_modules --exclude=./web/dist -cf - . | tar -C "$tree" -xf -
echo "$new" >"$tree/VERSION"
cp "$keys/test.pub.pem" "$tree/installer/release-key.pem"
(cd "$tree" && bash scripts/dist.sh "$out/updates/v$new" >/dev/null)
sign "$out/updates/v$new"

echo "built in $out: install $previous (from $previous_tag), update to $new (the current source)"
echo "$previous $new"
