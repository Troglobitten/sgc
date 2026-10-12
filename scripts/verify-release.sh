#!/bin/bash
#
# Checks a published release against the source it claims to be built from:
#
#   1. its checksum list carries a valid signature from the release key
#   2. building the release's tag gives exactly the published files
#   3. which version the "latest" install link installs (for information)
#
# The build is done in a clean, temporary copy of the tag, so it does not
# matter what is checked out or changed in the folder this is run from. Run
# it after a release, and whenever you want to see for yourself that a
# release is what the source says.
#
# Usage: scripts/verify-release.sh [version]     (default: the VERSION file)

set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

version="${1:-$(tr -d '[:space:]' <VERSION)}"
repository="https://github.com/Troglobitten/sgc"
base="$repository/releases/download/v$version"
work="$(mktemp -d)"
# shellcheck disable=SC2317  # not unreachable: run by the trap below
cleanup() {
    git worktree remove --force "$work/source" >/dev/null 2>&1
    rm -rf "$work"
    git worktree prune >/dev/null 2>&1
}
trap cleanup EXIT
problems=0

for file in SHA256SUMS SHA256SUMS.sig; do
    if ! curl -fsSL -o "$work/$file" "$base/$file"; then
        echo "Release $version could not be downloaded from $repository."
        exit 1
    fi
done

# A checkout of exactly the tag, with nothing changed and nothing added: the
# programs record which commit they were built from and whether anything
# differed from it, so only a clean checkout can give the published files.
if ! git worktree add --quiet --detach "$work/source" "v$version" 2>"$work/git.log"; then
    echo "The tag v$version could not be checked out (try: git fetch --tags):"
    sed 's/^/   /' "$work/git.log"
    exit 1
fi

echo "1. The signature of release $version"
if openssl pkeyutl -verify -pubin -inkey "$work/source/installer/release-key.pem" -rawin \
    -in "$work/SHA256SUMS" -sigfile "$work/SHA256SUMS.sig" >/dev/null 2>&1; then
    echo "   valid: the checksum list is signed by the release key in the repository"
else
    echo "   NOT VALID"
    problems=$((problems + 1))
fi

echo "2. Building tag v$version ($(git -C "$work/source" rev-parse --short HEAD)) and comparing"
# LC_ALL=C for releases built before dist.sh set it by itself (0.7.0).
if ! LC_ALL=C bash "$work/source/scripts/dist.sh" "$work/built" >"$work/build.log" 2>&1; then
    echo "   the build failed:"
    tail -n 20 "$work/build.log" | sed 's/^/     /'
    exit 1
fi
if diff "$work/SHA256SUMS" "$work/built/SHA256SUMS" >/dev/null; then
    echo "   identical: the published files are exactly what the source produces"
else
    echo "   NOT IDENTICAL. Published (<) and built here (>):"
    diff "$work/SHA256SUMS" "$work/built/SHA256SUMS" | sed 's/^/     /'
    problems=$((problems + 1))
fi

echo "3. The \"latest\" install link"
# Fetched whole first: a "grep -m1" reading straight from curl stops reading
# at the first match, and curl then reports a failure that is none.
installer="$(curl -fsSL "$repository/releases/latest/download/install.sh")"
latest="$(grep -m1 '^readonly SGC_VERSION' <<<"$installer" | cut -d"'" -f2)"
echo "   installs version ${latest:-unknown}"

if [ "$problems" -eq 0 ]; then echo "Release $version checks out."; else echo "$problems problem(s) with release $version."; fi
exit "$problems"
