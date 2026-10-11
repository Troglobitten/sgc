#!/bin/bash
#
# Runs inside the WSL build box, called by Test-Installer.ps1.
#
# Builds everything the whole-machine test needs, signed with a throwaway key
# made on the spot. The real release key is never involved, and nothing built
# here is ever published.
#
# For the installer (the version in the VERSION file):
#
#   good/                  genuine files, correctly signed
#   altered-download/      one byte appended to the amd64 archive
#   altered-checksums/     as above, and the checksum list updated to match,
#                          which is what an attacker without the key could do
#   wrong-key/             genuine files, signed with somebody else's key
#
# For the updater, laid out like an update source (three later versions):
#
#   updates/v<next1>/           a genuine newer release
#   updates/v<next2>/           a correctly signed release whose sgc program
#                               fails to start: the "deliberately broken" one
#   updates/v<next3>/           another genuine release, for "sgc update"
#   updates-tampered/v<next1>/  next1 with one byte appended to the archive
#
# Each version is built from a copy of the source tree in which only the
# VERSION file and the trusted key differ. The programs under test therefore
# contain no test-only switches.
#
# Usage: make-test-release.sh <output folder>

exec 2>&1
set -euo pipefail

out="${1:?usage: make-test-release.sh <output folder>}"
cd "$(dirname "$0")/../../.."
repo="$(pwd)"

keys="$(mktemp -d /dev/shm/sgc-test-key.XXXXXX)"
sources="$(mktemp -d)"
trap 'rm -rf "$keys" "$sources"' EXIT
openssl genpkey -algorithm ed25519 -out "$keys/test.pem"
openssl pkey -in "$keys/test.pem" -pubout -out "$keys/test.pub.pem"
openssl genpkey -algorithm ed25519 -out "$keys/other.pem"

sign() { # sign <folder> <private key>
    openssl pkeyutl -sign -inkey "$2" -rawin -in "$1/SHA256SUMS" -out "$1/SHA256SUMS.sig"
}

# build <version> <output folder>: a signed release of the current source,
# calling itself <version> and trusting the test key.
build() {
    local version="$1" destination="$2" tree="$sources/$1"
    mkdir -p "$tree"
    tar -C "$repo" --exclude=./.git --exclude=./dist --exclude=./bin --exclude=./docs \
        --exclude=./web/node_modules -cf - . | tar -C "$tree" -xf -
    echo "$version" >"$tree/VERSION"
    cp "$keys/test.pub.pem" "$tree/installer/release-key.pem"
    SGC_SKIP_WEB_BUILD=1 bash "$tree/scripts/dist.sh" "$destination" >/dev/null
    sign "$destination" "$keys/test.pem"
    rm -rf "$tree"
}

base="$(tr -d '[:space:]' <VERSION)"
IFS=. read -r major minor patch <<<"$base"
next1="$major.$minor.$((patch + 1))"
next2="$major.$minor.$((patch + 2))"
next3="$major.$minor.$((patch + 3))"

# The interface is the same in every version; build it once.
bash scripts/build-web.sh >/dev/null

rm -rf "$out"
mkdir -p "$out/updates" "$out/updates-tampered"

# --- For the installer --------------------------------------------------------
build "$base" "$out/good"
archive="sgc-$base-linux-amd64.tar.gz"

cp -r "$out/good" "$out/altered-download"
printf 'x' >>"$out/altered-download/$archive"

cp -r "$out/altered-download" "$out/altered-checksums"
(cd "$out/altered-checksums" && sha256sum sgc-*.tar.gz install.sh >SHA256SUMS)

cp -r "$out/good" "$out/wrong-key"
sign "$out/wrong-key" "$keys/other.pem"

# --- For the updater ----------------------------------------------------------
build "$next1" "$out/updates/v$next1"
build "$next2" "$out/updates/v$next2"
build "$next3" "$out/updates/v$next3"

cp -r "$out/updates/v$next1" "$out/updates-tampered/v$next1"
printf 'x' >>"$out/updates-tampered/v$next1/sgc-$next1-linux-amd64.tar.gz"

# Break next2: replace its sgc program with one that exits at once, then
# sign the result properly. Its signature is valid; it just does not work.
for arch in amd64 arm64; do
    broken="$(mktemp -d)"
    tar -xzf "$out/updates/v$next2/sgc-$next2-linux-$arch.tar.gz" -C "$broken"
    printf '#!/bin/sh\necho "this release is broken on purpose" >&2\nexit 1\n' >"$broken/sgc"
    chmod 0755 "$broken/sgc"
    # shellcheck disable=SC2046  # the file list is meant to be split into words
    tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
        -C "$broken" -cf - $(ls "$broken") | gzip -n >"$out/updates/v$next2/sgc-$next2-linux-$arch.tar.gz"
    rm -rf "$broken"
done
(cd "$out/updates/v$next2" && sha256sum sgc-*.tar.gz install.sh >SHA256SUMS)
sign "$out/updates/v$next2" "$keys/test.pem"

echo "test releases built in $out: install $base; updates $next1 (good), $next2 (broken), $next3 (good)"
