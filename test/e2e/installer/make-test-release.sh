#!/bin/bash
#
# Runs inside the WSL build box, called by Test-Installer.ps1.
#
# Builds a complete release into the given folder, signed with a throwaway key
# made on the spot, plus three deliberately bad variants. The real release key
# is never involved in testing.
#
#   good/                  genuine files, correctly signed
#   altered-download/      one byte appended to the amd64 archive
#   altered-checksums/     as above, and the checksum list updated to match,
#                          which is what an attacker without the key could do
#   wrong-key/             genuine files, signed with somebody else's key
#
# Usage: make-test-release.sh <output folder>

exec 2>&1
set -euo pipefail

out="${1:?usage: make-test-release.sh <output folder>}"
cd "$(dirname "$0")/../../.."

keys="$(mktemp -d /dev/shm/sgc-test-key.XXXXXX)"
trap 'rm -rf "$keys"' EXIT
openssl genpkey -algorithm ed25519 -out "$keys/test.pem"
openssl pkey -in "$keys/test.pem" -pubout -out "$keys/test.pub.pem"
openssl genpkey -algorithm ed25519 -out "$keys/other.pem"

sign() { # sign <folder> <private key>
    openssl pkeyutl -sign -inkey "$2" -rawin -in "$1/SHA256SUMS" -out "$1/SHA256SUMS.sig"
}

rm -rf "$out"
mkdir -p "$out"
RELEASE_PUBLIC_KEY_FILE="$keys/test.pub.pem" bash scripts/dist.sh "$out/good" >/dev/null
sign "$out/good" "$keys/test.pem"

version="$(tr -d '[:space:]' <VERSION)"
archive="sgc-$version-linux-amd64.tar.gz"

cp -r "$out/good" "$out/altered-download"
printf 'x' >>"$out/altered-download/$archive"

cp -r "$out/altered-download" "$out/altered-checksums"
(cd "$out/altered-checksums" && sha256sum sgc-*.tar.gz install.sh >SHA256SUMS)

cp -r "$out/good" "$out/wrong-key"
sign "$out/wrong-key" "$keys/other.pem"

echo "test release $version built in $out"
