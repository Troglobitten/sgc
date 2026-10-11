#!/bin/bash
#
# Builds the files that make up a release.
#
#   sgc-<version>-linux-amd64.tar.gz
#   sgc-<version>-linux-arm64.tar.gz
#   install.sh        the installer, with this version and the release
#                     public key filled in
#   SHA256SUMS        checksums of the files above
#
# Signing SHA256SUMS is a separate step (the release workflow does it), so
# this script never needs the private key.
#
# Usage: scripts/dist.sh [output folder]      (default: dist)
#
# RELEASE_PUBLIC_KEY_FILE can point at a different public key. The installer
# tests use that to build a release signed with a throwaway test key.

set -euo pipefail

cd "$(dirname "$0")/.."

out="${1:-dist}"
version="$(tr -d '[:space:]' <VERSION)"
key_file="${RELEASE_PUBLIC_KEY_FILE:-installer/release-key.pem}"

rm -rf "$out"
mkdir -p "$out"
out="$(cd "$out" && pwd)"

# The browser interface is embedded into the sgc binary, so it is built first.
# SGC_SKIP_WEB_BUILD=1 reuses what is already in web/dist; the tests use it to
# build several versions in a row without rebuilding an identical interface.
if [ "${SGC_SKIP_WEB_BUILD:-}" != 1 ]; then
    bash scripts/build-web.sh
fi

programs="sgc sgc-helper"
units="sgc.service sgc-helper.service sgc-helper.socket sgc-update@.service"

for arch in amd64 arm64; do
    stage="$(mktemp -d)"

    # Explicit modes: the source folder may be on a Windows drive, where every
    # file looks executable and world-writable.
    for program in $programs; do
        CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
            go build -trimpath -ldflags "-s -w" -o "$stage/build/$program" "./cmd/$program"
        install -m 0755 "$stage/build/$program" "$stage/$program"
    done
    for unit in $units; do
        install -m 0644 "installer/$unit" "$stage/$unit"
    done

    # Fixed order, dates and owners make the archive identical on every build
    # of the same source, so anyone can rebuild a release and compare.
    # The files are listed by name on purpose: archiving "." would also record
    # the temporary folder's own permissions and apply them on extraction.
    # shellcheck disable=SC2086  # the lists are meant to be split into words
    tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
        -C "$stage" -cf - $programs $units |
        gzip -n >"$out/sgc-$version-linux-$arch.tar.gz"

    rm -rf "$stage"
done

# Fill in the installer template. Newer bash treats "&" in a replacement
# specially; switch that off so the key text is always inserted literally.
shopt -u patsub_replacement 2>/dev/null || true
installer="$(cat installer/install.sh)"
installer="${installer//@VERSION@/$version}"
installer="${installer//@RELEASE_PUBLIC_KEY@/$(cat "$key_file")}"
printf '%s\n' "$installer" >"$out/install.sh"

(cd "$out" && sha256sum sgc-*.tar.gz install.sh >SHA256SUMS)

echo "release files for $version in $out:"
ls -l "$out"
