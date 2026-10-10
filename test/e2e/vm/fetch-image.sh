#!/bin/bash
# Runs inside the WSL build box, called by New-TestVM.ps1.
#
# Downloads Debian's official cloud image, verifies it against Debian's
# published checksum and converts it to the disk format Hyper-V uses.
# Both the download and the converted image are kept, so later rebuilds
# of the test machine need no network.
#
# Usage: fetch-image.sh <cache folder as a WSL path>
exec 2>&1
set -euo pipefail

cache="${1:?usage: fetch-image.sh <cache folder>}"
name="debian-13-generic-amd64"
base="https://cloud.debian.org/images/cloud/trixie/latest"

mkdir -p "$cache"
cd "$cache"

if [ -f "$name.vhdx" ]; then
  echo "image already prepared: $cache/$name.vhdx"
  exit 0
fi

if [ ! -f "$name.qcow2" ]; then
  echo "downloading $name.qcow2 ..."
  # Download under a temporary name so an interrupted download is never
  # mistaken for a complete image.
  curl -fL --retry 3 -sS -o "$name.qcow2.part" "$base/$name.qcow2"
  mv "$name.qcow2.part" "$name.qcow2"
fi

echo "verifying checksum ..."
curl -fL --retry 3 -sS -o SHA512SUMS "$base/SHA512SUMS"
grep " $name.qcow2\$" SHA512SUMS | sha512sum -c -

echo "converting to Hyper-V format ..."
qemu-img convert -f qcow2 -O vhdx -o subformat=dynamic "$name.qcow2" "$name.vhdx.part"
mv "$name.vhdx.part" "$name.vhdx"
echo "image prepared: $cache/$name.vhdx"
