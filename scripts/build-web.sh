#!/bin/bash
#
# Builds the browser interface from web/ into web/dist/, from where it is
# embedded into the sgc binary.
#
# Packages are installed with `npm ci`, which installs exactly the versions
# recorded in package-lock.json and fails if the two disagree.
#
# When the repository sits on a Windows drive seen through WSL, the build is
# done in a folder on the Linux side instead: installing thousands of small
# files through that bridge is extremely slow. On a normal Linux filesystem
# (CI) everything happens in place.

set -euo pipefail

cd "$(dirname "$0")/.."
repo="$(pwd)"
work="$repo/web"

if [ "$(stat -f -c %T .)" = "v9fs" ]; then
    work="${XDG_CACHE_HOME:-$HOME/.cache}/sgc-web-build"
    mkdir -p "$work"
    # Sources only; the installed packages and the previous build stay put.
    find "$work" -mindepth 1 -maxdepth 1 ! -name node_modules -exec rm -rf {} +
    tar -C "$repo/web" --exclude=./node_modules --exclude=./dist -cf - . | tar -C "$work" -xf -
fi

cd "$work"
npm ci --no-audit --no-fund
npm run lint
# The interface is told which SGC version it belongs to.
SGC_VERSION="$(tr -d '[:space:]' <"$repo/VERSION")" npm run build

if [ "$work" != "$repo/web" ]; then
    rm -rf "$repo/web/dist"
    mkdir -p "$repo/web/dist"
    cp -r dist/. "$repo/web/dist/"
fi

echo "interface built into web/dist:"
du -sh "$repo/web/dist" | cut -f1
