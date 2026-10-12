#!/bin/bash
#
# SGC installer.
#
#   curl -fsSL https://github.com/Troglobitten/sgc/releases/latest/download/install.sh | sudo bash
#
# What it does, in order:
#   1. checks that this is a supported machine (Debian 13, arm64 or amd64)
#   2. downloads this release of SGC, its checksum list and the list's signature
#   3. verifies the signature with the public key below, then the download
#      against the checksum list, and stops if either does not match
#   4. installs the programs under /opt/sgc and starts SGC as a service
#   5. prints a one-time link for creating the admin account in a browser
#
# Nothing is changed on the machine before step 3 has passed.
#
# In the repository this file is a template: the two @...@ placeholders are
# filled in when a release is built (scripts/dist.sh). Each published
# install.sh therefore installs exactly the release it belongs to.
#
# The script body is wrapped in functions and only started on the very last
# line, so a download that is cut off halfway cannot run half a script.

set -euo pipefail

readonly SGC_VERSION='@VERSION@'

# The public half of the release signing key. Only files signed with the
# matching private key are accepted.
readonly RELEASE_PUBLIC_KEY='@RELEASE_PUBLIC_KEY@'

# Where to download from. Can be overridden for mirrors, offline installs and
# tests; that is safe because whatever is downloaded must still carry a valid
# signature from the key above.
readonly DOWNLOAD_BASE="${SGC_DOWNLOAD_BASE:-https://github.com/Troglobitten/sgc/releases/download/v${SGC_VERSION}}"

readonly INSTALL_ROOT=/opt/sgc

info() { printf '  %s\n' "$*"; }

fail() {
    printf '\nSGC was not installed: %s\n' "$*" >&2
    exit 1
}

check_template_was_filled_in() {
    case "$SGC_VERSION" in
        @*) fail "this is the installer template from the source repository. Use the install.sh published with a release." ;;
    esac
}

check_platform() {
    [ "$(id -u)" -eq 0 ] || fail "the installer must run as root. Add 'sudo' before 'bash'."

    [ -r /etc/os-release ] || fail "cannot tell which operating system this is (/etc/os-release is missing)."
    # shellcheck source=/dev/null
    . /etc/os-release
    if [ "${ID:-}" != "debian" ] || [ "${VERSION_ID:-}" != "13" ]; then
        fail "SGC supports Debian 13 and Raspberry Pi OS based on it. This machine reports: ${PRETTY_NAME:-unknown}."
    fi

    arch="$(dpkg --print-architecture)"
    case "$arch" in
        amd64 | arm64) ;;
        armhf) fail "this is a 32-bit system. SGC needs the 64-bit version of Raspberry Pi OS." ;;
        *) fail "unsupported processor type '$arch'. SGC supports arm64 and amd64." ;;
    esac

    [ -d /run/systemd/system ] || fail "this machine does not use systemd, which SGC needs."

    local tool
    for tool in curl openssl sha256sum tar; do
        command -v "$tool" >/dev/null || fail "the '$tool' program is missing. Install it with: apt-get install $tool"
    done
}

download() {
    # --proto: never fall back to plain http, not even through a redirect.
    curl --fail --silent --show-error --location --retry 3 \
        --proto '=https,file' --proto-redir '=https' \
        --output "$2" "$1" \
        || fail "could not download $1"
}

download_and_verify() {
    tarball="sgc-${SGC_VERSION}-linux-${arch}.tar.gz"

    info "Downloading SGC ${SGC_VERSION} for ${arch}"
    download "$DOWNLOAD_BASE/SHA256SUMS" "$work/SHA256SUMS"
    download "$DOWNLOAD_BASE/SHA256SUMS.sig" "$work/SHA256SUMS.sig"
    download "$DOWNLOAD_BASE/$tarball" "$work/$tarball"

    info "Verifying the signature"
    printf '%s\n' "$RELEASE_PUBLIC_KEY" >"$work/release-key.pem"
    openssl pkeyutl -verify -pubin -inkey "$work/release-key.pem" -rawin \
        -in "$work/SHA256SUMS" -sigfile "$work/SHA256SUMS.sig" >/dev/null 2>&1 \
        || fail "the checksum list is not signed by the SGC release key. The download may have been tampered with."

    info "Verifying the download"
    # The file name contains the version, and the name is looked up in the
    # signed list. An older, genuinely signed release can therefore not be
    # passed off as this one.
    local expected actual
    expected="$(awk -v name="$tarball" '$2 == name { print $1 }' "$work/SHA256SUMS")"
    [ -n "$expected" ] || fail "the signed checksum list does not mention $tarball."
    actual="$(sha256sum "$work/$tarball" | awk '{ print $1 }')"
    [ "$expected" = "$actual" ] || fail "the download does not match its signed checksum. It may be damaged or tampered with."
}

install_files() {
    local release_dir="$INSTALL_ROOT/releases/$SGC_VERSION"

    info "Installing to $release_dir"
    install -d -m 0755 "$INSTALL_ROOT" "$INSTALL_ROOT/releases"

    # Unpack next to the final place first, so an interrupted install never
    # leaves a half-written release where the service would start it.
    rm -rf "$release_dir.new"
    install -d -m 0755 "$release_dir.new"
    tar -xzf "$work/$tarball" -C "$release_dir.new" --no-same-owner --no-same-permissions
    # Owned by root and writable by nobody else: the service user can run the
    # programs but can never replace them.
    chown -R root:root "$release_dir.new"
    chmod 0644 "$release_dir.new"/*
    chmod 0755 "$release_dir.new/sgc" "$release_dir.new/sgc-helper"

    "$release_dir.new/sgc" version | grep -q "^sgc ${SGC_VERSION} " \
        || fail "the downloaded program does not report version ${SGC_VERSION}."

    rm -rf "$release_dir"
    mv "$release_dir.new" "$release_dir"

    # Each release keeps its own folder; "current" points at the one in use.
    # That is what lets a later update be rolled back.
    ln -sfn "releases/$SGC_VERSION" "$INSTALL_ROOT/current"
    ln -sfn "$INSTALL_ROOT/current/sgc" /usr/local/bin/sgc
}

start_service() {
    # SGC's web-facing part runs as its own user without login or privileges.
    # The user must exist before the helper's socket is created, because the
    # socket is made accessible to this user's group.
    if ! id sgc >/dev/null 2>&1; then
        useradd --system --user-group --home-dir /var/lib/sgc --no-create-home \
            --shell /usr/sbin/nologin sgc
    fi

    # Every service definition the release brings, whatever their number.
    local unit
    for unit in "$INSTALL_ROOT/current/"*.service "$INSTALL_ROOT/current/"*.socket; do
        install -m 0644 "$unit" "/etc/systemd/system/$(basename "$unit")"
    done
    systemctl daemon-reload
    # The firewall unit loads the confirmed firewall rules at start-up. It
    # does nothing until a firewall has been switched on in SGC.
    systemctl enable --quiet sgc-helper.socket sgc.service sgc-firewall.service

    # On an update the old helper may still be running. Stop it, so the next
    # request starts the new one; then make sure its socket is listening.
    systemctl stop sgc-helper.service 2>/dev/null || true
    systemctl restart sgc-helper.socket
    systemctl restart sgc.service

    # Give it a moment, then make sure it stayed up.
    sleep 1
    systemctl is-active --quiet sgc.service \
        || fail "the service did not start. Details: journalctl -u sgc --no-pager -n 30"
}

print_next_step() {
    printf '\nSGC %s is installed and running.\n\n' "$SGC_VERSION"
    # On a new installation this prints the one-time link for creating the
    # admin account; on an existing one, where to sign in.
    "$INSTALL_ROOT/current/sgc" setup-link \
        || fail "SGC is installed, but the setup link could not be created. Try: sudo sgc setup-link"
}

main() {
    check_template_was_filled_in

    printf 'Installing SGC %s\n' "$SGC_VERSION"
    check_platform

    work="$(mktemp -d)"
    trap 'rm -rf "$work"' EXIT

    download_and_verify
    install_files
    start_service
    print_next_step
}

main "$@"
