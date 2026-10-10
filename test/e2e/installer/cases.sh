#!/bin/bash
#
# Runs ON the test machine, called by Test-Installer.ps1.
#
# Runs the installer against the release variants in /tmp/release and checks
# what it did. Start from a clean machine: the "refused" cases assert that
# nothing at all was installed.
#
# Usage: cases.sh refused|accepted <expected version>

exec 2>&1
set -uo pipefail

mode="${1:?usage: cases.sh refused|accepted <version>}"
version="${2:?usage: cases.sh refused|accepted <version>}"
failures=0

pass() { echo "  PASS  $*"; }
fail() {
    echo "  FAIL  $*"
    failures=$((failures + 1))
}
check() { # check <description> <command...>
    local description="$1"
    shift
    if "$@" >/dev/null 2>&1; then pass "$description"; else fail "$description"; fi
}

run_installer() { # run_installer <variant>; prints output, returns the installer's exit code
    sudo SGC_DOWNLOAD_BASE="file:///tmp/release/$1" bash "/tmp/release/$1/install.sh"
}

indent() { sed 's/^/        /'; }

# shellcheck disable=SC2317  # not unreachable: called indirectly through check()
nothing_installed() {
    [ ! -e /opt/sgc ] && [ ! -e /usr/local/bin/sgc ] &&
        [ ! -e /etc/systemd/system/sgc.service ] && ! id sgc >/dev/null 2>&1
}

expect_refusal() { # expect_refusal <variant> <text the message must contain>
    local output
    # The refusal message is written to the error stream; capture both.
    output="$(run_installer "$1" 2>&1)"
    local code=$?
    if [ "$code" -ne 0 ]; then pass "$1: installer refused (exit code $code)"; else fail "$1: installer did NOT refuse"; fi
    if echo "$output" | grep -q "$2"; then pass "$1: message says \"$2\""; else
        fail "$1: message does not say \"$2\""
        indent <<<"$output"
    fi
    check "$1: nothing was installed" nothing_installed
}

case "$mode" in
refused)
    echo "Altered files must be refused before anything is installed"
    expect_refusal altered-download "does not match its signed checksum"
    expect_refusal altered-checksums "not signed by the SGC release key"
    expect_refusal wrong-key "not signed by the SGC release key"
    ;;

accepted)
    echo "A genuine release installs and runs"
    if run_installer good >/tmp/install.log; then pass "installer succeeded"; else
        fail "installer failed"
        indent </tmp/install.log
    fi
    check "sgc reports version $version" sh -c "sgc version | grep -q '^sgc $version '"
    check "service is running" systemctl is-active --quiet sgc
    check "service starts at boot" systemctl is-enabled --quiet sgc
    check "service runs as the unprivileged user sgc" sh -c "[ \"\$(ps -o user= -C sgc)\" = sgc ]"
    check "program files belong to root" sh -c "[ \"\$(stat -c %U:%G /opt/sgc/current/sgc)\" = root:root ]"
    check "program is not writable by others" sh -c "[ \"\$(stat -c %a /opt/sgc/current/sgc)\" = 755 ]"
    check "state folder is private to sgc" sudo sh -c "[ \"\$(stat -c %U:%a /var/lib/sgc)\" = sgc:700 ]"
    check "service log shows it started" sh -c "sudo journalctl -u sgc --no-pager | grep -q 'sgc $version started'"

    echo "Running the installer a second time is harmless"
    if run_installer good >/tmp/install2.log; then pass "second run succeeded"; else
        fail "second run failed"
        indent </tmp/install2.log
    fi
    check "service is still running" systemctl is-active --quiet sgc

    echo "The service survives a restart of the machine's service manager"
    sudo systemctl restart sgc
    sleep 1
    check "service is running after restart" systemctl is-active --quiet sgc
    ;;

*)
    echo "unknown mode: $mode"
    exit 2
    ;;
esac

echo
if [ "$failures" -eq 0 ]; then echo "ALL CHECKS PASSED ($mode)"; else echo "$failures CHECK(S) FAILED ($mode)"; fi
exit "$failures"
