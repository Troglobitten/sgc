#!/bin/bash
#
# Runs ON the test machine, called by Test-Installer.ps1.
#
# Runs the installer against the release variants in /tmp/release and checks
# what it did, then drives SGC the way a browser would.
#
# Usage: cases.sh <mode> <expected version>
#
#   refused        bad releases are refused and leave nothing behind
#                  (needs a clean machine)
#   accepted       a genuine release installs; setup, sign-in and the
#                  dashboard data work; the root helper is locked down
#   restart        asks SGC to restart the machine (the machine goes down)
#   after-restart  SGC came back by itself and remembers everything

exec 2>&1
set -uo pipefail

mode="${1:?usage: cases.sh <mode> <version>}"
version="${2:?usage: cases.sh <mode> <version>}"
failures=0

api="https://127.0.0.1:8443"
# State kept between modes, in the home folder because /tmp is emptied by the
# restart. Not secrets worth protecting: a throwaway
# account on a throwaway machine.
cookies="$HOME/sgc-test-cookies"
password_file="$HOME/sgc-test-password"
username=tester-admin

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
indent() { sed 's/^/        /'; }

run_installer() { # run_installer <variant>; prints output, returns the installer's exit code
    sudo SGC_DOWNLOAD_BASE="file:///tmp/release/$1" bash "/tmp/release/$1/install.sh"
}

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

# http <method> <path> [json body]: prints the HTTP status code; the answer's
# body goes to /tmp/sgc-test-body. -k because the certificate is self-signed.
http() {
    local method="$1" path="$2" body="${3:-}"
    local args=(-sk -o /tmp/sgc-test-body -w '%{http_code}' -X "$method" -b "$cookies" -c "$cookies")
    if [ -n "$body" ]; then args+=(-H 'Content-Type: application/json' -d "$body"); fi
    curl "${args[@]}" "$api$path"
}

expect_status() { # expect_status <description> <wanted> <method> <path> [body]
    local description="$1" wanted="$2"
    shift 2
    local got
    got="$(http "$@")"
    if [ "$got" = "$wanted" ]; then pass "$description"; else
        fail "$description (status $got, wanted $wanted)"
        indent </tmp/sgc-test-body
    fi
}

# shellcheck disable=SC2317  # not unreachable: called indirectly through check()
body_has() { grep -q "$1" /tmp/sgc-test-body; }

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
    check "programs are not writable by others" sh -c "[ \"\$(stat -c %a /opt/sgc/current/sgc)\" = 755 ] && [ \"\$(stat -c %a /opt/sgc/current/sgc-helper)\" = 755 ]"
    check "state folder is private to sgc" sudo sh -c "[ \"\$(stat -c %U:%a /var/lib/sgc)\" = sgc:700 ]"
    check "database is private to sgc" sudo sh -c "[ \"\$(stat -c %U:%a /var/lib/sgc/sgc.db)\" = sgc:600 ]"
    check "service log shows it started" sh -c "sudo journalctl -u sgc --no-pager | grep -q 'sgc $version started'"

    echo "The installer hands over a one-time setup link"
    link="$(grep -o 'https://[^ ]*/setup#[A-Za-z0-9_-]*' /tmp/install.log)"
    token="${link##*#}"
    if [ -n "$token" ]; then pass "installer printed a setup link"; else
        fail "installer did not print a setup link"
        indent </tmp/install.log
    fi
    printed="$(grep -o 'SHA-256  [0-9A-F:]*' /tmp/install.log | awk '{print $2}')"
    served="$(openssl s_client -connect 127.0.0.1:8443 </dev/null 2>/dev/null |
        openssl x509 -noout -fingerprint -sha256 | cut -d= -f2)"
    if [ -n "$printed" ] && [ "$printed" = "$served" ]; then
        pass "printed fingerprint matches the certificate actually served"
    else
        fail "fingerprint mismatch: printed '$printed', served '$served'"
    fi

    echo "The web interface and API"
    rm -f "$cookies"
    expect_status "the interface is served" 200 GET /
    check "it is the SGC app" body_has '<title>SGC</title>'
    expect_status "state is public" 200 GET /api/state
    check "a fresh install asks for setup" body_has '"setupRequired":true'
    expect_status "dashboard data needs sign-in" 401 GET /api/health
    # A plain-http request to the TLS port gets a bare "400 Bad Request" from
    # the TLS layer; what matters is that it never reaches the API.
    check "the API is not served over plain http" \
        sh -c "[ \"\$(curl -s -m 5 -o /dev/null -w '%{http_code}' http://127.0.0.1:8443/api/state)\" = 400 ]"

    head -c 18 /dev/urandom | base64 >"$password_file"
    password="$(cat "$password_file")"
    expect_status "a wrong setup link is refused" 403 POST /api/setup \
        "{\"token\":\"wrong\",\"username\":\"$username\",\"password\":\"$password\"}"
    expect_status "the real setup link creates the admin" 200 POST /api/setup \
        "{\"token\":\"$token\",\"username\":\"$username\",\"password\":\"$password\"}"
    expect_status "the link cannot be used twice" 409 POST /api/setup \
        "{\"token\":\"$token\",\"username\":\"mallory\",\"password\":\"$password\"}"
    expect_status "dashboard data is available after setup" 200 GET /api/health
    check "it reports this machine" body_has "\"hostname\":\"$(hostname)\""
    check "it reports memory" sh -c "! grep -q '\"memoryTotalBytes\":0,' /tmp/sgc-test-body"
    expect_status "the activity log is available" 200 GET /api/audit
    check "it recorded the setup" body_has '"action":"setup.completed"'

    echo "Signing out and in again"
    expect_status "sign out" 200 POST /api/logout '{}'
    expect_status "signed out means no access" 401 GET /api/health
    expect_status "a wrong password is refused" 401 POST /api/login \
        "{\"username\":\"$username\",\"password\":\"not-the-password\"}"
    expect_status "the right password signs in" 200 POST /api/login \
        "{\"username\":\"$username\",\"password\":\"$password\"}"

    echo "The root helper is locked down"
    check "socket is root:sgc and not open to others" \
        sh -c "[ \"\$(stat -c %U:%G:%a /run/sgc-helper/helper.sock)\" = root:sgc:660 ]"
    check "an ordinary user cannot reach the helper" \
        sh -c "! curl -s -m 5 --unix-socket /run/sgc-helper/helper.sock http://helper/v1/ping"
    check "the helper answers the service user" \
        sh -c "sudo -u sgc curl -s -m 5 --unix-socket /run/sgc-helper/helper.sock http://helper/v1/ping | grep -q '\"version\":\"$version\"'"
    check "the helper has no 'run a command' operation" \
        sh -c "sudo -u sgc curl -s -m 5 -o /dev/null -w '%{http_code}' -X POST --unix-socket /run/sgc-helper/helper.sock http://helper/v1/exec | grep -q 404"

    echo "Running the installer a second time is harmless"
    if run_installer good >/tmp/install2.log; then pass "second run succeeded"; else
        fail "second run failed"
        indent </tmp/install2.log
    fi
    check "it says SGC is already set up instead of a new link" grep -q 'already set up' /tmp/install2.log
    check "no new setup link was printed" sh -c "! grep -q '/setup#' /tmp/install2.log"
    check "service is still running" systemctl is-active --quiet sgc
    sleep 1
    expect_status "the earlier sign-in still works" 200 GET /api/health
    ;;

restart)
    echo "Restarting the machine through SGC"
    expect_status "a restart without confirmation is refused" 400 POST /api/device/restart '{"confirm":false}'
    expect_status "a confirmed restart is accepted" 202 POST /api/device/restart '{"confirm":true}'
    ;;

after-restart)
    echo "After the restart"
    uptime_seconds="$(cut -d. -f1 /proc/uptime)"
    if [ "$uptime_seconds" -lt 300 ]; then pass "the machine really restarted (up for $uptime_seconds s)"; else
        fail "the machine does not look restarted (up for $uptime_seconds s)"
    fi
    check "SGC came back by itself" systemctl is-active --quiet sgc
    check "the helper socket is listening again" systemctl is-active --quiet sgc-helper.socket
    expect_status "the sign-in from before the restart still works" 200 GET /api/health
    expect_status "the activity log is available" 200 GET /api/audit
    check "the restart was recorded" body_has '"action":"device.restart"'
    check "no failed restart was recorded" sh -c "! grep -q 'device.restart_failed' /tmp/sgc-test-body"
    ;;

*)
    echo "unknown mode: $mode"
    exit 2
    ;;
esac

echo
if [ "$failures" -eq 0 ]; then echo "ALL CHECKS PASSED ($mode)"; else echo "$failures CHECK(S) FAILED ($mode)"; fi
exit "$failures"
