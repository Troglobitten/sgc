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
#   firewall       the firewall: off until switched on, undone by itself
#                  unless confirmed, refusing the outside once confirmed
#   update-setup   points the installed SGC at a local test update source
#   update-refused a tampered update is refused and changes nothing
#   update-good    a genuine update installs from the dashboard's API
#   update-broken  a signed but broken update is rolled back by itself
#   update-downgrade  an older release is never offered or installed
#   update-cli     "sgc update" over SSH
#   export         makes an export through the API (kept in the home folder)
#   restart        asks SGC to restart the machine (the machine goes down)
#   after-restart  SGC came back by itself and remembers everything
#   firewall-cli   "sgc doctor" and "sgc firewall off" over SSH
#   restore        on a freshly wiped machine: installs, then restores the
#                  export made earlier and checks that SGC is what it was

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
# The export and its passphrase. Test-Installer.ps1 carries these two and the
# password file across the wipe of the machine.
export_file="$HOME/sgc-test-export.age"
passphrase_file="$HOME/sgc-test-passphrase"
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

# --- Updates -----------------------------------------------------------------

# The three later versions that make-test-release.sh built.
IFS=. read -r major minor patch <<<"$version"
next1="$major.$minor.$((patch + 1))" # genuine
next2="$major.$minor.$((patch + 2))" # signed, but its sgc program does not start
next3="$major.$minor.$((patch + 3))" # genuine

# A folder served on this machine only, standing in for GitHub.
mirror="$HOME/mirror"
mirror_address="http://127.0.0.1:9000"

# offer <version> [folder to take it from]: make it the newest release there.
offer() {
    local offered="$1" from="${2:-/tmp/release/updates}"
    rm -rf "${mirror:?}/v$offered"
    if [ -d "$from/v$offered" ]; then cp -r "$from/v$offered" "$mirror/v$offered"; fi
    printf '{"version":"%s","notes":"Notes for test release %s.","publishedAt":"2026-01-01T00:00:00Z"}\n' \
        "$offered" "$offered" >"$mirror/latest.json"
}

wait_for() { # wait_for <seconds> <command...>: until the command succeeds
    local deadline=$(($(date +%s) + $1))
    shift
    until "$@" >/dev/null 2>&1; do
        [ "$(date +%s)" -lt "$deadline" ] || return 1
        sleep 1
    done
}

running_version() {
    curl -sk -m 5 "$api/api/state" | grep -o '"version":"[^"]*"' | cut -d'"' -f4
}

# shellcheck disable=SC2317  # called indirectly through check() and wait_for()
version_is() { [ "$(running_version)" = "$1" ]; }

# The updater has recorded the end of an attempt to install the given version.
# shellcheck disable=SC2317  # called indirectly through wait_for()
update_finished() {
    [ "$(http GET /api/update)" = 200 ] &&
        grep -q "\"to\":\"$1\"" /tmp/sgc-test-body &&
        ! grep -q '"state":"running"' /tmp/sgc-test-body
}

install_request() { printf '{"version":"%s","confirm":true}' "$1"; }

# The activity log contains the given text. SGC writes down the outcome of an
# update a moment after the updater has finished, hence the waiting.
# shellcheck disable=SC2317  # called indirectly through wait_for()
audit_has() { [ "$(http GET /api/audit)" = 200 ] && grep -q "$1" /tmp/sgc-test-body; }

expect_in_audit() { # expect_in_audit <description> <text>
    if wait_for 15 audit_has "$2"; then pass "$1"; else
        fail "$1"
        indent </tmp/sgc-test-body
    fi
}

# --- Firewall ----------------------------------------------------------------

# Stand-ins for other machines: a network namespace is a second, separate
# network stack on this machine, joined to it by a virtual cable. One of them
# gets a public address (as if from the internet), one a private address (as
# if from the home network). 203.0.113.0/24 is reserved for examples and
# never routed on the real internet.
outside_net=sgc-outside outside_gateway=203.0.113.1 outside_peer=203.0.113.2
inside_net=sgc-inside inside_gateway=192.168.77.1 inside_peer=192.168.77.2

neighbour() { # neighbour <name> <this machine's address> <the neighbour's address>
    sudo ip netns list | grep -q "^$1\b" && return 0
    sudo ip netns add "$1" &&
        sudo ip link add "$1-a" type veth peer name "$1-b" &&
        sudo ip link set "$1-b" netns "$1" &&
        sudo ip addr add "$2/24" dev "$1-a" &&
        sudo ip link set "$1-a" up &&
        sudo ip netns exec "$1" ip addr add "$3/24" dev "$1-b" &&
        sudo ip netns exec "$1" ip link set "$1-b" up
}

# reaches <name> <address> <port>: can that neighbour open a connection?
# shellcheck disable=SC2317  # called indirectly through check()
reaches() {
    sudo ip netns exec "$1" timeout 3 bash -c "exec 3<>/dev/tcp/$2/$3"
}
# shellcheck disable=SC2317  # called indirectly through check()
does_not_reach() { ! reaches "$@"; }

# shellcheck disable=SC2317  # called indirectly through check() and wait_for()
firewall_is() { [ "$(http GET /api/firewall)" = 200 ] && grep -q "\"state\":\"$1\"" /tmp/sgc-test-body; }
# shellcheck disable=SC2317  # called indirectly through check()
rules_loaded() { sudo /usr/sbin/nft list table inet sgc; }
# shellcheck disable=SC2317  # called indirectly through check()
no_rules_loaded() { [ ! -x /usr/sbin/nft ] || ! sudo /usr/sbin/nft list table inet sgc; }

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
    check "the unit that loads the firewall's rules at start-up is switched on" systemctl is-enabled --quiet sgc-firewall.service
    check "it has nothing to load yet" sh -c "[ ! -e /etc/sgc/firewall.nft ] && ! systemctl is-failed --quiet sgc-firewall.service"
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

firewall)
    echo "The firewall is off until it is switched on"
    expect_status "the firewall's state is available" 200 GET /api/firewall
    check "it is off" body_has '"state":"off"'
    check "a clean Debian does not have the firewall software" body_has '"softwareInstalled":false'
    check "this connection counts as coming from inside" body_has '"inside":true'
    check "nothing is loaded" no_rules_loaded
    if neighbour "$outside_net" "$outside_gateway" "$outside_peer" && neighbour "$inside_net" "$inside_gateway" "$inside_peer"; then
        pass "two stand-in neighbours are set up: one with a public address, one with a home address"
    else
        fail "the stand-in neighbours could not be set up"
    fi
    check "without a firewall the public neighbour reaches SGC's page" reaches "$outside_net" "$outside_gateway" 8443
    check "and SSH" reaches "$outside_net" "$outside_gateway" 22

    echo "Switched on and not confirmed: it undoes itself"
    expect_status "switching on is accepted" 202 POST /api/firewall/change '{"enabled":true}'
    check "the change is in effect and waits for confirmation" body_has '"state":"pending"'
    check "the firewall software was installed from Debian" test -x /usr/sbin/nft
    expect_in_audit "which is in the history" '"action":"system.packages_installed"'
    check "the rules are loaded" rules_loaded
    check "the public neighbour no longer reaches SGC's page" does_not_reach "$outside_net" "$outside_gateway" 8443
    check "nor SSH" does_not_reach "$outside_net" "$outside_gateway" 22
    check "the home neighbour still reaches SGC's page" reaches "$inside_net" "$inside_gateway" 8443
    check "and SSH" reaches "$inside_net" "$inside_gateway" 22
    expect_status "a second change while one waits is refused" 409 POST /api/firewall/change '{"enabled":false}'
    check "nothing is saved as confirmed" sudo sh -c '[ ! -e /etc/sgc/firewall.nft ]'
    echo "        (waiting a good minute without confirming)"
    if wait_for 80 firewall_is off; then pass "after a minute the firewall is off again"; else
        fail "the unconfirmed change was not undone"
        indent </tmp/sgc-test-body
    fi
    check "the rules are gone" no_rules_loaded
    check "the public neighbour gets through again" reaches "$outside_net" "$outside_gateway" 8443
    check "still nothing is saved as confirmed" sudo sh -c '[ ! -e /etc/sgc/firewall.nft ]'
    expect_in_audit "the history says it was undone for lack of confirmation" '"action":"firewall.change_expired"'
    expect_status "confirming now is too late" 409 POST /api/firewall/confirm '{}'
    expect_status "the firewall's state is available" 200 GET /api/firewall
    check "an unconfirmed change is not recorded as what the owner wants" body_has '"wanted":false'

    echo "The process that waits for the confirmation is killed: undone at once"
    expect_status "switching on again" 202 POST /api/firewall/change '{"enabled":true}'
    check "the rules are loaded" rules_loaded
    sudo kill -KILL "$(systemctl show -p MainPID --value sgc-firewall-change.service)"
    if wait_for 10 firewall_is off; then pass "the firewall is off again within seconds"; else fail "the change survived its guard being killed"; fi
    check "the rules are gone" no_rules_loaded
    expect_in_audit "the history says the wait was interrupted" 'the wait for confirmation was interrupted'

    echo "Everything belonging to that unit is killed, its cleanup included: still undone"
    expect_status "switching on again" 202 POST /api/firewall/change '{"enabled":true}'
    check "the rules are loaded" rules_loaded
    sudo systemctl kill --signal=KILL sgc-firewall-change.service
    if wait_for 10 firewall_is off; then pass "the firewall is off again within seconds"; else fail "the change survived the whole unit being killed"; fi
    check "the rules are gone" no_rules_loaded

    echo "Undone on request"
    expect_status "switching on again" 202 POST /api/firewall/change '{"enabled":true}'
    expect_status "undo" 200 POST /api/firewall/undo '{}'
    check "the firewall is off" body_has '"state":"off"'
    check "the rules are gone" no_rules_loaded
    expect_in_audit "the history says who undid it" "\"actor\":\"$username\",\"action\":\"firewall.change_undone\""

    echo "Many changes in quick succession"
    # More starts within ten seconds than systemd allows a unit by default;
    # neither a change nor its undoing may ever be refused for that.
    quick=0
    for _ in 1 2 3 4 5 6 7; do
        [ "$(http POST /api/firewall/change '{"enabled":true}')" = 202 ] &&
            [ "$(http POST /api/firewall/undo '{}')" = 200 ] && quick=$((quick + 1))
    done
    if [ "$quick" -eq 7 ]; then pass "seven times on and undone again, none refused"; else
        fail "only $quick of seven quick changes went through"
        indent </tmp/sgc-test-body
    fi
    check "the firewall is off after the last undo" no_rules_loaded
    check "none of the firewall's units was refused a start" \
        sh -c "! systemctl show -p Result sgc-firewall-change.service sgc-firewall-revert.service | grep -q start-limit"

    echo "Switched on and confirmed: it stays"
    expect_status "switching on again" 202 POST /api/firewall/change '{"enabled":true}'
    expect_status "confirming" 200 POST /api/firewall/confirm '{}'
    check "the firewall is on" body_has '"state":"on"'
    check "and recorded as what the owner wants" body_has '"wanted":true'
    check "SSH and SGC's page are what is let in" body_has '"sshPorts":\[22\],"webPort":8443'
    check "the confirmed rules are saved, owned by root" sudo sh -c "[ \"\$(stat -c %U:%a /etc/sgc/firewall.nft)\" = root:644 ]"
    check "the web process cannot change them" sh -c '! sudo -u sgc sh -c "echo >> /etc/sgc/firewall.nft"'
    sleep 2
    check "nothing is waiting any more" sh -c '! systemctl is-active --quiet sgc-firewall-change.service'
    check "the rules are loaded" rules_loaded
    check "the public neighbour is refused: SGC's page" does_not_reach "$outside_net" "$outside_gateway" 8443
    check "the public neighbour is refused: SSH" does_not_reach "$outside_net" "$outside_gateway" 22
    check "the home neighbour is let in: SGC's page" reaches "$inside_net" "$inside_gateway" 8443
    check "the home neighbour is let in: SSH" reaches "$inside_net" "$inside_gateway" 22
    check "the machine itself still reaches the internet" sh -c "curl -s -m 10 -o /dev/null https://deb.debian.org/"
    # A fresh install switches the start-up unit on by itself (checked with
    # the installer above). A machine that was updated from a version without
    # a firewall has it started through sgc.service instead. Either is enough.
    check "the rules load at every start-up" \
        sh -c "systemctl is-enabled --quiet sgc-firewall.service || systemctl show --property=Wants --value sgc.service | grep -q sgc-firewall.service"
    expect_in_audit "the confirmation is in the history" '"action":"firewall.change_confirmed"'

    echo "The root helper still takes no instructions about rules"
    check "a request with anything but on or off is refused" \
        sh -c "sudo -u sgc curl -s -m 5 -o /dev/null -w '%{http_code}' -X POST -d '{\"enabled\":false,\"rules\":\"accept\"}' --unix-socket /run/sgc-helper/helper.sock http://helper/v1/firewall/change | grep -q 400"
    check "the firewall is still on" rules_loaded
    ;;

update-setup)
    echo "Pointing SGC at a test update source on this machine"
    mkdir -p "$mirror"
    sudo systemd-run --quiet --unit sgc-test-mirror \
        python3 -m http.server 9000 --bind 127.0.0.1 --directory "$mirror"
    sudo mkdir -p /etc/systemd/system/sgc.service.d
    printf '[Service]\nEnvironment=SGC_UPDATE_SOURCE=%s\n' "$mirror_address" |
        sudo tee /etc/systemd/system/sgc.service.d/test-source.conf >/dev/null
    sudo systemctl daemon-reload
    sudo systemctl restart sgc
    if wait_for 30 version_is "$version"; then pass "SGC is running with the test source"; else fail "SGC did not come back"; fi
    expect_status "update status needs a sign-in" 200 GET /api/update
    # Whether SGC has already looked for updates by itself depends on how
    # long it has been running, so that is not checked here.
    check "it reports the installed version" body_has "\"current\":\"$version\""
    check "the daily check is on by default" body_has '"autoCheck":true'
    ;;

update-refused)
    echo "A tampered update is refused"
    offer "$next1" /tmp/release/updates-tampered
    expect_status "checking for updates" 200 POST /api/update/check '{}'
    check "the newer version is seen" body_has "\"latest\":\"$next1\""
    check "it is offered as an update" body_has '"updateAvailable":true'
    check "its notes are shown" body_has "Notes for test release $next1"
    expect_status "installing it is refused" 502 POST /api/update/install "$(install_request "$next1")"
    check "the message says why, and that nothing changed" \
        sh -c "grep -q 'does not match its signed checksum' /tmp/sgc-test-body && grep -q 'Nothing was changed' /tmp/sgc-test-body"
    check "the installed version is unchanged" version_is "$version"
    check "the root updater was never started" sh -c '[ ! -e /var/lib/sgc-update/status.json ]'
    expect_status "the activity log is available" 200 GET /api/audit
    check "the refusal was recorded" body_has '"action":"update.failed"'
    ;;

update-good)
    echo "A genuine update installs"
    offer "$next1"
    expect_status "checking for updates" 200 POST /api/update/check '{}'
    expect_status "an update without confirmation is refused" 400 POST /api/update/install "{\"version\":\"$next1\",\"confirm\":false}"
    expect_status "the update starts" 202 POST /api/update/install "$(install_request "$next1")"
    if wait_for 120 version_is "$next1"; then pass "SGC came back as $next1"; else fail "SGC did not come back as $next1 (it reports '$(running_version)')"; fi
    if wait_for 30 update_finished "$next1"; then pass "the updater recorded the outcome"; else fail "the updater recorded no outcome"; fi
    check "the outcome is a success" body_has '"state":"succeeded"'
    check "no further update is offered" body_has '"updateAvailable":false'
    check "the sgc command is the new version" sh -c "sgc version | grep -q '^sgc $next1 '"
    check "service is running" systemctl is-active --quiet sgc
    expect_status "the earlier sign-in still works" 200 GET /api/health
    expect_in_audit "the update was recorded in the activity log" '"action":"update.succeeded"'
    check "the previous version is kept for going back" test -x "/opt/sgc/releases/$version/sgc"
    check "the helper is the new version too" \
        sh -c "sudo -u sgc curl -s -m 5 --unix-socket /run/sgc-helper/helper.sock http://helper/v1/ping | grep -q '\"version\":\"$next1\"'"
    check "the database backup is kept by root only" sudo sh -c "[ \"\$(stat -c %U:%a /var/lib/sgc-update/database-backup)\" = root:700 ]"
    check "the download was cleaned up" sudo sh -c "[ -z \"\$(ls -A /var/lib/sgc/updates 2>/dev/null)\" ]"
    check "the firewall stayed on through the update" rules_loaded
    expect_status "the firewall's state is available" 200 GET /api/firewall
    check "and the new version knows it" body_has '"state":"on"'
    ;;

update-broken)
    echo "A signed but broken update is rolled back"
    before="$(running_version)"
    offer "$next2"
    expect_status "checking for updates" 200 POST /api/update/check '{}'
    check "the broken version is offered like any other" body_has "\"latest\":\"$next2\""
    expect_status "the update starts" 202 POST /api/update/install "$(install_request "$next2")"
    if wait_for 240 update_finished "$next2"; then pass "the updater finished"; else fail "the updater did not finish"; fi
    check "the outcome is a rollback" body_has '"state":"rolled-back"'
    check "the message explains it" sh -c "grep -q 'went back to $before' /tmp/sgc-test-body && grep -q 'Nothing was lost' /tmp/sgc-test-body"
    check "SGC is running the version from before" version_is "$before"
    check "the sgc command is the version from before" sh -c "sgc version | grep -q '^sgc $before '"
    check "service is running" systemctl is-active --quiet sgc
    check "current points at the version from before" sh -c "[ \"\$(readlink /opt/sgc/current)\" = releases/$before ]"
    check "the firewall stayed on through the failed update" rules_loaded
    expect_status "the earlier sign-in still works" 200 GET /api/health
    expect_in_audit "the rollback was recorded in the activity log" '"action":"update.rolled_back"'
    # The activity log shows the newest entries only, so this asks for what
    # happened shortly before the broken update.
    check "the earlier history survived" body_has '"action":"firewall.change_confirmed"'
    check "including the successful update before it" body_has '"action":"update.succeeded"'
    expect_status "the broken version is still offered, not silently hidden" 200 GET /api/update
    check "still offered" body_has '"updateAvailable":true'
    ;;

update-downgrade)
    echo "An older release is never installed"
    before="$(running_version)"
    offer "$version" /nonexistent
    expect_status "checking for updates" 200 POST /api/update/check '{}'
    check "an older newest-release is not an update" body_has '"updateAvailable":false'
    expect_status "asking for it anyway is refused" 409 POST /api/update/install "$(install_request "$version")"
    check "the installed version is unchanged" version_is "$before"
    ;;

update-cli)
    echo "Updating over SSH with 'sgc update'"
    before="$(running_version)"
    offer "$next3"
    if output="$(sgc update --check 2>&1)"; then
        fail "without sudo it was not refused"
    elif echo "$output" | grep -q 'needs root'; then
        pass "without sudo it explains that it needs root"
    else
        fail "without sudo: unexpected message"
        indent <<<"$output"
    fi
    output="$(sudo SGC_UPDATE_SOURCE="$mirror_address" sgc update --check 2>&1)"
    if echo "$output" | grep -q "Available: SGC $next3"; then pass "--check shows the available version"; else
        fail "--check did not show $next3"
        indent <<<"$output"
    fi
    check "--check installed nothing" version_is "$before"
    output="$(echo n | sudo SGC_UPDATE_SOURCE="$mirror_address" sgc update 2>&1)"
    if echo "$output" | grep -q 'Nothing was changed'; then pass "answering no changes nothing"; else
        fail "answering no: unexpected result"
        indent <<<"$output"
    fi
    check "still the version from before" version_is "$before"
    output="$(sudo SGC_UPDATE_SOURCE="$mirror_address" sgc update --yes 2>&1)"
    code=$?
    if [ "$code" -eq 0 ] && echo "$output" | grep -q "was updated from $before to $next3"; then pass "sgc update installed $next3"; else
        fail "sgc update failed (exit code $code)"
        indent <<<"$output"
    fi
    if wait_for 30 version_is "$next3"; then pass "SGC is running $next3"; else fail "SGC reports '$(running_version)'"; fi
    output="$(sudo SGC_UPDATE_SOURCE="$mirror_address" sgc update --check 2>&1)"
    if echo "$output" | grep -q 'This is the newest version'; then pass "afterwards it reports being up to date"; else
        fail "unexpected result after updating"
        indent <<<"$output"
    fi
    expect_status "the earlier sign-in still works" 200 GET /api/health
    expect_in_audit "the update over SSH was recorded" '"actor":"console","action":"update.started"'
    expect_in_audit "and so was its outcome" "updated from $before to $next3"
    ;;

export)
    echo "Exporting everything into one encrypted file"
    password="$(cat "$password_file")"
    head -c 18 /dev/urandom | base64 >"$passphrase_file"
    passphrase="$(cat "$passphrase_file")"
    rm -f "$export_file"

    # A setting changed away from its default, to see it come back later.
    expect_status "a setting is changed before exporting" 200 POST /api/update/settings '{"autoCheck":false}'

    expect_status "an export needs the admin password again" 403 POST /api/export \
        "{\"password\":\"not-the-password\",\"passphrase\":\"$passphrase\"}"
    expect_status "being refused did not end the session" 200 GET /api/health
    expect_status "a short passphrase is refused" 400 POST /api/export \
        "{\"password\":\"$password\",\"passphrase\":\"short\"}"

    code="$(curl -sk -o "$export_file" -w '%{http_code}' -b "$cookies" -H 'Content-Type: application/json' \
        -d "{\"password\":\"$password\",\"passphrase\":\"$passphrase\"}" "$api/api/export")"
    if [ "$code" = 200 ]; then pass "the export is delivered"; else fail "the export was not delivered (status $code)"; fi
    check "it is a standard age file" sh -c "head -c 21 '$export_file' | grep -q '^age-encryption.org/v1'"
    check "nothing in it is readable" sh -c "! grep -q -e '$username' -e 'argon2' '$export_file'"
    check "no temporary copy of the database is left behind" sudo sh -c "[ -z \"\$(ls -A /var/lib/sgc/tmp 2>/dev/null)\" ]"
    expect_in_audit "the export was recorded" '"action":"export.created"'
    ;;

restore)
    echo "A freshly wiped machine: install, then restore the export"
    password="$(cat "$password_file")"
    passphrase="$(cat "$passphrase_file")"
    if run_installer good >/tmp/install.log; then pass "installer succeeded on the wiped machine"; else
        fail "installer failed"
        indent </tmp/install.log
    fi
    link="$(grep -o 'https://[^ ]*/setup#[A-Za-z0-9_-]*' /tmp/install.log)"
    token="${link##*#}"
    rm -f "$cookies"
    expect_status "the fresh install asks for setup" 200 GET /api/state
    check "setup is required" body_has '"setupRequired":true'

    # upload <token> <passphrase>: prints the status code of a restore preview.
    upload() {
        curl -sk -o /tmp/sgc-test-body -w '%{http_code}' \
            -F "token=$1" -F "passphrase=$2" -F "file=@$export_file" "$api/api/setup/restore/preview"
    }
    code="$(upload wrong-token "$passphrase")"
    if [ "$code" = 403 ]; then pass "without the setup link the file is not even looked at"; else fail "wrong setup link: status $code"; fi
    code="$(upload "$token" not-the-passphrase)"
    if [ "$code" = 403 ]; then pass "a wrong passphrase is refused"; else fail "wrong passphrase: status $code"; fi
    code="$(upload "$token" "$passphrase")"
    if [ "$code" = 200 ]; then pass "the right passphrase opens the file"; else
        fail "preview failed (status $code)"
        indent </tmp/sgc-test-body
    fi
    check "the preview names the account in the export" body_has "\"adminUsername\":\"$username\""
    expect_status "previewing alone changes nothing" 200 GET /api/state
    check "setup is still required" body_has '"setupRequired":true'

    expect_status "confirming starts the restore" 202 POST /api/setup/restore/confirm "{\"token\":\"$token\"}"
    # shellcheck disable=SC2317  # called indirectly through wait_for()
    restored() { [ "$(http GET /api/state)" = 200 ] && grep -q '"setupRequired":false' /tmp/sgc-test-body; }
    if wait_for 30 restored; then pass "SGC came back on the restored data"; else fail "SGC did not come back restored"; fi

    echo "The restored SGC is the old one"
    expect_status "the old account signs in with its old password" 200 POST /api/login \
        "{\"username\":\"$username\",\"password\":\"$password\"}"
    expect_status "update settings are readable" 200 GET /api/update
    check "the changed setting came back" body_has '"autoCheck":false'
    expect_status "the firewall's state is available" 200 GET /api/firewall
    check "the export says the firewall was on" body_has '"wanted":true'
    check "but on this new machine nothing was switched on unasked" body_has '"state":"off"'
    check "no rules are loaded" no_rules_loaded
    # The activity log shows the newest entries only; everything asked for
    # here happened on the old machine shortly before the export. (That the
    # whole history survives, down to the first entry, is checked on the
    # database itself by the tests in internal/backup.)
    expect_in_audit "the history came back" '"action":"firewall.change_confirmed"'
    check "including the updates made on the old machine" body_has '"action":"update.succeeded"'
    expect_in_audit "the restore itself was recorded" '"action":"restore.completed"'
    expect_status "the fresh install's setup link is closed" 409 POST /api/setup \
        "{\"token\":\"$token\",\"username\":\"mallory\",\"password\":\"$password\"}"
    check "service is running" systemctl is-active --quiet sgc
    check "the database is still private to sgc" sudo sh -c "[ \"\$(stat -c %U:%a /var/lib/sgc/sgc.db)\" = sgc:600 ]"
    check "nothing is left waiting to be restored" sudo sh -c "[ ! -e /var/lib/sgc/restore ]"
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
    expect_status "the firewall's state is available" 200 GET /api/firewall
    check "the firewall is still on" body_has '"state":"on"'
    check "its rules were loaded at start-up" rules_loaded
    check "by the unit made for that" systemctl is-active --quiet sgc-firewall.service
    # network-pre.target is the point in start-up before which no network
    # interface is configured.
    check "before the network came up" sh -c "[ \"\$(systemctl show -p ActiveEnterTimestampMonotonic --value sgc-firewall.service)\" -lt \"\$(systemctl show -p ActiveEnterTimestampMonotonic --value network-pre.target)\" ]"
    ;;

firewall-cli)
    echo "'sgc doctor' looks at every part"
    if output="$(sgc doctor 2>&1)"; then
        fail "without sudo it was not refused"
    elif echo "$output" | grep -q 'needs root'; then
        pass "without sudo it explains that it needs root"
    else
        fail "without sudo: unexpected message"
        indent <<<"$output"
    fi
    output="$(sudo sgc doctor 2>&1)"
    code=$?
    if [ "$code" -eq 0 ]; then pass "on a healthy machine it reports no problems"; else
        fail "it reports problems on a healthy machine (exit code $code)"
        indent <<<"$output"
    fi
    for line in "The SGC service is running" "SGC's page answers on port 8443" "The root helper answers" \
        "The firewall is on, and its rules are loaded" "The firewall's rules load at every start-up"; do
        if echo "$output" | grep -q "ok    $line"; then pass "it says: $line"; else
            fail "it does not say: $line"
            indent <<<"$output"
        fi
    done

    echo "It notices what is wrong"
    sudo /usr/sbin/nft destroy table inet sgc
    output="$(sudo sgc doctor 2>&1)"
    code=$?
    if [ "$code" -ne 0 ] && echo "$output" | grep -q "FAIL  The firewall is switched on, but its rules are not loaded"; then
        pass "rules removed behind SGC's back are reported as a problem"
    else
        fail "missing rules were not reported (exit code $code)"
        indent <<<"$output"
    fi
    if echo "$output" | grep -q 'sudo systemctl restart sgc-firewall'; then pass "it says how to put them back"; else
        fail "it does not say how to put them back"
        indent <<<"$output"
    fi
    sudo systemctl restart sgc-firewall
    check "following that advice loads the rules again" rules_loaded
    sudo systemctl stop sgc
    output="$(sudo sgc doctor 2>&1)"
    code=$?
    if [ "$code" -ne 0 ] && echo "$output" | grep -q "FAIL  The SGC service is not running" && echo "$output" | grep -q "FAIL  SGC's page does not answer"; then
        pass "a stopped SGC is reported, and the doctor still works without it"
    else
        fail "a stopped SGC was not reported (exit code $code)"
        indent <<<"$output"
    fi
    check "the firewall does not depend on SGC running" rules_loaded
    sudo systemctl start sgc
    if wait_for 30 firewall_is on; then pass "SGC is back"; else fail "SGC did not come back"; fi

    echo "'sgc firewall' at the machine itself"
    check "the state can be read without sudo" sh -c "sgc firewall status | grep -q 'The firewall is on'"
    if output="$(sgc firewall off 2>&1)"; then
        fail "switching off without sudo was not refused"
    elif echo "$output" | grep -q 'needs root'; then
        pass "switching off without sudo is refused"
    else
        fail "without sudo: unexpected message"
        indent <<<"$output"
    fi
    check "the firewall is still on" rules_loaded
    output="$(sudo sgc firewall off 2>&1)"
    code=$?
    if [ "$code" -eq 0 ] && echo "$output" | grep -q 'The firewall is off'; then pass "with sudo it switches the firewall off"; else
        fail "switching off failed (exit code $code)"
        indent <<<"$output"
    fi
    check "no rules are loaded" no_rules_loaded
    check "off is what the machine would start with" sudo sh -c "grep -q '\"enabled\":false' /etc/sgc/firewall.nft"
    check "the state says so" sh -c "sgc firewall status | grep -q 'The firewall is off'"
    expect_status "SGC's page knows" 200 GET /api/firewall
    check "it shows the firewall as off" body_has '"state":"off"'
    check "and no longer as wanted" body_has '"wanted":false'
    check "SGC's own files still belong to its user" sudo sh -c "[ -z \"\$(find /var/lib/sgc ! -user sgc)\" ]"
    expect_in_audit "the history says it was done at the machine" '"actor":"console","action":"firewall.change_confirmed","detail":"firewall switched off"'

    echo "And it can be switched on again from the page"
    expect_status "switching on" 202 POST /api/firewall/change '{"enabled":true}'
    expect_status "confirming" 200 POST /api/firewall/confirm '{}'
    check "the rules are loaded" rules_loaded
    ;;

*)
    echo "unknown mode: $mode"
    exit 2
    ;;
esac

echo
if [ "$failures" -eq 0 ]; then echo "ALL CHECKS PASSED ($mode)"; else echo "$failures CHECK(S) FAILED ($mode)"; fi
exit "$failures"
