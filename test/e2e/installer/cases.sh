#!/bin/bash
#
# Runs ON the test machine, called by Test-Installer.ps1.
#
# Runs the installer against the release variants in /tmp/release and checks
# what it did, then drives SGC the way a browser would.
#
# Usage: cases.sh <mode> <expected version> [<new version>]
#
#   refused        bad releases are refused and leave nothing behind
#                  (needs a clean machine)
#   accepted       a genuine release installs; setup, sign-in and the
#                  dashboard data work; the root helper is locked down
#   firewall       the firewall: off until switched on, undone by itself
#                  unless confirmed, refusing the outside once confirmed
#   ssh            SSH keys added in the page; "keys only" is undone by
#                  itself unless a login with a key is seen, and stays if one is
#   update-setup   points the installed SGC at a local test update source
#   update-refused a tampered update is refused and changes nothing
#   update-good    a genuine update installs from the dashboard's API
#   update-broken  a signed but broken update is rolled back by itself
#   update-downgrade  an older release is never offered or installed
#   update-cli     "sgc update" over SSH
#   export         makes an export through the API (kept in the home folder)
#   restart        asks SGC to restart the machine (the machine goes down)
#   after-restart  SGC came back by itself and remembers everything
#   cli            "sgc doctor", "sgc firewall off" and "sgc ssh
#                  allow-passwords" over SSH
#   restore        on a freshly wiped machine: installs, then restores the
#                  export made earlier and checks that SGC is what it was
#
# For Test-UpgradeFromPrevious.ps1, where /tmp/release holds the previous
# published release and the current source as an update to it:
#
#   old-install    installs the previous release and creates the admin
#   upgrade        the previous release updates itself to <new version>,
#                  with its own updater

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

# --- SSH -----------------------------------------------------------------------

# Two key pairs made by the test, standing in for the owner's own. The second
# is still in SGC when the export is made, so Test-Installer.ps1 carries its
# private half across the wipe of the machine.
ssh_key="$HOME/sgc-test-ssh-key"
ssh_key2="$HOME/sgc-test-ssh-key2"
lan_address="$(hostname -I | awk '{print $1}')"
ssh_quiet=(-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5)

# The ways of logging in the SSH server offers someone who has nothing yet,
# for example "publickey,password". Asking is not a login.
# shellcheck disable=SC2317  # called by the two functions below
offered() {
    ssh "${ssh_quiet[@]}" -o PreferredAuthentications=none "tester@$lan_address" true 2>&1 |
        grep -o 'Permission denied ([a-z,-]*)' | head -1
}
# (Not "offered | grep": the ssh in there ends with an error by design, and
# with pipefail that would count as "not offered".)
# shellcheck disable=SC2317  # called indirectly through check()
passwords_offered() { [[ "$(offered)" == *password* ]]; }
# shellcheck disable=SC2317  # called indirectly through check()
passwords_not_offered() { [ "$(offered)" = "Permission denied (publickey)" ]; }
# gets_in <private key>: a login with that key and no other.
# shellcheck disable=SC2317  # called indirectly through check()
gets_in() { ssh "${ssh_quiet[@]}" -i "$1" -o IdentitiesOnly=yes "tester@$lan_address" true 2>/dev/null; }
# shellcheck disable=SC2317  # called indirectly through check()
does_not_get_in() { ! gets_in "$1"; }

# shellcheck disable=SC2317  # called indirectly through check() and wait_for()
ssh_state_has() { [ "$(http GET /api/ssh)" = 200 ] && grep -q "$1" /tmp/sgc-test-body; }
# shellcheck disable=SC2317  # called indirectly through wait_for()
ssh_settled() { ssh_state_has '"pending":null'; }
add_key_request() { # add_key_request <password> <label> <the key as pasted>
    printf '{"password":"%s","label":"%s","key":"%s","account":""}' "$1" "$2" "$3"
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
    check "the unit that loads the firewall's rules at start-up is switched on" systemctl is-enabled --quiet sgc-firewall.service
    check "and so is the one that puts the confirmed SSH settings in place" systemctl is-enabled --quiet sgc-ssh.service
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
    # After every single undo the rules must really be gone. This is also
    # what catches an undo that is cut short: it once left the rules in
    # effect about every other time, while SGC reported them as undone.
    quick=0
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        [ "$(http POST /api/firewall/change '{"enabled":true}')" = 202 ] &&
            [ "$(http POST /api/firewall/undo '{}')" = 200 ] &&
            no_rules_loaded >/dev/null 2>&1 && quick=$((quick + 1))
    done
    if [ "$quick" -eq 10 ]; then pass "ten times on and undone again: never refused, and the rules gone every time"; else
        fail "only $quick of ten quick changes were made and fully undone"
        indent </tmp/sgc-test-body
    fi
    check "the firewall is off after the last undo" no_rules_loaded
    check "no unit of the firewall's is marked as failed" \
        sh -c "! systemctl is-failed --quiet sgc-firewall-change.service && ! systemctl is-failed --quiet sgc-firewall-revert.service"
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

ssh)
    password="$(cat "$password_file")"
    echo "A device that accepts passwords over SSH, as a Raspberry Pi usually does"
    # The test machine's image comes with password logins switched off. Put it
    # in the state SGC is most likely to meet.
    sudo sed -i -E 's/^(PasswordAuthentication|KbdInteractiveAuthentication) no$/#&/' /etc/ssh/sshd_config
    sudo rm -f /etc/ssh/sshd_config.d/50-cloud-init.conf
    sudo systemctl reload ssh.service
    sleep 1
    check "the SSH server offers a password prompt" passwords_offered
    expect_status "the SSH state is available" 200 GET /api/ssh
    check "passwords are reported as accepted" body_has '"passwordLogins":true'
    check "root is reported as able to log in with a key" body_has '"rootLogin":"key"'
    check "the account a person logs in with is found, and no other" body_has '"accounts":\["tester"\]'
    check "this test's own login with a key was seen" body_has '"recentLogin":{"account":"tester"'
    check "nothing is restricted yet" body_has '"keysOnly":false'

    echo "A key is added in the page"
    rm -f "$ssh_key" "$ssh_key.pub" "$ssh_key2" "$ssh_key2.pub"
    ssh-keygen -q -t ed25519 -N '' -C 'laptop of the test' -f "$ssh_key"
    ssh-keygen -q -t ed25519 -N '' -C 'second key' -f "$ssh_key2"
    public="$(cat "$ssh_key.pub")"
    public2="$(cat "$ssh_key2.pub")"
    check "the new key does not get in yet" does_not_get_in "$ssh_key"
    expect_status "adding a key needs the admin password again" 403 POST /api/ssh/keys "$(add_key_request not-the-password laptop "$public")"
    expect_status "being refused did not end the session" 200 GET /api/ssh
    expect_status "a private key is refused" 400 POST /api/ssh/keys "$(add_key_request "$password" laptop '-----BEGIN OPENSSH PRIVATE KEY-----')"
    check "and the message says why" body_has 'private key'
    expect_status "a key with a login option in front of it is refused" 400 POST /api/ssh/keys \
        "$(add_key_request "$password" laptop "command=\\\"/bin/sh\\\" $public")"
    expect_status "two keys at once are refused" 400 POST /api/ssh/keys "$(add_key_request "$password" laptop "$public\\n$public2")"
    check "nothing has been installed by the refused requests" sudo sh -c '[ ! -e /etc/sgc/ssh/keys/tester ]'
    expect_status "the key is added" 200 POST /api/ssh/keys "$(add_key_request "$password" '' "$public")"
    check "it is listed, named after the comment it came with" body_has '"label":"laptop of the test"'
    check "with the fingerprint ssh-keygen reports for it" body_has "$(ssh-keygen -l -f "$ssh_key.pub" | awk '{print $2}')"
    check "it is installed for the account" body_has '"account":"tester"'
    check "the keys file belongs to root" sudo sh -c "[ \"\$(stat -c %U:%G:%a /etc/sgc/ssh/keys/tester)\" = root:root:644 ]"
    check "and holds the key and nothing else: no option, no comment" \
        sudo sh -c "[ \"\$(cat /etc/sgc/ssh/keys/tester)\" = \"$(cut -d' ' -f1,2 "$ssh_key.pub")\" ]"
    check "the web process cannot change it" sh -c '! sudo -u sgc sh -c "echo >> /etc/sgc/ssh/keys/tester"'
    check "nor SGC's part of the SSH settings" sh -c '! sudo -u sgc sh -c "echo >> /etc/ssh/sshd_config.d/00-sgc.conf"'
    check "the new key gets in" gets_in "$ssh_key"
    check "passwords are still offered: adding a key restricts nothing" passwords_offered
    expect_status "the same key a second time is refused" 409 POST /api/ssh/keys "$(add_key_request "$password" again "$public")"
    expect_in_audit "the key is in the history" '"action":"ssh.key_added"'

    echo "Keys only, and nobody logs in with a key: undone after two minutes"
    expect_status "switching to keys only" 200 POST /api/ssh/keys-only '{"enabled":true}'
    check "it is in effect and waits for a login with a key" body_has '"what":"switching to keys only"'
    check "it is not counted as switched on" body_has '"keysOnly":false'
    check "passwords are no longer offered" passwords_not_offered
    expect_status "nothing else about SSH can be changed meanwhile" 409 POST /api/ssh/keys-only '{"enabled":false}'
    echo "        (waiting two minutes without logging in; the logins made before the change must not count)"
    if wait_for 150 ssh_settled; then pass "after two minutes nothing is waiting any more"; else
        fail "the change is still waiting"
        indent </tmp/sgc-test-body
    fi
    check "keys only is not on" body_has '"keysOnly":false'
    check "passwords are offered again" passwords_offered
    check "the key that was added is still there and still gets in" gets_in "$ssh_key"
    expect_in_audit "the history says no login with a key was seen" '"action":"ssh.change_expired"'

    echo "The process that waits for the login is killed, then everything belonging to its unit"
    expect_status "switching to keys only" 200 POST /api/ssh/keys-only '{"enabled":true}'
    check "passwords are no longer offered" passwords_not_offered
    sudo kill -KILL "$(systemctl show -p MainPID --value sgc-ssh-change.service)"
    if wait_for 10 ssh_settled; then pass "undone within seconds"; else fail "the change survived its guard being killed"; fi
    check "passwords are offered again" passwords_offered
    expect_status "switching to keys only" 200 POST /api/ssh/keys-only '{"enabled":true}'
    sudo systemctl kill --signal=KILL sgc-ssh-change.service
    if wait_for 10 ssh_settled; then pass "undone within seconds again"; else fail "the change survived the whole unit being killed"; fi
    check "passwords are offered again" passwords_offered

    echo "Undone on request, several times in a row"
    undone=0
    for _ in 1 2 3 4 5; do
        [ "$(http POST /api/ssh/keys-only '{"enabled":true}')" = 200 ] && passwords_not_offered &&
            [ "$(http POST /api/ssh/undo '{}')" = 200 ] && passwords_offered && undone=$((undone + 1))
    done
    if [ "$undone" -eq 5 ]; then pass "five times switched and undone: passwords refused, then accepted again, every time"; else
        fail "only $undone of five changes were made and fully undone"
        indent </tmp/sgc-test-body
    fi
    expect_status "the SSH state is available" 200 GET /api/ssh
    check "nothing is waiting" body_has '"pending":null'
    check "no unit of SSH's is marked as failed" \
        sh -c "! systemctl is-failed --quiet sgc-ssh-change.service && ! systemctl is-failed --quiet sgc-ssh-revert.service"

    echo "Keys only, and a login with a key: it stays"
    expect_status "switching to keys only" 200 POST /api/ssh/keys-only '{"enabled":true}'
    check "passwords are no longer offered" passwords_not_offered
    check "a login with the key" gets_in "$ssh_key"
    if wait_for 15 ssh_state_has '"keysOnly":true'; then pass "SGC saw the login and keeps the change"; else
        fail "the login with a key was not noticed"
        indent </tmp/sgc-test-body
    fi
    check "and it is recorded as what the owner wants" body_has '"wanted":true'
    check "nothing is waiting any more" body_has '"pending":null'
    check "the SSH server reports: no passwords" body_has '"passwordLogins":false'
    check "and no login as root" body_has '"rootLogin":"no"'
    check "passwords are not offered" passwords_not_offered
    check "the key still gets in" gets_in "$ssh_key"
    expect_in_audit "the history says a login with a key confirmed it" '"action":"ssh.keys_only_on"'

    echo "Under keys only, taking a key away needs a login with another one"
    expect_status "a second key is added, which needs no proof" 200 POST /api/ssh/keys "$(add_key_request "$password" 'second key' "$public2")"
    check "the second key gets in" gets_in "$ssh_key2"
    first_id="$(grep -o '"id":[0-9]*,"label":"laptop of the test"' /tmp/sgc-test-body | grep -o '[0-9]*' | head -1)"
    expect_status "removing the first key" 200 POST /api/ssh/keys/remove "{\"id\":$first_id}"
    check "it waits for a login with a key" body_has '"what":"removing laptop of the test'
    check "the key is still listed while that is open" body_has '"label":"laptop of the test"'
    check "but no longer gets in" does_not_get_in "$ssh_key"
    expect_status "undo" 200 POST /api/ssh/undo '{}'
    check "undone: the first key gets in again" gets_in "$ssh_key"
    expect_status "removing the first key again" 200 POST /api/ssh/keys/remove "{\"id\":$first_id}"
    check "a login with the second key" gets_in "$ssh_key2"
    if wait_for 15 ssh_settled; then pass "SGC saw the login and keeps the change"; else fail "the login with the other key was not noticed"; fi
    check "the first key is gone from the list" sh -c "! grep -q 'laptop of the test' /tmp/sgc-test-body"
    check "and no longer gets in" does_not_get_in "$ssh_key"
    check "the second key does" gets_in "$ssh_key2"
    check "keys only is still on" body_has '"keysOnly":true'
    expect_in_audit "the removal is in the history" '"action":"ssh.key_removed"'

    echo "The root helper takes keys only as keys"
    check "a request with an option on a key is refused" \
        sh -c "sudo -u sgc curl -s -m 5 -o /dev/null -w '%{http_code}' -X POST -d '{\"account\":\"tester\",\"keys\":[{\"type\":\"ssh-ed25519\",\"blob\":\"AAAA\",\"fingerprint\":\"\",\"options\":\"command\"}],\"keysOnly\":true}' --unix-socket /run/sgc-helper/helper.sock http://helper/v1/ssh/change | grep -q 400"
    check "keys for root are refused" \
        sh -c "sudo -u sgc curl -s -m 30 -o /dev/null -w '%{http_code}' -X POST -d '{\"account\":\"root\",\"keys\":[{\"type\":\"$(cut -d' ' -f1 "$ssh_key.pub")\",\"blob\":\"$(cut -d' ' -f2 "$ssh_key.pub")\",\"fingerprint\":\"\"}],\"keysOnly\":true}' --unix-socket /run/sgc-helper/helper.sock http://helper/v1/ssh/change | grep -q 500"
    check "nothing was installed for root" sudo sh -c "[ \"\$(ls /etc/sgc/ssh/keys)\" = tester ]"
    check "a refused request leaves no unit marked as failed" sh -c "! systemctl is-failed --quiet sgc-ssh-change.service"
    check "the second key still gets in" gets_in "$ssh_key2"

    # sgc.service wants the unit that puts the confirmed SSH settings in
    # place, so that unit runs at every start of SGC, not only when the
    # machine starts. With everything in place it has nothing to do.
    echo "SGC's own service restarts: the SSH server is left alone"
    since="$(date '+%Y-%m-%d %H:%M:%S')"
    sudo systemctl restart sgc
    # shellcheck disable=SC2317  # called indirectly through wait_for()
    ssh_unit_done() { [ "$(systemctl is-active sgc-ssh.service)" != activating ] && [ "$(http GET /api/ssh)" = 200 ]; }
    if wait_for 30 ssh_unit_done; then pass "SGC is back"; else fail "SGC did not come back"; fi
    check "the unit ran" sh -c "sudo journalctl -u sgc-ssh.service --since '$since' --no-pager | grep -q 'Finished\|Deactivated'"
    check "and did not fail" sh -c "! systemctl is-failed --quiet sgc-ssh.service"
    check "the SSH server was not told to reload"         sh -c "! sudo journalctl -u ssh.service --since '$since' --no-pager | grep -q 'Server listening\|Reload'"
    check "keys only is still on" body_has '"keysOnly":true'
    check "passwords are still not offered" passwords_not_offered
    check "the second key still gets in" gets_in "$ssh_key2"
    ;;

old-install)
    echo "The previous release, as it was published"
    if run_installer good >/tmp/install.log; then pass "its installer succeeded"; else
        fail "its installer failed"
        indent </tmp/install.log
    fi
    check "sgc reports version $version" sh -c "sgc version | grep -q '^sgc $version '"
    check "service is running" systemctl is-active --quiet sgc
    link="$(grep -o 'https://[^ ]*/setup#[A-Za-z0-9_-]*' /tmp/install.log)"
    token="${link##*#}"
    rm -f "$cookies"
    head -c 18 /dev/urandom | base64 >"$password_file"
    expect_status "its setup link creates the admin" 200 POST /api/setup \
        "{\"token\":\"$token\",\"username\":\"$username\",\"password\":\"$(cat "$password_file")\"}"
    expect_status "the admin is signed in" 200 GET /api/health
    ;;

upgrade)
    target="${3:?usage: cases.sh upgrade <installed version> <new version>}"
    echo "SGC $version updates itself to $target, with its own updater"
    offer "$target"
    expect_status "checking for updates" 200 POST /api/update/check '{}'
    check "the new version is offered" body_has "\"latest\":\"$target\""
    expect_status "the update starts" 202 POST /api/update/install "$(install_request "$target")"
    if wait_for 120 version_is "$target"; then pass "SGC came back as $target"; else fail "SGC did not come back as $target (it reports '$(running_version)')"; fi
    if wait_for 30 update_finished "$target"; then pass "the updater recorded the outcome"; else fail "the updater recorded no outcome"; fi
    check "the outcome is a success" body_has '"state":"succeeded"'
    check "the sgc command is the new version" sh -c "sgc version | grep -q '^sgc $target '"
    check "service is running" systemctl is-active --quiet sgc
    expect_status "the sign-in from before the update still works" 200 GET /api/health
    check "the helper is the new version too" \
        sh -c "sudo -u sgc curl -s -m 5 --unix-socket /run/sgc-helper/helper.sock http://helper/v1/ping | grep -q '\"version\":\"$target\"'"
    expect_in_audit "the update is in the history" '"action":"update.succeeded"'

    echo "What the old updater made of the new release"
    missing=""
    for unit in /opt/sgc/current/*.service /opt/sgc/current/*.socket; do
        [ -f "/etc/systemd/system/$(basename "$unit")" ] || missing="$missing $(basename "$unit")"
    done
    if [ -z "$missing" ]; then pass "every unit of the new release is installed"; else fail "units of the new release that are not installed:$missing"; fi
    # A unit that has to run at start-up gets there either by being switched
    # on by the updater (which older updaters do not do) or by being wanted
    # by sgc.service (which the new release sees to for that reason).
    for unit in sgc-firewall.service sgc-ssh.service; do
        check "$unit will be part of start-up" \
            sh -c "systemctl is-enabled --quiet $unit || systemctl show --property=Wants --value sgc.service | grep -q $unit"
    done
    check "no unit of SGC's is marked as failed" sh -c "[ -z \"\$(systemctl list-units --failed --plain --no-legend 'sgc*')\" ]"
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
    check "SSH stayed on keys only through the update" passwords_not_offered
    expect_status "the SSH state is available" 200 GET /api/ssh
    check "and the new version knows it" body_has '"keysOnly":true'
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
    check "SSH stayed on keys only through the failed update" passwords_not_offered
    expect_status "the earlier sign-in still works" 200 GET /api/health
    expect_in_audit "the rollback was recorded in the activity log" '"action":"update.rolled_back"'
    # The activity log shows the newest entries only, so this asks for what
    # happened shortly before the broken update.
    check "the earlier history survived, with the successful update before it" body_has '"action":"update.succeeded"'
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

    echo "The SSH key from the old machine is known, and not installed unasked"
    # The private key travelled over the wipe by way of a Windows folder and
    # lost its permissions there; ssh refuses a key others can read.
    chmod 600 "$ssh_key2"
    expect_status "the SSH state is available" 200 GET /api/ssh
    check "the key is listed" body_has '"label":"second key"'
    check "as not on this device yet" body_has '"installed":false'
    check "keys only is known to have been on" body_has '"wanted":true'
    check "and is not on here" body_has '"keysOnly":false'
    check "nothing of SGC's is among the SSH settings" sudo sh -c '[ ! -e /etc/ssh/sshd_config.d/00-sgc.conf ] && [ ! -e /etc/sgc/ssh/keys/tester ]'
    check "the key does not get in" does_not_get_in "$ssh_key2"
    expect_status "installing it needs the admin password again" 403 POST /api/ssh/keys/install '{"password":"not-the-password","account":"tester"}'
    expect_status "with the password it is installed" 200 POST /api/ssh/keys/install "{\"password\":\"$password\",\"account\":\"tester\"}"
    check "it is listed as on this device" body_has '"installed":true'
    check "the key from the old machine gets in" gets_in "$ssh_key2"
    check "keys only is still not switched on by itself" body_has '"keysOnly":false'
    expect_in_audit "the installation is in the history" '"action":"ssh.keys_installed"'
    # The activity log shows the newest entries only; everything asked for
    # here happened on the old machine shortly before the export. (That the
    # whole history survives, down to the first entry, is checked on the
    # database itself by the tests in internal/backup.)
    expect_in_audit "the history came back, with the updates made on the old machine" '"action":"update.succeeded"'
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
    expect_status "the SSH state is available" 200 GET /api/ssh
    check "SSH is still on keys only" body_has '"keysOnly":true'
    check "passwords are not offered" passwords_not_offered
    check "the key added in the page still gets in" gets_in "$ssh_key2"
    check "the confirmed SSH settings were put in place at start-up" sh -c "[ \"\$(systemctl show -p Result --value sgc-ssh.service)\" = success ]"
    check "before the SSH server started" sh -c "[ \"\$(systemctl show -p ExecMainExitTimestampMonotonic --value sgc-ssh.service)\" -le \"\$(systemctl show -p ExecMainStartTimestampMonotonic --value ssh.service)\" ]"
    ;;

cli)
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
        "The firewall is on, and its rules are loaded" "The firewall's rules load at every start-up" \
        "SSH accepts keys only, and nobody logs in as root" "The 1 key(s) added in SGC's page are in place for the account tester"; do
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
    sudo rm /etc/ssh/sshd_config.d/00-sgc.conf /etc/sgc/ssh/keys/tester
    sudo systemctl reload ssh.service
    output="$(sudo sgc doctor 2>&1)"
    code=$?
    if [ "$code" -ne 0 ] && echo "$output" | grep -q 'FAIL  "Keys only" is switched on, but the SSH server accepts passwords or root' &&
        echo "$output" | grep -q "FAIL  Of the 1 key(s) added in SGC's page, 0 are in place"; then
        pass "SSH settings and keys removed behind SGC's back are reported as problems"
    else
        fail "the missing SSH settings were not reported (exit code $code)"
        indent <<<"$output"
    fi
    if echo "$output" | grep -q 'sudo systemctl start sgc-ssh'; then pass "it says how to put them back"; else fail "it does not say how to put them back"; fi
    if sudo systemctl start sgc-ssh; then pass "following that advice works on a running machine"; else
        fail "the unit that puts them back failed"
        sudo journalctl -u sgc-ssh.service -n 10 --no-pager | indent
    fi
    # The unit asks the SSH server to take the settings up and does not wait
    # for it (it cannot: see Restore in internal/sshd).
    if wait_for 10 passwords_not_offered; then pass "passwords are not offered again"; else fail "passwords are still offered"; fi
    check "and the key gets in again" gets_in "$ssh_key2"
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

    echo "'sgc ssh' at the machine itself"
    check "the state can be read without sudo" sh -c "sgc ssh status | grep -q 'SSH accepts keys only'"
    if output="$(sgc ssh allow-passwords 2>&1)"; then
        fail "allowing passwords without sudo was not refused"
    elif echo "$output" | grep -q 'needs root'; then
        pass "allowing passwords without sudo is refused"
    else
        fail "without sudo: unexpected message"
        indent <<<"$output"
    fi
    check "passwords are still not offered" passwords_not_offered
    output="$(sudo sgc ssh allow-passwords 2>&1)"
    code=$?
    if [ "$code" -eq 0 ] && echo "$output" | grep -q 'allowed again'; then pass "with sudo it allows passwords again"; else
        fail "allowing passwords failed (exit code $code)"
        indent <<<"$output"
    fi
    check "passwords are offered again" passwords_offered
    check "the key added in the page still gets in" gets_in "$ssh_key2"
    expect_status "SGC's page knows" 200 GET /api/ssh
    check "it shows keys only as off" body_has '"keysOnly":false'
    check "and no longer as wanted" body_has '"wanted":false'
    check "SGC's own files still belong to its user" sudo sh -c "[ -z \"\$(find /var/lib/sgc ! -user sgc)\" ]"
    expect_in_audit "the history says it was done at the machine" '"actor":"console","action":"ssh.keys_only_off"'
    ;;

*)
    echo "unknown mode: $mode"
    exit 2
    ;;
esac

echo
if [ "$failures" -eq 0 ]; then echo "ALL CHECKS PASSED ($mode)"; else echo "$failures CHECK(S) FAILED ($mode)"; fi
exit "$failures"
