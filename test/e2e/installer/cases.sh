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
#   os-updates     updates for the device: nothing until the owner chooses;
#                  by hand, the page lists what waits and installs it; then
#                  set to install by themselves
#   dns            AdGuard Home: there since the installer ran (or, on a
#                  machine updated from a version without it, since DNS was
#                  switched on), answers and blocks, its own page only behind
#                  SGC's login, switched off and on, let in by the firewall
#                  from the home network only
#   log2ram        logs in memory: there since the installer ran and off;
#                  refused when the logs do not fit; switched on, which waits
#                  for a restart (after-restart looks at it in memory)
#   domain         the owner's domain and Zone.eu account, against a
#                  stand-in for Zone.eu: saved only when accepted, a warning
#                  when the key stops working, never the key in an answer
#   certificate    the certificate for the domain, against stand-ins for
#                  Let's Encrypt: not without agreement, the test authority
#                  first, a failure that gets no real certificate, then the
#                  certificate itself and a renewal
#   update-setup   points the installed SGC at a local test update source
#   update-refused a tampered update is refused and changes nothing
#   update-good    a genuine update installs from the dashboard's API
#   update-broken  a signed but broken update is rolled back by itself
#   update-downgrade  an older release is never offered or installed
#   update-cli     "sgc update" over SSH
#   export         makes an export through the API (kept in the home folder)
#   restart        asks SGC to restart the machine (the machine goes down)
#   maintenance    the maintenance window: with a restart needed, nothing
#                  happens outside it, and inside it SGC restarts the machine
#                  by itself (the machine goes down)
#   after-restart  SGC came back by itself and remembers everything
#   after-window-restart  it was the window that restarted the machine
#   cli            "sgc doctor", "sgc firewall off" and "sgc ssh
#                  allow-passwords" over SSH
#   restore        on a freshly wiped machine: installs, then restores the
#                  export made earlier and checks that SGC is what it was
#
#   names          the gateway's own name: in AdGuard Home with this
#                  machine's address, the certificate for it on SGC's page,
#                  renamed and back, the owner's own rewrites left alone
#   proxy          Traefik: there since the installer ran and off; a web
#                  service and a game server through it, the friendly page
#                  when one is down, the key readable by Traefik only, the
#                  firewall's rules brought up to date
#   announce       a server announces with its token: taken up, the address
#                  from the connection (also through the proxy), pinned,
#                  first claim wins, a removed token stops working
#
#   vpn            the VPN: off until switched on; on, it listens, has its
#                  own firewall table and its public name at the stand-in
#                  Zone.eu; a phone (the public neighbour with a WireGuard
#                  interface of its own) reaches the service on its
#                  person's list and nothing else, then everything, then
#                  nothing once the guest's time ran out
#   gate           SGC's login in front of a service: the way to the
#                  sign-in and back, a pass for that name only, a way back
#                  that works once, a person whose login lacks the service
#   notify         ntfy (a stand-in), a service that stops answering in the
#                  bell, as a banner and at ntfy, and gone when it answers
#                  again; the logs of SGC's parts
#   backups        backups to a stand-in WebDAV folder: the backup key, the
#                  newest two kept, encrypted, the secret half not kept
#
# For Test-UpgradeFromPrevious.ps1, where /tmp/release holds the previous
# published release and the current source as an update to it:
#
#   old-install    installs the previous release and creates the admin
#   upgrade        the previous release updates itself to <new version>,
#                  with its own updater
#   os-updates-auto  updates for the device set to install by themselves, and
#                  Debian's own daily run then installs what is waiting

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

# --- Updates for the device ---------------------------------------------------

# shellcheck disable=SC2317  # called indirectly through check() and wait_for()
os_state_has() { [ "$(http GET /api/os-updates)" = 200 ] && grep -q "$1" /tmp/sgc-test-body; }
# No look and no installation is running.
# shellcheck disable=SC2317  # called indirectly through wait_for()
os_idle() { os_state_has '"running":""'; }
# What apt's settings amount to, all its files taken together. (Read whole
# first: "apt-config dump | grep -q" fails under pipefail whenever grep finds
# its line early and stops reading.)
# shellcheck disable=SC2317  # called indirectly through check()
apt_says() {
    local settings
    settings="$(apt-config dump)"
    grep -qF "$1" <<<"$settings"
}
# What Debian's update tool itself would install right now, as "a b c".
tool_would_install() {
    sudo env LC_ALL=C unattended-upgrade --dry-run -v 2>/dev/null |
        sed -n 's/^Packages that will be upgraded: //p' | xargs
}
# A list of names in the answer last fetched ("waiting", "packages"), as "a b c".
page_list() {
    grep -o "\"$1\":\[[^]]*\]" /tmp/sgc-test-body | head -1 |
        sed -e 's/^[^[]*\[//' -e 's/\]$//' -e 's/"//g' -e 's/,/ /g'
}
# A request to the root helper as SGC's own user; prints the HTTP status.
helper_status() { # helper_status <path> <json>
    sudo -u sgc curl -s -m 30 -o /dev/null -w '%{http_code}' -X POST -d "$2" \
        --unix-socket /run/sgc-helper/helper.sock "http://helper$1"
}
# SGC's one file among apt's settings, and nothing else of SGC's beside it.
# shellcheck disable=SC2317  # called indirectly through check()
one_file_of_sgc() { [ "$(find /etc/apt/apt.conf.d -maxdepth 1 -name '*sgc*' | wc -l)" = 1 ]; }
# --- DNS -------------------------------------------------------------------------

# dns_answer <server> <name> [network namespace]: asks the server for the
# name's address the way any device would (one UDP packet to port 53). Prints
# the address, or "none" if the answer holds no address; fails if no answer
# comes.
# shellcheck disable=SC2317  # called indirectly through the functions below
dns_answer() {
    local ask=(python3 -c '
import socket, struct, sys
server, name = sys.argv[1], sys.argv[2]
question = struct.pack(">HHHHHH", 0x5347, 0x0100, 1, 0, 0, 0)
question += b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\0" + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(4)
try:
    s.sendto(question, (server, 53))
    answer = s.recv(2048)
except OSError:
    sys.exit(1)
count = struct.unpack(">H", answer[6:8])[0]
at = 12
while answer[at]:
    at += answer[at] + 1
at += 5
for _ in range(count):
    while answer[at] and answer[at] & 0xC0 != 0xC0:
        at += answer[at] + 1
    at += 2 if answer[at] & 0xC0 == 0xC0 else 1
    kind, _, _, length = struct.unpack(">HHIH", answer[at:at + 10])
    at += 10
    if kind == 1 and length == 4:
        print(".".join(str(b) for b in answer[at:at + 4]))
        sys.exit(0)
    at += length
print("none")
' "$1" "$2")
    if [ -n "${3:-}" ]; then sudo ip netns exec "$3" "${ask[@]}"; else "${ask[@]}"; fi
}
# The answer is a real address: the name was looked up, not blocked.
# shellcheck disable=SC2317  # called indirectly through check() and wait_for()
resolves() { local got; got="$(dns_answer "$@")" && [ "$got" != none ] && [ "$got" != 0.0.0.0 ]; }
# AdGuard Home answers a blocked name with the address 0.0.0.0.
# shellcheck disable=SC2317  # called indirectly through check() and wait_for()
is_blocked() { [ "$(dns_answer "$@")" = 0.0.0.0 ]; }
# shellcheck disable=SC2317  # called indirectly through check()
gets_no_dns_answer() { ! dns_answer "$@" >/dev/null; }
# shellcheck disable=SC2317  # called indirectly through check() and wait_for()
dns_state_has() { [ "$(http GET /api/dns)" = 200 ] && grep -q "$1" /tmp/sgc-test-body; }
# shellcheck disable=SC2317  # called indirectly through check() and wait_for()
log2ram_state_has() { [ "$(http GET /api/log2ram)" = 200 ] && grep -q "$1" /tmp/sgc-test-body; }
# shellcheck disable=SC2317  # called indirectly through check()
logs_in_memory() { [ "$(findmnt -no FSTYPE /var/log)" = tmpfs ] && [ "$(findmnt -no SOURCE /var/log)" = log2ram ]; }
# shellcheck disable=SC2317  # called indirectly through check()
logs_on_disk() { ! findmnt /var/log >/dev/null; }
# shellcheck disable=SC2317  # called indirectly through check()
journal_takes_entries() {
    local mark="sgc-test-mark-$RANDOM" found
    logger -t sgc-test "$mark"
    sleep 1
    found="$(sudo journalctl -t sgc-test --no-pager -o cat)"
    [[ "$found" == *"$mark"* ]]
}
# journal_at_most <megabytes>: the journal on the disk takes no more than that.
# shellcheck disable=SC2317  # called indirectly through check()
journal_at_most() { [ "$(sudo du -sm /var/log/journal | cut -f1)" -le "$1" ]; }
# A file of the test's own in the log folder, of data that cannot be made
# smaller, to take up room there.
log_filler=/var/log/sgc-test-filler
# --- The domain and Zone.eu -----------------------------------------------------

# The test never talks to the real Zone.eu. A program of the test's own
# stands in for it on this machine: an account that has the DNS zone
# domain.tld and accepts one made-up username and key.
standin="$HOME/sgc-standin"
zone_address=127.0.0.1:9100
zone_user=alex
zone_key=a-made-up-api-key
# The same program stands in for Let's Encrypt: for its certificate authority
# and its test authority (both played by Pebble, Let's Encrypt's own small
# authority for tests), and for the name servers they look at.
dns_address=127.0.0.1:9153
trial_address=127.0.0.1:9143
authority_address=127.0.0.1:9144
# Where the stand-in keeps the certificate its two authorities show. SGC is
# told to trust it, so SGC's user must be able to read it.
standin_state=/etc/sgc-test

# What makes SGC ask this machine instead of the outside world: the lines of
# its service's environment.
standin_environment=(
    "SGC_ZONE_API=http://$zone_address/v2/"
    "SGC_ACME_DIRECTORY=https://$authority_address/dir"
    "SGC_ACME_TRIAL_DIRECTORY=https://$trial_address/dir"
    "SGC_ACME_ROOTS=$standin_state/authority-cert.pem"
    "SGC_ACME_DNS=$dns_address"
    "SGC_PUBLIC_IP_URL=http://$zone_address/ip"
)

# install_standin: puts the program in place. Copied as a program: what the
# build box wrote to a Windows folder does not arrive marked as one.
install_standin() {
    [ -x "$standin" ] || install -m 0755 /tmp/release/tools/sgc-standin "$standin"
}

# start_standin <the API key the account accepts>: (re)starts the stand-in.
start_standin() {
    install_standin || return 1
    sudo systemctl stop sgc-test-standin.service 2>/dev/null || true
    sudo systemctl reset-failed sgc-test-standin.service 2>/dev/null || true
    sudo systemd-run --quiet --unit sgc-test-standin "$standin" --state "$standin_state" \
        --listen "$zone_address" --dns "$dns_address" --trial "$trial_address" --authority "$authority_address" \
        --username "$zone_user" --api-key "$1" --domain domain.tld || return 1
    wait_for 10 curl -s -o /dev/null "http://$zone_address/" &&
        wait_for 10 curl -sk -o /dev/null "https://$authority_address/dir"
}

# pointed_at_standin: the running SGC asks this machine about everything:
# not Zone.eu, and not Let's Encrypt.
pointed_at_standin() {
    local environment line
    environment="$(systemctl show sgc.service -p Environment)"
    for line in "${standin_environment[@]}"; do
        [[ "$environment" == *"$line"* ]] || return 1
    done
}

# point_at_standin: makes SGC ask this machine instead of the outside world,
# from now on and after every restart, and starts the stand-in there.
#
# In that order, and checked: SGC must not be able to ask the real Zone.eu or
# Let's Encrypt even if the stand-in does not start. (A first version of this
# test started the stand-in first; when it did not start, SGC asked the real
# Zone.eu with the made-up account.)
point_at_standin() {
    install_standin || return 1
    # The certificate SGC is to trust has to be there when SGC starts.
    sudo "$standin" --state "$standin_state" --make-certificate >/dev/null || return 1
    sudo mkdir -p /etc/systemd/system/sgc.service.d
    {
        echo '[Service]'
        printf 'Environment=%s\n' "${standin_environment[@]}"
    } | sudo tee /etc/systemd/system/sgc.service.d/test-standin.conf >/dev/null || return 1
    sudo systemctl daemon-reload
    sudo systemctl restart sgc
    wait_for 30 curl -sk -o /dev/null "$api/api/state" || return 1
    pointed_at_standin || return 1
    start_standin "$zone_key"
}

# without_standin: ends the run. Nothing about a domain or a certificate is
# asked of an SGC that might turn to the real Zone.eu or Let's Encrypt.
without_standin() {
    fail "the stand-in for the outside world could not be set up; stopping here, so that nothing is asked of the real Zone.eu or Let's Encrypt"
    echo
    echo "$failures CHECK(S) FAILED ($mode)"
    exit "$failures"
}

# certificate_idle: no attempt at a certificate is running. The state is in
# /tmp/sgc-test-body afterwards.
# shellcheck disable=SC2317  # called indirectly through wait_for()
certificate_idle() { [ "$(http GET /api/certificate)" = 200 ] && grep -q '"running":null' /tmp/sgc-test-body; }
certificate_serial() { grep -o '"serial":"[^"]*"' /tmp/sgc-test-body | cut -d'"' -f4; }
# serial_differs_from <serial>: the certificate in the state just fetched is another one.
# shellcheck disable=SC2317  # called indirectly through check()
serial_differs_from() {
    local now
    now="$(certificate_serial)"
    [ -n "$1" ] && [ -n "$now" ] && [ "$now" != "$1" ]
}
# The serial number of the certificate, kept across the wipe of the machine
# (Test-Installer.ps1 carries the file), to see that a restore brings back
# that very certificate.
serial_file="$HOME/sgc-test-serial"

# zone_records: how many TXT records the stand-in for Zone.eu holds.
# shellcheck disable=SC2317  # called indirectly through check()
no_records_left() {
    local records
    records="$(curl -s -u "$zone_user:$zone_key" "http://$zone_address/v2/dns/domain.tld/txt")"
    [ "$(tr -d '[:space:]' <<<"$records")" = "[]" ]
}

# Nothing in SGC's log is a private key.
# shellcheck disable=SC2317  # called indirectly through check()
log_has_no_private_key() {
    local log
    log="$(sudo journalctl -u sgc --no-pager)"
    [[ "$log" != *"PRIVATE KEY"* ]]
}

# domain_request <domain> <username> <API key>: the request that saves them.
domain_request() { printf '{"domain":"%s","username":"%s","apiKey":"%s"}' "$1" "$2" "$3"; }

# The made-up key is nowhere in what SGC wrote to its log.
# shellcheck disable=SC2317  # called indirectly through check()
log_lacks_the_key() {
    local log
    log="$(sudo journalctl -u sgc --no-pager)"
    [[ "$log" != *"$zone_key"* ]]
}

# A name of the test's own that the "owner" blocks in AdGuard Home's page.
blocked_by_owner=sgc-test-blocked.domain.tld

# A full hour some hours from now, by the machine's own clock: "14:00".
hour() { date -d "$1" +%H:00; }
# shellcheck disable=SC2317  # called indirectly through check()
window_is() { grep -q "\"enabled\":$1" /tmp/sgc-test-body && grep -q "\"inWindow\":$2" /tmp/sgc-test-body; }
# A settings file that apt reads after SGC's and that says otherwise.
overruling_file=/etc/apt/apt.conf.d/99zz-sgc-test

# --- Names, the proxy, services ----------------------------------------------------

# answers_with <name> <address>: AdGuard Home on this machine answers the name
# with that address.
# shellcheck disable=SC2317  # called indirectly through check() and wait_for()
answers_with() { [ "$(dns_answer 127.0.0.1 "$1")" = "$2" ]; }

# serves_names <port> <name> <pattern>: asked for the name, the TLS server on
# this machine shows a certificate with a name matching the pattern.
# shellcheck disable=SC2317  # called indirectly through check()
serves_names() {
    echo | openssl s_client -connect "127.0.0.1:$1" -servername "$2" 2>/dev/null |
        openssl x509 -noout -ext subjectAltName 2>/dev/null | grep -q "$3"
}

# through_proxy <label> <path> <text>: label.domain.tld, opened through the
# proxy on this machine, shows the text.
# shellcheck disable=SC2317  # called indirectly through check() and wait_for()
through_proxy() {
    local page
    page="$(curl -sk --max-time 10 --resolve "$1.domain.tld:443:127.0.0.1" "https://$1.domain.tld$2")"
    [[ "$page" == *"$3"* ]]
}

# A small web server in the home neighbour, standing in for a device behind a name.
web_root=/tmp/sgc-test-www
start_web_neighbour() {
    sudo mkdir -p "$web_root" &&
        echo '<html><body>served by the test neighbour</body></html>' | sudo tee "$web_root/index.html" >/dev/null
    sudo systemctl stop sgc-test-web.service 2>/dev/null || true
    sudo systemctl reset-failed sgc-test-web.service 2>/dev/null || true
    sudo systemd-run --quiet --unit sgc-test-web ip netns exec "$inside_net" \
        python3 -m http.server 8080 --bind "$inside_peer" --directory "$web_root"
    wait_for 10 sudo ip netns exec "$inside_net" curl -s -o /dev/null "http://$inside_peer:8080/"
}

# start_tcp_neighbour <port>: a "game server" in the home neighbour that
# greets whoever connects.
start_tcp_neighbour() {
    sudo systemctl stop sgc-test-game.service 2>/dev/null || true
    sudo systemctl reset-failed sgc-test-game.service 2>/dev/null || true
    sudo systemd-run --quiet --unit sgc-test-game ip netns exec "$inside_net" python3 -c '
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2])))
s.listen(5)
while True:
    c, _ = s.accept()
    c.sendall(b"hello-from-the-game\n")
    c.close()
' "$inside_peer" "$1"
}

# service_state_is <name> <up|down|unknown>: as the page shows it.
# shellcheck disable=SC2317  # called indirectly through wait_for()
service_state_is() {
    [ "$(http GET /api/services)" = 200 ] && python3 -c '
import json, sys
services = [s for s in json.load(open("/tmp/sgc-test-body"))["services"] if s["name"] == sys.argv[1]]
sys.exit(0 if services and services[0]["health"]["state"] == sys.argv[2] else 1)
' "$1" "$2"
}

# service_has <name> <json text>: the service, as the page gets it, contains the text.
# shellcheck disable=SC2317  # called indirectly through check()
service_has() {
    [ "$(http GET /api/services)" = 200 ] && python3 -c '
import json, sys
services = [s for s in json.load(open("/tmp/sgc-test-body"))["services"] if s["name"] == sys.argv[1]]
sys.exit(0 if services and sys.argv[2] in json.dumps(services[0], separators=(",", ":")) else 1)
' "$1" "$2"
}

# announce_from <namespace> <base url> <token> <curl arguments...>: what a
# server's announce container does.
announce_from() {
    local ns="$1" base="$2" tok="$3"
    shift 3
    sudo ip netns exec "$ns" curl -sk -H "Authorization: Bearer $tok" "$@" "$base/api/announce"
}

# --- The VPN, the gate, notifications, backups --------------------------------------

# json_get <python expression on d>: a value from the last answer's body.
json_get() {
    python3 -c 'import json, sys; d = json.load(open("/tmp/sgc-test-body")); print(eval(sys.argv[1], {"d": d}))' "$1"
}

# service_id <name>: the service's number, as the page knows it.
service_id() {
    http GET /api/services >/dev/null && json_get "[s['id'] for s in d['services'] if s['name'] == '$1'][0]"
}

# A phone on the internet: the public neighbour, with a WireGuard interface
# of its own made from the settings SGC hands out.
phone_net="$outside_net"
phone_up() { # phone_up <settings file>
    local conf="$1" stripped
    stripped="$(mktemp)"
    # Not the public name: the phone reaches this machine at its address on
    # the stand-in internet.
    sed -i "s|^Endpoint = .*|Endpoint = $outside_gateway:51820|" "$conf"
    wg-quick strip "$conf" >"$stripped" || return 1
    sudo ip netns exec "$phone_net" ip link del wg-phone 2>/dev/null || true
    sudo ip netns exec "$phone_net" ip link add wg-phone type wireguard &&
        sudo ip netns exec "$phone_net" wg setconf wg-phone "$stripped" &&
        sudo ip netns exec "$phone_net" ip addr add "$(sed -n 's|^Address = ||p' "$conf")" dev wg-phone &&
        sudo ip netns exec "$phone_net" ip link set wg-phone up &&
        sudo ip netns exec "$phone_net" ip route replace 10.86.0.0/24 dev wg-phone &&
        sudo ip netns exec "$phone_net" ip route replace "$lan_address/32" dev wg-phone
    local code=$?
    rm -f "$stripped"
    return $code
}
phone_down() { sudo ip netns exec "$phone_net" ip link del wg-phone 2>/dev/null || true; }

# phone_gets <url> <text>: the phone opens a name through the tunnel.
# shellcheck disable=SC2317  # called indirectly through check() and wait_for()
phone_gets() {
    local host page
    host="$(echo "$1" | sed -E 's|https://([^/]+).*|\1|')"
    page="$(sudo ip netns exec "$phone_net" curl -sk --max-time 8 --resolve "$host:443:$lan_address" "$1")"
    [[ "$page" == *"$2"* ]]
}

# device_config <device id>: the device's settings, as its QR code holds them.
device_config() {
    local password
    password="$(cat "$password_file")"
    [ "$(http POST "/api/vpn/devices/$1/config" "{\"password\":\"$password\"}")" = 200 ] && json_get "d['config']"
}

# ntfy_got <text>: the stand-in ntfy server was sent the text.
# shellcheck disable=SC2317  # called indirectly through wait_for()
ntfy_got() { sudo grep -q "$1" "$standin_state/ntfy.log" 2>/dev/null; }

# device_connected: the page shows a VPN device as connected.
# shellcheck disable=SC2317  # called indirectly through wait_for()
device_connected() { [ "$(http GET /api/vpn)" = 200 ] && grep -q '"connected":true' /tmp/sgc-test-body; }

# answers_at <server> <name> <namespace> <address>: asked from inside the
# namespace, the server answers the name with the address.
# shellcheck disable=SC2317  # called indirectly through check()
answers_at() { [ "$(dns_answer "$1" "$2" "$3")" = "$4" ]; }

# banner_has <text> / banner_gone <text>: a banner with the text is shown, or not.
# shellcheck disable=SC2317  # called indirectly through check() and wait_for()
banner_has() { [ "$(http GET /api/notifications/summary)" = 200 ] && grep -q "$1" /tmp/sgc-test-body; }
# shellcheck disable=SC2317  # called indirectly through wait_for()
banner_gone() { [ "$(http GET /api/notifications/summary)" = 200 ] && ! grep -q "$1" /tmp/sgc-test-body; }

# notified <text>: the bell has a notification with the text.
# shellcheck disable=SC2317  # called indirectly through wait_for()
notified() { [ "$(http GET /api/notifications)" = 200 ] && grep -q "$1" /tmp/sgc-test-body; }

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

    echo "AdGuard Home, the DNS server, came with it"
    check "the installer says that it installs AdGuard Home" grep -q '^Installing AdGuard Home [0-9.]*, the DNS server' /tmp/install.log
    check "and that DNS is on" grep -q '^DNS is on: AdGuard Home answers' /tmp/install.log
    check "it is running" systemctl is-active --quiet sgc-adguard.service
    check "it will start with the machine" systemctl is-enabled --quiet sgc-adguard.service
    if wait_for 60 resolves 127.0.0.1 debian.org; then pass "it answers a name lookup"; else fail "it does not answer a name lookup"; fi
    check "nothing of the download is left behind" sudo sh -c "[ -z \"\$(ls /var/lib/sgc/components 2>/dev/null)\" ]"

    echo "log2ram came with it too, switched off"
    check "the installer says that it installs log2ram" grep -q '^Installing log2ram from Debian' /tmp/install.log
    check "and that it is switched off" grep -q '^log2ram is installed and switched off' /tmp/install.log
    check "Debian's package is installed" test -x /usr/bin/log2ram
    check "and the program it copies with" test -x /usr/bin/rsync
    check "it is not part of start-up" sh -c '! systemctl is-enabled --quiet log2ram.service && ! systemctl is-enabled --quiet log2ram-daily.timer'
    check "the logs are on the disk" logs_on_disk

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
    check "and AdGuard Home is not installed a second time" sh -c "! grep -q 'Installing AdGuard Home' /tmp/install2.log"
    check "nor log2ram" sh -c "! grep -q 'Installing log2ram' /tmp/install2.log"
    check "service is still running" systemctl is-active --quiet sgc
    sleep 1
    expect_status "the earlier sign-in still works" 200 GET /api/health
    expect_in_audit "that AdGuard Home was installed with SGC is in the history" '"action":"dns.installed"'
    expect_status "the page knows about DNS" 200 GET /api/dns
    check "and shows it as switched on" body_has '"enabled":true'
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
    if [ -e /opt/sgc/components/adguardhome/current ]; then
        # AdGuard Home came with the installer and runs before there is any
        # firewall. It is AdGuard Home itself that answers home addresses only.
        dns_from_start=true
        check "without a firewall, AdGuard Home answers the neighbour with a home address" resolves "$inside_gateway" debian.org "$inside_net"
        check "and not the one with a public address" gets_no_dns_answer "$outside_gateway" debian.org "$outside_net"
    else
        # A machine updated from a version that did not install it.
        dns_from_start=false
    fi

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
    check "SSH and SGC's page are let in, and DNS where AdGuard Home is there ($dns_from_start)" body_has "\"sshPorts\":\[22\],\"dns\":$dns_from_start,\"webPort\":8443"
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

os-updates)
    # Changes with every start of the machine.
    boot_id="$(cat /proc/sys/kernel/random/boot_id)"
    echo "Updates for the device: nothing is touched until the owner chooses"
    expect_status "the state is available" 200 GET /api/os-updates
    check "the owner has not chosen yet" body_has '"mode":""'
    check "Debian's update tool is on this machine" body_has '"toolInstalled":true'
    check "SGC has written nothing among apt's settings" sh -c '[ ! -e /etc/apt/apt.conf.d/52sgc-updates ]'
    expect_status "looking for updates is refused until then" 409 POST /api/os-updates/check '{}'
    expect_status "and so is installing" 409 POST /api/os-updates/install '{}'
    expect_status "a choice must be spelled out" 400 POST /api/os-updates/mode '{}'
    check "no package tool was run" sh -c '[ ! -e /run/sgc-os-updates/report.json ]'

    echo "By hand: SGC's settings file, and a look"
    expect_status "choosing \"by hand\"" 200 POST /api/os-updates/mode '{"automatic":false}'
    check "the page says so" body_has '"mode":"by-hand"'
    check "SGC's settings file is in place" grep -q 'sgc-mode: by-hand' /etc/apt/apt.conf.d/52sgc-updates
    check "apt reads it: nothing installs by itself" apt_says 'APT::Periodic::Unattended-Upgrade "0";'
    check "the lists are still fetched every day" apt_says 'APT::Periodic::Update-Package-Lists "1";'
    check "the update tool will never restart the device" apt_says 'Unattended-Upgrade::Automatic-Reboot "false";'
    check "Raspberry Pi's archive is added to what may install" apt_says 'origin=Raspberry Pi Foundation,'
    check "Debian's own archives are still among it" apt_says 'label=Debian-Security'
    check "the timer that fetches the lists runs" systemctl is-active --quiet apt-daily.timer
    check "no temporary file is left among apt's settings" one_file_of_sgc
    if wait_for 240 os_idle; then pass "the look that follows the choice has ended"; else fail "the look did not end"; fi
    if grep -q '"checkError":""' /tmp/sgc-test-body && ! grep -q '"checkedAt":null' /tmp/sgc-test-body; then pass "and it worked"; else
        fail "the look failed"
        indent </tmp/sgc-test-body
    fi
    waiting="$(page_list waiting)"
    expected="$(tool_would_install)"
    if [ -n "$expected" ]; then pass "updates are waiting on this machine ($(wc -w <<<"$expected"))"; else
        fail "nothing is waiting on this machine, so installing cannot be tested (is the machine's image brand new?)"
    fi
    if [ "$waiting" = "$expected" ]; then pass "the page lists exactly what Debian's update tool would install"; else
        fail "the page lists: $waiting"
        echo "        the update tool would install: $expected"
    fi

    echo "By hand: Debian's own daily run installs nothing"
    sudo systemctl start apt-daily-upgrade.service
    if [ "$(tool_would_install)" = "$expected" ]; then pass "the same updates are still waiting after it"; else fail "the daily run installed something"; fi

    echo "By hand: installing from the page"
    expect_status "the installation starts" 202 POST /api/os-updates/install '{}'
    check "it is reported as running" body_has '"running":"install"'
    expect_status "a second one is refused meanwhile" 409 POST /api/os-updates/install '{}'
    expect_status "and so is a look" 409 POST /api/os-updates/check '{}'
    expect_status "and so is restarting the device" 409 POST /api/device/restart '{"confirm":true}'
    if wait_for 1200 os_idle; then pass "the installation has ended"; else fail "the installation did not end"; fi
    if grep -q '"result":"ok"' /tmp/sgc-test-body; then pass "it ended well"; else
        fail "it did not end well"
        indent </tmp/sgc-test-body
        sudo journalctl -u sgc-os-updates.service --no-pager -n 25 -o cat | indent
    fi
    if [ "$(page_list packages)" = "$expected" ]; then pass "the page names what was installed"; else fail "the page names as installed: $(page_list packages)"; fi
    check "nothing is waiting any more" body_has '"waiting":\[\]'
    check "what SGC started is not taken for Debian's own daily run" body_has '"lastRun":null'
    if [ -z "$(tool_would_install)" ]; then pass "Debian's update tool agrees: nothing left to install"; else fail "the update tool would still install: $(tool_would_install)"; fi
    expect_in_audit "the installation is in the history" '"action":"os_updates.installed"'
    check "with who started it" body_has "started by $username"
    check "the unit that did the work is not marked as failed" sh -c "! systemctl is-failed --quiet sgc-os-updates.service"

    echo "A look while Debian's servers cannot be reached"
    expect_status "the state is available" 200 GET /api/os-updates
    looked_before="$(grep -o '"checkedAt":"[^"]*"' /tmp/sgc-test-body)"
    # apt is sent to a proxy that does not exist.
    printf 'Acquire::http::Proxy "http://127.0.0.1:9";\nAcquire::https::Proxy "http://127.0.0.1:9";\nAcquire::Retries "0";\n' |
        sudo tee "$overruling_file" >/dev/null
    expect_status "looking" 202 POST /api/os-updates/check '{}'
    if wait_for 240 os_idle; then pass "the look has ended"; else fail "the look did not end"; fi
    check "the page says that it failed, and why" body_has '"checkError":"Debian.s servers could not be reached'
    if [ -n "$looked_before" ] && grep -qF "$looked_before" /tmp/sgc-test-body; then pass "and does not pass off what it knew before as freshly looked at"; else
        fail "the failed look is shown as if it had worked"
        indent </tmp/sgc-test-body
    fi
    sudo rm -f "$overruling_file"
    expect_status "looking again, with the servers back" 202 POST /api/os-updates/check '{}'
    if wait_for 240 os_idle; then pass "the look has ended"; else fail "the look did not end"; fi
    check "a look that works clears the complaint" body_has '"checkError":""'

    echo "A restart that an update needs is shown, and not carried out"
    # Debian's packages say so with a file in /run (a kernel's does). If the
    # updates just installed did not, the test does it for them.
    made_up=no
    if [ ! -e /run/reboot-required ]; then
        made_up=yes
        sudo touch /run/reboot-required
        echo "linux-image-0.0.0-test-amd64" | sudo tee /run/reboot-required.pkgs >/dev/null
    fi
    check "the page says a restart is needed" os_state_has '"restartNeeded":true'
    check "and for what" sh -c "grep -q '\"restartPackages\":\[\"' /tmp/sgc-test-body"
    if [ "$(cat /proc/sys/kernel/random/boot_id)" = "$boot_id" ]; then pass "the device was not restarted by anything"; else fail "the device has restarted"; fi
    if [ "$made_up" = yes ]; then sudo rm -f /run/reboot-required /run/reboot-required.pkgs; fi

    echo "The root helper takes a job or a feature by name, and nothing else"
    # A small package that no machine has by accident.
    if dpkg -s cowsay >/dev/null 2>&1; then fail "cowsay is already on this machine; the next checks prove nothing"; fi
    for request in '/v1/os-updates/start {"job":"install","packages":["cowsay"]}' '/v1/os-updates/start {"job":"remove"}' \
        '/v1/os-updates/mode {"automatic":true,"origins":["origin=*"]}' '/v1/install-packages {"for":"cowsay"}' \
        '/v1/install-packages {"for":"updates","packages":["cowsay"]}'; do
        if [ "$(helper_status "${request%% *}" "${request#* }")" = 400 ]; then pass "refused: $request"; else fail "not refused: $request"; fi
    done
    if dpkg -s cowsay >/dev/null 2>&1; then fail "a package named in a request was installed"; else pass "nothing named in a request was installed"; fi

    echo "A setting elsewhere on the device that would overrule SGC's"
    printf 'APT::Periodic::Unattended-Upgrade "0";\n' | sudo tee "$overruling_file" >/dev/null
    expect_status "choosing \"by themselves\" is refused" 502 POST /api/os-updates/mode '{"automatic":true}'
    check "and the answer says why" body_has 'overrules SGC'
    check "SGC's file still says by hand" grep -q 'sgc-mode: by-hand' /etc/apt/apt.conf.d/52sgc-updates
    check "the refusal leaves no unit marked as failed" sh -c "! systemctl is-failed --quiet sgc-os-updates-set.service"
    sudo rm -f "$overruling_file"

    echo "By themselves"
    expect_status "choosing \"by themselves\"" 200 POST /api/os-updates/mode '{"automatic":true}'
    check "the page says so" body_has '"mode":"automatic"'
    check "SGC's settings file says so" grep -q 'sgc-mode: automatic' /etc/apt/apt.conf.d/52sgc-updates
    check "apt reads it: updates install every day" apt_says 'APT::Periodic::Unattended-Upgrade "1";'
    # Test-Installer.ps1 stopped Debian's timers when it reset the machine.
    check "SGC started Debian's daily timers" sh -c "systemctl is-active --quiet apt-daily.timer && systemctl is-active --quiet apt-daily-upgrade.timer"
    check "and they will start with the device" sh -c "systemctl is-enabled --quiet apt-daily.timer && systemctl is-enabled --quiet apt-daily-upgrade.timer"
    check "the device now installs updates by itself" os_state_has '"daily":true'
    check "nothing is wrong with that" body_has '"problem":""'
    if wait_for 240 os_idle; then pass "the look that follows the choice has ended"; else fail "the look did not end"; fi
    expect_in_audit "the choice is in the history" '"action":"os_updates.mode_automatic"'
    check "no unit of SGC's is marked as failed" sh -c "[ -z \"\$(systemctl list-units --failed --plain --no-legend 'sgc*')\" ]"
    ;;

os-updates-auto)
    echo "Updates for the device, set to install by themselves"
    expect_status "the state is available" 200 GET /api/os-updates
    check "the owner has not chosen yet" body_has '"mode":""'
    expect_status "choosing \"by themselves\"" 200 POST /api/os-updates/mode '{"automatic":true}'
    check "the page says so" body_has '"mode":"automatic"'
    check "apt reads SGC's file: updates install every day" apt_says 'APT::Periodic::Unattended-Upgrade "1";'
    check "the device now installs updates by itself" os_state_has '"daily":true'
    if wait_for 240 os_idle; then pass "the look that follows the choice has ended"; else fail "the look did not end"; fi
    expected="$(tool_would_install)"
    if [ -n "$expected" ]; then pass "updates are waiting on this machine ($(wc -w <<<"$expected"))"; else
        fail "nothing is waiting on this machine, so installing cannot be tested (is the machine's image brand new?)"
    fi
    if [ "$(page_list waiting)" = "$expected" ]; then pass "the page lists exactly what Debian's update tool would install"; else fail "the page lists: $(page_list waiting)"; fi

    echo "Debian's own daily run installs them"
    # What Debian's timer does once a day, done now.
    sudo systemctl start apt-daily-upgrade.service
    if [ -z "$(tool_would_install)" ]; then pass "nothing is left to install after it"; else fail "still waiting after the daily run: $(tool_would_install)"; fi
    expect_status "looking again" 202 POST /api/os-updates/check '{}'
    if wait_for 240 os_idle; then pass "the look has ended"; else fail "the look did not end"; fi
    check "the page agrees: nothing is waiting" body_has '"waiting":\[\]'
    check "and knows that Debian's daily run has run" sh -c "! grep -q '\"lastRun\":null' /tmp/sgc-test-body"
    check "no unit of SGC's is marked as failed" sh -c "[ -z \"\$(systemctl list-units --failed --plain --no-legend 'sgc*')\" ]"
    ;;

dns)
    expect_status "the state is available" 200 GET /api/dns
    if body_has '"installed":true'; then
        echo "AdGuard Home: there since the installer ran"
    else
        echo "AdGuard Home on a machine updated from a version without it: not there until DNS is switched on"
        check "DNS is off" body_has '"enabled":false'
        check "nothing answers DNS on this machine" gets_no_dns_answer 127.0.0.1 debian.org
        check "its page behind SGC's login says that it is not there" sh -c "[ \"\$(curl -sk -o /dev/null -w '%{http_code}' -b '$cookies' '$api/adguard/')\" = 502 ]"
        check "the command line says so too" sh -c "sgc dns | grep -q '^DNS is off: AdGuard Home is not on this device'"
        expect_status "switching DNS on downloads and installs it" 200 POST /api/dns/enabled '{"enabled":true}'
        expect_in_audit "the installation is in the history" '"action":"dns.installed"'
    fi
    expect_status "the page reports on it" 200 GET /api/dns
    check "it is installed, switched on and running" sh -c "grep -q '\"installed\":true' /tmp/sgc-test-body && grep -q '\"enabled\":true' /tmp/sgc-test-body && grep -q '\"running\":true' /tmp/sgc-test-body"
    pinned="$(grep -o '"pinned":"[^"]*"' /tmp/sgc-test-body | cut -d'"' -f4)"
    check "the program is the version SGC pins ($pinned)" sh -c "/opt/sgc/components/adguardhome/current/AdGuardHome --version | grep -q 'v$pinned\$'"
    check "it belongs to root, not to the account it runs as" sh -c "[ \"\$(stat -c %U /opt/sgc/components/adguardhome/current/AdGuardHome)\" = root ]"
    check "it runs under an account of its own" sh -c "[ \"\$(stat -c %U /proc/\$(pgrep -x AdGuardHome))\" = sgc-adguard ]"
    check "it will start with the machine" systemctl is-enabled --quiet sgc-adguard.service
    check "nothing of the download is left behind" sudo sh -c "[ -z \"\$(ls /var/lib/sgc/components 2>/dev/null)\" ]"
    if wait_for 60 resolves 127.0.0.1 debian.org; then pass "it answers a name lookup"; else fail "it does not answer a name lookup"; fi
    # The blocklist is fetched at the first start.
    if wait_for 120 is_blocked 127.0.0.1 doubleclick.net; then pass "an advertising name is answered with nothing"; else fail "an advertising name is not blocked"; fi

    echo "Its own page: on this machine only, and through SGC's login"
    check "it listens on this machine only" sh -c "ss -H -ltn 'sport = :3000' | grep -q '127.0.0.1:3000' && ! ss -H -ltn 'sport = :3000' | grep -qv '127.0.0.1:3000'"
    check "signed in, SGC passes its page on" sh -c "[ \"\$(curl -sk -o /tmp/sgc-test-agh -w '%{http_code}' -b '$cookies' '$api/adguard/')\" = 200 ] && grep -qi 'adguard' /tmp/sgc-test-agh"
    expect_status "and its own interface for settings" 200 GET /adguard/control/status
    check "which says it is running" body_has '"running":true'
    check "without SGC's sign-in there is no way in" sh -c "[ \"\$(curl -sk -o /dev/null -w '%{http_code}' '$api/adguard/control/status')\" = 401 ]"
    check "nor to change anything" sh -c "[ \"\$(curl -sk -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{\"rules\":[]}' '$api/adguard/control/filtering/set_rules')\" = 401 ]"
    expect_status "its settings can be read through SGC" 200 GET /adguard/control/dns_info
    check "it asks Quad9, over an encrypted connection" body_has 'https://dns.quad9.net/dns-query'
    expect_status "and the settings of its log" 200 GET /adguard/control/querylog/config
    check "the log is kept for 7 days" body_has '"interval":604800000'

    echo "The owner changes something in AdGuard Home's page"
    expect_status "a rule of the owner's is saved" 200 POST /adguard/control/filtering/set_rules "{\"rules\":[\"||$blocked_by_owner^\"]}"
    if wait_for 15 is_blocked 127.0.0.1 "$blocked_by_owner"; then pass "and takes effect"; else fail "the owner's rule does not take effect"; fi

    echo "Switched off, and on again"
    expect_status "a request that does not say on or off is refused" 400 POST /api/dns/enabled '{}'
    expect_status "switching DNS off" 200 POST /api/dns/enabled '{"enabled":false}'
    check "the page shows it as off, and still on the machine" sh -c "grep -q '\"enabled\":false' /tmp/sgc-test-body && grep -q '\"installed\":true' /tmp/sgc-test-body && grep -q '\"running\":false' /tmp/sgc-test-body"
    check "nothing answers DNS any more" gets_no_dns_answer 127.0.0.1 debian.org
    check "it would not start with the machine" sh -c '! systemctl is-enabled --quiet sgc-adguard.service'
    check "the machine itself still looks up names" getent ahosts deb.debian.org
    output="$(sudo sgc doctor 2>&1)"
    if grep -q 'ok    DNS is switched off' <<<"$output"; then pass "the doctor says that DNS is switched off, not that something is wrong"; else
        fail "the doctor does not say that DNS is switched off"
        indent <<<"$output"
    fi
    check "the command line says so too" sh -c "sgc dns | grep -q '^DNS is off. AdGuard Home [0-9.]* and its settings are on this device'"
    expect_status "switching DNS on again" 200 POST /api/dns/enabled '{"enabled":true}'
    check "the page shows it as on and running" sh -c "grep -q '\"enabled\":true' /tmp/sgc-test-body && grep -q '\"running\":true' /tmp/sgc-test-body"
    if wait_for 30 resolves 127.0.0.1 debian.org; then pass "it answers again"; else fail "it does not answer after being switched on"; fi
    if wait_for 30 is_blocked 127.0.0.1 "$blocked_by_owner"; then pass "the owner's rule is still in force"; else fail "the owner's rule was lost"; fi
    check "it will start with the machine again" systemctl is-enabled --quiet sgc-adguard.service
    expect_in_audit "switching off is in the history" '"action":"dns.switched_off"'
    expect_in_audit "and so is switching on" '"action":"dns.switched_on"'

    echo "From the network: only once the firewall lets DNS in, and only from inside"
    neighbour "$outside_net" "$outside_gateway" "$outside_peer"
    neighbour "$inside_net" "$inside_gateway" "$inside_peer"
    expect_status "the firewall's state is available" 200 GET /api/firewall
    check "the firewall is on" body_has '"state":"on"'
    if body_has '"dns":false'; then
        echo "The firewall was switched on before AdGuard Home was there"
        check "a neighbour with a home address gets no answer" gets_no_dns_answer "$inside_gateway" debian.org "$inside_net"
        expect_status "the rules are made afresh" 202 POST /api/firewall/change '{"enabled":true,"again":true}'
        expect_status "and confirmed like any firewall change" 200 POST /api/firewall/confirm '{}'
    fi
    check "the firewall lets DNS in" firewall_is on
    check "the page knows" body_has '"dns":true'
    check "the neighbour with a home address gets answers" resolves "$inside_gateway" debian.org "$inside_net"
    check "and has advertising left out" is_blocked "$inside_gateway" doubleclick.net "$inside_net"
    check "the neighbour with a public address gets none" gets_no_dns_answer "$outside_gateway" debian.org "$outside_net"
    check "AdGuard Home's own page is out of reach even from a home address" does_not_reach "$inside_net" "$inside_gateway" 3000
    check "no unit of SGC's is marked as failed" sh -c "[ -z \"\$(systemctl list-units --failed --plain --no-legend 'sgc*')\" ]"
    ;;

log2ram)
    expect_status "the state is available" 200 GET /api/log2ram
    if body_has '"installed":true'; then
        echo "Logs in memory: installed with SGC, and off"
    else
        echo "Logs in memory on a machine updated from a version without it: installed when switched on"
        check "log2ram is not on the machine" test ! -e /usr/bin/log2ram
    fi
    check "it is switched off" body_has '"enabled":false'
    check "and the logs are on the disk" logs_on_disk

    echo "Logs that do not fit are refused, and nothing is changed"
    sudo dd if=/dev/urandom of="$log_filler" bs=1M count=100 status=none
    expect_status "switching on is refused" 502 POST /api/log2ram/enabled '{"enabled":true}'
    check "the refusal names what is in the way" body_has 'sgc-test-filler (100 MB)'
    check "log2ram is not part of start-up" sh -c '! systemctl is-enabled --quiet log2ram.service'
    check "the journal has no limit of SGC's" test ! -e /etc/systemd/journald.conf.d/60-sgc-log2ram.conf
    check "the unit that refused is not marked as failed" sh -c '! systemctl is-failed --quiet sgc-log2ram-set.service'
    sudo rm -f "$log_filler"

    echo "Switched on: it waits for a restart"
    expect_status "switching on" 200 POST /api/log2ram/enabled '{"enabled":true}'
    check "the page shows it as on, waiting for a restart" sh -c "grep -q '\"enabled\":true' /tmp/sgc-test-body && grep -q '\"active\":false' /tmp/sgc-test-body && grep -q '\"restartNeeded\":true' /tmp/sgc-test-body"
    check "Debian's package is installed" test -x /usr/bin/log2ram
    check "log2ram is part of start-up" systemctl is-enabled --quiet log2ram.service
    check "and so is its daily write to the disk" systemctl is-enabled --quiet log2ram-daily.timer
    check "nothing was started on the running machine" sh -c '! systemctl is-active --quiet log2ram.service'
    check "the logs are still on the disk" logs_on_disk
    check "the journal has its limit" sudo grep -q '^SystemMaxUse=32M$' /etc/systemd/journald.conf.d/60-sgc-log2ram.conf
    check "and keeps to it" journal_at_most 48
    check "the journal still takes entries" journal_takes_entries
    check "SGC is still running" systemctl is-active --quiet sgc
    expect_status "and answering" 200 GET /api/health
    expect_in_audit "switching on is in the history" '"action":"log2ram.switched_on"'
    output="$(sudo sgc doctor 2>&1)"
    if grep -q 'ok    Logs in memory is switched on, and takes effect when the device restarts' <<<"$output"; then pass "the doctor says that it waits for a restart"; else
        fail "the doctor does not say that it waits for a restart"
        indent <<<"$output"
    fi

    echo "Switched off again before any restart, and on once more"
    expect_status "switching off" 200 POST /api/log2ram/enabled '{"enabled":false}'
    check "the page shows it as off, with nothing waiting" sh -c "grep -q '\"enabled\":false' /tmp/sgc-test-body && grep -q '\"restartNeeded\":false' /tmp/sgc-test-body"
    check "log2ram is not part of start-up" sh -c '! systemctl is-enabled --quiet log2ram.service && ! systemctl is-enabled --quiet log2ram-daily.timer'
    check "the journal's limit is gone" test ! -e /etc/systemd/journald.conf.d/60-sgc-log2ram.conf
    check "the journal still takes entries" journal_takes_entries
    expect_in_audit "switching off is in the history" '"action":"log2ram.switched_off"'
    expect_status "switching on once more" 200 POST /api/log2ram/enabled '{"enabled":true}'
    check "log2ram is part of start-up again" systemctl is-enabled --quiet log2ram.service
    check "no unit of SGC's is marked as failed" sh -c "[ -z \"\$(systemctl list-units --failed --plain --no-legend 'sgc*')\" ]"
    ;;

domain)
    echo "SGC is pointed at a stand-in for Zone.eu; the test never talks to the real one"
    if point_at_standin; then pass "the stand-in runs, and SGC asks it"; else without_standin; fi
    expect_status "the earlier sign-in still works" 200 GET /api/health
    expect_status "the state is available" 200 GET /api/domain
    check "no domain is set up" body_has '"configured":false'

    echo "What Zone.eu does not accept is not saved"
    expect_status "a wrong key is refused" 400 POST /api/domain "$(domain_request domain.tld "$zone_user" another-key)"
    check "in words" body_has 'does not accept the username and API key'
    expect_status "a domain that is not in the account is refused" 400 POST /api/domain "$(domain_request other.tld "$zone_user" "$zone_key")"
    check "in words" body_has 'has no DNS zone for other.tld'
    expect_status "what is no domain name is refused" 400 POST /api/domain "$(domain_request 'domain.tld/../x' "$zone_user" "$zone_key")"
    expect_status "the state is available" 200 GET /api/domain
    check "nothing was saved" body_has '"configured":false'

    echo "Saved once Zone.eu says yes"
    expect_status "the domain with the right key is saved" 200 POST /api/domain "$(domain_request Domain.TLD "$zone_user" "$zone_key")"
    check "the page shows the domain, and that Zone.eu accepted the key" sh -c "grep -q '\"configured\":true' /tmp/sgc-test-body && grep -q '\"domain\":\"domain.tld\"' /tmp/sgc-test-body && grep -q '\"ok\":true' /tmp/sgc-test-body"
    check "the answer does not carry the key" sh -c "! grep -q '$zone_key' /tmp/sgc-test-body"
    expect_in_audit "it is in the history" '"action":"domain.saved"'
    check "the history does not carry the key" sh -c "! grep -q '$zone_key' /tmp/sgc-test-body"
    check "nor does SGC's log" log_lacks_the_key
    output="$(sudo sgc doctor 2>&1)"
    if grep -q 'ok    Zone.eu accepted the saved API key for domain.tld when SGC last asked' <<<"$output"; then pass "the doctor says that Zone.eu accepted the key"; else
        fail "the doctor does not say that Zone.eu accepted the key"
        indent <<<"$output"
    fi

    echo "The key is withdrawn at Zone.eu"
    check "SGC still asks the stand-in" pointed_at_standin
    start_standin a-key-made-later
    expect_status "asking Zone.eu now" 200 POST /api/domain/check '{}'
    check "the page says that the key is not accepted" sh -c "grep -q '\"ok\":false' /tmp/sgc-test-body && grep -q 'does not accept the username and API key' /tmp/sgc-test-body"
    expect_in_audit "that it stopped working is in the history" '"action":"zone.check_failed"'
    output="$(sudo sgc doctor 2>&1)"
    code=$?
    if [ "$code" -ne 0 ] && grep -q 'FAIL  The domain domain.tld: Zone.eu does not accept the username and API key' <<<"$output"; then
        pass "the doctor reports it as a problem"
    else
        fail "the doctor does not report the refused key (exit code $code)"
        indent <<<"$output"
    fi
    if grep -q 'make a new one in your ZoneID account' <<<"$output"; then pass "and says what to do"; else fail "it does not say what to do"; fi

    echo "Zone.eu out of reach"
    sudo systemctl stop sgc-test-standin.service
    expect_status "asking Zone.eu now" 200 POST /api/domain/check '{}'
    check "the page says that it could not be reached" body_has 'could not be reached'

    echo "The key accepted again"
    start_standin "$zone_key"
    expect_status "asking Zone.eu now" 200 POST /api/domain/check '{}'
    check "the page says that all is well" body_has '"ok":true'
    expect_in_audit "that it works again is in the history" '"action":"zone.check_recovered"'

    echo "Removed, and saved again"
    expect_status "removing needs to be meant" 400 POST /api/domain/remove '{}'
    expect_status "removing the domain" 200 POST /api/domain/remove '{"confirm":true}'
    check "nothing is left" body_has '"configured":false'
    expect_status "saving it again" 200 POST /api/domain "$(domain_request domain.tld "$zone_user" "$zone_key")"
    check "it is there again" body_has '"configured":true'
    check "no unit of SGC's is marked as failed" sh -c "[ -z \"\$(systemctl list-units --failed --plain --no-legend 'sgc*')\" ]"
    ;;

certificate)
    echo "SGC asks stand-ins, never Let's Encrypt or Zone.eu"
    if pointed_at_standin && start_standin "$zone_key"; then pass "SGC is pointed at the stand-ins, and they run"; else without_standin; fi
    expect_status "the state is available" 200 GET /api/certificate
    check "it is for the domain that is set up" body_has '"domain":"domain.tld"'
    check "there is no certificate yet" body_has '"certificate":null'
    check "and certificates are not switched off" body_has '"disabled":""'

    echo "Not without the owner's agreement to the authority's terms"
    expect_status "a request without it is refused" 409 POST /api/certificate/request '{}'
    check "in words" body_has 'needs your agreement'

    echo "What fails with the test authority gets no real certificate"
    start_standin a-key-made-later
    expect_status "a request, with the key withdrawn at Zone.eu" 202 POST /api/certificate/request '{"agreeToTerms":true}'
    if wait_for 120 certificate_idle; then pass "the attempt ended"; else fail "the attempt is still running"; fi
    check "it failed, and says why" sh -c "grep -q '\"ok\":false' /tmp/sgc-test-body && grep -q 'Zone.eu does not accept the username and API key' /tmp/sgc-test-body"
    check "there is still no certificate" body_has '"certificate":null'
    expect_in_audit "the failure is in the history" '"action":"certificate.failed"'
    output="$(sudo sgc doctor 2>&1)"
    code=$?
    if [ "$code" -ne 0 ] && grep -q 'FAIL  No certificate yet, and the last attempt failed: Zone.eu does not accept' <<<"$output"; then
        pass "the doctor reports it as a problem"
    else
        fail "the doctor does not report the failed attempt (exit code $code)"
        indent <<<"$output"
    fi

    echo "The first certificate"
    start_standin "$zone_key"
    expect_status "the request is accepted (the agreement was given before)" 202 POST /api/certificate/request '{}'
    check "it starts with the test authority" body_has '"phase":"trial"'
    if wait_for 180 certificate_idle; then pass "the attempt ended"; else fail "the attempt is still running"; fi
    check "it worked" sh -c "grep -q '\"lastAttempt\":{\"kind\":\"first\"' /tmp/sgc-test-body && grep -q '\"ok\":true' /tmp/sgc-test-body"
    check "the certificate is for every name under the domain" body_has '"names":\["\*\.domain\.tld"\]'
    check "and for the domain that is set up" body_has '"forDomain":true'
    check "SGC says when it will renew it" sh -c "! grep -q '\"renewsAt\":null' /tmp/sgc-test-body"
    check "between the trial and the real request it waited" body_has 'before asking for the real certificate'
    check "and each time it waited for name servers further away" body_has 'more, for name servers further away'
    check "the answer carries no key" sh -c "! grep -q 'PRIVATE KEY' /tmp/sgc-test-body"
    first_serial="$(certificate_serial)"
    check "the proof was removed from the zone again" no_records_left
    expect_in_audit "the certificate is in the history" '"action":"certificate.issued"'
    check "the owner's agreement is in the history too" body_has '"action":"certificate.terms_agreed"'
    check "SGC's log holds no private key" log_has_no_private_key
    check "nor the Zone.eu key" log_lacks_the_key
    output="$(sudo sgc doctor 2>&1)"
    if grep -q 'ok    The certificate for \*\.domain\.tld is valid for [0-9]* more days, and SGC renews it by itself' <<<"$output"; then pass "the doctor says that the certificate is valid"; else
        fail "the doctor does not say that the certificate is valid"
        indent <<<"$output"
    fi

    echo "Renewed from the page"
    expect_status "renewing now" 202 POST /api/certificate/request '{}'
    check "without a trial this time" body_has '"phase":"real"'
    if wait_for 120 certificate_idle; then pass "the attempt ended"; else fail "the attempt is still running"; fi
    check "it worked" sh -c "grep -q '\"lastAttempt\":{\"kind\":\"manual\"' /tmp/sgc-test-body && grep -q '\"ok\":true' /tmp/sgc-test-body"
    check "the certificate is a new one" serial_differs_from "$first_serial"
    certificate_serial >"$serial_file"
    check "the proof was removed again" no_records_left
    expect_in_audit "the renewal is in the history" '"action":"certificate.renewed"'
    check "no unit of SGC's is marked as failed" sh -c "[ -z \"\$(systemctl list-units --failed --plain --no-legend 'sgc*')\" ]"
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
    echo "A setting for the export to carry: the maintenance window"
    expect_status "the window's state is available" 200 GET /api/maintenance
    check "it is off until switched on" body_has '"enabled":false'
    # Hours from now, so that nothing happens in it during this test or on
    # the machine the export is restored to.
    expect_status "switched on, for some hours from now" 200 POST /api/maintenance \
        "{\"enabled\":true,\"start\":\"$(hour '+5 hours')\",\"end\":\"$(hour '+6 hours')\"}"
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
    # The export carries a domain and a (made-up) Zone.eu key. SGC is pointed
    # at the stand-in before the export is restored, so that it never asks
    # the real Zone.eu about them.
    if point_at_standin; then pass "SGC is pointed at the stand-in for Zone.eu"; else without_standin; fi

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

    echo "AdGuard Home came with the installer, and the owner's settings went into it by themselves"
    if wait_for 90 dns_state_has '"restorePending":false'; then pass "the DNS part of the restore is done, without a click"; else fail "the DNS part of the restore is still waiting"; fi
    check "DNS is on and running, as on the old machine" sh -c "grep -q '\"enabled\":true' /tmp/sgc-test-body && grep -q '\"running\":true' /tmp/sgc-test-body"
    expect_in_audit "what was done is in the history" '"action":"dns.restored"'
    if wait_for 60 resolves 127.0.0.1 debian.org; then pass "it answers"; else fail "it does not answer"; fi
    if wait_for 30 is_blocked 127.0.0.1 "$blocked_by_owner"; then pass "the rule the owner made on the old machine is in force here"; else fail "the owner's rule did not travel"; fi
    expect_status "its settings can be read through SGC" 200 GET /adguard/control/dns_info
    check "it still asks Quad9" body_has 'https://dns.quad9.net/dns-query'

    echo "The domain and the Zone.eu account came back, key included"
    expect_status "the state is available" 200 GET /api/domain
    check "the domain and the account are there" sh -c "grep -q '\"configured\":true' /tmp/sgc-test-body && grep -q '\"domain\":\"domain.tld\"' /tmp/sgc-test-body && grep -q '\"username\":\"$zone_user\"' /tmp/sgc-test-body"
    expect_status "asking Zone.eu with the key that came in the export" 200 POST /api/domain/check '{}'
    check "it is accepted" body_has '"ok":true'

    echo "The certificate came back with its key; no new one was asked for"
    expect_status "the state is available" 200 GET /api/certificate
    check "the certificate is the very one from the old machine" body_has "\"serial\":\"$(cat "$serial_file")\""
    check "and is for the domain that is set up" body_has '"forDomain":true'
    check "no attempt was made on this machine" body_has '"lastAttempt":null'
    check "the certificate's key is in SGC's database" sudo sh -c "grep -qa 'PRIVATE KEY' /var/lib/sgc/sgc.db /var/lib/sgc/sgc.db-wal 2>/dev/null"

    echo "Logs in memory was on on the old machine; here it waits for the owner"
    expect_status "the state is available" 200 GET /api/log2ram
    check "log2ram is installed here, by the installer" body_has '"installed":true'
    check "the page knows it was on on the old machine" body_has '"wanted":true'
    check "and did not switch it on unasked" body_has '"enabled":false'
    check "log2ram is not part of start-up" sh -c '! systemctl is-enabled --quiet log2ram.service'

    echo "The maintenance window came back as it was set"
    expect_status "the window's state is available" 200 GET /api/maintenance
    check "it is on and hours away, as on the old machine" window_is true false
    check "what belongs to the old machine alone did not travel" body_has '"lastRestart":null'

    echo "How the old machine got its updates is known, and this one is not set up unasked"
    expect_status "the state of the device's updates is available" 200 GET /api/os-updates
    check "on the old machine they installed by themselves" body_has '"wanted":"automatic"'
    check "here nothing has been chosen" body_has '"mode":""'
    check "and SGC has written nothing among apt's settings" sh -c '[ ! -e /etc/apt/apt.conf.d/52sgc-updates ]'

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

    echo "Services, people, the VPN, the proxy, notifications and backups came back"
    expect_status "the services are available" 200 GET /api/services
    check "the web service is there" body_has '"name":"web"'
    check "and the game server" body_has '"name":"game"'
    expect_status "the people are available" 200 GET /api/people
    check "the person with a login is there" body_has '"name":"Lee"'
    if wait_for 180 systemctl is-active --quiet sgc-wireguard.service; then pass "the VPN runs again (its tools were installed for it)"; else
        fail "the VPN does not run on the restored machine"
    fi
    check "with the server's key from the old machine" sh -c "[ -n \"\$(sudo wg show sgc-wg public-key 2>/dev/null)\" ]"
    if wait_for 120 sh -c "ss -Hltn sport = :443 | grep -q ."; then pass "the proxy runs again"; else fail "the proxy does not run on the restored machine"; fi
    expect_status "the backups are available" 200 GET /api/backups
    check "with the backup key's public half" body_has '"hasKey":true'
    check "and switched on" body_has '"enabled":true'
    expect_status "the notifications are available" 200 GET /api/notifications/settings
    check "with ntfy as it was set up" body_has '"topic":"sgc-test-made-up-topic"'
    check "service is running" systemctl is-active --quiet sgc
    check "the database is still private to sgc" sudo sh -c "[ \"\$(stat -c %U:%a /var/lib/sgc/sgc.db)\" = sgc:600 ]"
    check "nothing is left waiting to be restored" sudo sh -c "[ ! -e /var/lib/sgc/restore ]"
    ;;

restart)
    echo "Restarting the machine through SGC"
    expect_status "a restart without confirmation is refused" 400 POST /api/device/restart '{"confirm":false}'
    expect_status "a confirmed restart is accepted" 202 POST /api/device/restart '{"confirm":true}'
    ;;

maintenance)
    echo "The maintenance window"
    boot_id="$(cat /proc/sys/kernel/random/boot_id)"
    expect_status "the state is available" 200 GET /api/maintenance
    check "it is on and hours away, as it was set before the export" window_is true false
    if grep -q '"clockSynchronised":true' /tmp/sgc-test-body; then pass "the machine's clock has been set from the network"; else
        fail "the machine's clock has not been set from the network, so nothing will happen in the window"
    fi
    expect_status "a time that is none is refused" 400 POST /api/maintenance '{"enabled":true,"start":"25:00","end":"05:00"}'
    expect_status "and so is a window without a length" 400 POST /api/maintenance '{"enabled":true,"start":"04:00","end":"04:00"}'
    expect_status "and a request that leaves something out" 400 POST /api/maintenance '{"enabled":true}'

    echo "A restart is needed, and it is not the window's time"
    # What a kernel package's script does.
    sudo touch /run/reboot-required
    echo "linux-image-0.0.0-test-amd64" | sudo tee /run/reboot-required.pkgs >/dev/null
    expect_status "a window some hours from now" 200 POST /api/maintenance \
        "{\"enabled\":true,\"start\":\"$(hour '+2 hours')\",\"end\":\"$(hour '+3 hours')\"}"
    check "the page knows that it is not now" body_has '"inWindow":false'
    check "and that a restart is waiting" body_has '"restartNeeded":true'
    # SGC looks at the window twice a minute.
    sleep 75
    if [ "$(cat /proc/sys/kernel/random/boot_id)" = "$boot_id" ]; then pass "outside the window the machine is left alone"; else fail "the machine restarted outside the window"; fi
    expect_in_audit "the setting is in the history" 'maintenance window: every day from'

    echo "The window opens"
    expect_status "a window around now" 200 POST /api/maintenance \
        "{\"enabled\":true,\"start\":\"$(hour '-1 hour')\",\"end\":\"$(hour '+2 hours')\"}"
    check "the page knows that it is now" body_has '"inWindow":true'
    # From here SGC restarts the machine by itself, within half a minute. This
    # script cannot watch that; Test-Installer.ps1 waits for the machine to go
    # down, and "after-window-restart" looks at what SGC wrote down.
    ;;

after-window-restart)
    echo "It was SGC that restarted the machine, in the window"
    expect_status "the activity log is available" 200 GET /api/audit
    check "the history says so, and for what" body_has '"actor":"system","action":"device.restart","detail":"in the maintenance window, needed by linux-image-0.0.0-test-amd64"'
    expect_status "the window's state is available" 200 GET /api/maintenance
    check "SGC remembers that it restarted the machine" sh -c "! grep -q '\"lastRestart\":null' /tmp/sgc-test-body"
    check "no restart is needed any more" body_has '"restartNeeded":false'
    check "the window is still on" body_has '"enabled":true'
    sleep 45
    uptime_seconds="$(cut -d. -f1 /proc/uptime)"
    if [ "$uptime_seconds" -gt 45 ]; then pass "and it restarted once, not again (up for $uptime_seconds s)"; else fail "the machine restarted again (up for $uptime_seconds s)"; fi
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
    if wait_for 60 resolves 127.0.0.1 debian.org; then pass "AdGuard Home came back by itself and answers"; else fail "AdGuard Home does not answer after the restart"; fi
    check "the owner's rule is still in force" is_blocked 127.0.0.1 "$blocked_by_owner"
    check "the firewall's rules still let DNS in" sh -c "sudo /usr/sbin/nft list table inet sgc | grep -q 'dport 53'"
    expect_status "the state of the device's updates is available" 200 GET /api/os-updates
    check "updates are still set to install by themselves" body_has '"mode":"automatic"'
    check "and the device does so" body_has '"daily":true'
    check "nothing is wrong with that" body_has '"problem":""'
    check "no restart is needed right after one" body_has '"restartNeeded":false'
    expect_status "the certificate's state is available" 200 GET /api/certificate
    check "the certificate is still there after the restart" body_has '"forDomain":true'

    echo "Logs in memory, after the restart"
    check "the logs are in memory" logs_in_memory
    expect_status "the state is available" 200 GET /api/log2ram
    check "the page says so, with nothing waiting" sh -c "grep -q '\"active\":true' /tmp/sgc-test-body && grep -q '\"restartNeeded\":false' /tmp/sgc-test-body && grep -q '\"startFailed\":false' /tmp/sgc-test-body"
    check "log2ram's own unit did not fail" sh -c '! systemctl is-failed --quiet log2ram.service'
    check "the daily write to the disk is scheduled" systemctl is-active --quiet log2ram-daily.timer
    check "writing to the disk works" sudo systemctl reload log2ram.service
    check "the journal takes entries" journal_takes_entries

    echo "The space in memory nearly full"
    sudo dd if=/dev/urandom of="$log_filler" bs=1M count=100 status=none
    check "the page says that it is almost full" log2ram_state_has '"nearlyFull":true'
    check "and what takes the room" body_has '"name":"sgc-test-filler"'
    output="$(sudo sgc doctor 2>&1)"
    if grep -q 'WARN  The logs are in memory, and the space for them is almost full' <<<"$output" && grep -q 'sgc-test-filler (100 MB)' <<<"$output"; then
        pass "the doctor warns, and names what takes the room"
    else
        fail "the doctor does not warn about the nearly full space"
        indent <<<"$output"
    fi
    check "DNS still answers" resolves 127.0.0.1 debian.org
    expect_status "and so does SGC" 200 GET /api/health
    check "the journal still takes entries" journal_takes_entries
    sudo rm -f "$log_filler"
    check "with room again, the page says so" log2ram_state_has '"nearlyFull":false'

    echo "Switched off: in memory until the next restart. And on again"
    expect_status "switching off" 200 POST /api/log2ram/enabled '{"enabled":false}'
    check "off, and still in memory until a restart" sh -c "grep -q '\"enabled\":false' /tmp/sgc-test-body && grep -q '\"active\":true' /tmp/sgc-test-body && grep -q '\"restartNeeded\":true' /tmp/sgc-test-body"
    check "the logs are still in memory" logs_in_memory
    check "the daily write to the disk goes on meanwhile" systemctl is-active --quiet log2ram-daily.timer
    expect_status "switching on again" 200 POST /api/log2ram/enabled '{"enabled":true}'
    check "on and in memory, with nothing waiting" sh -c "grep -q '\"enabled\":true' /tmp/sgc-test-body && grep -q '\"active\":true' /tmp/sgc-test-body && grep -q '\"restartNeeded\":false' /tmp/sgc-test-body"
    check "no unit of SGC's is marked as failed" sh -c "[ -z \"\$(systemctl list-units --failed --plain --no-legend 'sgc*')\" ]"
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
        "SSH accepts keys only, and nobody logs in as root" "The 1 key(s) added in SGC's page are in place for the account tester" \
        "Updates for the device install by themselves" "AdGuard Home [0-9.]* runs and answers DNS questions" "The logs are in memory ([0-9]* MB of 128 MB used)" \
        "Zone.eu accepted the saved API key for domain.tld when SGC last asked" \
        "The certificate for \*\.domain\.tld is valid for [0-9]* more days, and SGC renews it by itself" \
        "The ports SGC needs, now or later, are free"; do
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
    echo "DNS from the command line"
    check "it says that DNS is on" sh -c "sgc dns | grep -q '^DNS is on: AdGuard Home [0-9.]* is running'"
    check "switching it needs root" sh -c "! sgc dns off 2>/dev/null"
    output="$(sudo sgc dns off 2>&1)"
    if grep -q '^DNS is off' <<<"$output"; then pass "sudo sgc dns off switches it off"; else
        fail "sudo sgc dns off did not"
        indent <<<"$output"
    fi
    check "nothing answers DNS" gets_no_dns_answer 127.0.0.1 debian.org
    output="$(sudo sgc dns on 2>&1)"
    if grep -q '^DNS is on' <<<"$output"; then pass "sudo sgc dns on switches it on"; else
        fail "sudo sgc dns on did not"
        indent <<<"$output"
    fi
    if wait_for 30 resolves 127.0.0.1 debian.org; then pass "and it answers again"; else fail "it does not answer after being switched on"; fi

    echo "The doctor again, with things broken on purpose"
    sudo systemctl stop sgc-adguard
    # Something else on a port a later part of SGC will need.
    sudo python3 -m http.server 80 --bind 127.0.0.1 >/dev/null 2>&1 &
    sleep 1
    output="$(sudo sgc doctor 2>&1)"
    code=$?
    if [ "$code" -ne 0 ] && echo "$output" | grep -q 'FAIL  AdGuard Home [0-9.]* is installed but not running'; then
        pass "a stopped AdGuard Home is reported as a problem"
    else
        fail "the stopped AdGuard Home was not reported (exit code $code)"
        indent <<<"$output"
    fi
    if echo "$output" | grep -q 'sudo systemctl start sgc-adguard'; then pass "it says how to start it"; else fail "it does not say how to start it"; fi
    if echo "$output" | grep -q 'WARN  In use by another program: port 80 (the proxy) by python3'; then pass "a program on a port SGC will need is pointed out"; else
        fail "the taken port was not pointed out"
        indent <<<"$output"
    fi
    sudo pkill -x -f 'python3 -m http.server 80 --bind 127.0.0.1' || true
    sudo systemctl start sgc-adguard
    if wait_for 30 resolves 127.0.0.1 debian.org; then pass "following that advice: AdGuard Home answers again"; else fail "AdGuard Home does not answer after being started"; fi
    printf 'APT::Periodic::Unattended-Upgrade "0";\n' | sudo tee "$overruling_file" >/dev/null
    output="$(sudo sgc doctor 2>&1)"
    code=$?
    if [ "$code" -ne 0 ] && echo "$output" | grep -q 'FAIL  Another settings file on this device overrules what SGC set up for updates (APT::Periodic::Unattended-Upgrade)'; then
        pass "a setting that overrules SGC's choice for updates is reported as a problem"
    else
        fail "the overruling setting was not reported (exit code $code)"
        indent <<<"$output"
    fi
    if echo "$output" | grep -q 'sorts after 52sgc-updates'; then pass "it says where to look"; else fail "it does not say where to look"; fi
    sudo rm -f "$overruling_file"
    sudo systemctl stop apt-daily-upgrade.timer
    output="$(sudo sgc doctor 2>&1)"
    code=$?
    if [ "$code" -ne 0 ] && echo "$output" | grep -q "FAIL  Updates are set to install by themselves, but Debian's daily timers are not running"; then
        pass "a stopped daily timer is reported as a problem"
    else
        fail "the stopped timer was not reported (exit code $code)"
        indent <<<"$output"
    fi
    if echo "$output" | grep -q 'sudo systemctl enable --now apt-daily.timer apt-daily-upgrade.timer'; then pass "it says how to start it"; else fail "it does not say how to start it"; fi
    sudo systemctl enable --now apt-daily.timer apt-daily-upgrade.timer 2>/dev/null
    sudo touch /run/reboot-required
    output="$(sudo sgc doctor 2>&1)"
    code=$?
    if [ "$code" -eq 0 ] && echo "$output" | grep -q 'ok    Updates for the device install by themselves' &&
        echo "$output" | grep -q 'WARN  A restart is needed for an installed update to take effect'; then
        pass "following that advice puts it right, and a restart that is needed is mentioned without being a problem"
    else
        fail "after starting the timer again (exit code $code)"
        indent <<<"$output"
    fi
    sudo rm -f /run/reboot-required
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

names)
    echo "The gateway's own name, in AdGuard Home and on its page"
    expect_status "the names are available" 200 GET /api/names
    check "the gateway is called sgc under the domain" body_has '"fqdn":"sgc.domain.tld"'
    check "SGC knows this device's address in the home network" body_has "\"address\":\"$lan_address\""
    if wait_for 90 answers_with sgc.domain.tld "$lan_address"; then pass "AdGuard Home answers sgc.domain.tld with this device's address"; else
        fail "AdGuard Home does not answer sgc.domain.tld with $lan_address (it says: $(dns_answer 127.0.0.1 sgc.domain.tld))"
    fi
    check "asked for by that name, SGC's page shows the certificate for *.domain.tld" serves_names 8443 sgc.domain.tld '\*\.domain\.tld'
    check "asked for by address, it shows its own certificate" sh -c "! echo | openssl s_client -connect 127.0.0.1:8443 -noservername 2>/dev/null | openssl x509 -noout -ext subjectAltName 2>/dev/null | grep -q domain.tld"
    # A rewrite of the owner's own in AdGuard Home is never touched.
    curl -s -o /dev/null -X POST -H 'Content-Type: application/json' -d '{"domain":"printer.home","answer":"192.168.77.9"}' http://127.0.0.1:3000/control/rewrite/add
    expect_status "a name SGC uses for AdGuard Home's page is refused" 400 POST /api/names/gateway '{"name":"adguard"}'
    expect_status "and one that is not a name" 400 POST /api/names/gateway '{"name":"Not A Name"}'
    expect_status "the gateway can be renamed" 200 POST /api/names/gateway '{"name":"gw"}'
    if wait_for 30 answers_with gw.domain.tld "$lan_address"; then pass "the new name is in AdGuard Home"; else fail "the new name is not in AdGuard Home"; fi
    if wait_for 30 sh -c "! curl -s http://127.0.0.1:3000/control/rewrite/list | grep -q sgc.domain.tld"; then pass "and the old one is gone"; else fail "the old name is still there"; fi
    check "the owner's own rewrite is still there" sh -c "curl -s http://127.0.0.1:3000/control/rewrite/list | grep -q printer.home"
    expect_status "renamed back" 200 POST /api/names/gateway '{"name":"sgc"}'
    wait_for 30 answers_with sgc.domain.tld "$lan_address" || fail "sgc.domain.tld did not come back"
    expect_in_audit "the history has the renaming" '"action":"gateway.renamed"'
    output="$(sudo sgc doctor 2>&1)"
    if echo "$output" | grep -q 'sgc.domain.tld points at this device'; then pass "the doctor sees the name in place"; else
        fail "the doctor does not see the name"
        indent <<<"$output"
    fi
    ;;

proxy)
    echo "The proxy: installed with SGC and off until switched on"
    expect_status "the proxy's state is available" 200 GET /api/proxy
    if [ -e /opt/sgc/components/traefik/current/traefik ]; then
        check "it is off" body_has '"wanted":false'
        check "nothing listens on port 443 yet" sh -c "! ss -Hltn sport = :443 | grep -q ."
        traefik_from_start=true
    else
        # A machine updated from a version that did not install it.
        traefik_from_start=false
    fi
    neighbour "$inside_net" "$inside_gateway" "$inside_peer" || fail "the home neighbour could not be set up"
    start_web_neighbour
    expect_status "a web service is added by hand" 200 POST /api/services \
        "{\"name\":\"web\",\"title\":\"Web\",\"kind\":\"http\",\"mode\":\"proxied\",\"upstreamIp\":\"$inside_peer\",\"upstreamPort\":8080,\"scheme\":\"http\",\"verifyTls\":false,\"listenPort\":0,\"category\":\"Test\",\"protected\":false,\"enabled\":true}"
    expect_status "one pointing outside the home network is refused" 400 POST /api/services \
        '{"name":"outside","title":"","kind":"http","mode":"proxied","upstreamIp":"203.0.113.2","upstreamPort":80,"scheme":"http","verifyTls":false,"listenPort":0,"category":"","protected":false,"enabled":true}'
    expect_status "switching the proxy on" 200 POST /api/proxy/enabled '{"enabled":true}'
    check "it is on and running" sh -c "grep -q '\"wanted\":true' /tmp/sgc-test-body && grep -q '\"running\":true' /tmp/sgc-test-body"
    if [ "$traefik_from_start" = false ]; then check "switching on installed Traefik" test -x /opt/sgc/components/traefik/current/traefik; fi
    check "Traefik runs under its own account" sh -c "[ \"\$(ps -o user= -C traefik | head -1)\" = sgc-traefik ]"
    check "the key of the certificate is Traefik's and root's only" sh -c "[ \"\$(sudo stat -c '%U:%G %a' /etc/sgc/traefik/certs/wildcard.key)\" = 'root:sgc-traefik 640' ]"
    check "SGC's own account cannot read it" sh -c "! sudo -u sgc cat /etc/sgc/traefik/certs/wildcard.key >/dev/null 2>&1"
    check "web.domain.tld opens the service through the proxy" through_proxy web '/' 'served by the test neighbour'
    check "the proxy shows the certificate for *.domain.tld" serves_names 443 web.domain.tld '\*\.domain\.tld'
    check "plain http is sent on to https" sh -c "curl -s -o /dev/null -w '%{http_code} %{redirect_url}' --resolve web.domain.tld:80:127.0.0.1 http://web.domain.tld/x | grep -qE '^30[18] https://web.domain.tld/x'"
    check "the gateway's own name sends you to SGC's page" sh -c "curl -sk -o /dev/null -w '%{http_code} %{redirect_url}' --resolve sgc.domain.tld:443:127.0.0.1 https://sgc.domain.tld/system | grep -q '^302 https://sgc.domain.tld:8443/system'"
    check "a name SGC does not know gets SGC's page saying so" through_proxy nothing '/' 'No service by this name'
    if wait_for 90 answers_with web.domain.tld "$lan_address"; then pass "AdGuard Home answers web.domain.tld with this device's address"; else fail "web.domain.tld is not in AdGuard Home"; fi
    check "AdGuard Home's page has a name too" answers_with adguard.domain.tld "$lan_address"
    echo "A service that stops answering"
    sudo systemctl stop sgc-test-web.service
    check "the proxy answers with SGC's friendly page" through_proxy web '/' 'Not reachable right now'
    if wait_for 90 service_state_is web down; then pass "the page shows it as down"; else fail "the service is not shown as down"; fi
    start_web_neighbour
    if wait_for 90 service_state_is web up; then pass "and as up again once it answers"; else fail "the service is not shown as up again"; fi
    echo "What the root side refuses, whatever the web process sends"
    if [ "$(helper_status /v1/proxy/apply '{"enabled":true,"domain":"domain.tld","gatewayName":"sgc","webPort":8443,"certificatePem":"x","privateKeyPem":"y","services":[]}')" = 400 ]; then
        pass "a configuration without a valid certificate"
    else fail "the helper took a configuration without a valid certificate"; fi
    echo "A game server, through a port of the gateway"
    start_tcp_neighbour 25565
    expect_status "a proxied TCP service is added" 200 POST /api/services \
        "{\"name\":\"game\",\"title\":\"\",\"kind\":\"tcp\",\"mode\":\"proxied\",\"upstreamIp\":\"$inside_peer\",\"upstreamPort\":25565,\"scheme\":\"http\",\"verifyTls\":false,\"listenPort\":25565,\"category\":\"Test\",\"protected\":false,\"enabled\":true}"
    if wait_for 60 sh -c "ss -Hltn sport = :25565 | grep -q ."; then pass "the gateway listens on port 25565"; else fail "the gateway does not listen on 25565"; fi
    check "a connection there reaches the game server" sh -c "timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/25565; read -r line <&3; [ \"\$line\" = hello-from-the-game ]'"
    expect_status "a second service on the same port is refused" 400 POST /api/services \
        "{\"name\":\"game2\",\"title\":\"\",\"kind\":\"tcp\",\"mode\":\"proxied\",\"upstreamIp\":\"$inside_peer\",\"upstreamPort\":25566,\"scheme\":\"http\",\"verifyTls\":false,\"listenPort\":25565,\"category\":\"\",\"protected\":false,\"enabled\":true}"
    expect_status "a direct one is added" 200 POST /api/services \
        "{\"name\":\"voice\",\"title\":\"\",\"kind\":\"udp\",\"mode\":\"direct\",\"upstreamIp\":\"$inside_peer\",\"upstreamPort\":9987,\"scheme\":\"http\",\"verifyTls\":false,\"listenPort\":0,\"category\":\"\",\"protected\":false,\"enabled\":true}"
    if wait_for 90 answers_with voice.domain.tld "$inside_peer"; then pass "its name points at the device itself"; else fail "voice.domain.tld does not point at $inside_peer"; fi
    if firewall_is on; then
        echo "The firewall's rules follow"
        expect_status "the firewall's state is available" 200 GET /api/firewall
        check "it says its rules lag behind the proxy" body_has 'the proxy (ports 80 and 443)'
        check "and the game's port" body_has 'port 25565/tcp'
        check "the home neighbour does not get through to the proxy yet" does_not_reach "$inside_net" "$inside_gateway" 443
        expect_status "bringing the rules up to date" 202 POST /api/firewall/change '{"enabled":true,"again":true}'
        expect_status "confirmed" 200 POST /api/firewall/confirm '{}'
        check "the home neighbour reaches the proxy" reaches "$inside_net" "$inside_gateway" 443
        check "and the game" reaches "$inside_net" "$inside_gateway" 25565
        expect_status "the firewall's state is available" 200 GET /api/firewall
        check "nothing lags behind any more" body_has '"behind":\[\]'
    fi
    output="$(sudo sgc doctor 2>&1)"
    if echo "$output" | grep -q 'The proxy runs: Traefik'; then pass "the doctor sees the proxy running"; else
        fail "the doctor does not see the proxy"
        indent <<<"$output"
    fi
    expect_in_audit "the history has the proxy switched on" '"action":"proxy.switched_on"'
    ;;

announce)
    echo "A server announces its services with a token"
    neighbour "$inside_net" "$inside_gateway" "$inside_peer" || fail "the home neighbour could not be set up"
    start_web_neighbour
    expect_status "a token is made" 200 POST /api/tokens '{"label":"media server"}'
    token="$(grep -o '"secret":"[^"]*"' /tmp/sgc-test-body | cut -d'"' -f4)"
    check "the token is in that answer" test -n "$token"
    expect_status "the list of tokens is available" 200 GET /api/tokens
    check "but not the token itself" sh -c "! grep -q '$token' /tmp/sgc-test-body"
    answer="$(announce_from "$inside_net" "https://$inside_gateway:8443" "$token" -d service=media:8080 -d category=Media)"
    if [[ "$answer" == *"media: https://media.domain.tld"* ]]; then pass "the announcement is taken up"; else fail "the announcement: $answer"; fi
    check "the service has the server's address, taken from the connection" service_has media "\"upstreamIp\":\"$inside_peer\""
    check "and the token's name" service_has media '"tokenLabel":"media server"'
    if wait_for 60 through_proxy media '/' 'served by the test neighbour'; then pass "it opens by its name at once"; else fail "media.domain.tld does not open"; fi
    answer="$(announce_from "$inside_net" "https://$inside_gateway:8443" "$token" -d service=web:8080)"
    if [[ "$answer" == *"web: refused"* ]]; then pass "a name added in the page is not taken over"; else fail "a taken name: $answer"; fi
    answer="$(announce_from "$inside_net" "https://$inside_gateway:8443" "sgc_made-up" -d service=x:80)"
    if [[ "$answer" == *"does not know this token"* ]]; then pass "a made-up token is refused"; else fail "a made-up token: $answer"; fi
    answer="$(curl -sk -H "Authorization: Bearer $token" -d service=media:8080 "$api/api/announce")"
    if [[ "$answer" == *"belongs to the server at $inside_peer"* ]]; then pass "the token is refused from another address"; else fail "from another address: $answer"; fi
    echo "Through the proxy, the address comes from the connection, not from the request"
    if firewall_is on || true; then
        answer="$(sudo ip netns exec "$inside_net" curl -sk --resolve "sgc.domain.tld:443:$inside_gateway" -H "Authorization: Bearer $token" \
            -H 'X-Forwarded-For: 192.168.77.99' -d service=media:8081 https://sgc.domain.tld/api/announce)"
        if [[ "$answer" == *"media: https://media.domain.tld"* ]]; then pass "an announcement through the proxy is taken up"; else fail "through the proxy: $answer"; fi
        check "the address that pretended otherwise was not used" service_has media "\"upstreamIp\":\"$inside_peer\""
        check "the new port was" service_has media '"upstreamPort":8081'
    fi
    expect_in_audit "the history has the announcement" '"action":"service.announced"'
    expect_in_audit "and the refused one" '"action":"token.refused"'
    tokens_id="$(http GET /api/tokens >/dev/null; grep -o '"id":[0-9]*' /tmp/sgc-test-body | head -1 | cut -d: -f2)"
    expect_status "the token is removed, its services switched off" 200 POST "/api/tokens/$tokens_id/remove" '{"keep":false}'
    check "the service is off" service_has media '"enabled":false'
    answer="$(announce_from "$inside_net" "https://$inside_gateway:8443" "$token" -d service=media:8080)"
    if [[ "$answer" == *"does not know this token"* ]]; then pass "the removed token no longer works"; else fail "a removed token: $answer"; fi
    ;;

vpn)
    echo "The VPN: off until switched on"
    if ! neighbour "$outside_net" "$outside_gateway" "$outside_peer" || ! neighbour "$inside_net" "$inside_gateway" "$inside_peer"; then
        fail "the stand-in neighbours could not be set up"
    fi
    start_web_neighbour
    expect_status "the VPN's state is available" 200 GET /api/vpn
    check "it is off" body_has '"enabled":false'
    check "nothing listens on its port" sh -c "! ss -Hlun sport = :51820 | grep -q ."
    expect_status "switching it on (WireGuard's tools come from Debian)" 200 POST /api/vpn/settings \
        '{"enabled":true,"port":51820,"network":"10.86.0.0/24","name":"vpn","endpointMode":"dynamic","staticIp":""}'
    check "its program runs" systemctl is-active --quiet sgc-wireguard.service
    check "WireGuard listens on UDP port 51820" sh -c "ss -Hlun sport = :51820 | grep -q ."
    check "the VPN's own firewall table is loaded" sudo /usr/sbin/nft list table inet sgc_vpn
    check "the kernel passes packets on" sh -c "[ \"\$(cat /proc/sys/net/ipv4/ip_forward)\" = 1 ]"
    if wait_for 90 sh -c "curl -s -u '$zone_user:$zone_key' http://$zone_address/v2/dns/domain.tld/a | grep -q 203.0.113.7"; then
        pass "the public name points at the home's public address, at (the stand-in for) Zone.eu"
    else fail "no A record for vpn.domain.tld at the stand-in"; fi
    if wait_for 90 answers_with vpn.domain.tld "$lan_address"; then pass "inside the home network the name points at this device"; else
        fail "vpn.domain.tld does not point at $lan_address in AdGuard Home"
    fi
    if firewall_is on; then
        expect_status "the firewall's state is available" 200 GET /api/firewall
        check "it says the VPN's port is not let in yet" body_has 'the VPN (port 51820/udp'
        expect_status "bringing the rules up to date" 202 POST /api/firewall/change '{"enabled":true,"again":true}'
        expect_status "confirmed" 200 POST /api/firewall/confirm '{}'
        check "the rules let the VPN's port in from anywhere" sh -c "sudo /usr/sbin/nft list table inet sgc | grep -q 'udp dport 51820 accept'"
    fi

    echo "A person who reaches one service, with a phone"
    web_id="$(service_id web)"
    expect_status "a second web service that is not on the person's list" 200 POST /api/services \
        "{\"name\":\"other\",\"title\":\"\",\"kind\":\"http\",\"mode\":\"proxied\",\"upstreamIp\":\"$inside_peer\",\"upstreamPort\":8080,\"scheme\":\"http\",\"verifyTls\":false,\"listenPort\":0,\"category\":\"\",\"protected\":false,\"enabled\":true}"
    expect_status "the person is added" 200 POST /api/people \
        "{\"name\":\"Kim\",\"network\":\"services\",\"allServices\":false,\"serviceIds\":[$web_id],\"loginEnabled\":false,\"username\":\"\",\"password\":\"\",\"expiresAt\":null,\"disabled\":false}"
    person_id="$(json_get "d['id']")"
    expect_status "a phone is added" 200 POST /api/vpn/devices "{\"personId\":$person_id,\"name\":\"phone\",\"allTraffic\":false,\"enabled\":true}"
    device_id="$(json_get "d['id']")"
    expect_status "its QR code needs the admin's password" 403 POST "/api/vpn/devices/$device_id/config" '{"password":"not the password"}'
    device_config "$device_id" >/tmp/sgc-phone.conf || fail "the phone's settings were not handed out"
    check "the settings name the public name" grep -q '^Endpoint = vpn.domain.tld:51820' /tmp/sgc-phone.conf
    check "and the gateway for DNS" grep -q '^DNS = 10.86.0.1' /tmp/sgc-phone.conf
    expect_in_audit "showing them is in the history" '"action":"device.revealed"'
    if phone_up /tmp/sgc-phone.conf; then pass "the phone sets up its tunnel"; else fail "the phone's tunnel could not be set up"; fi
    if wait_for 30 phone_gets "https://web.domain.tld/" 'served by the test neighbour'; then pass "through the tunnel the phone opens the service on its list"; else
        fail "the phone does not get web.domain.tld through the tunnel"
    fi
    if wait_for 30 device_connected; then pass "the page shows the phone as connected"; else fail "the phone is not shown as connected"; fi
    check "the gateway answers its DNS questions through the tunnel" answers_at 10.86.0.1 web.domain.tld "$phone_net" "$lan_address"
    check "a service not on the list is refused" sh -c "! sudo ip netns exec $phone_net curl -sk --max-time 8 --resolve other.domain.tld:443:$lan_address https://other.domain.tld/ | grep -q 'served by the test neighbour'"
    check "SGC's page is not reachable through the tunnel" does_not_reach "$phone_net" "$lan_address" 8443
    check "nor SSH" does_not_reach "$phone_net" "$lan_address" 22
    echo "Changed to the whole home network"
    expect_status "the person is changed" 200 POST "/api/people/$person_id" \
        "{\"name\":\"Kim\",\"network\":\"full\",\"allServices\":true,\"serviceIds\":[],\"loginEnabled\":false,\"username\":\"\",\"password\":\"\",\"expiresAt\":null,\"disabled\":false}"
    if wait_for 30 reaches "$phone_net" "$lan_address" 8443; then pass "now SGC's page is reachable through the tunnel"; else fail "SGC's page is still out of reach"; fi
    # The VPN's rules change first; the proxy's list of who may open the
    # service follows a moment later (it waits for Traefik to take it up).
    if wait_for 30 phone_gets "https://other.domain.tld/" 'served by the test neighbour'; then pass "and the other service"; else
        fail "the other service is still out of reach"
    fi
    echo "A guest whose time ran out"
    expect_status "the person gets an end date in the past" 200 POST "/api/people/$person_id" \
        "{\"name\":\"Kim\",\"network\":\"full\",\"allServices\":true,\"serviceIds\":[],\"loginEnabled\":false,\"username\":\"\",\"password\":\"\",\"expiresAt\":\"2020-01-01T00:00:00Z\",\"disabled\":false}"
    if wait_for 30 sh -c "! sudo wg show sgc-wg peers | grep -q ."; then pass "the phone's key is no longer in WireGuard"; else fail "the expired guest's phone is still in"; fi
    check "and the phone gets nothing any more" sh -c "! sudo ip netns exec $phone_net curl -sk --max-time 5 --resolve web.domain.tld:443:$lan_address https://web.domain.tld/ | grep -q served"
    phone_down
    expect_status "the person is removed, with the phone" 200 POST "/api/people/$person_id/remove" '{}'
    output="$(sudo sgc doctor 2>&1)"
    if echo "$output" | grep -q 'The VPN runs and listens on UDP port 51820'; then pass "the doctor sees the VPN"; else
        fail "the doctor does not see the VPN"
        indent <<<"$output"
    fi
    ;;

gate)
    echo "SGC's login in front of a service"
    start_web_neighbour
    web_id="$(service_id web)"
    expect_status "the web service is put behind SGC's login" 200 POST "/api/services/$web_id" \
        "{\"name\":\"web\",\"title\":\"Web\",\"kind\":\"http\",\"mode\":\"proxied\",\"upstreamIp\":\"$inside_peer\",\"upstreamPort\":8080,\"scheme\":\"http\",\"verifyTls\":false,\"listenPort\":0,\"category\":\"Test\",\"protected\":true,\"enabled\":true}"
    gate_jar="$HOME/sgc-test-gate-cookies"
    rm -f "$gate_jar"
    gcurl() { curl -sk --max-time 10 -b "$gate_jar" -c "$gate_jar" --resolve web.domain.tld:443:127.0.0.1 --resolve sgc.domain.tld:8443:127.0.0.1 "$@"; }
    if wait_for 30 sh -c "curl -sk -o /dev/null -w '%{http_code}' --resolve web.domain.tld:443:127.0.0.1 https://web.domain.tld/ | grep -q 302"; then
        pass "without a pass the service sends you to SGC's sign-in"
    else fail "the protected service did not send to the sign-in"; fi
    check "to SGC's own name, with the way back" sh -c "curl -sk -o /dev/null -w '%{redirect_url}' --resolve web.domain.tld:443:127.0.0.1 'https://web.domain.tld/a?b=1' | grep -q '^https://sgc.domain.tld:8443/gate?rd=https%3A%2F%2Fweb.domain.tld%2Fa%3Fb%3D1'"
    expect_status "a person with a login that has the service" 200 POST /api/people \
        "{\"name\":\"Sam\",\"network\":\"services\",\"allServices\":false,\"serviceIds\":[$web_id],\"loginEnabled\":true,\"username\":\"sam\",\"password\":\"a-made-up-password\",\"expiresAt\":null,\"disabled\":false}"
    sam_id="$(json_get "d['id']")"
    expect_status "and one whose login does not" 200 POST /api/people \
        '{"name":"Lee","network":"services","allServices":false,"serviceIds":[],"loginEnabled":true,"username":"lee","password":"another-made-up-password","expiresAt":null,"disabled":false}'
    gcurl -o /dev/null -X POST -H 'Content-Type: application/json' -d '{"username":"sam","password":"wrong-password-here"}' https://sgc.domain.tld:8443/api/gate/login
    check "a wrong password is refused" sh -c "! grep -q sgc_person '$gate_jar' 2>/dev/null"
    gcurl -o /dev/null -X POST -H 'Content-Type: application/json' -d '{"username":"sam","password":"a-made-up-password"}' https://sgc.domain.tld:8443/api/gate/login
    check "the right one signs Sam in" grep -q sgc_person "$gate_jar"
    back="$(gcurl -X POST -H 'Content-Type: application/json' -d '{"rd":"https://web.domain.tld/"}' https://sgc.domain.tld:8443/api/gate/ticket | python3 -c 'import json,sys; print(json.load(sys.stdin).get("redirect",""))')"
    check "SGC hands out the way back to the service" sh -c "echo '$back' | grep -q '^https://web.domain.tld/.sgc-gate/return?ticket='"
    gcurl -o /dev/null "$back"
    check "the service's name gets its own pass" grep -q 'web.domain.tld.*sgc_gate' "$gate_jar"
    check "with it Sam gets in" sh -c "curl -sk --max-time 10 -b '$gate_jar' --resolve web.domain.tld:443:127.0.0.1 https://web.domain.tld/ | grep -q 'served by the test neighbour'"
    check "the way back works once" sh -c "[ \"\$(curl -sk -o /dev/null -w '%{http_code}' --resolve web.domain.tld:443:127.0.0.1 '$back')\" = 403 ]"
    check "a way back to another site is refused" sh -c "curl -sk -b '$gate_jar' --resolve sgc.domain.tld:8443:127.0.0.1 -X POST -H 'Content-Type: application/json' -d '{\"rd\":\"https://evil.example.com/\"}' https://sgc.domain.tld:8443/api/gate/ticket | grep -q 'not a service behind'"
    rm -f "$gate_jar"
    gcurl -o /dev/null -X POST -H 'Content-Type: application/json' -d '{"username":"lee","password":"another-made-up-password"}' https://sgc.domain.tld:8443/api/gate/login
    check "Lee, whose login does not have the service, gets no way back" sh -c "curl -sk -b '$gate_jar' --resolve sgc.domain.tld:8443:127.0.0.1 -X POST -H 'Content-Type: application/json' -d '{\"rd\":\"https://web.domain.tld/\"}' https://sgc.domain.tld:8443/api/gate/ticket | grep -q 'does not include'"
    check "and a person's sign-in does not open SGC's own page" sh -c "[ \"\$(curl -sk -o /dev/null -w '%{http_code}' -b '$gate_jar' --resolve sgc.domain.tld:8443:127.0.0.1 https://sgc.domain.tld:8443/api/health)\" = 401 ]"
    expect_in_audit "the history has Sam passing" '"action":"gate.login"'
    expect_status "the service comes out from behind the login again" 200 POST "/api/services/$web_id" \
        "{\"name\":\"web\",\"title\":\"Web\",\"kind\":\"http\",\"mode\":\"proxied\",\"upstreamIp\":\"$inside_peer\",\"upstreamPort\":8080,\"scheme\":\"http\",\"verifyTls\":false,\"listenPort\":0,\"category\":\"Test\",\"protected\":false,\"enabled\":true}"
    http POST "/api/people/$sam_id/remove" '{}' >/dev/null
    ;;

notify)
    echo "Notifications and the logs"
    expect_status "the bell is available" 200 GET /api/notifications/summary
    expect_status "ntfy is set up (a stand-in on this machine)" 200 POST /api/notifications/settings \
        '{"email":{"enabled":false,"host":"","port":587,"security":"starttls","username":"","from":"","to":""},"ntfy":{"enabled":true,"server":"http://127.0.0.1:9400","topic":"sgc-test-made-up-topic","token":"tk_madeup"},"routes":{}}'
    check "the token is not shown again" sh -c "! grep -q tk_madeup /tmp/sgc-test-body"
    expect_status "a test message" 200 POST /api/notifications/test '{"channel":"ntfy"}'
    if wait_for 10 ntfy_got 'A test from SGC'; then pass "it reached ntfy, with the token"; else fail "ntfy got no test message"; fi
    check "with the topic and the token" sh -c "sudo grep -q 'Bearer tk_madeup.*sgc-test-made-up-topic' $standin_state/ntfy.log"
    echo "        (stopping a service and waiting for the notification: a few minutes)"
    # The proxy step stops the same service, and the bell may still have
    # that warning, from before ntfy was set up: first let it end, then
    # wait for the banner, which shows only what is going on now (the bell
    # also lists what is over).
    if ! wait_for 150 banner_gone 'does not answer'; then fail "a banner from an earlier step did not go"; fi
    sudo systemctl stop sgc-test-web.service
    if wait_for 300 banner_has 'does not answer'; then pass "a service that stops answering shows as a banner"; else fail "no banner about the stopped service"; fi
    if wait_for 60 ntfy_got 'does not answer'; then pass "and was sent to ntfy"; else fail "it did not reach ntfy"; fi
    check "and is in the bell" notified 'does not answer'
    start_web_neighbour
    if wait_for 300 banner_gone 'does not answer'; then pass "once it answers again the banner goes"; else fail "the banner stayed"; fi
    expect_status "the logs of SGC" 200 POST /api/logs '{"part":"sgc","priority":6,"sinceSeconds":3600,"text":"","limit":50,"after":""}'
    check "have entries" test "$(json_get 'len(d["entries"])')" -gt 0
    through_proxy web '/' 'served' || true
    expect_status "the proxy's log, for one service" 200 POST /api/logs '{"part":"proxy","priority":6,"sinceSeconds":3600,"text":"http-web","limit":50,"after":""}'
    check "has its requests" body_has 'http-web@file'
    expect_status "a part SGC does not know is refused" 400 POST /api/logs '{"part":"../../etc","priority":6,"sinceSeconds":3600,"text":"","limit":50,"after":""}'
    ;;

backups)
    echo "Backups to another device (a stand-in WebDAV folder)"
    expect_status "the state of backups is available" 200 GET /api/backups
    check "nothing is set up" body_has '"hasKey":false'
    expect_status "switching on without a backup key is refused" 400 POST /api/backups/settings \
        '{"enabled":true,"target":{"kind":"webdav","host":"","port":0,"share":"","path":"","url":"http://127.0.0.1:9300/","username":"","hostKey":"","skipVerify":false},"time":"03:30","keep":2,"publicKey":"","since":"0001-01-01T00:00:00Z"}'
    password="$(cat "$password_file")"
    expect_status "the backup key is made, after the admin's password" 200 POST /api/backups/key "{\"password\":\"$password\"}"
    check "its secret half is shown" body_has 'AGE-SECRET-KEY-1'
    json_get "d['secret']" >"$HOME/sgc-test-backup-key"
    expect_status "the target is tested" 200 POST /api/backups/test \
        '{"kind":"webdav","host":"","port":0,"share":"","path":"","url":"http://127.0.0.1:9300/","username":"","hostKey":"","skipVerify":false}'
    check "and reached" body_has '"ok":true'
    expect_status "backups are switched on" 200 POST /api/backups/settings \
        '{"enabled":true,"target":{"kind":"webdav","host":"","port":0,"share":"","path":"","url":"http://127.0.0.1:9300/","username":"","hostKey":"","skipVerify":false},"time":"03:30","keep":2,"publicKey":"","since":"0001-01-01T00:00:00Z"}'
    for i in 1 2 3; do
        expect_status "a backup is made now ($i)" 200 POST /api/backups/run '{}'
        sleep 1
    done
    check "the newest two are on the target" sh -c "[ \"\$(sudo ls $standin_state/webdav | grep -c '^sgc-backup-.*\.age$')\" = 2 ]"
    check "they are encrypted" sh -c "sudo head -c 22 \"$standin_state/webdav/\$(sudo ls $standin_state/webdav | tail -1)\" | grep -q 'age-encryption.org/v1'"
    check "SGC does not keep the secret half" sh -c "! sudo grep -rq \"\$(cut -c1-40 $HOME/sgc-test-backup-key)\" /var/lib/sgc"
    output="$(sudo sgc doctor 2>&1)"
    if echo "$output" | grep -q 'The last backup to another device was made'; then pass "the doctor sees the backup"; else
        fail "the doctor does not see the backup"
        indent <<<"$output"
    fi
    expect_in_audit "the history has it" '"action":"backup.made"'
    ;;

*)
    echo "unknown mode: $mode"
    exit 2
    ;;
esac

echo
if [ "$failures" -eq 0 ]; then echo "ALL CHECKS PASSED ($mode)"; else echo "$failures CHECK(S) FAILED ($mode)"; fi
exit "$failures"
