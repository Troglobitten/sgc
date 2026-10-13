# SGC — Server Gateway Control

A secure front door for your home network, running on a Raspberry Pi or any small Debian machine.

> **Status: early development.** The installer, the admin account, a dashboard with system health, self-updating, export and restore, the device's firewall, SSH keys with "keys only", updates for the device, a maintenance window and DNS (AdGuard Home) work. VPN and the reverse proxy are not built yet.

## What it will do

- **VPN** — WireGuard access to your network, with per-person access rules and QR codes for phones.
- **DNS** — AdGuard Home for the whole network and for VPN devices.
- **Reverse proxy** — every service on your network gets `service.yourdomain.tld` with a Let's Encrypt certificate, without being exposed to the internet.
- **Dashboard** — system health, service status, updates and end-of-life warnings in one place.
- **Export / import** — one file restores the whole setup on a fresh device.

SGC does not implement VPN, DNS or proxying itself. It installs and configures WireGuard, AdGuard Home, Traefik and nftables, and keeps their configuration in one place.

## Requirements (planned)

- Debian 13 or Raspberry Pi OS based on it, 64-bit (arm64 or amd64)
- A domain whose DNS is hosted at Zone.eu

## Installation

On a clean Debian 13 or Raspberry Pi OS (64-bit) machine:

```sh
curl -fsSL https://github.com/Troglobitten/sgc/releases/latest/download/install.sh | sudo bash
```

The installer checks the machine, downloads the release, and installs it only if the download carries a valid signature from the SGC release key. To read the script before running it, download it first:

```sh
curl -fsSLO https://github.com/Troglobitten/sgc/releases/latest/download/install.sh
less install.sh
sudo bash install.sh
```

It then has SGC install AdGuard Home, the DNS server, and start it (see [DNS](#dns-adguard-home) below). At the end the installer prints a one-time link. Open it in a browser on your network to create the admin account; you then land on the dashboard. Until SGC has a certificate from Let's Encrypt (a later milestone) it uses a self-signed one, so the browser shows a warning; the installer prints the certificate's fingerprint so you can check you are talking to your own device.

If the link has expired, `sudo sgc setup-link` prints a new one.

### Updating

The dashboard shows when a newer version exists and installs it with one click. Over SSH:

```sh
sudo sgc update --check   # only look
sudo sgc update           # look, ask, install
```

Before installing, SGC verifies the release's signature and that it is newer than what is installed. After installing, it waits for the new version to answer; if it does not, SGC puts back the previous version together with its data, and reports what happened.

SGC asks GitHub for the newest release once a day (a switch on the dashboard turns that off). That request tells GitHub your IP address and that you run SGC, nothing else.

### Export and restore

The dashboard's **Export** saves everything SGC holds (the admin account, settings and history) as one encrypted file. You choose a passphrase for it, and SGC asks for your password again before handing it out. Sign-in sessions and other things that only make sense on the running machine are left out.

To restore, install SGC on a clean machine and open the setup link: next to creating an account it offers **Restore from an export**. You see what the file contains before confirming. A newer SGC can restore an export made by an older one; an export made by a newer SGC is refused.

The file is a standard [age](https://age-encryption.org) file containing a tar archive, so it can be opened without SGC:

```sh
age -d sgc-export-<host>-<date>.age | tar -x
```

That gives `manifest.json` and `database.sqlite`. Keep the file and its passphrase somewhere other than the gateway; without the passphrase nobody can open it.

### Firewall

The **System** page can switch on a firewall for the device SGC runs on. With it on, SGC's page and SSH answer only to devices with a private address (192.168.x.x, 10.x.x.x, 172.16–31.x.x); everything else that arrives uninvited is ignored. What the device itself fetches from the internet is not affected. The first time, SGC installs nftables from Debian for it.

Switching it on or off cannot lock you out:

1. The change takes effect at once.
2. The page asks you to confirm that you can still reach SGC. Only a confirmation that arrives over a new connection counts, because a firewall lets connections that already exist carry on.
3. Without that confirmation within 60 seconds, SGC puts back the rules you confirmed last. The same happens if the device restarts, or if the part of SGC that waits for your confirmation fails.

The rules are loaded at start-up by a unit of their own, before the network comes up and whether or not SGC is running. They live in one nftables table (`inet sgc`); other tables on the machine are left alone.

Should you ever need to switch it off from the device itself:

```sh
sudo sgc firewall off
```

### SSH keys and "keys only"

The **System** page can add SSH keys for an account on the device: you paste the public key, and SGC asks for your password again, because a key is a way to log in to the device itself. SGC keeps these keys in a root-owned file of its own (`/etc/sgc/ssh/keys/<account>`) next to the ones the account keeps in its home folder, which go on working. A key is parsed and written out again, never copied as text: options in front of it, a second line or a private key are refused.

**Keys only** makes the SSH server refuse passwords and logins as root. That is the one step that could lock you out, so it works on proof:

1. It is only offered once SGC has seen a login with a key in the SSH server's log.
2. It takes effect at once.
3. It stays only if SGC then sees another login with a key within two minutes. Otherwise the previous settings come back, as they do if the device restarts in the meantime.

The proof is a login that the device itself observes. Nothing the page sends can stand in for it. Removing a key while "keys only" is on works the same way: the key comes back unless a login with another key is seen.

Should a key ever stop working, at the device itself:

```sh
sudo sgc ssh allow-passwords
```

Being able to add keys in the page means that whoever gets into SGC's page, with your password, can get a login on the device. That is a trade of safety for convenience, made on purpose; it is why the password is asked for again, why every key change is in the activity log, and why the page is only reachable from inside your network.

### DNS: AdGuard Home

[AdGuard Home](https://github.com/AdguardTeam/AdGuardHome) answers the name lookups of your network and leaves out advertising and tracking. It is part of SGC: the installer installs it and starts it. To use it, enter the device's address as the DNS server in your router, or on single devices.

On the **System** page it is a switch. Off means that AdGuard Home does not run and does not start with the device; the program and your settings stay. `sgc dns` says whether it is on; `sudo sgc dns on` and `sudo sgc dns off` do what the switch does. A device that was updated from a version without AdGuard Home gets it when DNS is first switched on. If the installer could not download it, SGC is installed all the same and says so.

- **A program of its own.** It runs as a service of its own under an account of its own (`sgc-adguard.service`), and keeps answering when SGC is stopped or being updated.
- **Pinned.** SGC downloads the release from AdGuard's page on GitHub and installs it only if it is exactly the file this version of SGC expects (size and SHA-256, checked by the web process and again by the root side). A newer AdGuard Home comes with a newer SGC.
- **Its settings are yours.** SGC writes AdGuard Home's settings once, at installation: Quad9 over HTTPS as the upstream, DNSSEC, a query log kept for 7 days, AdGuard's own blocklist. From then on you change them in AdGuard Home's own page and SGC leaves them alone.
- **One login.** That page listens on the device only and has no login of its own. SGC serves it at `/adguard/` behind its own sign-in.
- **Answers the home network only.** AdGuard Home runs from the moment SGC is installed, when the firewall is still off, so the settings SGC gives it name who gets answers: private addresses and the device itself (`allowed_clients`). Anyone else gets none. With the firewall on, DNS is let in from home-network addresses only, which is a second lock on the same door. A firewall switched on before AdGuard Home was there has to have its rules made afresh ("Let DNS in"), which you confirm like any firewall change.
- **systemd-resolved.** On a Debian that runs it (the cloud images do; Raspberry Pi OS does not), it holds the DNS port. Installing AdGuard Home makes it give up its listener (`/etc/systemd/resolved.conf.d/60-sgc-adguard.conf`) and points `/etc/resolv.conf` at the real name servers, so the device's own lookups never depend on AdGuard Home. If the device could not look up names afterwards, both are undone and nothing is installed. Switching DNS off leaves this as it is: the device's own lookups do not go through AdGuard Home either way.
- **In the export.** An export carries AdGuard Home's settings and whether DNS was on. After a restore SGC puts those settings into the AdGuard Home of the new device by itself: AdGuard Home checks them first, and if it does not stay up on them the previous ones come back. If that could not be done, the System page says so and offers to try again.

### Updates for the device

SGC's own updates are one thing (see [Updating](#updating)); the device underneath it gets its updates from Debian, and on a Raspberry Pi its kernel and firmware from Raspberry Pi. The **System** page looks after those too. You choose once:

- **By themselves.** Once a day, Debian's own tool for the job (`unattended-upgrades`) installs what is waiting.
- **By hand.** Nothing installs until you press **Install now** on that page. SGC looks once a day and shows what is waiting.

Either way it is the same tool installing the same updates: what Debian's own automatic updates cover (security fixes and the corrections of its point releases), plus Raspberry Pi's archive where the device uses it. That archive has no separate channel for security fixes, so without it a Pi's kernel would never be updated.

What SGC adds to the device is one small file among apt's settings (`/etc/apt/apt.conf.d/52sgc-updates`), which says whether the daily run installs anything and adds the Raspberry Pi archive. Debian's own settings stay as they are. The page can ask for exactly two things, "look" and "install"; it cannot name a package or an archive.

**Nothing restarts the device by itself.** Some updates, a new kernel above all, only take effect after a restart. The System page and the dashboard say when one is needed, and the restart is yours to start.

Until you have chosen, SGC changes nothing here. A Debian that already installs its updates by itself keeps doing so.

### Maintenance window

Some updates only take effect after a restart. The **System** page can set a time of day, for example 04:00 to 05:00, at which SGC may restart the device by itself when that is needed. It is off until you switch it on, and the times are those of the device's own clock, which the page shows.

Inside the window SGC restarts the device only if an installed update asked for it, at most once, never in the first minutes after start-up, never while updates are being installed, and only once the device's clock has been set from the network. It is SGC that does this, so if SGC is not running, nothing happens.

On the dashboard, SGC's own updates can be set to install by themselves in the same window (off by default). A new version then waits until your device has known it for three days, counted from when the device first saw it, not from a date the release carries. That leaves time for a faulty release to be noticed and withdrawn. With this on, a release reaches the device without a click from you; the wait is what stands between a bad release and your gateway.

### When something is wrong

```sh
sudo sgc doctor
```

checks every part of SGC on the machine (the service, its page, the root helper, storage, the clock, the firewall, SSH, the device's updates, AdGuard Home, the ports SGC needs) and says what to do about each problem it finds. It asks the machine directly, so it also works when SGC's page does not answer.

### How releases are verified

Every release contains `SHA256SUMS`, a list of checksums of the release files, and `SHA256SUMS.sig`, an Ed25519 signature over that list. The public key is [`installer/release-key.pem`](installer/release-key.pem) and is built into the installer. To check a download by hand:

```sh
openssl pkeyutl -verify -pubin -inkey release-key.pem -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
sha256sum --check --ignore-missing SHA256SUMS
```

The signing key is held by this repository's release workflow on GitHub. A signature therefore shows that a file was published through that workflow; it is not independent of GitHub.

What is independent of GitHub is the build: a release is built so that the same source gives the same files, byte for byte, on any machine.

```sh
bash scripts/verify-release.sh 0.7.0
```

checks the published signature of that version, builds its tag in a clean temporary copy and compares the result with the published files.

## Development

SGC is built on Linux. The backend is Go (compiler version pinned in `go.mod`); the browser interface in `web/` is React, TypeScript and Tailwind CSS, built with Node.js (version pinned in `.node-version`, packages pinned in `web/package-lock.json`) and embedded into the `sgc` binary.

```sh
make check   # format check, static analysis, shell script checks and tests
make web     # build the browser interface into web/dist
make build   # the interface, then bin/sgc-* and bin/sgc-helper-* for amd64 and arm64
make dist    # the files that make up a release, in dist/
```

To work on the interface, run `sgc serve --dev-insecure-http --state-dir <folder>` (plain http, this machine only) and `npm run dev` in `web/`.

### How it is put together

| Part | Runs as | What it does |
|---|---|---|
| `sgc serve` | unprivileged user `sgc`, in a systemd sandbox | The web interface and API |
| `sgc-helper` | root, in a systemd sandbox, started on demand | The few operations that need root, as a fixed list; no "run a command" |
| `sgc-helper update` | root, as a one-off systemd unit | Installs a downloaded release and rolls it back if it does not come up |
| `sgc-helper firewall` | root with only the right to load firewall rules, as one-off systemd units | Puts firewall rules into effect, keeps them on confirmation, undoes them otherwise |
| `sgc-helper ssh` | root without any capabilities, as one-off systemd units | Installs SSH keys and settings, keeps a restricting change only if a login with a key is seen, undoes it otherwise; puts the confirmed settings in place before the SSH server starts |
| `sgc-helper packages` | root, as a one-off systemd unit | Installs the Debian packages one of SGC's features needs, from lists fixed in the program (nftables for the firewall, unattended-upgrades for the device's updates) |
| `sgc-helper adguard` | root, as one-off systemd units | Installs the pinned release of AdGuard Home that the web process downloaded, after checking it again; puts the settings from a restored export in place; copies its settings for an export (that unit can read files and do nothing else). Switching it on and off is done by the helper itself, which asks systemd |
| AdGuard Home | its own unprivileged user, in a systemd sandbox | Answers DNS; may bind port 53 and write to its own folder, nothing else |
| `sgc-helper os-updates` | root, as one-off systemd units | Writes SGC's one file among apt's settings; runs Debian's update tool to look for the device's updates or to install them |
| `nft -f /etc/sgc/firewall.nft` | systemd, early at start-up | Loads the confirmed firewall rules; uses none of SGC's own programs |
| `sgc setup-link` | from the installer or `sudo` | Prints the one-time link for creating the admin account |
| `sgc update` | `sudo` | Looks for a newer version and installs it |
| `sgc doctor`, `sgc firewall`, `sgc ssh` | `sudo` | Checks every part; shows the firewall's or SSH's state; switches the firewall off or allows SSH passwords again |

The web process never has root. It reaches the helper through a Unix socket that only it may open, and the helper additionally checks who is calling. The helper itself can do next to nothing: for real work it starts a unit that has exactly the privileges that job needs.

The firewall is split the same way. The web process can ask for "on" or "off" and nothing more; the rules are written by the root side, checked by nftables before they are loaded, and loaded completely or not at all.

Updating is split the same way: the unprivileged web process downloads a release, and the root updater, which never talks to the internet, verifies it again by itself before installing.

So are the device's own updates: the web process can ask for "look" or "install" and choose between "by themselves" and "by hand". Which updates there are is worked out by Debian's update tool from the device's settings; no request carries a package name.

SSH is split the same way again, with one difference the owner chose: the web process may pass on public keys, which is more than a yes or no. The root side checks each one itself and accepts them for ordinary accounts only, never for root.

Whole-machine tests run against a disposable Hyper-V virtual machine; see [`test/e2e/vm`](test/e2e/vm) and [`test/e2e/installer`](test/e2e/installer). One of them installs the previous published release and lets it update itself to the current source, because an update is always carried out by the version that is already installed.

A release is published by pushing a tag that matches the `VERSION` file (for example `v0.5.0`). Its description is that version's section of [CHANGELOG.md](CHANGELOG.md), which is also what SGC shows before an update; `make check` fails if the section is missing.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

[MIT](LICENSE)
