# SGC — Server Gateway Control

A secure front door for your home network, running on a Raspberry Pi or any small Debian machine.

> **Status: early development.** The installer, the admin account and a first dashboard with system health work. VPN, DNS and the reverse proxy are not built yet.

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

At the end the installer prints a one-time link. Open it in a browser on your network to create the admin account; you then land on the dashboard. Until SGC has a certificate from Let's Encrypt (a later milestone) it uses a self-signed one, so the browser shows a warning; the installer prints the certificate's fingerprint so you can check you are talking to your own device.

If the link has expired, `sudo sgc setup-link` prints a new one.

### Updating

The dashboard shows when a newer version exists and installs it with one click. Over SSH:

```sh
sudo sgc update --check   # only look
sudo sgc update           # look, ask, install
```

Before installing, SGC verifies the release's signature and that it is newer than what is installed. After installing, it waits for the new version to answer; if it does not, SGC puts back the previous version together with its data, and reports what happened.

SGC asks GitHub for the newest release once a day (a switch on the dashboard turns that off). That request tells GitHub your IP address and that you run SGC, nothing else.

### How releases are verified

Every release contains `SHA256SUMS`, a list of checksums of the release files, and `SHA256SUMS.sig`, an Ed25519 signature over that list. The public key is [`installer/release-key.pem`](installer/release-key.pem) and is built into the installer. To check a download by hand:

```sh
openssl pkeyutl -verify -pubin -inkey release-key.pem -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
sha256sum --check --ignore-missing SHA256SUMS
```

The signing key is held by this repository's release workflow on GitHub. A signature therefore shows that a file was published through that workflow; it is not independent of GitHub.

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
| `sgc setup-link` | from the installer or `sudo` | Prints the one-time link for creating the admin account |
| `sgc update` | `sudo` | Looks for a newer version and installs it |

The web process never has root. It reaches the helper through a Unix socket that only it may open, and the helper additionally checks who is calling.

Updating is split the same way: the unprivileged web process downloads a release, and the root updater, which never talks to the internet, verifies it again by itself before installing.

Whole-machine tests run against a disposable Hyper-V virtual machine; see [`test/e2e/vm`](test/e2e/vm) and [`test/e2e/installer`](test/e2e/installer).

A release is published by pushing a tag that matches the `VERSION` file (for example `v0.5.0`). Its description is that version's section of [CHANGELOG.md](CHANGELOG.md), which is also what SGC shows before an update; `make check` fails if the section is missing.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

[MIT](LICENSE)
