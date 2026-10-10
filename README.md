# SGC — Server Gateway Control

A secure front door for your home network, running on a Raspberry Pi or any small Debian machine.

> **Status: early development.** The installer works, but what it installs does not do anything useful yet.

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

At this stage it installs an empty service. The web-based setup wizard comes next.

### How releases are verified

Every release contains `SHA256SUMS`, a list of checksums of the release files, and `SHA256SUMS.sig`, an Ed25519 signature over that list. The public key is [`installer/release-key.pem`](installer/release-key.pem) and is built into the installer. To check a download by hand:

```sh
openssl pkeyutl -verify -pubin -inkey release-key.pem -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
sha256sum --check --ignore-missing SHA256SUMS
```

The signing key is held by this repository's release workflow on GitHub. A signature therefore shows that a file was published through that workflow; it is not independent of GitHub.

## Development

SGC is built on Linux with Go; the exact compiler version is pinned in `go.mod`.

```sh
make check   # format check, static analysis, shell script checks and tests
make build   # bin/sgc-linux-amd64 and bin/sgc-linux-arm64
make dist    # the files that make up a release, in dist/
```

Whole-machine tests run against a disposable Hyper-V virtual machine; see [`test/e2e/vm`](test/e2e/vm) and [`test/e2e/installer`](test/e2e/installer).

A release is published by pushing a tag that matches the `VERSION` file (for example `v0.3.0`).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

[MIT](LICENSE)
