# SGC — Server Gateway Control

A secure front door for your home network, running on a Raspberry Pi or any small Debian machine.

> **Status: early development.** There is nothing to install yet.

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

Not available yet. The goal is a single command over SSH that starts a web-based setup wizard.

## Development

SGC is built on Linux with Go; the exact compiler version is pinned in `go.mod`.

```sh
make check   # format check, static analysis and tests
make build   # bin/sgc-linux-amd64 and bin/sgc-linux-arm64
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

[MIT](LICENSE)
