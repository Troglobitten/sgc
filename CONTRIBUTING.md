# Contributing

## Branches

- `main` is always in a working, releasable state.
- Changes are made on short-lived branches (`feat/<name>`, `fix/<name>`, `docs/<name>`, `chore/<name>`) and merged into `main` through a pull request.
- Releases are tagged on `main` with their version (`v0.2.0`).

## Commit messages

A short, imperative subject line with a type prefix:

- `feat:` new functionality
- `fix:` bug fix
- `docs:` documentation only
- `chore:` tooling, scaffolding, dependencies
- `refactor:` internal change, no behaviour change

Version bumps are noted in the commit that makes them.

## Versioning

[Semantic Versioning](https://semver.org). The current version is in the `VERSION` file.

Every version has a section in `CHANGELOG.md`, written for the person running SGC rather than for developers: it is shown in the dashboard before an update.

## Never commit

Passwords, API keys, tokens, export files, real domain names or addresses, or any real user data. Examples and tests use placeholder values such as `domain.tld` and `192.168.1.x`.
