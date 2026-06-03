# Contributing

## Requirements Language

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## Workflow

- Run `make lint` and `make test` before opening a pull request. They MUST pass.
- Commits MUST be signed.
- Pull request titles MUST follow Conventional Commits (`type(scope): Subject`).

## Style

- Indentation is hard tabs (width 4) everywhere except YAML (2 spaces).
- Rust: no `unwrap` / `expect` / `panic` in production code; enum error types via tightbeam's `Errorizable`, no string-based errors; prefer `From` / `TryFrom` and `?`.

## Releases

The crate is versioned from `[workspace.package]` in `Cargo.toml`.

- `make release v0.1.0` - release at an explicit version.
- `make release` - prompt for the next version.
- `make release v0.1.0 --dry-run` - preview without mutations.
- `make release v0.1.0 --yank` - yank a published version.

A release bumps the manifest, opens a release pull request, and on merge creates a signed `releases/v<version>` tag that publishes to crates.io. The deploy guard `check-yanked.sh` refuses yanked versions (`yanked/v<version>`).
