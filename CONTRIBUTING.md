# Contributing

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", and "MAY" in this document are interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## Getting Started

Contributors MUST have the Rust toolchain (via [rustup](https://rustup.rs)), Node.js (>=24, for the hybrid TS/wasm client), Docker (for the e2e stack), Git, and Make.

```bash
make setup
make lint
make ci
```

Use `make help` for the full command list. Apply fixes with `make lint fix=1`.

Git hooks live in `.husky/` and are installed automatically by [husky-rs](https://crates.io/crates/husky-rs) (which sets `core.hooksPath`) the first time `cargo test` builds dev-dependencies. Set `NO_HUSKY_HOOKS=1` to skip installation (CI does this).

- `commit-msg` - enforces the commit header format (see [Title](#title))
- `pre-push` - runs `make lint` and verifies commit signatures. Commits MUST be signed before push.

### Code Style

Contributors MUST:

- Use hard tabs everywhere except YAML (2 spaces), enforced by EditorConfig
- Pass `make lint` (and preferably `make ci`) before opening a PR
- Rust: no `unwrap` / `expect` / `panic` in production code; enum error types via tightbeam's `Errorizable`, no string-based errors; prefer `From` / `TryFrom` and `?`
- Keep test-support Rust code behind the `testing` cargo feature; it MUST NOT compile into a default build

### Architecture notes

- Each extension lives in its own directory (`ws/` for the WebSocket transport) containing its crates, the npm workspace, tests, and Docker stack.
- The e2e stack allocates free host ports via `scripts/get-port.sh`. Tests MUST read endpoints from the environment, never hardcode ports.

## Pull Requests

All pull requests MUST conform to the title, body, and metadata specifications below. The `PR Checks` workflow (`Title`, `Body`, `Metadata` jobs) blocks merge on non-compliance.

### Title

PR titles and commit headers MUST follow [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/):

```
<type>[optional scope][!]: <description>
```

#### Type

The type MUST be lowercase and one of:

| Type       | Purpose                                                 | Semver |
| ---------- | ------------------------------------------------------- | ------ |
| `feat`     | New feature                                             | MINOR  |
| `fix`      | Bug fix                                                 | PATCH  |
| `docs`     | Documentation only                                      | -      |
| `style`    | Formatting, whitespace, no logic change                 | -      |
| `refactor` | Code change that neither fixes a bug nor adds a feature | -      |
| `perf`     | Performance improvement                                 | PATCH  |
| `test`     | Adding or correcting tests                              | -      |
| `build`    | Build system or dependency changes                      | -      |
| `ci`       | CI configuration changes                                | -      |
| `chore`    | Maintenance, no production code change                  | -      |
| `revert`   | Revert a previous commit                                | -      |

#### Scope

The scope is OPTIONAL, MUST be lowercase (`[a-z0-9/-]+`), and identifies the affected area. Recommended scopes:

- Crate: `ws`, `wasm`
- Package: `client`, `tests`
- Cross-cutting: `deps`, `docs`, `ci`, `scripts`

#### Description

The description MUST:

- Use imperative mood ("add" not "added" / "adds")
- Start with a lowercase letter or digit (not Sentence case)
- NOT end with a period
- Keep the full header under 100 characters

#### Breaking Changes

Append `!` after the type or scope to indicate a breaking change:

```
feat!: drop support for Node 22
refactor(client)!: rename exported type
```

#### Examples

- `feat(wasm): expose the frame-integrity verdict binding`
- `fix(ws): close the socket on handshake failure`
- `chore(deps): bump tightbeam-rs`
- `refactor(client)!: rename exported type`
- `docs: document the ECIES session flow`
- `revert: undo accidental export rename`

### Body

The PR body MUST contain these five sections, each with non-empty content:

| Section               | Purpose                                                                 |
| --------------------- | ----------------------------------------------------------------------- |
| `## Summary`          | WHY this change exists and WHAT it accomplishes                         |
| `## Related Issues`   | Issue links (`Fixes #N`, `Closes #N`, `Refs #N`, or `None`)             |
| `## Changes Made`     | Bullet list of user/system-visible changes                              |
| `## Testing`          | How a reviewer verifies the change (commands, steps, expected outcomes) |
| `## Breaking Changes` | Migration path for consumers, or `None`                                 |

The PR template at `.github/PULL_REQUEST_TEMPLATE.md` auto-populates these sections.

Testing section SHOULD cite `make ci` (or the relevant `make` targets) when behavior changes.

### Metadata

Each PR MUST have:

- At least one **assignee** (the person responsible for landing the PR)
- At least one **label** (for categorization and triage)

### Guidelines

- PRs SHOULD be under 400 lines of diff for fastest review
- The Summary MUST explain _why_; the diff already shows _what_
- Use `Fixes #N` / `Closes #N` to auto-close linked issues on merge
- Apply GitHub labels for additional categorization (orthogonal to the type prefix)

## Releasing

The workspace is versioned from `[workspace.package]` in `Cargo.toml`. Maintainers release with:

```bash
make release version=vX.Y.Z
```

Use `dry-run=1`, `allow-staged=1`, or `yank=1` as documented in `make help`.

A release bumps the manifest, opens a release pull request, and on merge creates a signed `releases/v<version>` tag that publishes to crates.io. The deploy guard `check-yanked.sh` refuses yanked versions (`yanked/v<version>`).
