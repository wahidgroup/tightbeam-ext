# Contributing

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", and "MAY" in this document are interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## Getting Started

Contributors MUST have these tools:

- [rustup](https://rustup.rs), Node.js, Git, and Make
- Docker, rsync, and lsof, which build and start the e2e stack
- [jq](https://jqlang.github.io/jq/), which the scripts read `cargo metadata` with
- [ShellCheck](https://www.shellcheck.net), which `make lint` runs over every shell script

Pin files are the source of truth:

- Rust: [`rust-toolchain.toml`](rust-toolchain.toml) (channel, components, and targets)
- Node: [`.nvmrc`](.nvmrc)

`make setup` installs that Rust pin with its components and targets via `rustup toolchain install`, then each extension's tooling.

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

- Indent with hard tabs, except in YAML, which takes two spaces. rustfmt checks the Rust. prettier checks the `.mjs` and `.mts` repo scripts, and the sources of each npm package whose `lint` script runs prettier. `.editorconfig` sets the same indent in an editor, and it is the one home of the indent of the shell scripts
- Pass `make lint` (and preferably `make ci`) before opening a PR
- Rust: no `unwrap` / `expect` / `panic` in production code. Enum error types via tightbeam's `Errorizable`, no string-based errors. Prefer `From` / `TryFrom` and `?`
- Keep test-support Rust code behind the `testing` cargo feature. It MUST NOT compile into a default build
- Rust: follow the integration-test rule of [docs/development.md](docs/development.md#rust-integration-tests)

### Architecture notes

- Each extension lives in its own directory (`ws/` for the WebSocket transport) containing its crates, the npm workspace, tests, and Docker stack.
- The e2e stack allocates free host ports via `scripts/get-port.sh`. Tests MUST read endpoints from the environment and MUST NOT hardcode ports.

## Pull Requests

All pull requests MUST conform to the title, body, and metadata specifications below. The `PR Checks` workflow (`Title`, `Body`, `Metadata` jobs) blocks merge on non-compliance.

### Title

PR titles and commit headers MUST follow [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/):

```
<type>[optional scope][!]: <description>
```

The `commit-msg` hook ([`.husky/commit-msg`](.husky/commit-msg)) holds the rule: the allowed types, the case of the type, the scope, and the description, and the length of the header. Its error message names each part. The `Title` job runs the same hook on the PR title in its `title` mode, which checks the subjects that Git writes for a commit too, such as `Merge` and `Revert`.

Write the description in the imperative mood, and append `!` after the type or the scope for a breaking change. Scope by crate (`grpc`, `wire`, `ws`, `wasm`), by package (`client`, `tests`), or across the repo (`deps`, `docs`, `ci`, `scripts`). These headers pass the hook:

- `feat(wasm): expose the frame-integrity verdict binding`
- `fix(ws): close the socket on handshake failure`
- `chore(deps): bump tightbeam-rs`
- `refactor(client)!: rename exported type`
- `docs: document the HPKE session flow`
- `revert: undo accidental export rename`

### Body

The PR template at [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md) holds the required sections, one `## ` heading each, and it auto-populates them. The `Body` job runs `scripts/check-pr-body.sh`, which requires every heading of the template with at least three characters of content. A release PR, whose head is the process branch of `scripts/release.sh`, is exempt.

The Testing section SHOULD cite `make ci` (or the relevant `make` targets) when behavior changes.

### Metadata

Each PR MUST have:

- At least one **assignee** (the person responsible for landing the PR)
- At least one **label** (for categorization and triage)

### Guidelines

- PRs SHOULD be under 400 lines of diff for fastest review
- The Summary MUST explain _why_. The diff already shows _what_
- Use `Fixes #N` / `Closes #N` to auto-close linked issues on merge
- Apply GitHub labels for additional categorization (orthogonal to the type prefix)

## Releasing

Extensions release independently. A maintainer releases one with:

```bash
make release <ext> version=vX.Y.Z
```

[docs/development.md](docs/development.md#releases) specifies the release, its tags, its yank, and the order in which dependent extensions release.
