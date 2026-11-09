# Development and Release

This page specifies how the repository builds, checks, and releases its extensions:

- the extension projects and how the root Makefile composes them
- the make targets and the variables they read
- the release of one extension, its tags, and its yank

It drills down from the [repository README](../README.md) for engineers who work on the extensions or review a release. The README holds what each part is for and the standards it follows.

## Contents

- [Projects](#projects)
- [Targets](#targets)
- [Variables](#variables)
- [Tests](#tests)
- [Releases](#releases)
- [Yanks](#yanks)
- [Sources](#sources)

## Projects

Every top-level directory that owns a `Makefile` is an extension project: `asn`, `grpc`, `pubsub`, `wire`, and `ws`. Each project owns its targets in `<project>/Makefile` and its setup in `<project>/scripts/setup.sh`, and the root `Makefile` composes them. A project name after a target scopes the target to that project, and with no project name a target runs for every project.

```sh
make test ws     # ws only: cargo + vitest + its e2e lanes
make lint pubsub # pubsub only
make setup ws    # skips the pubsub install entirely
```

## Targets

| Target         | Runs                                                                                                |
| -------------- | --------------------------------------------------------------------------------------------------- |
| `setup`        | The toolchains, the npm workspaces, and Playwright. It is idempotent                                |
| `check`        | `cargo check` for each project, under the cargo feature variables                                   |
| `build`        | `cargo build --release` for each project, under the cargo feature variables                         |
| `lint`         | rustfmt, clippy with `-D warnings`, eslint and prettier, `cargo doc` with `-D warnings`, and cspell |
| `test`         | The cargo tests, the TypeScript units, and the dockerized end-to-end lanes                          |
| `wasm`         | Lint and build the browser engine for `wasm32-unknown-unknown`                                      |
| `client`       | Build the published client packages                                                                 |
| `sbom`         | Generate the software bill of materials of the client                                               |
| `smoke`        | Load the exports of each built client package                                                       |
| `pack`         | Assert the contents of `npm pack`                                                                   |
| `doc`          | Build the documentation with all features and `-D warnings`                                         |
| `audit`        | `cargo audit` and `npm audit`                                                                       |
| `ci`           | The full pipeline: lint, build, test, wasm, client, smoke, and pack                                 |
| `release`      | Release one extension ([Releases](#releases))                                                       |
| `check-yanked` | Check whether the version of the extension is yanked                                                |

`make help` prints the full list, and `make help-ref` prints the references of the conventions it follows.

## Variables

| Variable         | Effect                                                                           |
| ---------------- | -------------------------------------------------------------------------------- |
| `fix=1`          | Apply the lint and audit fixes. `cargo doc` still denies warnings                |
| `debug=1`        | Set `RUST_LOG=debug`, and run the end-to-end suite with a verbose reporter       |
| `features=...`   | Pass a comma-separated list to cargo as `--features`                             |
| `no-default=1`   | Pass `--no-default-features` to cargo                                            |
| `ui=1`           | Run the end-to-end suite in Playwright UI mode                                   |
| `trace=1`        | Force Playwright traces                                                          |
| `wasm_opt=1`     | Keep `wasm-opt` during `make test`, which skips it by default. `make ci` sets it |
| `version=vX.Y.Z` | The version of a release                                                         |
| `ext=<name>`     | The extension of a release or of `make version`, `ws` by default                 |
| `dry-run=1`      | Preview a release with no change                                                 |
| `allow-staged=1` | Include staged files in the release commit                                       |
| `yank=1`         | Yank a published version                                                         |

## Tests

- Tests run real engines and real peers. No mocks.
- A behavior that needs a peer runs in an e2e lane against the docker stack.
- A behavior with no peer runs on its owner, over frames that the real engine builds.
- A server mode that the stack lacks goes on the demo server.
- `scripts/eslint/real-dependencies.mjs` refuses `vi.mock`, `vi.spyOn`, `vi.hoisted`, `vi.fn`, and call assertions.

### Rust integration tests

Every test under `tests/` is a `tb_scenario!` graded by a `tb_assert_spec!`. Unit tests in `src/` stay plain.

| To test                                | Use                                                   |
| -------------------------------------- | ----------------------------------------------------- |
| One server and one client              | `environment ServiceClient`                           |
| A gateway and its hives                | `environment Cluster`                                 |
| Anything else                          | `environment Bare`                                    |
| An order of events                     | `tb_process_spec!` through `ScenarioConfig::with_csp` |
| A fact that no code under test records | An event under a `test` URN, graded with `equals!`    |
| A path that only a failing trace takes | A `FaultModel` under `testing-fault`                  |
| That a spec rejects a broken run       | `Expect::Violation(Layer::Assertion)`                 |

- Attach the scenario trace to every transport you can: `with_trace` on `server!` and on a pool, and `TcpTransport::with_trace` on a hand-built transport. `client!` and `ClientBuilder` take none.
- Count only the events the scenario owns. A colony records its own background work, such as heartbeat dials, on the same trace.
- A process grades order, not completion. Pair it with counts.
- Wait for an event that a server records after it answers before the client returns.
- The specs of the suites that every transport shares live in `tightbeam_ws::testing::specs`.

Outside the macro:

- Browser suites run under `wasm-bindgen-test`: `tightbeam-ws-wasm/tests` and `tightbeam-asn/tests/wasm_js_roundtrip.rs`.
- Compile-time proofs are `const` items, such as `tightbeam-asn/tests/marker.rs`.

### Docker stack

- Scenarios that need the stack compile under the `e2e` feature, such as the hop and stock lanes of grpc. `make test` leaves it off, `make lint` compiles it, and `<project>/scripts/test-e2e.sh` runs it.
- A project adds its own certificates with a `STACK_CERT_STEPS` entry in its `scripts/stack-env.sh`.

## Releases

Each top-level extension directory versions its crates on its own, so each extension releases on its own. The canonical version manifest of an extension is `<ext>/tightbeam-<ext>/Cargo.toml`.

```sh
make release version=v0.1.0            # release the default extension (ws)
make release version=v0.1.0 ext=ws     # release a named extension
make release                           # prompt for the next version
make release version=v0.1.0 dry-run=1  # preview without mutations
make release yank=1                    # yank a published version
```

`scripts/release.sh` drives a release as a state machine, so an interrupted release resumes when the same command runs again:

1. Prepare: bump the versions of the extension. A forward release cuts `process/<ext>/v<version>` from the default branch. A version older than the latest tag is a backport, and it cuts from the matching `release/<ext>/vX.Y` branch, which the script creates on demand and cherry-picks onto.
2. Push the release branch and open the release pull request.
3. Wait for the merge.
4. Push the tag `releases/<ext>/v<version>`, signed with GPG or SSH.

Before it prepares anything, the script resolves every crate the release publishes against crates.io. A crate that requires a release of another extension that crates.io does not have yet refuses the release, so `tightbeam-wire` releases before `tightbeam-ws` and `tightbeam-grpc`, and `tightbeam-ws` before `tightbeam-pubsub`. `tightbeam-ws` also releases before `tightbeam-grpc`, whose tests run the shared suites of the `tightbeam-ws` test support. The check resolves versions, not the items a crate uses, so it cannot see that order, and the release of `tightbeam-grpc` waits for the release of `tightbeam-ws` that the release of `tightbeam-wire` makes possible.

The script compiles the release notes from the titles and labels of the merged pull requests. The push of that tag publishes the publishable crates of that extension to crates.io, as one Cargo multi-package publish in dependency order, and creates the GitHub release. It publishes only the crates of that extension, and never the whole workspace.

## Yanks

`make release yank=1` deletes the GitHub release and pushes a signed `yanked/<ext>/v<version>` marker tag. It keeps the release tag. The deploy guard `scripts/check-yanked.sh` refuses a version that carries a yank marker.

## Sources

- GNU Coding Standards, Command-Line Interfaces: <https://www.gnu.org/prep/standards/html_node/Command_002dLine-Interfaces.html>
- POSIX.1-2017, Utility Conventions, chapter 12: <https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html>
- GNU Make, Arguments to Specify the Goals: <https://www.gnu.org/software/make/manual/html_node/Goals.html>
