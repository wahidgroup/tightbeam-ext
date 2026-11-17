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

- Every top-level directory that owns a `Makefile` is an extension project.
- `scripts/lib/projects.sh` decides the set, and `make help` lists it.
- Each project owns its targets in `<project>/Makefile` and its setup in `<project>/scripts/setup.sh`.
- The root `Makefile` composes them.
- A project name after a target scopes the target to that project.
- With no project name, a target runs for every project.

```sh
make test ws     # ws only: cargo + vitest + its e2e lanes
make lint pubsub # pubsub only
make setup ws    # skips the pubsub install entirely
```

### Setup

- `scripts/setup.sh` installs the toolchain, then runs the setup of each selected project.
- Each setup that installs sources `scripts/lib/stamp.sh`, and takes the one setup lock of the repo with `acquire_lock`.
- It installs when its own staleness check holds, then records its stamp with `write_stamp`.

| Setup                     | Staleness check      | Installs when                                                                                                              |
| ------------------------- | -------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `scripts/setup.sh`        | `toolchain_required` | `cargo-audit` is missing, or the stamp is stale                                                                            |
| `asn/scripts/setup.sh`    | `setup_required`     | `node_modules` is missing, the wasm-bindgen CLI differs from the version that `Cargo.lock` resolves, or the stamp is stale |
| `pubsub/scripts/setup.sh` | `setup_required`     | `node_modules` is missing, or the stamp is stale                                                                           |
| `ws/scripts/setup.sh`     | `setup_required`     | `node_modules` or `wasm-pack` is missing, or the stamp is stale                                                            |

`stamp_stale` reads a stamp as stale when it is missing, or when one of these changed since `write_stamp` recorded it:

- a manifest that the script lists
- the npm install command
- `NPM_INSTALL_FLAGS`

`grpc/scripts/setup.sh` and `wire/scripts/setup.sh` print that they are up to date, because their crates need the toolchain alone.

## Targets

| Target         | Runs                                                                                                                                                    |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `setup`        | The Rust toolchain and `cargo-audit`, then the setup of each project: the npm workspaces, the Playwright chromium, the wasm-bindgen CLI and `wasm-pack` |
| `check`        | `cargo check` for each project, under the cargo feature variables                                                                                       |
| `build`        | `cargo build --release` for each project, under the cargo feature variables                                                                             |
| `lint`         | The checks that [Lint](#lint) lists                                                                                                                     |
| `test`         | The cargo tests, the TypeScript units, and the dockerized end-to-end lanes                                                                              |
| `wasm`         | Lint and build the browser engine for `wasm32-unknown-unknown`                                                                                          |
| `client`       | Build the published client packages                                                                                                                     |
| `sbom`         | Generate the software bill of materials of the client                                                                                                   |
| `smoke`        | Load the exports of each built client package                                                                                                           |
| `pack`         | Assert the contents of `npm pack`                                                                                                                       |
| `doc`          | Build the documentation with all features and `-D warnings`                                                                                             |
| `audit`        | `cargo audit` and `npm audit`                                                                                                                           |
| `ci`           | The full pipeline: lint, build, test, wasm, client, smoke, and pack                                                                                     |
| `release`      | Release one extension ([Releases](#releases))                                                                                                           |
| `check-yanked` | Check whether the version of the extension is yanked                                                                                                    |

`make help` prints the full list, and `make help-ref` prints the references of the conventions it follows.

### Lint

`make lint` runs:

- rustfmt
- clippy with `-D warnings`
- eslint and prettier
- `cargo doc` with `-D warnings`
- cspell
- the script checks of `format-scripts`
- shellcheck over every shell script and git hook

## Variables

### Build and check

| Variable       | Effect                                                                     |
| -------------- | -------------------------------------------------------------------------- |
| `fix=1`        | Apply the lint and audit fixes. `cargo doc` still denies warnings          |
| `debug=1`      | Set `RUST_LOG=debug`, and run the end-to-end suite with a verbose reporter |
| `features=...` | Pass a comma-separated list to cargo as `--features`                       |
| `no-default=1` | Pass `--no-default-features` to cargo                                      |

### End-to-end

| Variable     | Effect                                                                           |
| ------------ | -------------------------------------------------------------------------------- |
| `ui=1`       | Run the end-to-end suite in Playwright UI mode                                   |
| `trace=1`    | Force Playwright traces                                                          |
| `wasm_opt=1` | Keep `wasm-opt` during `make test`, which skips it by default. `make ci` sets it |

### Release

| Variable         | Effect                                                                  |
| ---------------- | ----------------------------------------------------------------------- |
| `version=vX.Y.Z` | The version of a release. Without it, `make release` asks on a terminal |
| `ext=<name>`     | The extension of a release, in place of a project name                  |
| `dry-run=1`      | Preview a release with no change                                        |
| `allow-staged=1` | Include staged files in the release commit                              |
| `yank=1`         | Yank a published version                                                |

## Tests

Tests run real engines and real peers. No mocks.

| A behavior                            | Runs                                                  |
| ------------------------------------- | ----------------------------------------------------- |
| That needs a peer                     | In an e2e lane against the docker stack               |
| With no peer                          | On its owner, over frames that the real engine builds |
| Of a server mode that the stack lacks | On the demo server                                    |

### Test support

| Script                                 | Role                                                                                         |
| -------------------------------------- | -------------------------------------------------------------------------------------------- |
| `scripts/eslint/real-dependencies.mjs` | Allows only the `vi` members it lists, and refuses the call assertions it lists              |
| `scripts/vitest/byte-equality.mjs`     | The setup file of every vitest suite. It compares two byte arrays of one class in one loop   |
| `scripts/vitest/doc-samples.mts`       | Compiles each `ts` fence of a page as a module of its own, under the tsconfig of one package |

- `real-dependencies.mjs` is a lint, not a proof. `vi` is a third-party API, so no type of this repo can refuse a double.
- `byte-equality.mjs` exists because the default matcher reads a `Uint8Array` one element at a time, at over a second per megabyte.
- `byte-equality.mjs` leaves every other pair to the default rules.
- In `doc-samples.mts`, a prelude declares the names that the samples of one page take from their surroundings.
- Each package that imports `doc-samples.mts` maps `typescript` in the `paths` of its tsconfig, so the module type-checks against the compiler of that package.

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

- Attach the scenario trace to every transport you can: `with_trace` on `server!` and on a pool, and `TcpTransport::with_trace` on a hand-built transport.
- `client!` and `ClientBuilder` take no trace.
- Count only the events the scenario owns. A colony records its own background work, such as heartbeat dials, on the same trace.
- A process grades order, not completion. Pair it with counts.
- Wait for an event that a server records after it answers before the client returns.
- The specs of the suites that every transport shares live in `tightbeam_ws::testing::specs`.

Outside the macro:

- Browser suites run under `wasm-bindgen-test`: `tightbeam-ws-wasm/tests` and `tightbeam-asn/tests/wasm_js_roundtrip.rs`.

### Docker stack

Scenarios that need the stack compile under the `e2e` feature, such as the hop and stock lanes of grpc.

| Command                         | The `e2e` feature |
| ------------------------------- | ----------------- |
| `make test`                     | Leaves it off     |
| `make lint`                     | Compiles it       |
| `<project>/scripts/test-e2e.sh` | Runs it           |

- A project takes part in the stack through its fragment, `<project>/scripts/stack-env.sh`, which holds every value of the project.
- `make test` starts the stack only when a selected project ships a fragment.
- `make test` then runs the `scripts/test-e2e.sh` lane of each such project.
- A project adds its own certificates with a `STACK_CERT_STEPS` entry in its `scripts/stack-env.sh`.
- A project adds its own images with a `STACK_IMAGES` entry in its `scripts/stack-env.sh`.

## Releases

- Each top-level extension directory versions its crates on its own, so each extension releases on its own.
- The version of an extension is the version of its crate `tightbeam-<ext>`.
- `scripts/lib/extension.sh` reads it, and the other facts of a release, from `cargo metadata` for each script that sources it.

```sh
make release ws version=v0.1.0            # release the ws extension
make release ws                           # ask for the version, then release
make release ws version=v0.1.0 dry-run=1  # preview without mutations
make release ws yank=1                    # yank a published version
```

### Release gate

`make release` refuses a release before `scripts/release.sh` runs. The check is `extension_release_gate` of `scripts/lib/extension.sh`, and it refuses:

- No extension, or more than one. A project name or `ext=<name>` names the extension.
- A version that is not `X.Y.Z`, with or without a leading `v`.
- A version below the latest release tag of the extension, because releases only go forward.
- An extension that a crate of the release depends on through a path, while it has no release tag, or has commits under its directory since its latest release tag.

The rules of that check:

- A yank runs the first check alone.
- The version of the latest release passes, so a release that stopped before its tag push resumes.
- The path rule orders the releases. `wire` releases before `ws` and `grpc`.
- `ws` releases before `pubsub` and before `grpc`, whose tests run the shared suites of the `tightbeam-ws` test support.
- The check reads the release tags of the clone after it fetches the tags of origin, as `scripts/release.sh` does.

### Version

With no `version=`, a release takes its version from the check:

| Where          | The check                                                                        |
| -------------- | -------------------------------------------------------------------------------- |
| On a terminal  | Asks for the version in the words of `scripts/release.sh`, and checks the answer |
| Off a terminal | Refuses the release                                                              |

`make release` passes the version that the check printed to `scripts/release.sh`.

### Release steps

`scripts/release.sh` drives a release as a state machine, so an interrupted release resumes when the same command runs again:

1. Prepare: cut `process/<ext>/v<version>` from the default branch and bump the versions of the extension.
2. Push the release branch and open the release pull request.
3. Wait for the merge.
4. Push the tag `releases/<ext>/v<version>`, signed with GPG or SSH.

- Before it prepares anything, `scripts/release.sh` checks that every crate the release publishes resolves against crates.io.
- The script compiles the release notes from the titles and labels of the merged pull requests.

### Release workflow

- The push of the tag runs the release workflow.
- The workflow publishes the publishable crates of that extension to crates.io, as one Cargo multi-package publish in dependency order.
- The workflow creates the GitHub release.
- The publish covers the crates of that one extension alone.
- `scripts/verify-release-tag.sh` exports the facts of the tag to each job of the release workflow, such as the SBOM that the GitHub release attaches.

| Job       | Token     | Runs                                                                                                                                                                        |
| --------- | --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `build`   | Read-only | The setup, the tag check, and the SBOM, then packages the crates, and builds, checks, and packs the npm client. It runs no `make ci` and no audit                           |
| `publish` | Write     | No setup and no build. `scripts/publish-release.sh` publishes each crate and the client tarball that its registry lacks, then the job creates or updates the GitHub release |

So a run of the workflow after a partial publish finishes the release.

## Yanks

- `make release <ext> yank=1` deletes the GitHub release, and pushes a signed `yanked/<ext>/v<version>` marker tag.
- A yank keeps the release tag.
- The deploy guard `scripts/check-yanked.sh` refuses a version that carries a yank marker.
- `scripts/publish-release.sh` runs it before each registry read or write, so a re-run of a publish step refuses a version that was yanked after the first attempt.

## Sources

- GNU Coding Standards, Command-Line Interfaces: <https://www.gnu.org/prep/standards/html_node/Command_002dLine-Interfaces.html>
- POSIX.1-2017, Utility Conventions, chapter 12: <https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html>
- GNU Make, Arguments to Specify the Goals: <https://www.gnu.org/software/make/manual/html_node/Goals.html>
