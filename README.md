# tightbeam-ext

Official, canonical extensions for the [tightbeam](https://crates.io/crates/tightbeam-rs) messaging protocol.

This repository is the supported home for everything beyond the tightbeam core: additional transports, browser/WebAssembly clients, and the various packages that let non-Rust environments speak tightbeam.

## Extensions

Each extension lives in its own directory carrying everything it needs: crates, browser packages, and end-to-end tests. Each carries its own README with usage and design details.

### [ws/](ws) - WebSocket transport

- **[ws/tightbeam-ws](ws/tightbeam-ws)** - the host transport. Carries DER-encoded tightbeam envelopes as WebSocket binary frames ([RFC 6455](https://www.rfc-editor.org/rfc/rfc6455)), one envelope per message, with cleartext and ECIES-encrypted round-trips. Published to crates.io.
- **[ws/client](ws/client)** - `@wahidgroup/tightbeam-ws-client`, the published hybrid TS/wasm package for browsers and Node. Fluent frame builder with algorithm selection, `Frame` with Rust-parity verification methods, `Signatory` external signers, and ECIES sessions.

### [pubsub/](pubsub) - Topic pub/sub

- **[pubsub/tightbeam-pubsub](pubsub/tightbeam-pubsub)** - server-side topic registry over the core mux: publish fan-out with dense per-topic ordering, bounded per-subscriber queues with delivery policies, subscribe authorization, and orderly quiesce. Carrier-agnostic, no new wire protocol.
- **[pubsub/client](pubsub/client)** - `@wahidgroup/tightbeam-pubsub-client`, typed subscribe/unsubscribe lifecycle over the ws client: exact-match dispatch, per-topic ordering gates with gap detection, completion callbacks, and reconnect replay.

## Development

```sh
make setup       # toolchains + npm workspaces + Playwright (idempotent)
make lint        # rustfmt + clippy -D warnings + eslint/prettier + cspell
make lint fix=1  # apply lint/format fixes
make test        # cargo tests (all features) + dockerized e2e (TS app)
make build       # cargo build --release
make audit       # cargo audit + npm audit
make ci          # full CI pipeline
```

Each extension owns its targets in `<project>/Makefile` and its setup in
`<project>/scripts/setup.sh`. The root composes them. Naming a project
scopes a target to it:

```sh
make test ws     # ws only: cargo + vitest + its e2e lanes
make lint pubsub # pubsub only
make setup ws    # skips the pubsub install entirely
```

Run `make help` for the full target list.

## Releasing

```sh
make release version=v0.1.0            # release the default extension (ws)
make release version=v0.1.0 ext=ws     # release a named extension
make release                           # prompt for the next version
make release version=v0.1.0 dry-run=1  # preview without mutations
make release yank=1                    # yank a published version
```

Extensions are released independently: each top-level extension directory (e.g. `ws/`) versions its crates on its own. A release bumps that extension's versions, opens a release pull request, and on merge creates a signed `releases/<ext>/v<version>` tag. Pushing that tag publishes that extension's publishable crates to crates.io (Cargo multi-package, dependency order - not the whole workspace) and creates the GitHub release. The deploy guard `check-yanked.sh` refuses yanked versions (`yanked/<ext>/v<version>`).

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
