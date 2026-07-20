# tightbeam-ext

Official, canonical extensions for the [tightbeam](https://crates.io/crates/tightbeam-rs) messaging protocol.

tightbeam ships with a raw TCP transport (`tightbeam::transport::tcp`). This repository is the supported home for everything beyond that core: additional transports, browser/WebAssembly clients, and the TypeScript packages that let non-Rust environments speak tightbeam.

## Extensions

Each extension lives in its own directory carrying everything it needs: crates, browser packages, and end-to-end tests. Each carries its own README with usage and design details.

### [ws/](ws) - WebSocket transport

- **[ws/tightbeam-ws](ws/tightbeam-ws)** - the host transport. Carries DER-encoded tightbeam envelopes as WebSocket binary frames ([RFC 6455](https://www.rfc-editor.org/rfc/rfc6455)), one envelope per message, with cleartext and ECIES-encrypted round-trips. Published to crates.io.
- **[ws/tightbeam-ws-wasm](ws/tightbeam-ws-wasm)** - the browser counterpart, compiled to WebAssembly via `wasm-pack`. Not published to crates.io; consumed by the web client package below.
- **[ws/client](ws/client)** - `@wahidgroup/tightbeam-ws-client`, the published hybrid TS/wasm package for browsers and Node. Fluent frame builder with algorithm selection, `Frame` with Rust-parity verification methods, `Signatory` external signers, and ECIES sessions.
- **[ws/tests](ws/tests)** - end-to-end suites exercising the compiled client against dockerized echo servers: Playwright (Chromium) plus a vitest lane on Node's global WebSocket.

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

Run `make help` for the full target list.

## Releasing

```sh
make release version=v0.1.0            # release at an explicit version
make release                           # prompt for the next version
make release version=v0.1.0 dry-run=1  # preview without mutations
make release yank=1                    # yank a published version
```

A release bumps the workspace version, opens a release pull request, and on merge creates a signed `releases/v<version>` tag. Pushing that tag publishes `tightbeam-ws` to crates.io and creates the GitHub release. The deploy guard `check-yanked.sh` refuses yanked versions (`yanked/v<version>`).

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
