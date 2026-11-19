# store

A driver-agnostic store of [tightbeam](https://crates.io/crates/tightbeam-rs) frames, typed by message.

## Status

This project is under active development. Public APIs MAY change without notice. No security audit has been conducted. Use this software at your own risk.

## Contents

- [tightbeam-store](tightbeam-store): the published package, with the `Storable` and `Catalog` traits and their derives.
- [tightbeam-store-derive](tightbeam-store-derive): the `#[derive(Storable)]` and `#[derive(Catalog)]` proc macros.

The [tightbeam-store README](tightbeam-store/README.md) holds the quick start. Implementation: [docs/store.md](../docs/store.md).

## Development

```sh
make setup store
make test store
make lint store
```

Implementation: [docs/development.md](../docs/development.md).

## License

Licensed under either of [MIT](../LICENSE-MIT) or [Apache-2.0](../LICENSE-APACHE) at your option.
