# asn

DER-backed ASN.1 codec bridge for TypeScript `MessageCodec` façades over [tightbeam](https://crates.io/crates/tightbeam-rs) DER types.

## Status

This project is under active development. Public APIs MAY change without notice. No security audit has been conducted. Use this software at your own risk.

## Contents

- [tightbeam-asn](tightbeam-asn): the published package, with the `AsnCodec` trait and derive and the `tightbeam-asn-emit` binary.
- [tightbeam-asn-derive](tightbeam-asn-derive): the `#[derive(AsnCodec)]` proc macro.
- [tightbeam-asn-names](tightbeam-asn-names): the TypeScript type-name rule that the derive and the emitter share.

The [tightbeam-asn README](tightbeam-asn/README.md) holds the quick start. Implementation: [docs/asn.md](../docs/asn.md).

## Development

```sh
make setup asn
make test asn
make lint asn
```

Implementation: [docs/development.md](../docs/development.md).

## License

Licensed under either of [MIT](../LICENSE-MIT) or [Apache-2.0](../LICENSE-APACHE) at your option.
