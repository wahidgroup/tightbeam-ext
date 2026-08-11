# asn

DER-backed ASN.1 codec bridge for TypeScript `MessageCodec` façades over [tightbeam](https://crates.io/crates/tightbeam-rs) wire types.

## Contents

- **[tightbeam-asn](tightbeam-asn)** - published package: `AsnCodec` trait, JS helpers, derive entry, and the `tightbeam-asn-emit` binary that writes consumer MessageCodec TypeScript modules
- **[tightbeam-asn-derive](tightbeam-asn-derive)** - `#[derive(AsnCodec)]`

See [tightbeam-asn/README.md](tightbeam-asn/README.md) for emit usage and the field map.

## Development

```sh
make setup asn
make test asn
make lint asn
```

## License

Licensed under either of [MIT](../LICENSE-MIT) or [Apache-2.0](../LICENSE-APACHE) at your option.
