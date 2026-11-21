# tightbeam-store

A driver-agnostic store of [tightbeam](https://crates.io/crates/tightbeam-rs) frames, typed by message.

## Status

This project is under active development. Public APIs MAY change without notice. No security audit has been conducted. Use this software at your own risk.

## Install

```sh
cargo add tightbeam-store
```

A message type also takes `tightbeam-rs` and the `derive` feature of `der` 0.7:

```sh
cargo add tightbeam-rs der@0.7 --features der/derive
```

## Declare a type

A tightbeam message derives `Storable` to name its table and its row id. A `Catalog` lists the types that one store holds, and two types that claim one table fail to compile.

```rust
use der::Sequence;
use tightbeam::Beamable;
use tightbeam_store::{Catalog, RowId, RowKey, Storable, StoreError};

#[derive(Beamable, Sequence, Storable, Clone, Debug, PartialEq)]
#[storable(frame_type = "colony-leaf")]
pub struct HiveLeaf {
	#[storable(id)]
	pub id: RowId,
	pub colony: String,
}

#[derive(Catalog)]
#[catalog(HiveLeaf)]
pub struct Colony;

let leaf = HiveLeaf { id: RowId::from(*b"leaf-42"), colony: String::from("north") };
let key = RowKey::new(HiveLeaf::FRAME_TYPE, leaf.row_id())?;

assert!(Colony::TABLES.holds(HiveLeaf::FRAME_TYPE));
assert_eq!(key.urn().to_string(), "urn:tightbeam:store:colony-leaf:6c6561662d3432");
# Ok::<(), StoreError>(())
```

Implementation: [docs/store.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/store.md).

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
