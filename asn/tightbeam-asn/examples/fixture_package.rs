//! The fixture wire types of the integration tests as a wasm package.
//!
//! A consumer derives `AsnCodec` on its wire types, builds the crate for
//! `wasm32`, and runs `tightbeam-asn-emit` over the `.d.ts` that the build
//! writes. This example is that crate for the fixture types, so the emit
//! integration of `asn/tests` reads the declarations and runs the exports
//! that a real build writes.

#[path = "../tests/fixtures/mod.rs"]
pub mod fixtures;
