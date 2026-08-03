//! Register AFL's `cfg(fuzzing)` as expected.
//!
//! Declared here (not `[lints.rust.unexpected_cfgs].check-cfg`) so Cargo.toml
//! stays valid under SchemaStore / Even Better TOML validators that still
//! reject the `check-cfg` lint object form.
fn main() {
	println!("cargo::rustc-check-cfg=cfg(fuzzing)");
}
