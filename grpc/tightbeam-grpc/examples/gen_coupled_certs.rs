//! Generate the TLS material of the coupled edge of the end-to-end stack.
//!
//! Mints one TLS root, and writes under `$CERT_DIR/coupled`:
//!
//! - `root.pem`: the root, which the edge trusts its callers under, and which
//!   a caller trusts the edge under.
//! - `edge.crt` and `edge.key`: the certificate of the edge for `localhost`
//!   and loopback, and its key.
//! - `caller.crt` and `caller.key`: the client certificate of the stock
//!   caller, the SPIFFE ID `spiffe://acme/grpcurl`, and its key.
//! - `claims.pem`: the root that the claims of the edge verify under.
//!
//! The step is idempotent: material that exists stays, so a restart of the
//! stack keeps its trust anchors.
//!
//! Usage:
//!
//! ```sh
//! CERT_DIR=./.dev/e2e/certs \
//!   cargo run -p tightbeam-grpc --features couple,testing --example gen_coupled_certs
//! ```

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use tightbeam::der::pem::LineEnding;
use tightbeam::der::EncodePem;
use tightbeam_grpc::testing::TlsAuthority;
use tightbeam_ws::testing::{EnvVar, Identity};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

const ONE_YEAR: Duration = Duration::from_secs(365 * 24 * 60 * 60);

fn main() -> Result<(), BoxError> {
	let base = EnvVar::new("CERT_DIR").parsed_or(PathBuf::from("./.dev/certs"))?;
	let dir = base.join("coupled");
	if dir.join("root.pem").is_file() {
		return Ok(());
	}

	fs::create_dir_all(&dir)?;

	let authority = TlsAuthority::mint("CN=coupled edge root,O=acme,C=US", ONE_YEAR)?;
	let edge = authority.server("CN=coupled edge,O=acme,C=US")?;
	let caller = authority.caller("CN=grpcurl,O=acme,C=US", Some("spiffe://acme/grpcurl"))?;
	let claims = Identity::mint("CN=coupled claims,O=acme,C=US", 1, ONE_YEAR)?;

	fs::write(dir.join("root.pem"), authority.root_pem()?)?;
	fs::write(dir.join("edge.crt"), edge.certificate_pem())?;
	fs::write(dir.join("edge.key"), edge.key_pem())?;
	fs::write(dir.join("caller.crt"), caller.certificate_pem())?;
	fs::write(dir.join("caller.key"), caller.key_pem())?;
	fs::write(dir.join("claims.pem"), claims.certificate().to_pem(LineEnding::LF)?)?;
	println!(
		"[gen-coupled-certs] wrote the TLS material of the coupled edge under {}",
		dir.display()
	);

	Ok(())
}
