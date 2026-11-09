//! Writes the TLS material of the coupled edge of the e2e stack under
//! `$CERT_DIR/coupled`, and keeps material that exists.
//!
//! ```sh
//! CERT_DIR=./.dev/e2e/certs cargo run -p tightbeam-grpc --features couple,testing --example gen_coupled_certs
//! ```

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use tightbeam::der::pem::LineEnding;
use tightbeam::der::EncodePem;
use tightbeam_grpc::testing::TlsAuthority;
use tightbeam_ws::testing::{EnvVar, Identity, IdentityFiles};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

const ONE_YEAR: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// The subject of the signing caller, and of the claim identity it signs
/// under.
const SIGNER: &str = "CN=coupled claims,O=acme,C=US";

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
	let signer = authority.caller(SIGNER, None)?;
	let claims = Identity::mint(SIGNER, 1, ONE_YEAR)?;

	fs::write(dir.join("root.pem"), authority.root_pem()?)?;
	fs::write(dir.join("edge.crt"), edge.certificate_pem())?;
	fs::write(dir.join("edge.key"), edge.key_pem())?;
	fs::write(dir.join("caller.crt"), caller.certificate_pem())?;
	fs::write(dir.join("caller.key"), caller.key_pem())?;
	fs::write(dir.join("signer.crt"), signer.certificate_pem())?;
	fs::write(dir.join("signer.key"), signer.key_pem())?;
	fs::write(dir.join("claims.pem"), claims.certificate().to_pem(LineEnding::LF)?)?;
	IdentityFiles::new(&dir, "claims")?.provision(&claims)?;
	println!(
		"[gen-coupled-certs] wrote the TLS material of the coupled edge under {}",
		dir.display()
	);

	Ok(())
}
