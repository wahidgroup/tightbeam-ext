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
use tightbeam_grpc::testing::CoupledStack;
use tightbeam_ws::testing::{EnvVar, Identity, IdentityFiles};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

const ONE_YEAR: Duration = Duration::from_secs(365 * 24 * 60 * 60);

fn main() -> Result<(), BoxError> {
	let base = EnvVar::new("CERT_DIR").parsed_or(PathBuf::from("./.dev/certs"))?;
	let files = CoupledStack::under(base);
	if files.exists() {
		return Ok(());
	}

	files.write(ONE_YEAR, |staged| -> Result<(), BoxError> {
		let claims = Identity::mint(CoupledStack::SIGNER, 1, ONE_YEAR)?;
		fs::write(staged.claims(), claims.certificate().to_pem(LineEnding::LF)?)?;
		IdentityFiles::new(staged.dir(), CoupledStack::CLAIMS)?.provision(&claims)?;
		Ok(())
	})?;

	println!(
		"[gen-coupled-certs] wrote the TLS material of the coupled edge under {}",
		files.dir().display()
	);

	Ok(())
}
