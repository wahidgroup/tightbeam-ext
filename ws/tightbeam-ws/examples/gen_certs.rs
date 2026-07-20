//! Generate X.509 identity fixtures for the encrypted end-to-end stack.
//!
//! Creates a server and a client self-signed root identity and writes each as
//! a DER certificate plus a raw 32-byte signing key under `CERT_DIR`.
//!
//! Usage:
//!   CERT_DIR=./.dev/certs cargo run -p tightbeam-ws --features testing --example gen_certs

use std::env;
use std::fs;
use std::path::Path;
use std::time::Duration;

use tightbeam_ws::testing::Identity;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

const ONE_YEAR: Duration = Duration::from_secs(365 * 24 * 60 * 60);

fn write_identity(dir: &Path, name: &str, identity: &Identity) -> Result<(), BoxError> {
	let cert_path = dir.join(format!("{name}.cert.der"));
	let key_path = dir.join(format!("{name}.key"));

	fs::write(&cert_path, identity.certificate_der()?)?;
	fs::write(&key_path, identity.signing_key_bytes())?;

	println!("[gen-certs] wrote {} + {}", cert_path.display(), key_path.display());

	Ok(())
}

fn main() -> Result<(), BoxError> {
	let dir = env::var("CERT_DIR").unwrap_or_else(|_| "./.dev/certs".to_string());
	let dir = Path::new(&dir);
	fs::create_dir_all(dir)?;

	let server = Identity::mint_root("CN=tightbeam-ws echo,O=tightbeam-ws,C=US", 1, ONE_YEAR)?;
	let client = Identity::mint_root("CN=tightbeam-ws client,O=tightbeam-ws,C=US", 2, ONE_YEAR)?;

	write_identity(dir, "server", &server)?;
	write_identity(dir, "client", &client)?;

	Ok(())
}
