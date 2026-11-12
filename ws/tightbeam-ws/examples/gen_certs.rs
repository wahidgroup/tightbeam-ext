//! Write the server and the client identity of the e2e stack under
//! `CERT_DIR`, as `docs/ws.md` (Demo servers) states it.
//!
//! Usage:
//!
//! ```sh
//! CERT_DIR=./.dev/certs \
//!   cargo run -p tightbeam-ws --features testing --example gen_certs
//! ```

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use tightbeam_ws::testing::{EnvVar, Identity, IdentityFiles};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

const ONE_YEAR: Duration = Duration::from_secs(365 * 24 * 60 * 60);

fn main() -> Result<(), BoxError> {
	let dir = EnvVar::new("CERT_DIR").parsed_or(PathBuf::from("./.dev/certs"))?;
	fs::create_dir_all(&dir)?;

	let server = Identity::mint("CN=tightbeam-ws echo,O=tightbeam-ws,C=US", 1, ONE_YEAR)?;
	let client = Identity::mint("CN=tightbeam-ws client,O=tightbeam-ws,C=US", 2, ONE_YEAR)?;
	IdentityFiles::new(&dir, "server")?.provision(&server)?;
	IdentityFiles::new(&dir, "client")?.provision(&client)?;
	println!("[gen-certs] wrote the server and client identities under {}", dir.display());

	Ok(())
}
