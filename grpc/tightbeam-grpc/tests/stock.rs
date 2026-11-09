//! Stock gRPC callers through the coupled edge of the docker stack. Runs in
//! the grpc e2e lane, under the `e2e` feature.

mod support;

use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::Duration;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use tightbeam_grpc::couple::ClaimSigner;
use tightbeam_grpc::protocol::GrpcAddr;
use tightbeam_ws::testing::IdentityFiles;
use tonic::transport::{
	Certificate as TonicCertificate, Channel, ClientTlsConfig, Endpoint, Identity as TonicIdentity,
};

use tightbeam::testing::error::TestingError;
use tightbeam::testing::SetupEnv;
use tightbeam::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_scenario, urn, TightBeamError};
use tightbeam_ws::testing::EnvVar;

/// The host port of the coupled edge, which the stack allocates.
const COUPLED_PORT: EnvVar = EnvVar::new("GRPC_COUPLED_HOST_PORT");

/// The directory of the stack identities.
const CERT_DIR: EnvVar = EnvVar::new("CERT_DIR");

/// grpcurl, pinned by digest.
const GRPCURL: &str =
	"fullstorydev/grpcurl:v1.9.3@sha256:085e183ca334eb4e81ca81ee12cbb2b2737505d1d77f5e33dabc5d066593d998";

/// The order that the caller sends, and reads back.
const ORDER: &str = "order-7";

/// What grpcurl read from the edge: the order id of the answer, or `failed`.
const STOCK_ANSWER: Urn<'static> = urn!("test", "event:stock/answer");

/// What the signed call read from the edge: `served` or `failed`.
const SIGNED_ANSWER: Urn<'static> = urn!("test", "event:stock/signed");

/// The signed method of the coupled edge.
const PLACE: &str = "/orders.v1.Orders/Place";

/// How long a case retries while the coupler opens its session.
const OPENING: Duration = Duration::from_secs(20);

/// The coupled edge of the stack, and the files that a stock caller loads.
struct Stack {
	port: u16,
	certs: PathBuf,
	proto: PathBuf,
}

impl Stack {
	/// The stack that the e2e lane exports.
	fn exported() -> Self {
		let port = COUPLED_PORT
			.parsed()
			.expect("the grpc e2e lane exports the port of the coupled edge");
		let certs: PathBuf = CERT_DIR.parsed().expect("the grpc e2e lane exports the certificate directory");
		let proto = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../docker/proto");
		Self { port, certs: certs.join("coupled"), proto }
	}

	/// One call of `Get` by grpcurl, on the host network, where the edge
	/// certificate names loopback.
	fn grpcurl(&self) -> std::io::Result<Output> {
		let certs = format!("{}:/coupled:ro", self.certs.display());
		let proto = format!("{}:/proto:ro", self.proto.display());
		let request = format!(r#"{{"id":"{ORDER}"}}"#);
		let target = format!("localhost:{}", self.port);

		Command::new("docker")
			.args(["run", "--rm", "--network", "host", "-v", &certs, "-v", &proto, GRPCURL])
			.args([
				"-cacert",
				"/coupled/root.pem",
				"-cert",
				"/coupled/caller.crt",
				"-key",
				"/coupled/caller.key",
			])
			.args(["-servername", "localhost", "-import-path", "/proto", "-proto", "orders.proto"])
			.args(["-d", &request, &target, "orders.v1.Orders/Get"])
			.output()
	}

	/// The order id that grpcurl read, retried until the coupler serves.
	async fn answer(&self) -> Result<String, TightBeamError> {
		let deadline = tokio::time::Instant::now() + OPENING;
		loop {
			let output = self.grpcurl()?;
			let printed = String::from_utf8_lossy(&output.stdout);
			if output.status.success() && printed.contains(ORDER) {
				return Ok(ORDER.to_owned());
			}

			if tokio::time::Instant::now() >= deadline {
				eprintln!("grpcurl: {}", String::from_utf8_lossy(&output.stderr));
				return Err(TightBeamError::TestingError(TestingError::UnexpectedOutcome(
					"grpcurl never read its order",
				)));
			}

			tokio::time::sleep(Duration::from_millis(500)).await;
		}
	}
}

impl Stack {
	/// A tonic channel to the edge under the signing caller of the stack.
	async fn signer_channel(&self) -> Result<Channel, TightBeamError> {
		let read = |name: &str| std::fs::read_to_string(self.certs.join(name));
		let root = TonicCertificate::from_pem(read("root.pem")?);
		let identity = TonicIdentity::from_pem(read("signer.crt")?, read("signer.key")?);
		let tls = ClientTlsConfig::new()
			.ca_certificate(root)
			.domain_name("localhost")
			.identity(identity);

		let edge = GrpcAddr::from(std::net::SocketAddr::from(([127, 0, 0, 1], self.port)));
		let endpoint = Endpoint::from_shared(format!("https://{edge}")).map_err(support::unexpected)?;
		endpoint
			.tls_config(tls)
			.map_err(support::unexpected)?
			.connect()
			.await
			.map_err(support::unexpected)
	}

	/// One signed call of `Place`, retried until the coupler serves.
	async fn signed(&self, body: &[u8]) -> Result<Vec<u8>, TightBeamError> {
		let channel = self.signer_channel().await?;
		let leaf = CertificateDer::from_pem_file(self.certs.join("signer.crt")).map_err(support::unexpected)?;
		let identity = IdentityFiles::new(&self.certs, "claims")?.load()?;
		let signer = ClaimSigner::new(identity.signing_identity()?, [], &leaf);

		let deadline = tokio::time::Instant::now() + OPENING;
		loop {
			let claim = signer.sign(PLACE, body).await?;
			let answer = support::call(&channel, PLACE, body, Some(&claim)).await;
			match answer {
				Ok(answer) => return Ok(answer),
				Err(status) if tokio::time::Instant::now() >= deadline => {
					eprintln!("signed call: {status:?}");
					return Err(TightBeamError::TestingError(TestingError::UnexpectedOutcome(
						"the signed call never served",
					)));
				}
				Err(_) => tokio::time::sleep(Duration::from_millis(500)).await,
			}
		}
	}
}

tb_assert_spec! {
	/// The signed call reads back the order it sent.
	pub SignedCallSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(SIGNED_ANSWER, exactly!(1), equals!("served"))
		]
	}
}

// A tonic caller signs a claim, which the edge and the servlet both verify.
tb_scenario! {
	name: a_signed_call_reaches_a_servlet_through_the_coupled_edge,
	spec: SignedCallSpec,
	environment Bare {
		context: Stack::exported(),
		exec: |SetupEnv { trace, context }| async move {
			let order = [&[0x0a, 7][..], b"order-8"].concat();
			let answer = context.signed(&order).await;
			let read = if answer.as_deref().ok() == Some(order.as_slice()) { "served" } else { "failed" };
			trace.event_with(SIGNED_ANSWER, &[], read)?;
			answer.map(|_| ())
		}
	}
}

tb_assert_spec! {
	/// grpcurl reads back the order it sent.
	pub StockCallSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(STOCK_ANSWER, exactly!(1), equals!(ORDER))
		]
	}
}

// grpcurl, a Go client, sends an `Order` and reads it back.
tb_scenario! {
	name: grpcurl_reaches_a_servlet_through_the_coupled_edge,
	spec: StockCallSpec,
	environment Bare {
		context: Stack::exported(),
		exec: |SetupEnv { trace, context }| async move {
			let answer = context.answer().await;
			let read = answer.as_deref().unwrap_or("failed").to_owned();
			trace.event_with(STOCK_ANSWER, &[], read)?;
			answer.map(|_| ())
		}
	}
}
