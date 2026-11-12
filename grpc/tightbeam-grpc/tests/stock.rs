//! Stock gRPC callers through the coupled edge of the docker stack. Runs in
//! the grpc e2e lane, under the `e2e` feature.

mod support;

use std::path::PathBuf;
use std::process::{Command, Output};

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use tightbeam_grpc::couple::ClaimSigner;
use tightbeam_grpc::protocol::GrpcAddr;
use tightbeam_grpc::testing::CoupledStack;
use tightbeam_ws::testing::IdentityFiles;
use tonic::transport::{Certificate as TonicCertificate, ClientTlsConfig, Endpoint, Identity as TonicIdentity};

use tightbeam::testing::SetupEnv;
use tightbeam::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_scenario, urn, TightBeamError};
use tightbeam_ws::testing::EnvVar;

use support::{ScenarioClock, StockChannel, OPENING};

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

/// What a call of the signing caller with no claim read from the edge:
/// `denied` or `other`.
const UNSIGNED_ANSWER: Urn<'static> = urn!("test", "event:stock/unsigned");

/// The coupled edge of the stack, and the files that a stock caller loads.
struct Stack {
	port: u16,
	files: CoupledStack,
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
		Self { port, files: CoupledStack::under(certs), proto }
	}

	/// One call of `Get` by grpcurl, on the host network, where the edge
	/// certificate names loopback, which grpcurl ends past [`OPENING`].
	fn grpcurl(&self) -> std::io::Result<Output> {
		let mounted = CoupledStack::at("/coupled");
		let certs = format!("{}:{}:ro", self.files.dir().display(), mounted.dir().display());
		let proto = format!("{}:/proto:ro", self.proto.display());
		let request = format!(r#"{{"id":"{ORDER}"}}"#);
		let target = format!("localhost:{}", self.port);
		let method = CoupledStack::GET.trim_start_matches('/');
		let (root, caller, key) = (mounted.root(), mounted.caller_chain(), mounted.caller_key());

		Command::new("docker")
			.args(["run", "--rm", "--network", "host", "-v", &certs, "-v", &proto, GRPCURL])
			.arg("-cacert")
			.arg(root)
			.arg("-cert")
			.arg(caller)
			.arg("-key")
			.arg(key)
			.args(["-servername", "localhost", "-import-path", "/proto", "-proto", "orders.proto"])
			.arg("-max-time")
			.arg(OPENING.as_secs_f64().to_string())
			.args(["-d", &request, &target, method])
			.output()
	}

	/// The order id that grpcurl read, once the coupler serves.
	async fn answer(&self) -> Result<String, TightBeamError> {
		self.signer_channel().await?.serving(&ScenarioClock::System).await?;
		let output = self.grpcurl()?;
		let printed = String::from_utf8_lossy(&output.stdout);
		if output.status.success() && printed.contains(ORDER) {
			return Ok(ORDER.to_owned());
		}

		eprintln!("grpcurl: {}", String::from_utf8_lossy(&output.stderr));
		Err(support::unexpected("grpcurl did not read its order"))
	}
}

impl Stack {
	/// A tonic channel to the edge under the signing caller of the stack.
	async fn signer_channel(&self) -> Result<StockChannel, TightBeamError> {
		let read = std::fs::read_to_string;
		let root = TonicCertificate::from_pem(read(self.files.root())?);
		let identity = TonicIdentity::from_pem(read(self.files.signer_chain())?, read(self.files.signer_key())?);
		let tls = ClientTlsConfig::new()
			.ca_certificate(root)
			.domain_name("localhost")
			.identity(identity);

		let edge = GrpcAddr::from(std::net::SocketAddr::from(([127, 0, 0, 1], self.port)));
		let endpoint = Endpoint::from_shared(format!("https://{edge}")).map_err(support::unexpected)?;
		let endpoint = endpoint.tls_config(tls).map_err(support::unexpected)?;
		let channel = support::bounded(endpoint.connect()).await?.map_err(support::unexpected)?;
		Ok(StockChannel::from(channel))
	}

	/// One signed call of `Place`, once the coupler serves.
	async fn signed(&self, body: &[u8]) -> Result<Vec<u8>, TightBeamError> {
		let channel = self.signer_channel().await?;
		channel.serving(&ScenarioClock::System).await?;
		let leaf = CertificateDer::from_pem_file(self.files.signer_chain()).map_err(support::unexpected)?;
		let identity = IdentityFiles::new(self.files.dir(), CoupledStack::CLAIMS)?.load()?;
		let signer = ClaimSigner::new(identity.signing_identity(), [], &leaf);
		let place = CoupledStack::PLACE.parse().map_err(support::edge_error)?;

		let claim = signer.sign(&place, body).await?;
		let answer = channel.call(CoupledStack::PLACE, body, Some(&claim)).await?;
		answer.map_err(support::unexpected)
	}
}

tb_assert_spec! {
	/// The signed call reads back the order it sent, and the same call with
	/// no claim proves less than the route requires.
	pub SignedCallSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(SIGNED_ANSWER, exactly!(1), equals!("served")),
			(UNSIGNED_ANSWER, exactly!(1), equals!("denied"))
		]
	}
}

// A tonic caller signs a claim, which the edge and the servlet both verify,
// and its call with no claim is denied.
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

			let unsigned = context.signer_channel().await?.call(CoupledStack::PLACE, &order, None).await?;
			let denied = support::code_of(unsigned) == Some(tonic::Code::PermissionDenied);
			trace.event_with(UNSIGNED_ANSWER, &[], if denied { "denied" } else { "other" })?;
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
