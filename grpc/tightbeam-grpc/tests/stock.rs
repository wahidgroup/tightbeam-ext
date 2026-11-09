//! A stock gRPC caller in another language through the coupled edge of the
//! docker stack, as a tightbeam scenario.
//!
//! The stack runs a gateway whose coupled edge serves `orders.v1.Orders/Get`
//! over TLS. The scenario runs grpcurl, a Go gRPC client, in its own
//! container: it loads the root, its client certificate, and `orders.proto`
//! from the files of the stack, encodes an `Order` as protobuf, and calls the
//! edge, whose servlet answers with the same `Order`. No code under test
//! records what grpcurl read, so the scenario records it as its own event.
//!
//! The case compiles under the `e2e` feature alone, and runs in the grpc e2e
//! lane, `grpc/scripts/test-e2e.sh`, which reads the port of the edge and the
//! certificate directory of the stack from the stack environment.

use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::Duration;

use tightbeam::testing::error::TestingError;
use tightbeam::testing::SetupEnv;
use tightbeam::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_scenario, urn, TightBeamError};
use tightbeam_ws::testing::EnvVar;

/// The host port of the coupled edge, which the stack allocates.
const COUPLED_PORT: EnvVar = EnvVar::new("GRPC_COUPLED_HOST_PORT");

/// The directory of the stack identities, whose `coupled` directory holds
/// the TLS material of the coupled edge.
const CERT_DIR: EnvVar = EnvVar::new("CERT_DIR");

/// grpcurl, pinned by digest.
const GRPCURL: &str =
	"fullstorydev/grpcurl:v1.9.3@sha256:085e183ca334eb4e81ca81ee12cbb2b2737505d1d77f5e33dabc5d066593d998";

/// The order that the caller sends, and reads back.
const ORDER: &str = "order-7";

/// What grpcurl read from the edge: the order id of the answer, or `failed`.
const STOCK_ANSWER: Urn<'static> = urn!("test", "event:stock/answer");

/// How long the scenario retries while the loopback session of the coupler
/// opens.
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

	/// One call of `orders.v1.Orders/Get` by grpcurl, on the host network, so
	/// it dials the edge on loopback as the certificate of the edge names it.
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

// grpcurl calls the coupled edge of the stack with a client certificate and a
// protobuf `Order`, and reads the same `Order` back from the servlet.
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
