//! The stock gRPC harness that the coupler and the adapter scenarios share:
//! the identities and the TLS PKI of a scenario, a coupler built from them, a
//! stock tonic caller over its own TLS, and the configs that grade a run.
//!
//! Each test binary compiles this module on its own, and uses part of it.
#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, BufMut};
use http::uri::PathAndQuery;
use tightbeam::colony::cluster::{Cluster, ClusterGateway};
use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::x509::policy::CertificateValidation;
use tightbeam::crypto::x509::store::{CertificateTrustBuilder, NoRevocation, TrustBuilder};
use tightbeam::crypto::x509::KeyCurves;
use tightbeam::testing::error::TestingError;
use tightbeam::testing::macros::BuiltAssertSpec;
use tightbeam::testing::{Expect, Layer, ScenarioConfig, ScenarioConfigError};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::handshake::PeerAuthentication;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::Protocol;
use tightbeam::TightBeamError;
use tightbeam_grpc::couple::{CallClaim, CallerTrust, ClaimSigner, Coupler, Grants, Routes, Servlet, Voucher};
use tightbeam_grpc::edge::{Dial, Edge};
use tightbeam_grpc::protocol::{GrpcAddr, HEALTH_CHECK_PATH};
use tightbeam_grpc::testing::{TlsAuthority, TlsLeaf};
use tightbeam_ws::testing::Identity;
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::transport::{
	Certificate as TonicCertificate, Channel, ClientTlsConfig, Endpoint, Identity as TonicIdentity,
};
use tonic::{Request, Status};

/// The SPIFFE ID of the billing caller.
pub const BILLING: &str = "spiffe://acme/billing";

/// The subject of the web caller, and of the identity its claims sign under.
pub const WEB: &str = "CN=web,O=acme,C=US";

/// How long every identity of a scenario stays valid.
pub const LIFETIME: Duration = Duration::from_secs(3600);

/// How long a scenario waits for the loopback session of its coupler to open.
pub const OPENING: Duration = Duration::from_secs(5);

/// Declare the staged profile `$edge` of one scenario, and the gateway
/// `$gateway` whose coupled edge binds under it.
#[macro_export]
macro_rules! coupled {
	($edge:ident, $gateway:ident) => {
		tightbeam_grpc::staged_profile! {
			/// The coupled edge of one scenario.
			$edge
		}

		tightbeam::cluster! {
			/// The gateway of one scenario, with its coupled edge.
			pub $gateway,
			protocol: tightbeam::transport::tcp::r#async::TokioListener,
			edge: tightbeam_grpc::protocol::GrpcListener<tightbeam::crypto::profiles::DefaultCryptoProvider, $edge>
		}
	};
}

/// The codec of a stock call whose messages the scenario encodes itself.
#[derive(Clone, Copy, Debug, Default)]
pub struct RawCodec;

impl Codec for RawCodec {
	type Encode = Vec<u8>;
	type Decode = Vec<u8>;
	type Encoder = RawCodec;
	type Decoder = RawCodec;

	fn encoder(&mut self) -> Self::Encoder {
		*self
	}

	fn decoder(&mut self) -> Self::Decoder {
		*self
	}
}

impl Encoder for RawCodec {
	type Item = Vec<u8>;
	type Error = Status;

	fn encode(&mut self, item: Vec<u8>, dst: &mut EncodeBuf<'_>) -> Result<(), Status> {
		dst.put_slice(&item);
		Ok(())
	}
}

impl Decoder for RawCodec {
	type Item = Vec<u8>;
	type Error = Status;

	fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Vec<u8>>, Status> {
		let length = src.remaining();
		Ok(Some(src.copy_to_bytes(length).to_vec()))
	}
}

/// The identities and the TLS PKI of one scenario.
pub struct Coupled {
	/// The colony: the gateway, the hive, and the servlet run under it.
	pub transport: Identity,
	/// The signer of the answers of the servlet, which each route pins.
	pub answers: Identity,
	/// The handshake identity of the loopback session of the coupler.
	pub session: Identity,
	/// The signer of the calls the coupler vouches for.
	pub vouching: Identity,
	/// The identity that the web caller signs its claims and its direct calls
	/// under.
	pub claims: Identity,
	/// The root of the TLS of the edge, of every caller, and of a backend.
	pub tls: TlsAuthority,
}

impl Coupled {
	/// Mint every identity of a scenario.
	pub fn mint() -> Self {
		let identity = |subject: &str, serial| Identity::mint(subject, serial, LIFETIME).expect("an identity mints");
		let tls = TlsAuthority::mint("CN=edge root,O=acme,C=US", LIFETIME).expect("a TLS root mints");
		Self {
			transport: identity("CN=colony,O=acme,C=US", 1),
			answers: identity("CN=orders servlet,O=acme,C=US", 2),
			session: identity("CN=coupler session,O=acme,C=US", 3),
			vouching: identity("CN=coupler,O=acme,C=US", 4),
			claims: identity(WEB, 5),
			tls,
		}
	}

	/// The coupler of the edge, which routes `routes`, grants `grants`, and
	/// records on `trace`.
	pub fn coupler(
		&self,
		trace: &TraceCollector,
		routes: Routes<Servlet>,
		grants: Grants,
	) -> Result<Coupler, TightBeamError> {
		let callers = CallerTrust::new([self.tls.root()], self.claims.trust_anchor()?).map_err(edge_error)?;
		let voucher = Voucher::new(self.session.signing_identity()?, self.vouching.signing_identity()?);
		let coupler = Coupler::new(callers, voucher, routes, grants).map_err(edge_error)?;
		Ok(coupler.with_trace(trace.share()))
	}

	/// Stage the coupled edge of `coupler` through `stage`.
	pub fn stage_coupler(&self, stage: fn(Edge, Dial), coupler: Coupler) -> Result<(), TightBeamError> {
		let tls = self.tls.edge("CN=orders edge,O=acme,C=US").map_err(mint_error)?;
		let dial = self.tls.dial().map_err(edge_error)?;
		stage(Edge::Coupled(tls, coupler), Dial::Tls(dial));
		Ok(())
	}

	/// Start the gateway `G`, whose edge binds on loopback.
	pub async fn gateway<G: Cluster>(&self, trace: &TraceCollector) -> Result<G, TightBeamError> {
		let config = self.transport.cluster_config("127.0.0.1:0")?;
		G::start(Arc::new(trace.share()), config).await
	}

	/// Start the gateway `G`, whose accept planes authenticate each client
	/// under the certificates of `trusted` alone.
	pub async fn mutual_gateway<G: Cluster>(
		&self,
		trace: &TraceCollector,
		trusted: &[&Identity],
	) -> Result<G, TightBeamError> {
		let mut builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
		for identity in trusted {
			builder = builder.with_certificate(identity.certificate().clone())?;
		}

		let validator: Arc<dyn CertificateValidation> = Arc::new(builder.build());
		let mut config = self.transport.cluster_config("127.0.0.1:0")?;
		config.tls.client_authentication = PeerAuthentication::Anonymous.and(validator);
		G::start(Arc::new(trace.share()), config).await
	}

	/// The billing caller, and a channel to the edge of `gateway` under it
	/// once the coupler serves.
	pub async fn billing<E>(&self, gateway: &ClusterGateway<TokioListener, E>) -> Result<Channel, TightBeamError>
	where
		E: Protocol<Address = GrpcAddr>,
	{
		let billing = self.caller("CN=billing,O=acme,C=US", Some(BILLING));
		let channel = self.channel(&edge_of(gateway)?, Some(&billing)).await?;
		serving(&channel).await?;
		Ok(channel)
	}

	/// The web caller, and a channel to the edge of `gateway` under it once
	/// the coupler serves.
	pub async fn web<E>(&self, gateway: &ClusterGateway<TokioListener, E>) -> Result<(TlsLeaf, Channel), TightBeamError>
	where
		E: Protocol<Address = GrpcAddr>,
	{
		let web = self.caller(WEB, None);
		let channel = self.channel(&edge_of(gateway)?, Some(&web)).await?;
		serving(&channel).await?;
		Ok((web, channel))
	}

	/// The TLS client material of a caller named `subject`, with `spiffe` as
	/// its SPIFFE ID when it is `Some`.
	pub fn caller(&self, subject: &str, spiffe: Option<&str>) -> TlsLeaf {
		let minted = self.tls.caller(subject, spiffe);
		minted.expect("a caller certificate mints")
	}

	/// A stock tonic channel to the edge at `edge` that trusts the TLS root,
	/// and presents `caller` when it is `Some`.
	pub async fn channel(&self, edge: &GrpcAddr, caller: Option<&TlsLeaf>) -> Result<Channel, TightBeamError> {
		let root = TonicCertificate::from_pem(self.tls.root_pem().map_err(mint_error)?);
		let mut tls = ClientTlsConfig::new().ca_certificate(root).domain_name("localhost");
		if let Some(caller) = caller {
			tls = tls.identity(TonicIdentity::from_pem(caller.certificate_pem(), caller.key_pem()));
		}

		let endpoint = Endpoint::from_shared(format!("https://{edge}")).map_err(unexpected)?;
		let endpoint = endpoint.tls_config(tls).map_err(unexpected)?;
		endpoint.connect().await.map_err(unexpected)
	}

	/// The claim of the web caller over `body` for `method`, bound to `caller`.
	pub async fn claim(&self, caller: &TlsLeaf, method: &str, body: &[u8]) -> Result<CallClaim, TightBeamError> {
		let signer = ClaimSigner::new(self.claims.signing_identity()?, [], caller.leaf());
		signer.sign(method, body).await
	}
}

/// A unary call of `method` with `body`, and `claim` when it is `Some`, as a
/// stock client makes it.
pub async fn call(
	channel: &Channel,
	method: &'static str,
	body: &[u8],
	claim: Option<&CallClaim>,
) -> Result<Vec<u8>, Status> {
	let mut grpc = tonic::client::Grpc::new(channel.clone());
	grpc.ready().await.map_err(|error| Status::unavailable(error.to_string()))?;

	let mut request = Request::new(body.to_vec());
	if let Some(claim) = claim {
		claim
			.attach(request.metadata_mut())
			.map_err(|error| Status::internal(error.to_string()))?;
	}

	let path = PathAndQuery::from_static(method);
	let response = grpc.unary(request, path, RawCodec).await?;
	Ok(response.into_inner())
}

/// Wait until the health check of the edge answers `SERVING`, which it does
/// once the loopback session of the coupler opens.
pub async fn serving(channel: &Channel) -> Result<(), TightBeamError> {
	let deadline = tokio::time::Instant::now() + OPENING;
	loop {
		let answer = call(channel, HEALTH_CHECK_PATH, &[], None).await;
		if answer.as_deref().ok() == Some(&[0x08, 0x01][..]) {
			return Ok(());
		}

		if tokio::time::Instant::now() >= deadline {
			return Err(TightBeamError::TestingError(TestingError::UnexpectedOutcome(
				"the coupler never served",
			)));
		}

		tokio::time::sleep(Duration::from_millis(50)).await;
	}
}

/// The address of the edge plane of `gateway`.
pub fn edge_of<E>(gateway: &ClusterGateway<TokioListener, E>) -> Result<GrpcAddr, TightBeamError>
where
	E: Protocol<Address = GrpcAddr>,
{
	let bound = gateway.edge_addr().cloned();
	bound.ok_or(TightBeamError::TestingError(TestingError::UnexpectedOutcome(
		"the edge plane did not bind",
	)))
}

pub fn edge_error(error: tightbeam_grpc::edge::EdgeError) -> TightBeamError {
	TightBeamError::from(tightbeam::transport::TransportError::from(error))
}

pub fn mint_error(_error: tightbeam_grpc::testing::MintError) -> TightBeamError {
	TightBeamError::TestingError(TestingError::UnexpectedOutcome("the test PKI failed to mint"))
}

pub fn unexpected<E>(_error: E) -> TightBeamError {
	TightBeamError::TestingError(TestingError::UnexpectedOutcome("the stock channel failed to connect"))
}

/// The config that grades a run with `spec`, and expects the spec to reject
/// it.
pub fn rejected_by(spec: &'static BuiltAssertSpec) -> Result<ScenarioConfig, ScenarioConfigError> {
	let config = ScenarioConfig::builder().with_spec(spec);
	config.with_expect(Expect::Violation(Layer::Assertion)).build()
}

/// The status code of a refused call.
pub fn code_of(answer: Result<Vec<u8>, Status>) -> Option<tonic::Code> {
	answer.err().map(|status| status.code())
}
