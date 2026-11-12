//! The colony configuration and the work probe of the work-plane gateways, as
//! `docs/ws.md` (Cluster work plane) states it.

// The colony macros expand `cfg(feature = ...)` probes that name upstream
// features, which this crate declares under other names.
#![allow(unexpected_cfgs)]

use core::fmt::Write;
use core::hash::Hash;
use core::num::NonZeroUsize;
use core::time::Duration;
use std::sync::Arc;

use der::asn1::OctetString;
use der::Sequence;
use tightbeam::builder::TypeBuilder;
use tightbeam::clock::UnixMillis;
use tightbeam::colony::cluster::{Cluster, ClusterConfig, ClusterGateway, ClusterTlsConfig, EdgePlane};
use tightbeam::colony::hive::{Hive, HiveConfig, HiveTlsConfig};
use tightbeam::colony::servlet::ServletConfig;
use tightbeam::colony::urn::ColonyNamespace;
use tightbeam::colony::SubmitWork;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::x509::store::CertificateTrust;
use tightbeam::crypto::x509::KeyPurposes;
use tightbeam::marker::MaybeSend;
use tightbeam::policy::TransitStatus;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::handshake::PeerAuthentication;
use tightbeam::transport::policy::PolicyConfig;
use tightbeam::transport::{
	ClientBuilder, ConnectionBuilder, ConnectionPool, GenericClient, MessageCollector, MessageEmitter, PoolConfig,
	Protocol,
};
use tightbeam::urn::Urn;
use tightbeam::{cluster, compose, hive, servlet, Beamable, Frame, Message, TightBeamError, Version};

use super::{Error, Identity, Result as WsResult};
use crate::protocol::WsListener;

/// Concurrent streams of every colony mux offer: the gateway pool, the hive
/// pool, and the servlet listener.
const COLONY_STREAMS: u32 = 8;

/// The opaque work body of a probe request and of its answer, the profile
/// body that the browser client builds with `frameBuilder(bytes)`.
#[derive(Beamable, Clone, Debug, Eq, PartialEq, Sequence)]
#[beam(min_version = "V0")]
pub struct WorkBody {
	body: OctetString,
}

impl WorkBody {
	/// A body that carries `bytes`.
	///
	/// # Errors
	///
	/// - [`Error::Ws`] -- `bytes` passes the length that DER encodes.
	pub fn new(bytes: impl Into<Vec<u8>>) -> WsResult<Self> {
		let body = OctetString::new(bytes.into()).map_err(TightBeamError::from)?;
		Ok(Self { body })
	}

	/// The bytes the body carries.
	pub fn as_bytes(&self) -> &[u8] {
		self.body.as_bytes()
	}

	/// The answer of the probe to this body: `pong:<payload-hex>:<valid>`,
	/// where `valid` is whether the end-to-end signature of the request
	/// verified on the bytes the servlet received.
	fn answer(&self, signature_valid: bool) -> Result<Self, TightBeamError> {
		let mut text = String::from("pong:");
		for byte in self.as_bytes() {
			// Writing into a String cannot fail, so the fmt result carries
			// no signal.
			let _ = write!(text, "{byte:02x}");
		}
		let _ = write!(text, ":{signature_valid}");

		let body = OctetString::new(text.into_bytes())?;
		Ok(Self { body })
	}
}

servlet! {
	/// Answers each work body with a `pong:<payload-hex>:<valid>` echo that
	/// the work identity of its configuration signs.
	///
	/// - `valid` is whether the end-to-end signature of the client verified on the bytes that the servlet
	///   received, so a gateway that forwards the frame unchanged answers `true`.
	pub WorkProbeServlet<WorkBody, EnvConfig = Identity>,
	protocol: WsListener,
	handle: |req, frame, ctx| async move {
		let identity = ctx.env_config();
		let signature_valid = identity.verifies(&frame);
		let reply = req.answer(signature_valid)?;

		let mut signed = compose! {
			V1: id: frame.metadata().id(),
				message: reply
		}?;

		signed.sign_with_provider(&identity.signing_identity()).await?;
		Ok(Some(signed))
	}
}

hive! {
	/// The hive that hosts the work probe over the WebSocket colony.
	pub WorkProbeHive,
	protocol: WsListener
}

cluster! {
	/// The WebSocket colony gateway with a WebSocket edge accept plane: hives
	/// register over WebSocket, and edge clients submit work over WebSocket.
	pub WorkGateway,
	protocol: WsListener,
	edge: WsListener
}

impl Identity {
	/// The gateway config of this identity, with `edge` as its edge plane.
	///
	/// - This identity serves TLS and anchors the trust of the hive plane.
	/// - Every accepted connection shares one mux offer.
	/// - The colony plane binds the default address of its protocol, an ephemeral loopback port.
	///
	/// # Errors
	///
	/// - [`Error::Ws`] -- the certificate does not assert the signer purpose.
	/// - [`Error::Ws`] -- the trust anchor fails to build.
	pub fn cluster_config(&self, edge: EdgePlane) -> WsResult<ClusterConfig> {
		let signing = self.signing_identity();
		let tls = ClusterTlsConfig::from_identity(signing, KeyPurposes::HOUSE).map_err(TightBeamError::from)?;
		let tls = tls.with_hive_trust(Some(self.trust_anchor()?));
		let offer = TransportOffer::mux(COLONY_STREAMS);

		let mut config = ClusterConfig::new(tls);
		config.edge = Some(edge);
		config.pool_config.mux_offer = Some(Arc::new(offer));
		Ok(config)
	}

	/// Hive config: control-plane TLS from this identity, and this identity as
	/// the trust anchor for dialing the gateway and the servlet.
	///
	/// # Errors
	///
	/// - [`Error::Ws`] -- the certificate does not assert the signer purpose.
	/// - [`Error::Ws`] -- the trust anchor fails to build.
	pub fn hive_config(&self) -> WsResult<HiveConfig> {
		let signing = self.signing_identity();
		let authentication = PeerAuthentication::Anonymous;
		let hive_tls = HiveTlsConfig::from_identity(signing, authentication, KeyPurposes::HOUSE);
		let hive_tls = hive_tls.map_err(TightBeamError::from)?;
		let offer = TransportOffer::mux(COLONY_STREAMS);

		let mut config = HiveConfig {
			trust_store: Some(self.trust_anchor()?),
			hive_tls: Some(Arc::new(hive_tls)),
			..Default::default()
		};
		config.pool.mux_offer = Some(Arc::new(offer));
		Ok(config)
	}

	/// Servlet config: an encrypted WebSocket listener under this identity,
	/// with a mux offer that matches the hive pool, and `env` as the
	/// configuration its handler reads.
	pub fn servlet_config<M: Message, Env>(
		&self,
		env: Arc<Env>,
	) -> ServletConfig<WsListener, M, DefaultCryptoProvider, Env> {
		let signing = self.signing_identity();
		let offer = TransportOffer::mux(COLONY_STREAMS);

		let builder = ServletConfig::<WsListener, M, DefaultCryptoProvider>::builder();
		let builder = builder.with_identity(signing, vec![]).with_mux_offer(Some(offer));
		builder.with_config(env).build()
	}

	/// A work frame of `payload` under `id`, signed end to end by this
	/// identity, as a client submits it to the work probe.
	///
	/// # Errors
	///
	/// - [`Error::Ws`] -- the frame fails to build or to sign.
	pub async fn signed_work(&self, id: &[u8], payload: impl Into<Vec<u8>>) -> WsResult<Frame> {
		let body = WorkBody::new(payload)?;
		let order = UnixMillis::now().get();
		let mut frame = Version::V1.compose().with_id(id).with_order(order).with_message(body).build()?;

		frame.sign_with_provider(&self.signing_identity()).await?;
		Ok(frame)
	}
}

/// The payload of every probe work frame.
const PROBE_PAYLOAD: &[u8] = b"21";

/// The servlet type that the work probe serves.
const PROBE_SERVLET: &str = "work-probe";

/// The two identities of a work plane, and what each one starts.
///
/// - The transport identity runs the gateway, the hive, and the servlet, and
///   the client pins it at the edge.
/// - The work identity signs each work frame and each answer end to end.
pub struct WorkPlane {
	/// Shared with the restart of the servlet, which runs under it too.
	transport: Arc<Identity>,
	client: WorkClient,
	/// The servlet type that the hive of the plane serves the probe under.
	probe: Urn<'static>,
}

impl WorkPlane {
	/// A plane whose colony runs under `transport` and whose work signs as
	/// `work`.
	///
	/// # Errors
	///
	/// - [`Error::Ws`] -- the trust anchor of `transport` fails to build.
	pub fn new(transport: Identity, work: Arc<Identity>) -> WsResult<Self> {
		let client = WorkClient::new(&transport, work)?;
		let probe = WorkClient::probe()?;
		Ok(Self { transport: Arc::new(transport), client, probe })
	}

	/// This plane, whose hive serves the work probe under the servlet type
	/// `probe` in place of [`WorkClient::probe`], such as the one that the e2e
	/// stack names.
	#[must_use]
	pub fn serving(self, probe: Urn<'static>) -> Self {
		Self { probe, ..self }
	}

	/// A plane of two identities created for `organization`, valid for one
	/// hour.
	///
	/// # Errors
	///
	/// - [`Error::Ws`] -- an identity fails to issue.
	pub fn mint(organization: &str) -> WsResult<Self> {
		let validity = Duration::from_secs(3600);
		let transport = Identity::mint(&format!("CN=work plane,O={organization},C=US"), 1, validity)?;
		let work = Identity::mint(&format!("CN=work probe,O={organization},C=US"), 2, validity)?;
		Self::new(transport, Arc::new(work))
	}

	/// Start a gateway of type `G` under the transport identity, with its edge
	/// at `edge`, that records on `trace`.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a config that fails to build, or of a
	///   gateway that fails to start.
	pub async fn gateway<G: Cluster>(
		&self,
		trace: &TraceCollector,
		edge: impl Into<String>,
	) -> Result<G, TightBeamError> {
		let config = self.transport.cluster_config(EdgePlane::new(edge))?;
		G::start(Arc::new(trace.share()), config).await
	}

	/// A hive under the transport identity that hosts the work probe under the
	/// servlet type of this plane, signing each answer under the work identity,
	/// established over the WebSocket colony and ready to register with a
	/// gateway.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a config that fails to build, or of a
	///   servlet or a hive that fails to start.
	pub async fn hive(&self, trace: &TraceCollector) -> Result<WorkProbeHive, TightBeamError> {
		let work = Arc::clone(&self.client.work);
		let servlet_config = self.transport.servlet_config(Arc::clone(&work));
		let served = WorkProbeServlet::start(Arc::new(trace.share()), servlet_config).await?;

		// A hive restarts a servlet that stops under the same identity and mux
		// offer, because the pool of the hive pins that identity and dials the
		// restarted servlet as it dialed the first.
		let transport = Arc::clone(&self.transport);
		let restart = move |trace| {
			let config = transport.servlet_config(Arc::clone(&work));
			async move { WorkProbeServlet::start(trace, config).await }
		};

		let mut hive = WorkProbeHive::new(Some(self.transport.hive_config()?))?;
		hive.register(self.probe.clone(), served, restart)?;
		hive.establish(Arc::new(trace.share())).await?;
		Ok(hive)
	}

	/// The transport identity, which signs the control frames of the colony.
	pub fn transport(&self) -> &Identity {
		&self.transport
	}

	/// The client side of the work probe.
	pub fn client(&self) -> &WorkClient {
		&self.client
	}
}

/// The client side of the work probe: the trust anchor of the gateway, and
/// the work identity that signs each work frame and verifies each answer end
/// to end.
pub struct WorkClient {
	trust: Arc<dyn CertificateTrust>,
	work: Arc<Identity>,
}

impl WorkClient {
	/// A client that pins the transport identity of `gateway` and signs as
	/// `work`.
	///
	/// # Errors
	///
	/// - [`Error::Ws`] -- the trust anchor of `gateway` fails to build.
	pub fn new(gateway: &Identity, work: Arc<Identity>) -> WsResult<Self> {
		let trust = gateway.trust_anchor()?;
		Ok(Self { trust, work })
	}

	/// The URN of the servlet type `name` under the default colony namespace.
	///
	/// # Errors
	///
	/// - [`Error::Ws`] -- `name` breaks the servlet URN grammar.
	pub fn servlet(name: &str) -> WsResult<Urn<'static>> {
		let urn = ColonyNamespace::default().servlet(name).map_err(TightBeamError::from)?;
		Ok(urn)
	}

	/// The URN of the servlet type that the work probe serves.
	///
	/// # Errors
	///
	/// - [`Error::Ws`] -- the probe name breaks the servlet URN grammar.
	pub fn probe() -> WsResult<Urn<'static>> {
		Self::servlet(PROBE_SERVLET)
	}

	/// A client of the protocol `P` connected to the edge at `addr`.
	///
	/// # Errors
	///
	/// - [`Error::Transport`] -- the dial or the handshake fails.
	pub async fn connect<P>(&self, addr: P::Address) -> WsResult<GenericClient<P>>
	where
		P: Protocol + MaybeSend,
		P::Transport: MessageEmitter + MessageCollector + PolicyConfig,
	{
		let builder = ClientBuilder::<P>::builder().with_trust_store(Arc::clone(&self.trust));
		let client = builder.build().connect(addr).await?;
		Ok(client)
	}

	/// A pool of the protocol `P` that pins the transport identity of the
	/// gateway and records its pool and session events on `trace`, with one
	/// exclusive connection per destination.
	pub fn pool<P>(&self, trace: &TraceCollector) -> Arc<ConnectionPool<P>>
	where
		P: Protocol + Send + Sync,
		P::Address: Hash + Eq + Clone + Send + Sync,
		P::Transport: Send + Sync,
	{
		let config = PoolConfig { idle_timeout: None, max_connections: NonZeroUsize::MIN, mux_offer: None };
		let builder = ConnectionPool::<P>::builder().with_config(config);
		let builder = builder.with_trust_store(Arc::clone(&self.trust)).with_trace(trace.share());
		Arc::new(builder.build())
	}

	/// The address that the edge plane of `gateway` bound.
	///
	/// # Errors
	///
	/// - [`Error::EdgeUnbound`] -- the gateway started with no edge plane.
	pub fn edge_of<P, E>(gateway: &ClusterGateway<P, E>) -> WsResult<E::Address>
	where
		P: Protocol,
		E: Protocol,
		E::Address: Clone,
	{
		gateway.edge_addr().cloned().ok_or(Error::EdgeUnbound)
	}

	/// Submit one probe work frame under `id` through the edge of `gateway`
	/// to the servlet type `servlet`, and return how the submission ended: the
	/// signed answer of the servlet, or the refusal that the client read.
	///
	/// # Errors
	///
	/// - The errors of [`edge_of`](Self::edge_of).
	/// - [`Error::Transport`] -- the dial or the handshake fails.
	/// - [`Error::Ws`] -- the work frame fails to build or to sign.
	pub async fn submit<P, E>(
		&self,
		gateway: &ClusterGateway<P, E>,
		servlet: Urn<'static>,
		id: &[u8],
	) -> WsResult<Result<Frame, TightBeamError>>
	where
		P: Protocol,
		E: Protocol + MaybeSend,
		E::Address: Clone,
		E::Transport: MessageEmitter + MessageCollector + PolicyConfig,
	{
		let edge = Self::edge_of(gateway)?;
		let mut client = self.connect::<E>(edge).await?;
		let work = self.work(id).await?;

		let submitted = client.submit_work_to(servlet, &work).await;
		Ok(submitted)
	}

	/// A probe work frame under `id`, signed end to end by the work identity.
	///
	/// # Errors
	///
	/// - [`Error::Ws`] -- the frame fails to build or to sign.
	pub async fn work(&self, id: &[u8]) -> WsResult<Frame> {
		self.work.signed_work(id, PROBE_PAYLOAD).await
	}

	/// The answer of the probe in `served`, when its end-to-end signature
	/// verifies under the work identity. For a probe work frame, the answer
	/// of a gateway that forwards every frame unchanged is `pong:3231:true`.
	///
	/// # Errors
	///
	/// - [`Error::Ws`] -- `served` carries no work body.
	pub fn answer(&self, served: &Frame) -> WsResult<Option<Vec<u8>>> {
		if !self.work.verifies(served) {
			return Ok(None);
		}

		let body: WorkBody = served.decode_message()?;
		Ok(Some(body.as_bytes().to_vec()))
	}
}

/// A gateway of type `G` with a hive that serves the work probe, over the
/// WebSocket colony of one [`WorkPlane`].
pub struct WorkStack<G> {
	gateway: G,
	hive: WorkProbeHive,
}

impl<G: Cluster<Address = TightBeamSocketAddr>> WorkStack<G> {
	/// Start the gateway of `plane`, with its edge at `edge`, and register the
	/// hive of `plane` with it.
	///
	/// # Errors
	///
	/// - [`Error::Ws`] -- a config fails to build, a part fails to
	///   start, or the hive registration fails.
	/// - [`Error::Registration`] -- the gateway answers the registration with a
	///   status other than [`TransitStatus::Ok`].
	pub async fn start(trace: &TraceCollector, plane: &WorkPlane, edge: impl Into<String>) -> WsResult<Self> {
		let gateway = plane.gateway::<G>(trace, edge).await?;
		let hive = plane.hive(trace).await?;

		let registered = hive.register_with_cluster(gateway.addr()).await?;
		if registered.status != TransitStatus::Ok {
			return Err(Error::Registration(registered.status));
		}

		Ok(Self { gateway, hive })
	}

	/// The gateway of the stack.
	pub fn gateway(&self) -> &G {
		&self.gateway
	}

	/// Stop the hive and the gateway.
	pub fn stop(self) {
		self.hive.stop();
		self.gateway.stop();
	}
}
