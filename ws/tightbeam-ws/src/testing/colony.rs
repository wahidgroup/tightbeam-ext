//! Colony configuration for the work-plane gateway example and its test.
//!
//! Compiled only under the `colony` feature. Every colony process presents one
//! [`Identity`], so the gateway, the hive, and the servlet derive their
//! configuration from it.

use std::sync::Arc;

use tightbeam::colony::cluster::{ClusterConfig, ClusterTlsConfig};
use tightbeam::colony::hive::{HiveConfig, HiveTlsConfig};
use tightbeam::colony::servlet::ServletConfig;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::x509::KeyPurposes;
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::handshake::PeerAuthentication;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::{Message, TightBeamError};

use super::Identity;
use crate::Result;

/// Concurrent streams of every colony mux offer: the gateway pool, the hive
/// pool, and the servlet listener.
const COLONY_STREAMS: u32 = 8;

impl Identity {
	/// Gateway config: this identity for TLS and as the hive-plane trust
	/// anchor, the WebSocket edge at `edge`, and a mux offer that every
	/// accepted connection shares.
	///
	/// The colony plane keeps the protocol's default bind, a loopback address
	/// on an ephemeral port, so hives dial the address the gateway reports.
	///
	/// # Errors
	///
	/// - [`Error::Tightbeam`] -- the certificate does not assert the signer purpose.
	/// - [`Error::Tightbeam`] -- the signing identity or the trust anchor fails to build.
	///
	/// [`Error::Tightbeam`]: crate::Error::Tightbeam
	pub fn cluster_config(&self, edge: impl Into<String>) -> Result<ClusterConfig> {
		let signing = self.signing_identity()?;
		let tls = ClusterTlsConfig::from_identity(signing, KeyPurposes::HOUSE).map_err(TightBeamError::from)?;
		let tls = tls.with_hive_trust(Some(self.trust_anchor()?));
		let offer = TransportOffer::mux(COLONY_STREAMS);

		let mut config = ClusterConfig::new(tls);
		config.edge_bind_addr = Some(edge.into());
		config.pool_config.mux_offer = Some(Arc::new(offer));
		Ok(config)
	}

	/// Hive config: control-plane TLS from this identity, and this identity as
	/// the trust anchor for dialing the gateway and the servlet.
	///
	/// # Errors
	///
	/// - [`Error::Tightbeam`] -- the certificate does not assert the signer purpose.
	/// - [`Error::Tightbeam`] -- the signing identity or the trust anchor fails to build.
	///
	/// [`Error::Tightbeam`]: crate::Error::Tightbeam
	pub fn hive_config(&self) -> Result<HiveConfig> {
		let signing = self.signing_identity()?;
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

	/// Servlet config: an encrypted TCP listener under this identity, with a
	/// mux offer that matches the hive pool.
	///
	/// # Errors
	///
	/// - [`Error::Tightbeam`] -- the signing identity fails to build.
	///
	/// [`Error::Tightbeam`]: crate::Error::Tightbeam
	pub fn servlet_config<M: Message>(&self) -> Result<ServletConfig<TokioListener, M, DefaultCryptoProvider>> {
		let signing = self.signing_identity()?;
		let offer = TransportOffer::mux(COLONY_STREAMS);

		let config = ServletConfig::<TokioListener, M, DefaultCryptoProvider>::builder()
			.with_identity(signing, vec![])
			.with_mux_offer(Some(offer))
			.with_config(Arc::new(()))
			.build();
		Ok(config)
	}
}
