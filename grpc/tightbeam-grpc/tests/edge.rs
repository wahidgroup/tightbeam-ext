//! What an edge does for every kind of call: the trace of a gateway edge, the
//! PROXY protocol of a hop in front of it, its health, and its bind.

// The colony runtime macros expand `cfg(feature = ...)` probes against the
// invoking crate's feature namespace, which holds the features of this crate
// alone, so the leaked cfg warnings carry no signal here.
#![allow(unexpected_cfgs)]

mod support;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http::uri::PathAndQuery;
use tonic::client::Grpc;
use tonic::transport::Endpoint;
use tonic::Status;

use tightbeam::clock::{Clock, ManualClock};
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::{ClientEnv, ClusterEnv, SetupEnv};
use tightbeam::transport::{TransportError, TransportLimits};
use tightbeam::urn::Urn;
use tightbeam::{cluster, exactly, tb_assert_spec, tb_scenario, urn, TightBeamError};
use tightbeam_grpc::couple::{Assurance, Grants, Routes, Servlet};
use tightbeam_grpc::edge::{Dial, Edge, ProxyHops};
use tightbeam_grpc::events::{EDGE_REFUSED, PROXY_HEADER_READ, PROXY_HEADER_REFUSED};
use tightbeam_grpc::protocol::{GrpcListener, HEALTH_WATCH_PATH};
use tightbeam_grpc::testing::TlsAuthority;
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::testing::{EventWatch, WorkClient, WorkPlane};

use support::{bounded, unexpected, EchoServer, Graded, H2Tunnel, RawCodec};

/// The client that the PROXY header of a hop names.
const CLIENT: &str = "203.0.113.7:4242";

/// The peer of a tunnel that a PROXY header named.
const PROXIED_CLIENT: Urn<'static> = urn!("test", "event:edge/proxied-client");

/// The peer of a tunnel that a local PROXY header left as the hop.
const HOP_PEER: Urn<'static> = urn!("test", "event:edge/hop-peer");

tightbeam_grpc::staged_profile! {
	/// The h2c edge of a gateway, which records on the trace of the scenario.
	TracedEdge
}

cluster! {
	/// A WebSocket colony gateway whose h2c edge records on the trace.
	pub TracedEdgeGateway,
	protocol: WsListener,
	edge: GrpcListener<DefaultCryptoProvider, TracedEdge>
}

tb_assert_spec! {
	/// A stock call on another path of a gateway edge: the edge records the
	/// refusal on its trace.
	pub TracedEdgeSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(EDGE_REFUSED, exactly!(1), equals!("path"))
		]
	}
}

// A gateway binds its edge with no trace of its own, so the profile carries
// one, and the edge records what it refuses there.
tb_scenario! {
	name: a_gateway_edge_records_its_refusals_on_the_trace_of_its_profile,
	spec: TracedEdgeSpec,
	environment Cluster {
		context: WorkPlane::mint("tightbeam-grpc").expect("the work plane identities are created"),
		start: |SetupEnv { trace, context }| async move {
			TracedEdge::stage(Edge::h2c().with_trace(trace.share()), Dial::H2c);
			context.gateway::<TracedEdgeGateway>(&trace, "127.0.0.1:0").await
		},
		client: |ClusterEnv { cluster, .. }| async move {
			let edge = WorkClient::edge_of(&cluster)?;
			let endpoint = Endpoint::from_shared(format!("http://{edge}")).map_err(unexpected)?;
			let mut grpc = Grpc::new(bounded(endpoint.connect()).await?.map_err(unexpected)?);
			bounded(grpc.ready()).await?.map_err(unexpected)?;

			let path = PathAndQuery::from_static("/other.v1.Service/Call");
			let called = bounded(grpc.unary(tonic::Request::new(b"probe".to_vec()), path, RawCodec)).await?;
			assert_eq!(called.map(|_| ()).map_err(|status| status.code()), Err(tonic::Code::Unimplemented));

			cluster.stop();
			Ok(())
		}
	}
}

tightbeam_grpc::staged_profile! {
	/// The h2c edge behind a loopback hop that sends PROXY headers.
	ProxiedEdge
}

/// A PROXY protocol v2 header of `command` that names [`CLIENT`] as the
/// source of a TCP connection over IPv4.
fn proxy_header(command: u8) -> Result<Vec<u8>, TightBeamError> {
	let client: SocketAddr = CLIENT.parse().map_err(unexpected)?;
	let SocketAddr::V4(client) = client else {
		return Err(unexpected("the client is no IPv4 address"));
	};

	let block = [
		&client.ip().octets()[..],
		&[127, 0, 0, 1],
		&client.port().to_be_bytes(),
		&443_u16.to_be_bytes(),
	]
	.concat();

	let length = u16::try_from(block.len()).map_err(unexpected)?;
	let header = [
		b"\r\n\r\n\0\r\nQUIT\n".as_slice(),
		&[0x20 | command, 0x11],
		&length.to_be_bytes(),
		&block,
	];
	Ok(header.concat())
}

/// Open a tunnel call over `tunnel`, and hold it until a trace of `events`
/// files `filed_as`.
async fn hold_until(mut tunnel: H2Tunnel, events: &EventWatch, filed_as: Urn<'static>) -> Result<(), TightBeamError> {
	let (_response, _requests) = tunnel.open(tunnel.tunnel_head()?)?;
	Ok(events.recorded(filed_as, 1).await?)
}

/// Open a tunnel call to the edge at `addr` over one connection that opens
/// with `header`, and hold it until a trace of `events` files `filed_as`.
async fn tunnel_behind(
	addr: TightBeamSocketAddr,
	header: &[u8],
	events: &EventWatch,
	filed_as: Urn<'static>,
) -> Result<(), TightBeamError> {
	hold_until(H2Tunnel::connect(addr.0, header).await?, events, filed_as).await
}

/// Open a tunnel call to the edge at `addr` over one connection that opens
/// with `header`, which the edge refuses: the failure that ends it.
async fn tunnel_refused(addr: TightBeamSocketAddr, header: &[u8]) -> Result<h2::Error, TightBeamError> {
	let mut tunnel = H2Tunnel::connect(addr.0, header).await?;
	let (response, _requests) = tunnel.open(tunnel.tunnel_head()?)?;
	let ended = bounded(response).await?;
	ended.err().ok_or_else(|| unexpected("the edge answered a hop with no header"))
}

tb_assert_spec! {
	/// Two tunnels behind a hop: the edge reads a header that names its
	/// client, and a local one that keeps the hop as its peer, and refuses a
	/// connection of the hop with no header as `malformed`.
	pub ProxiedSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(PROXY_HEADER_READ, exactly!(2)),
			(PROXY_HEADER_REFUSED, exactly!(1), equals!("malformed")),
			(PROXIED_CLIENT, exactly!(1), equals!(CLIENT)),
			(HOP_PEER, exactly!(1))
		]
	}
}

/// The events of the scenario of a proxied tunnel.
static PROXIED_EVENTS: EventWatch = EventWatch::new();

// A hop in front of the edge names the client of each connection in a PROXY
// header, which the edge takes as the peer of the tunnel.
tb_scenario! {
	name: a_proxied_tunnel_names_the_client_of_its_hop,
	config: ProxiedSpec::latest().watched(&PROXIED_EVENTS),
	environment ServiceClient {
		server: |SetupEnv { trace, .. }| async move {
			let hops = ProxyHops::new(["127.0.0.0/8"]).map_err(support::edge_error)?;
			ProxiedEdge::stage(Edge::h2c().with_proxy_protocol(hops).with_trace(trace.share()), Dial::H2c);

			let listener = GrpcListener::<DefaultCryptoProvider, ProxiedEdge>::bind_cleartext("127.0.0.1:0").await?;
			let addr = TightBeamSocketAddr(listener.local_addr());

			let recorder = trace.share();
			let accepted = tokio::spawn(async move {
				while let Ok((_transport, peer)) = listener.accept().await {
					let event = match peer.ip().is_loopback() {
						true => HOP_PEER,
						false => PROXIED_CLIENT,
					};
					let _ = recorder.event_with(event, &[], peer.to_string());
				}
			});
			Ok::<_, TightBeamError>((accepted, addr))
		},
		client: |ClientEnv { addr, .. }| async move {
			tunnel_behind(addr, &proxy_header(0x1)?, &PROXIED_EVENTS, PROXIED_CLIENT).await?;
			tunnel_behind(addr, &proxy_header(0x0)?, &PROXIED_EVENTS, HOP_PEER).await?;

			tunnel_refused(addr, &[]).await?;
			Ok(PROXIED_EVENTS.recorded(PROXY_HEADER_REFUSED, 1).await?)
		}
	}
}

/// A health answer that a watcher read, in hex.
const WATCH_ANSWER: Urn<'static> = urn!("test", "event:edge/watch-answer");

/// How a watch ended, as its watcher read it: `connection` for the end of
/// its connection, and `status-N` for a status that the edge sent.
const WATCH_END: Urn<'static> = urn!("test", "event:edge/watch-end");

/// How the stream of a watch ended, as [`WATCH_END`] records it.
fn watch_end(end: &Result<Option<Vec<u8>>, Status>) -> String {
	let Err(status) = end else {
		return "status-0".to_owned();
	};

	let mut cause = std::error::Error::source(status);
	while let Some(error) = cause {
		if error.downcast_ref::<h2::Error>().is_some_and(h2::Error::is_io) {
			return "connection".to_owned();
		}
		cause = error.source();
	}

	format!("status-{}", status.code() as i32)
}

tb_assert_spec! {
	/// A health watch of a tunnel edge: one answer of SERVING, then the end
	/// of its connection, and no session.
	pub TunnelWatchSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(WATCH_ANSWER, exactly!(1), equals!("0801")),
			(WATCH_END, exactly!(1), equals!("connection")),
			(EDGE_REFUSED, exactly!(0))
		]
	}
}

tightbeam_grpc::staged_profile! {
	/// The h2c edge whose health a watch reads.
	WatchedEdge
}

/// The deadline of a connection of the watched edge, which ends its watch, on
/// a clock that the scenario moves: past [`support::OPENING`], so only an
/// advance of that clock ends the watch in time.
const WATCH_DEADLINE: Duration = support::OPENING.saturating_add(Duration::from_secs(3));

// A tunnel edge serves while it listens, so a watch reads SERVING once and
// then holds, with no further answer, until the deadline of its connection
// ends it.
tb_scenario! {
	name: a_health_watch_of_a_tunnel_edge_reads_serving_and_holds,
	spec: TunnelWatchSpec,
	environment ServiceClient {
		context: (support::server_identity("CN=watched edge,O=tightbeam-grpc,C=US"), Arc::new(ManualClock::default())),
		server: |SetupEnv { trace, context }| async move {
			let clock = Arc::clone(&context.1) as Arc<dyn Clock>;
			WatchedEdge::stage(Edge::h2c().with_trace(trace.share()).with_clock(clock), Dial::H2c);
			let limits = TransportLimits { handshake_timeout: WATCH_DEADLINE, ..TransportLimits::default() };
			let config = context.0.server_config().with_limits(limits)?;
			EchoServer::encrypted::<WatchedEdge>(config, None, &trace).await
		},
		client: |ClientEnv { trace, addr, context }| async move {
			let endpoint = Endpoint::from_shared(format!("http://{}", addr.0)).map_err(unexpected)?;
			let mut grpc = Grpc::new(bounded(endpoint.connect()).await?.map_err(unexpected)?);
			bounded(grpc.ready()).await?.map_err(unexpected)?;

			let path = PathAndQuery::from_static(HEALTH_WATCH_PATH);
			let watched = grpc.server_streaming(tonic::Request::new(Vec::new()), path, RawCodec);
			let mut answers = bounded(watched).await?.map_err(unexpected)?.into_inner();
			// The first answer comes on a connection that read its deadline
			// when the edge accepted it.
			let read = async {
				let end = loop {
					match answers.message().await {
						Ok(Some(answer)) => {
							let read: String = answer.iter().map(|byte| format!("{byte:02x}")).collect();
							trace.event_with(WATCH_ANSWER, &[], read)?;
							context.1.advance(WATCH_DEADLINE);
						}
						end => break end,
					}
				};

				trace.event_with(WATCH_END, &[], watch_end(&end))?;
				Ok::<_, TightBeamError>(())
			};

			bounded(read).await?
		}
	}
}

tightbeam_grpc::staged_profile! {
	/// The h2c edge behind hops of `10.0.0.0/8`, which loopback is not.
	FarHopEdge
}

/// The peer of a tunnel from an address that is no hop.
const DIRECT_PEER: Urn<'static> = urn!("test", "event:edge/direct-peer");

tb_assert_spec! {
	/// Two connections from an address that is no hop: the edge reads no
	/// header of either, the one with no header reaches a caller with its own
	/// peer, and the one that sends a header fails.
	pub NoHopSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(PROXY_HEADER_READ, exactly!(0)),
			(PROXY_HEADER_REFUSED, exactly!(0)),
			(DIRECT_PEER, exactly!(1)),
			(PROXIED_CLIENT, exactly!(0))
		]
	}
}

/// The events of the scenario of a header from an address that is no hop.
static NO_HOP_EVENTS: EventWatch = EventWatch::new();

// A peer that is no hop keeps its own address: the edge reads no header of
// it, so its connection with a header fails, and its plain connection reaches
// a caller with its own address.
tb_scenario! {
	name: a_proxy_header_from_an_address_that_is_no_hop_is_never_read,
	config: NoHopSpec::latest().watched(&NO_HOP_EVENTS),
	environment ServiceClient {
		server: |SetupEnv { trace, .. }| async move {
			let hops = ProxyHops::new(["10.0.0.0/8"]).map_err(support::edge_error)?;
			FarHopEdge::stage(Edge::h2c().with_proxy_protocol(hops).with_trace(trace.share()), Dial::H2c);
			let listener = GrpcListener::<DefaultCryptoProvider, FarHopEdge>::bind_cleartext("127.0.0.1:0").await?;
			let addr = TightBeamSocketAddr(listener.local_addr());

			let recorder = trace.share();
			let accepted = tokio::spawn(async move {
				while let Ok((_transport, peer)) = listener.accept().await {
					let event = match peer.ip().is_loopback() {
						true => DIRECT_PEER,
						false => PROXIED_CLIENT,
					};
					let _ = recorder.event_with(event, &[], peer.to_string());
				}
			});
			Ok::<_, TightBeamError>((accepted, addr))
		},
		client: |ClientEnv { addr, .. }| async move {
			tunnel_refused(addr, &proxy_header(0x1)?).await?;
			tunnel_behind(addr, &[], &NO_HOP_EVENTS, DIRECT_PEER).await
		}
	}
}

tightbeam_grpc::staged_profile! {
	/// The TLS edge behind a loopback hop that sends PROXY headers.
	TlsProxiedEdge
}

/// The client that a PROXY header named over TLS.
const TLS_PROXIED_CLIENT: Urn<'static> = urn!("test", "event:edge/tls-proxied-client");

tb_assert_spec! {
	/// A tunnel over TLS behind a hop, whose header the edge reads before the
	/// handshake, and which names its client.
	pub TlsProxiedSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(PROXY_HEADER_READ, exactly!(1), equals!(CLIENT)),
			(TLS_PROXIED_CLIENT, exactly!(1), equals!(CLIENT))
		]
	}
}

/// The events of the scenario of a proxied TLS tunnel.
static TLS_PROXIED_EVENTS: EventWatch = EventWatch::new();

// The PROXY header comes before the TLS handshake, so a TLS edge reads it
// first and takes the client it names as the peer of the tunnel.
tb_scenario! {
	name: a_proxied_tls_tunnel_names_the_client_of_its_hop,
	config: TlsProxiedSpec::latest().watched(&TLS_PROXIED_EVENTS),
	environment ServiceClient {
		context: TlsAuthority::mint("CN=edge root,O=acme,C=US", support::LIFETIME).expect("a TLS root is created"),
		server: |SetupEnv { trace, context }| async move {
			let hops = ProxyHops::new(["127.0.0.0/8"]).map_err(support::edge_error)?;
			let tls = context.edge("CN=edge,O=acme,C=US").map_err(support::mint_error)?;
			TlsProxiedEdge::stage(Edge::tls(tls).with_proxy_protocol(hops).with_trace(trace.share()), Dial::H2c);

			let listener = GrpcListener::<DefaultCryptoProvider, TlsProxiedEdge>::bind_cleartext("127.0.0.1:0").await?;
			let addr = TightBeamSocketAddr(listener.local_addr());

			let recorder = trace.share();
			let accepted = tokio::spawn(async move {
				while let Ok((_transport, peer)) = listener.accept().await {
					let _ = recorder.event_with(TLS_PROXIED_CLIENT, &[], peer.to_string());
				}
			});
			Ok::<_, TightBeamError>((accepted, addr))
		},
		client: |ClientEnv { addr, context, .. }| async move {
			let tunnel = H2Tunnel::connect_tls(addr.0, &proxy_header(0x1)?, &context, None).await?;
			hold_until(tunnel, &TLS_PROXIED_EVENTS, TLS_PROXIED_CLIENT).await
		}
	}
}

tightbeam_grpc::staged_profile! {
	/// A coupled edge, which binds in the clear and so refuses its bind.
	ClearCoupledEdge
}

/// How the bind of a refused profile failed, which the scenario records:
/// `missing-encryption` once the profile is refused, or `address-in-use` when
/// the bind reached the socket first.
const BIND_REFUSED: Urn<'static> = urn!("test", "event:edge/bind-refused");

tb_assert_spec! {
	/// A coupled profile bound in the clear on a port that another socket
	/// holds: the profile is refused before the bind reaches the socket.
	pub RefusedBindSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(BIND_REFUSED, exactly!(1), equals!("missing-encryption"))
		]
	}
}

// A coupled edge needs the tightbeam handshake, so its cleartext bind is
// refused, and it is refused before any socket binds: on a port that another
// socket holds, the refusal is that of the profile, not that of the port.
tb_scenario! {
	name: a_refused_profile_binds_no_socket,
	spec: RefusedBindSpec,
	environment Bare {
		context: support::Coupled::mint(),
		exec: |SetupEnv { trace, context }| async move {
			let servlet = tightbeam_ws::testing::WorkClient::servlet("orders")?;
			let orders = Servlet::new(servlet, context.answers.certificate().clone()).map_err(support::edge_error)?;
			let routes = Routes::new().unary("/orders.v1.Orders/Get", orders, Assurance::Vouched);
			let coupler = context.coupler(routes.map_err(support::edge_error)?, Grants::deny_all())?;
			context.stage_coupler(&trace, ClearCoupledEdge::stage, coupler)?;

			let held = std::net::TcpListener::bind("127.0.0.1:0")?;
			let port = held.local_addr()?;
			let bound = GrpcListener::<DefaultCryptoProvider, ClearCoupledEdge>::bind_cleartext(port.to_string()).await;
			let refused = match bound.err() {
				Some(TransportError::MissingEncryption) => "missing-encryption",
				Some(TransportError::IoError(error)) if error.kind() == std::io::ErrorKind::AddrInUse => "address-in-use",
				Some(_) => "other",
				None => "bound",
			};

			trace.event_with(BIND_REFUSED, &[], refused)?;
			assert_eq!(refused, "missing-encryption", "the profile MUST be refused before the bind");
			Ok(())
		}
	}
}
