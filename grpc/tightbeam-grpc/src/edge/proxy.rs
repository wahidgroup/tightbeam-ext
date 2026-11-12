//! PROXY protocol v2 from trusted hops: the client address that a load
//! balancer in front of an edge forwards.
//!
//! # Sources
//!
//! - The PROXY protocol, versions 1 and 2, HAProxy `doc/proxy-protocol.txt`:
//!   <https://www.haproxy.org/download/3.0/doc/proxy-protocol.txt>

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt};

use super::EdgeError;
#[cfg(feature = "instrument")]
use crate::events::{PROXY_HEADER_READ, PROXY_HEADER_REFUSED};
use crate::tunnel::EdgeAudit;

/// The 12 bytes that open a version 2 header.
const SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";

/// The longest address block, TLVs included, that the edge reads.
const MAX_BLOCK: usize = 2048;

/// One range of hops: an address, and how many of its leading bits a hop
/// shares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HopRange {
	addr: IpAddr,
	prefix: u32,
}

impl HopRange {
	/// The range of `text`: an address, or an address and a prefix length.
	fn parse(text: &str) -> Option<Self> {
		let (addr, prefix) = match text.split_once('/') {
			Some((addr, prefix)) => (addr, Some(prefix)),
			None => (text, None),
		};

		let addr: IpAddr = addr.parse().ok()?;
		let width = Self::width(addr);
		let prefix = match prefix {
			Some(prefix) => prefix.parse::<u32>().ok().filter(|prefix| *prefix <= width)?,
			None => width,
		};
		Some(Self { addr: addr.to_canonical(), prefix })
	}

	/// The bits of an address of the family of `addr`.
	fn width(addr: IpAddr) -> u32 {
		match addr.to_canonical() {
			IpAddr::V4(_) => 32,
			IpAddr::V6(_) => 128,
		}
	}

	/// The bits of `addr`, in its own family.
	fn bits(addr: IpAddr) -> u128 {
		match addr {
			IpAddr::V4(addr) => u128::from(u32::from(addr)),
			IpAddr::V6(addr) => u128::from(addr),
		}
	}

	/// Whether `addr` falls in the range.
	fn contains(&self, addr: IpAddr) -> bool {
		let addr = addr.to_canonical();
		let width = Self::width(self.addr);
		if Self::width(addr) != width {
			return false;
		}

		let shift = width - self.prefix;
		let (range, addr) = (Self::bits(self.addr), Self::bits(addr));
		shift == 128 || range >> shift == addr >> shift
	}
}

/// The hops in front of an edge, such as a load balancer, whose PROXY
/// protocol v2 headers the edge reads.
///
/// # Examples
///
/// ```
/// use tightbeam_grpc::edge::ProxyHops;
///
/// let hops = ProxyHops::new(["10.0.0.0/8", "192.0.2.7", "2001:db8::/32"])?;
/// # Ok::<(), tightbeam_grpc::edge::EdgeError>(())
/// ```
#[derive(Clone, Debug, Default)]
pub struct ProxyHops {
	ranges: Arc<[HopRange]>,
}

impl ProxyHops {
	/// The hops of `ranges`, each an address, such as `192.0.2.7`, or a CIDR
	/// range, such as `10.0.0.0/8`.
	///
	/// # Errors
	///
	/// - [`EdgeError::ProxyHop`] -- a range is no address, or its prefix is longer than its address.
	pub fn new<R: AsRef<str>>(ranges: impl IntoIterator<Item = R>) -> Result<Self, EdgeError> {
		let parsed: Result<Vec<HopRange>, EdgeError> = ranges
			.into_iter()
			.map(|range| HopRange::parse(range.as_ref()).ok_or_else(|| EdgeError::ProxyHop(range.as_ref().to_owned())))
			.collect();
		Ok(Self { ranges: Arc::from(parsed?) })
	}

	/// The read of the header that a connection from `peer` opens with, or
	/// `None` when `peer` is no hop, so its connection opens with no header.
	pub(crate) fn expects(&self, peer: SocketAddr) -> Option<HeaderRead> {
		self.sends_header(peer.ip()).then_some(HeaderRead { hop: peer })
	}

	/// Whether a connection from `peer` opens with a header.
	fn sends_header(&self, peer: IpAddr) -> bool {
		self.ranges.iter().any(|range| range.contains(peer))
	}
}

/// The read of the PROXY header of one connection of a hop.
pub(crate) struct HeaderRead {
	hop: SocketAddr,
}

impl HeaderRead {
	/// Read the header at the start of `stream`, and give what it names.
	pub(crate) async fn read<S: AsyncRead + Unpin>(self, stream: &mut S) -> HeaderVerdict {
		match ProxyHeader::read(stream).await {
			Ok(Some(client)) => HeaderVerdict::Client(client),
			Ok(None) => HeaderVerdict::Local(self.hop),
			Err(refusal) => HeaderVerdict::Refused(refusal),
		}
	}
}

/// Why the edge refuses the PROXY header of a connection of a hop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HeaderRefusal {
	/// The connection opens with no version 2 header, or with a malformed one.
	Malformed,
	/// The connection ends, or fails, within its header.
	Ended,
}

impl HeaderRefusal {
	/// The name that the audit trail records the refusal under.
	#[cfg(feature = "instrument")]
	fn as_str(self) -> &'static str {
		match self {
			Self::Malformed => "malformed",
			Self::Ended => "ended",
		}
	}
}

/// What the PROXY header of one connection of a hop names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HeaderVerdict {
	/// The client of the connection, which becomes its peer.
	Client(SocketAddr),
	/// No client, such as the health check of the hop, so the hop stays the
	/// peer.
	Local(SocketAddr),
	/// A header that the edge refuses, so the connection closes.
	Refused(HeaderRefusal),
}

impl HeaderVerdict {
	/// The peer of the connection, or `None` when the header refuses it.
	pub(crate) fn peer(&self) -> Option<SocketAddr> {
		match self {
			Self::Client(peer) | Self::Local(peer) => Some(*peer),
			Self::Refused(_) => None,
		}
	}

	/// Record the verdict on `audit`, as [`PROXY_HEADER_READ`] or
	/// [`PROXY_HEADER_REFUSED`].
	#[cfg(feature = "instrument")]
	pub(crate) fn record(&self, audit: &EdgeAudit) {
		match self {
			Self::Client(peer) => audit.record(PROXY_HEADER_READ, "client", peer.to_string()),
			Self::Local(peer) => audit.record(PROXY_HEADER_READ, "local", peer.to_string()),
			Self::Refused(refusal) => audit.record(PROXY_HEADER_REFUSED, refusal.as_str(), refusal.as_str()),
		}
	}

	#[cfg(not(feature = "instrument"))]
	pub(crate) fn record(&self, _audit: &EdgeAudit) {}
}

/// The PROXY protocol v2 header that a hop sends ahead of a connection.
struct ProxyHeader;

impl ProxyHeader {
	/// Read the header at the start of `stream`, and give the client address
	/// it names, or `None` for a local connection of the hop, such as its
	/// health check, and a connection of another family.
	///
	/// # Errors
	///
	/// - [`HeaderRefusal::Malformed`] -- the stream opens with no version 2 header, or with a malformed one.
	/// - [`HeaderRefusal::Ended`] -- the stream ends, or fails, within the header.
	async fn read<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Option<SocketAddr>, HeaderRefusal> {
		let mut fixed = [0_u8; 16];
		stream.read_exact(&mut fixed).await.map_err(|_| HeaderRefusal::Ended)?;
		let (signature, rest) = fixed.split_at(SIGNATURE.len());
		if signature != SIGNATURE {
			return Err(HeaderRefusal::Malformed);
		}

		let [version_command, family, high, low] = <[u8; 4]>::try_from(rest).map_err(|_| HeaderRefusal::Malformed)?;
		let length = usize::from(u16::from_be_bytes([high, low]));
		if version_command >> 4 != 2 || length > MAX_BLOCK {
			return Err(HeaderRefusal::Malformed);
		}

		let mut block = vec![0_u8; length];
		stream.read_exact(&mut block).await.map_err(|_| HeaderRefusal::Ended)?;
		match version_command & 0x0f {
			0x0 => Ok(None),
			0x1 => Self::source(family, &block),
			_ => Err(HeaderRefusal::Malformed),
		}
	}

	/// The source address of the address `block` of `family`, or `None` for a
	/// family that names no IP address.
	///
	/// # Errors
	///
	/// - [`HeaderRefusal::Malformed`] -- the block is shorter than the addresses of its family.
	fn source(family: u8, block: &[u8]) -> Result<Option<SocketAddr>, HeaderRefusal> {
		match family >> 4 {
			0x1 => {
				let block: &[u8; 12] = block.first_chunk().ok_or(HeaderRefusal::Malformed)?;
				let [a, b, c, d, _, _, _, _, high, low, _, _] = *block;
				let source = IpAddr::V4(Ipv4Addr::new(a, b, c, d));
				Ok(Some(SocketAddr::new(source, u16::from_be_bytes([high, low]))))
			}
			0x2 => {
				let block: &[u8; 36] = block.first_chunk().ok_or(HeaderRefusal::Malformed)?;
				let (source, rest) = block.split_at(16);
				let source = <[u8; 16]>::try_from(source).map_err(|_| HeaderRefusal::Malformed)?;
				let port = u16::from_be_bytes([rest[16], rest[17]]);
				Ok(Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(source)), port)))
			}
			_ => Ok(None),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The command of a version 2 header: `0x1` for a proxied connection, and
	/// `0x0` for a local one.
	#[derive(Clone, Copy)]
	struct Command(u8);

	/// The address family and protocol byte of a version 2 header.
	#[derive(Clone, Copy)]
	struct Family(u8);

	/// A version 2 header of `command` and `family` over `block`.
	fn header(Command(command): Command, Family(family): Family, block: &[u8]) -> Vec<u8> {
		let length = u16::try_from(block.len()).expect("a test block fits");
		[&SIGNATURE[..], &[0x20 | command, family], &length.to_be_bytes(), block].concat()
	}

	/// The address block of a TCP connection over IPv4 from the client
	/// `203.0.113.7:4242`, and `tail` after it.
	fn v4(tail: &[u8]) -> Vec<u8> {
		[
			&[203, 0, 113, 7, 10, 0, 0, 2][..],
			&4242_u16.to_be_bytes(),
			&443_u16.to_be_bytes(),
			tail,
		]
		.concat()
	}

	/// The address block of a TCP connection over IPv6 from the client
	/// `[2001:db8::7]:4242`.
	fn v6() -> Vec<u8> {
		let client = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7);
		[&client.octets()[..], &[0; 16], &4242_u16.to_be_bytes(), &443_u16.to_be_bytes()].concat()
	}

	fn peer() -> SocketAddr {
		SocketAddr::from(([10, 0, 0, 1], 443))
	}

	/// What a read of `bytes` from a hop gives: the peer, or its refusal.
	async fn read(bytes: Vec<u8>) -> Result<SocketAddr, HeaderRefusal> {
		let read = HeaderRead { hop: peer() }.read(&mut &bytes[..]).await;
		match read {
			HeaderVerdict::Refused(refusal) => Err(refusal),
			verdict => verdict.peer().ok_or(HeaderRefusal::Ended),
		}
	}

	tightbeam::tb_cases! {
		async fn a_header_names_the_peer((bytes, expected): (Vec<u8>, SocketAddr)) {
			assert_eq!(read(bytes).await, Ok(expected));
		}

		cases {
			a_client_over_ipv4 => (
				header(Command(0x1), Family(0x11), &v4(&[])),
				SocketAddr::from(([203, 0, 113, 7], 4242))
			),
			a_client_over_ipv6 => (
				header(Command(0x1), Family(0x21), &v6()),
				SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7)), 4242)
			),
			a_client_before_a_tlv => (
				header(Command(0x1), Family(0x11), &v4(&[0x04, 0x00, 0x01, 0xff])),
				SocketAddr::from(([203, 0, 113, 7], 4242))
			),
			a_local_connection_of_the_hop => (header(Command(0x0), Family(0x00), &[]), peer()),
			an_unspecified_family => (header(Command(0x1), Family(0x00), &[]), peer()),
			a_unix_source => (header(Command(0x1), Family(0x31), &[0; 216]), peer()),
		}
	}

	/// A header that declares one byte past the longest block, and carries
	/// every byte it declares.
	fn oversize() -> Vec<u8> {
		let mut block = v4(&[]);
		block.resize(MAX_BLOCK + 1, 0);
		header(Command(0x1), Family(0x11), &block)
	}

	tightbeam::tb_cases! {
		async fn a_malformed_header_is_invalid(bytes: Vec<u8>) {
			assert_eq!(read(bytes).await, Err(HeaderRefusal::Malformed));
		}

		cases {
			a_block_short_of_its_family => header(Command(0x1), Family(0x11), &[0; 4]),
			an_unknown_command => header(Command(0x2), Family(0x11), &v4(&[])),
			version_one => b"PROXY TCP4 203.0.113.7 10.0.0.2 4242 443\r\n".to_vec(),
			a_block_past_the_longest => oversize(),
		}
	}

	tightbeam::tb_cases! {
		async fn a_connection_that_ends_within_its_header_ended(bytes: Vec<u8>) {
			assert_eq!(read(bytes).await, Err(HeaderRefusal::Ended));
		}

		cases {
			no_byte => Vec::new(),
			part_of_the_signature => SIGNATURE[..5].to_vec(),
			part_of_the_block => header(Command(0x1), Family(0x11), &v4(&[]))[..20].to_vec(),
		}
	}

	/// The hops of the ranges that the cases test.
	fn hops() -> ProxyHops {
		ProxyHops::new(["10.0.0.0/8", "192.0.2.7", "2001:db8::/32"]).expect("the test ranges parse")
	}

	tightbeam::tb_cases! {
		fn a_hop_range_holds_the_addresses_under_its_prefix((address, holds): (&str, bool)) {
			let address: IpAddr = address.parse().expect("a test address parses");
			assert_eq!(hops().sends_header(address), holds);
		}

		cases {
			an_address_under_a_prefix => ("10.200.3.4", true),
			a_mapped_address_under_a_prefix => ("::ffff:10.1.2.3", true),
			an_ipv6_address_under_a_prefix => ("2001:db8:1::9", true),
			an_exact_address => ("192.0.2.7", true),
			an_address_past_a_prefix => ("11.0.0.1", false),
			a_neighbor_of_an_exact_address => ("192.0.2.8", false),
			an_ipv6_address_past_a_prefix => ("2001:db9::1", false),
		}
	}

	#[test]
	fn an_empty_prefix_holds_every_address_of_its_family() -> Result<(), EdgeError> {
		let every = ProxyHops::new(["0.0.0.0/0"])?;
		assert!(every.sends_header(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
		Ok(())
	}

	tightbeam::tb_cases! {
		fn a_range_off_the_grammar_is_refused(range: &str) {
			assert!(ProxyHops::new([range]).is_err());
		}

		cases {
			an_ipv4_prefix_past_its_width => "10.0.0.0/33",
			an_ipv6_prefix_past_its_width => "2001:db8::/129",
			a_host_name => "host",
			a_prefix_that_is_no_number => "10.0.0.0/x",
		}
	}
}
