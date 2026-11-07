//! The body compression the engine owns: zstd over the pure-Rust `ruzstd`
//! decoder and encoder.
//!
//! [`ZstdCompression`] implements tightbeam's [`Inflator`] and [`Compressor`]
//! with the clauses of upstream's `tightbeam::compress::ZstdCompression`.
//! Upstream links libzstd through `zstd-sys`, which needs a C compiler for
//! `wasm32-unknown-unknown`, and the build host has none. The engine therefore
//! copies the clauses (`tb:src/compress/mod.rs:116-121`, `:150-157`,
//! `:159-214`) and names its own refusals in [`ZstdRefusal`], because every
//! upstream refusal variant exists only under the `zstd` feature
//! (`tb:src/error.rs:47-86`).
//!
//! - The engine admits one frame: a zstd frame, or a skippable frame that
//!   inflates to no octets. An octet after it is refused.
//! - The output never grows past the ceiling of the compressor, and the window
//!   a frame declares is held to that ceiling, rounded up to a power of two.
//! - The level range of [`ZSTD_MIN_LEVEL`] and [`ZSTD_MAX_LEVEL`] is a fact
//!   copied from libzstd, because upstream reads it from libzstd at runtime.
//!
//! The host-only interop tests compare each clause with upstream, which the
//! native build links.
//!
//! # Sources
//!
//! - RFC 8878, Zstandard Compression and the `application/zstd` Media Type,
//!   section 3.1.1 (the frame layout and `Window_Descriptor`) and section
//!   3.1.2 (skippable frames): <https://datatracker.ietf.org/doc/html/rfc8878>
//! - CWE-409, Improper Handling of Highly Compressed Data:
//!   <https://cwe.mitre.org/data/definitions/409.html>
//! - CWE-770, Allocation of Resources Without Limits or Throttling:
//!   <https://cwe.mitre.org/data/definitions/770.html>

use std::io::{self, Read, Write};

use ruzstd::decoding::errors::{FrameDecoderError, FrameHeaderError, ReadFrameHeaderError};
use ruzstd::decoding::{BlockDecodingStrategy, FrameDecoder};
use ruzstd::encoding::{compress_to_vec, CompressionLevel};

use tightbeam::cms::compressed_data::CompressedData;
use tightbeam::cms::content_info::CmsVersion;
use tightbeam::cms::signed_data::EncapsulatedContentInfo;
use tightbeam::compress::{Compressor, Inflator};
use tightbeam::constants::DEFAULT_MAX_DECOMPRESSED_LEN;
use tightbeam::der::asn1::ObjectIdentifier;
use tightbeam::der::Any;
use tightbeam::error::{CompressionError, CompressionResult};
use tightbeam::oids::{COMPRESSION_ZSTD, DATA};
use tightbeam::spki::AlgorithmIdentifierOwned;
use tightbeam::Errorizable;

#[cfg(target_arch = "wasm32")]
use js_sys::Uint8Array;
#[cfg(target_arch = "wasm32")]
use tightbeam::der::{Decode, Encode};
#[cfg(target_arch = "wasm32")]
use tightbeam::TightBeamError;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
use crate::fault::{JsFault, RefusalCode};
#[cfg(target_arch = "wasm32")]
use crate::promise::{JsBytes, Record, WholeNumber};

/// The lowest compression level libzstd accepts, `ZSTD_minCLevel`.
///
/// The value is a fact copied from zstd 1.5.7, because upstream reads the
/// range from libzstd at runtime (`tb:src/compress/mod.rs:155`), which this
/// crate cannot link for wasm32. zstd-sys 2.1.2 defines it as
/// `-ZSTD_TARGETLENGTH_MAX` (`zstd/lib/compress/zstd_compress.c:7674`), which
/// is `ZSTD_BLOCKSIZE_MAX` (`zstd/lib/zstd.h:1277`), `1 << 17`
/// (`zstd/lib/zstd.h:147-148`). The bound cases of the host tests pin it
/// against upstream.
pub const ZSTD_MIN_LEVEL: i32 = -131_072;

/// The highest compression level libzstd accepts, `ZSTD_maxCLevel`.
///
/// The value is a fact copied from zstd 1.5.7, as [`ZSTD_MIN_LEVEL`] is.
/// zstd-sys 2.1.2 returns `ZSTD_MAX_CLEVEL`
/// (`zstd/lib/compress/zstd_compress.c:7673`), which
/// `zstd/lib/compress/clevels.h:19` defines.
pub const ZSTD_MAX_LEVEL: i32 = 22;

/// The growth step of the output buffer, as upstream's `RESERVE_HINT`.
///
/// The output starts small and grows toward the ceiling, so a frame that
/// declares a large content size cannot make the first allocation the attack.
const RESERVE_HINT: usize = 64 * 1024;

/// The smallest window log zstd accepts, `ZSTD_WINDOWLOG_ABSOLUTEMIN`, as
/// upstream names it (`tb:src/compress/mod.rs:38-39`).
const ZSTD_WINDOW_LOG_MIN: u32 = 10;

/// The largest window log zstd accepts on a 32-bit target,
/// `ZSTD_WINDOWLOG_MAX_32`, as upstream names it
/// (`tb:src/compress/mod.rs:43-45`). `wasm32-unknown-unknown` is such a target.
#[cfg(target_pointer_width = "32")]
const ZSTD_WINDOW_LOG_MAX: u32 = 30;

/// The largest window log zstd accepts on a 64-bit target,
/// `ZSTD_WINDOWLOG_MAX_64`, as upstream names it
/// (`tb:src/compress/mod.rs:47-51`). The host interop tests run here.
#[cfg(not(target_pointer_width = "32"))]
const ZSTD_WINDOW_LOG_MAX: u32 = 31;

/// The octet that a zstd frame header carries its `Frame_Header_Descriptor`
/// at, after the four octets of the magic number (RFC 8878 section 3.1.1.1).
const DESCRIPTOR_AT: usize = 4;

/// The octets of a skippable frame header: the magic number and
/// `Frame_Size` (RFC 8878 section 3.1.2).
const SKIPPABLE_HEADER: u64 = 8;

/// A zstd body the engine refuses to inflate.
///
/// Each variant has the `RefusalCode` of the same name, the `code` that a
/// JavaScript caller of `ZstdCompression.decompress` reads. On the frame inflate path the refusal
/// travels inside upstream's `CompressionError::IO`, as
/// [`ZstdCompression`]'s [`Inflator`] implementation states.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Errorizable)]
pub enum ZstdRefusal {
	/// The frame declares a window past the ceiling of the decoder, so the
	/// decoder would reserve more memory than the output may fill (CWE-770).
	#[error("the zstd window of {declared} octets exceeds the {max}-octet ceiling")]
	WindowTooLarge {
		/// The window the frame declares, in octets.
		declared: u64,
		/// The largest window the decoder admits, in octets.
		max: u64,
	},
	/// The output grows past the ceiling that the variant carries (CWE-409).
	#[error("decompressed output exceeds the {0}-byte limit")]
	OutputLimitExceeded(usize),
	/// The input ends before the frame it opens completes.
	#[error("the zstd frame is truncated")]
	Truncated,
	/// Octets follow the one frame of the body, and the variant counts them.
	#[error("{0} trailing octets after the zstd frame")]
	TrailingBytes(usize),
	/// The decoder consumed no input and produced no output, so a further
	/// step would repeat this one (CWE-835).
	#[error("the zstd decoder stalled without consuming input")]
	Stalled,
	/// The octets are no zstd frame: a bad magic number, a reserved field,
	/// a corrupt block, a wrong checksum, or a content size the blocks do not
	/// fill.
	#[error("the octets are no well-formed zstd frame")]
	Malformed,
}

/// The engine zstd compressor and inflator, with a ceiling on the output of
/// decompression.
///
/// - The default ceiling is upstream's `DEFAULT_MAX_DECOMPRESSED_LEN`
///   (`tb:src/constants.rs:656`), 16 MiB.
/// - Output past the ceiling is refused with
///   [`ZstdRefusal::OutputLimitExceeded`] (CWE-409).
/// - The window a frame declares is held to the ceiling rounded up to a power
///   of two, so a short header cannot make the decoder reserve more memory
///   than the output may fill (CWE-770).
/// - The compressor writes at the `Fastest` level of ruzstd and records no
///   parameters, because ruzstd 0.9.0 implements no higher level
///   (`src/encoding/mod.rs:47-67`).
/// - The compressor declares the 128 KiB window that ruzstd 0.9.0 always
///   writes (`src/encoding/frame_compressor.rs:83`, `:149`), so a peer admits
///   its bodies once the ceiling of that peer exceeds 64 KiB.
///
/// # Examples
///
/// ```
/// use tightbeam::compress::{Compressor, Inflator};
/// use tightbeam_ws_wasm::compress::{ZstdCompression, ZstdRefusal};
///
/// let zstd = ZstdCompression::default();
/// let (compressed, _) = zstd.compress(b"frame body", None)?;
/// assert_eq!(zstd.inflate(&compressed), Ok(b"frame body".to_vec()));
///
/// let truncated = &compressed[..compressed.len() - 1];
/// assert_eq!(zstd.inflate(truncated), Err(ZstdRefusal::Truncated));
/// # Ok::<(), tightbeam::error::CompressionError>(())
/// ```
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZstdCompression {
	max_output: usize,
}

impl Default for ZstdCompression {
	fn default() -> Self {
		Self { max_output: DEFAULT_MAX_DECOMPRESSED_LEN }
	}
}

impl ZstdCompression {
	/// A compressor whose decompression output is capped at `max_output`
	/// octets.
	#[must_use]
	pub const fn with_max_output(max_output: usize) -> Self {
		Self { max_output }
	}

	/// Whether `parameters`, the parameters of a `compressionAlgorithm` that
	/// names zstd, take the form upstream admits: absent, or an `INTEGER`
	/// level from [`ZSTD_MIN_LEVEL`] to [`ZSTD_MAX_LEVEL`]
	/// (`tb:src/compress/mod.rs:150-157`).
	#[must_use]
	pub fn admits_parameters(&self, parameters: Option<&Any>) -> bool {
		let Some(parameters) = parameters else {
			return true;
		};

		let levels = ZSTD_MIN_LEVEL..=ZSTD_MAX_LEVEL;
		parameters.decode_as::<i32>().is_ok_and(|level| levels.contains(&level))
	}

	/// Inflate `data`, which holds exactly one frame, within the ceiling.
	///
	/// A skippable frame carries no content, so it inflates to no octets, as
	/// upstream's decoder reads it (RFC 8878 section 3.1.2).
	///
	/// # Errors
	///
	/// - [`ZstdRefusal::WindowTooLarge`] -- the frame declares a window past the rounded ceiling.
	/// - [`ZstdRefusal::OutputLimitExceeded`] -- the output grows past the ceiling.
	/// - [`ZstdRefusal::Truncated`] -- the input ends inside the frame.
	/// - [`ZstdRefusal::TrailingBytes`] -- octets follow the frame.
	/// - [`ZstdRefusal::Stalled`] -- a decode step consumed no input.
	/// - [`ZstdRefusal::Malformed`] -- the octets are no well-formed frame.
	pub fn inflate(&self, data: &[u8]) -> Result<Vec<u8>, ZstdRefusal> {
		let max_window = self.max_window();
		let mut source = Source::over(data);
		let mut decoder = FrameDecoder::new();
		decoder.set_max_window_size(max_window);

		match decoder.reset(&mut source) {
			Ok(()) => {}
			Err(FrameDecoderError::ReadFrameHeaderError(ReadFrameHeaderError::SkipFrame { length, .. })) => {
				let skipped = Skippable::spanning(length).within(data)?;
				return Ok(skipped);
			}
			Err(error) => return Err(source.refusal(&error, max_window)),
		}

		// Every frame holds at least one block, so the loop runs, and the drain
		// of the step that finishes the frame releases the window too.
		let header = Descriptor::of(data)?;
		let mut sink = Ceiling::new(self.max_output);
		while !decoder.is_finished() {
			let consumed = decoder.bytes_read_from_source();
			let decoded = decoder.decode_blocks(&mut source, BlockDecodingStrategy::UptoBlocks(1));
			decoded.map_err(|error| source.refusal(&error, max_window))?;
			sink.drain(&mut decoder)?;

			let advanced = decoder.bytes_read_from_source() > consumed;
			if !advanced {
				return Err(ZstdRefusal::Stalled);
			}
		}

		header.check(&decoder, sink.len())?;
		source.check_end()?;

		Ok(sink.into_octets())
	}

	/// The largest window log a frame may declare: the smallest power of two
	/// at or above the ceiling, within the range zstd accepts, as upstream
	/// sets `WindowLogMax` (`tb:src/compress/mod.rs:109-118`).
	fn window_log_max(&self) -> u32 {
		let window = self.max_output.checked_next_power_of_two();
		let ceil_log2 = window.map_or(usize::BITS, usize::trailing_zeros);
		ceil_log2.clamp(ZSTD_WINDOW_LOG_MIN, ZSTD_WINDOW_LOG_MAX)
	}

	/// The largest window a frame may declare, in octets.
	fn max_window(&self) -> u64 {
		1 << self.window_log_max()
	}
}

impl Compressor for ZstdCompression {
	/// Compress `data` at the `Fastest` level of ruzstd, and describe it with the
	/// `CompressedData` upstream emits (`tb:src/compress/mod.rs:124-139`):
	/// version 0, zstd with no parameters, and the content type `id-data`
	/// when `content_info` names none (RFC 3274 section 1.1).
	fn compress(
		&self,
		data: &[u8],
		content_info: Option<EncapsulatedContentInfo>,
	) -> CompressionResult<(Vec<u8>, CompressedData)> {
		let output = compress_to_vec(data, CompressionLevel::Fastest);

		let compression_alg = AlgorithmIdentifierOwned { oid: self.algorithm_oid(), parameters: None };
		let encap_content_info =
			content_info.unwrap_or(EncapsulatedContentInfo { econtent_type: DATA, econtent: None });
		let compressed_data = CompressedData { version: CmsVersion::V0, compression_alg, encap_content_info };

		Ok((output, compressed_data))
	}
}

/// The engine inflator on upstream's frame paths, such as
/// `Frame::inflate_in_place` (`tb:src/frame/compress.rs:128`) and
/// `CleartextFrame::inflate` (`tb:src/router.rs:170`).
///
/// `Inflator::decompress` returns upstream's error type
/// (`tb:src/core.rs:81-82`), and every upstream refusal variant exists only
/// under the `zstd` feature. The implementation therefore carries a
/// [`ZstdRefusal`] inside `CompressionError::IO`, the one variant that exists
/// without `zstd`, and a caller of the frame path reads `CompressionError`.
/// The engine never recovers the variant from the `io::Error`.
impl Inflator for ZstdCompression {
	fn algorithm_oid(&self) -> ObjectIdentifier {
		COMPRESSION_ZSTD
	}

	fn admits_parameters(&self, parameters: Option<&Any>) -> bool {
		ZstdCompression::admits_parameters(self, parameters)
	}

	fn decompress(&self, data: &[u8]) -> tightbeam::error::Result<Vec<u8>> {
		let inflated = self.inflate(data);
		inflated.map_err(|refusal| CompressionError::IO(io::Error::other(refusal)).into())
	}
}

#[cfg(target_arch = "wasm32")]
impl ZstdCompression {
	/// The compression capped at `max_output`, the ceiling as JavaScript
	/// passes it: `undefined` for 16 MiB, or a whole number of octets. The
	/// value is `Copy` and holds only the ceiling, so a call that reads a
	/// ceiling makes no handle.
	///
	/// # Errors
	///
	/// - `InvalidMaxOutput` -- `max_output` is no whole, non-negative number that the target
	///   holds, such as `NaN`, `-1`, or `0.5`.
	pub(crate) fn within(max_output: &JsValue) -> Result<Self, JsFault> {
		let Some(ceiling) = Record::present(max_output.clone()) else {
			return Ok(Self::default());
		};

		let whole = WholeNumber::read::<usize>(&ceiling);
		let refusal = || {
			RefusalCode::InvalidMaxOutput
				.because("must be a whole number of octets")
				.at("maxOutput")
		};

		let max_output = whole.ok_or_else(refusal)?;
		Ok(Self::with_max_output(max_output))
	}
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
impl ZstdCompression {
	/// The engine zstd compression of the realm. The handle holds no ceiling
	/// that JavaScript chose: each [`decompress`](Self::decompress_js) takes
	/// its ceiling as an argument, so no ceiling leaves state behind.
	#[wasm_bindgen(constructor)]
	#[must_use]
	pub fn realm() -> ZstdCompression {
		Self::default()
	}

	/// The ceiling `maxOutput` names, parsed once into a whole number of
	/// octets: 16 MiB for `undefined`. A holder passes the answer to each
	/// inflate, so one handle serves every ceiling.
	///
	/// # Errors
	///
	/// - `InvalidMaxOutput` -- `maxOutput` is no whole, non-negative number that the target
	///   holds.
	#[wasm_bindgen(js_name = ceiling)]
	pub fn ceiling_js(
		&self,
		#[wasm_bindgen(unchecked_param_type = "number | undefined")] max_output: JsValue,
	) -> Result<usize, JsFault> {
		let within = Self::within(&max_output)?;
		Ok(within.max_output)
	}

	/// Whether `parametersDer`, the DER parameters a compactness info names,
	/// take a form zstd defines: absent, or a level inside the range libzstd
	/// accepts. Octets that are no DER value answer `false`.
	///
	/// # Errors
	///
	/// - `InvalidBytes` -- `parametersDer` is neither `undefined` nor a `Uint8Array`.
	#[wasm_bindgen(js_name = admitsParameters)]
	pub fn admits_parameters_js(
		&self,
		#[wasm_bindgen(unchecked_param_type = "Uint8Array | undefined")] parameters_der: JsValue,
	) -> Result<bool, JsFault> {
		let Some(parameters) = Record::present(parameters_der) else {
			return Ok(self.admits_parameters(None));
		};

		let octets = JsBytes::read_value(&parameters, "parametersDer")?;
		let decoded = Any::from_der(&octets);
		let admitted = decoded.is_ok_and(|parameters| self.admits_parameters(Some(&parameters)));
		Ok(admitted)
	}

	/// Compress `bodyDer` into the `CompressedBody` a frame installs: the
	/// compressed octets, under the algorithm that `algorithmOid` names. The
	/// engine writes no parameters.
	///
	/// # Errors
	///
	/// - `InvalidBytes` -- `bodyDer` is not a `Uint8Array`.
	#[wasm_bindgen(js_name = compress, unchecked_return_type = "CompressedBody")]
	pub fn compress_js(&self, body_der: JsBytes) -> Result<JsValue, JsFault> {
		let body = body_der.read()?;
		let compressed = Compressor::compress(self, &body, None).map_err(TightBeamError::from)?;
		let (data, info) = compressed;

		let parameters = info.compression_alg.parameters.as_ref().map(Encode::to_der).transpose()?;
		let parameters = parameters.map(|der| Uint8Array::from(der.as_slice()));

		let record = Record::new();
		record.set_present("parametersDer", parameters);
		record.set_bytes("data", &data);
		Ok(record.into())
	}

	/// Inflate `data`, which holds exactly one frame, within the ceiling
	/// `maxOutput` that [`ceiling`](Self::ceiling_js) answered.
	///
	/// # Errors
	///
	/// - `InvalidBytes` -- `data` is not a `Uint8Array`.
	/// - The errors of the ceiling parse.
	/// - The variant name of each [`ZstdRefusal`] of [`Self::inflate`]: `WindowTooLarge`,
	///   `OutputLimitExceeded`, `Truncated`, `TrailingBytes`, `Stalled`, `Malformed`.
	#[wasm_bindgen(js_name = decompress)]
	pub fn decompress_js(
		&self,
		data: JsBytes,
		#[wasm_bindgen(unchecked_param_type = "number")] max_output: JsValue,
	) -> Result<Vec<u8>, JsFault> {
		let within = Self::within(&max_output)?;
		let data = data.read()?;

		let inflated = within.inflate(&data)?;
		Ok(inflated)
	}
}

#[cfg(target_arch = "wasm32")]
impl From<ZstdRefusal> for JsFault {
	fn from(refusal: ZstdRefusal) -> Self {
		let code = RefusalCode::from(&refusal);
		code.because(refusal)
	}
}

/// The input of one inflate: a reader over the octets that records whether a
/// read asked for more octets than remained.
///
/// ruzstd reads its source with `read_exact` alone, so a short read means the
/// frame continues past the input, which libzstd reports as more input to
/// wait for, and upstream as [`ZstdRefusal::Truncated`].
struct Source<'a> {
	rest: &'a [u8],
	starved: bool,
}

impl<'a> Source<'a> {
	fn over(data: &'a [u8]) -> Self {
		Self { rest: data, starved: false }
	}

	/// The refusal that `error`, a failure of the decoder over this source,
	/// stands for. A window past the format itself is past `max_window` too.
	fn refusal(&self, error: &FrameDecoderError, max_window: u64) -> ZstdRefusal {
		match error {
			FrameDecoderError::WindowSizeTooBig { requested, max } => {
				ZstdRefusal::WindowTooLarge { declared: *requested, max: *max }
			}
			FrameDecoderError::FrameHeaderError(FrameHeaderError::WindowTooBig { got }) => {
				ZstdRefusal::WindowTooLarge { declared: *got, max: max_window }
			}
			_ if self.starved => ZstdRefusal::Truncated,
			_ => ZstdRefusal::Malformed,
		}
	}

	/// Refuse the octets that follow the frame the decoder read.
	fn check_end(&self) -> Result<(), ZstdRefusal> {
		if self.rest.is_empty() {
			return Ok(());
		}

		Err(ZstdRefusal::TrailingBytes(self.rest.len()))
	}
}

impl Read for Source<'_> {
	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		let count = self.rest.len().min(buf.len());
		if count < buf.len() {
			self.starved = true;
		}

		let (taken, rest) = self.rest.split_at(count);
		buf[..count].copy_from_slice(taken);
		self.rest = rest;
		Ok(count)
	}
}

/// A skippable frame, by the `Frame_Size` its header declares
/// (RFC 8878 section 3.1.2).
struct Skippable {
	end: u64,
}

impl Skippable {
	fn spanning(length: u32) -> Self {
		Self { end: SKIPPABLE_HEADER + u64::from(length) }
	}

	/// The content of this frame, which inflates to no octets, once `data`
	/// holds the frame alone.
	///
	/// # Errors
	///
	/// - [`ZstdRefusal::Truncated`] -- `data` ends inside the frame.
	/// - [`ZstdRefusal::TrailingBytes`] -- octets follow the frame.
	fn within(&self, data: &[u8]) -> Result<Vec<u8>, ZstdRefusal> {
		let held = data.len() as u64;
		if held < self.end {
			return Err(ZstdRefusal::Truncated);
		}
		if held > self.end {
			let trailing = held - self.end;
			return Err(ZstdRefusal::TrailingBytes(trailing as usize));
		}

		Ok(Vec::new())
	}
}

/// The `Frame_Header_Descriptor` of a zstd frame (RFC 8878 section 3.1.1.1.1),
/// for the two clauses libzstd checks that ruzstd 0.9.0 reads but neither
/// checks nor exposes: the reserved bit, and whether the frame declares its
/// content size (`src/decoding/frame.rs:200-260`).
struct Descriptor(u8);

impl Descriptor {
	/// The bit RFC 8878 reserves, which a valid frame clears.
	const RESERVED: u8 = 0x08;
	/// `Single_Segment_flag`, which implies a declared content size.
	const SINGLE_SEGMENT: u8 = 0x20;
	/// The shift of `Frame_Content_Size_flag`.
	const CONTENT_SIZE_SHIFT: u32 = 6;

	/// The descriptor of the zstd frame that opens `data`.
	///
	/// # Errors
	///
	/// - [`ZstdRefusal::Truncated`] -- `data` ends before the descriptor.
	/// - [`ZstdRefusal::Malformed`] -- the descriptor sets the reserved bit.
	fn of(data: &[u8]) -> Result<Self, ZstdRefusal> {
		let descriptor = data.get(DESCRIPTOR_AT).copied().ok_or(ZstdRefusal::Truncated)?;
		if descriptor & Self::RESERVED != 0 {
			return Err(ZstdRefusal::Malformed);
		}

		Ok(Self(descriptor))
	}

	/// Whether the frame declares its content size.
	fn declares_size(&self) -> bool {
		let flagged = self.0 >> Self::CONTENT_SIZE_SHIFT != 0;
		flagged || self.0 & Self::SINGLE_SEGMENT != 0
	}

	/// Refuse a frame whose content checksum or declared content size the
	/// `inflated` octets that `decoder` produced do not match, as libzstd
	/// refuses it.
	///
	/// # Errors
	///
	/// - [`ZstdRefusal::Malformed`] -- the checksum or the content size differs.
	fn check(&self, decoder: &FrameDecoder, inflated: usize) -> Result<(), ZstdRefusal> {
		let carried = decoder.get_checksum_from_data();
		if carried.is_some() && carried != decoder.get_calculated_checksum() {
			return Err(ZstdRefusal::Malformed);
		}

		let sized = inflated as u64 == decoder.content_size();
		if self.declares_size() && !sized {
			return Err(ZstdRefusal::Malformed);
		}

		Ok(())
	}
}

/// The output of one inflate, which refuses any octet past the ceiling
/// before it holds it, and grows in steps of [`RESERVE_HINT`].
struct Ceiling {
	output: Vec<u8>,
	max_output: usize,
	exceeded: bool,
}

impl Ceiling {
	fn new(max_output: usize) -> Self {
		let output = Vec::with_capacity(max_output.min(RESERVE_HINT));
		Self { output, max_output, exceeded: false }
	}

	/// Move the octets `decoder` releases into the output.
	///
	/// # Errors
	///
	/// - [`ZstdRefusal::OutputLimitExceeded`] -- the octets grow past the ceiling.
	/// - [`ZstdRefusal::Malformed`] -- the decoder fails to release its octets.
	fn drain(&mut self, decoder: &mut FrameDecoder) -> Result<(), ZstdRefusal> {
		let drained = decoder.collect_to_writer(&mut *self);
		match drained {
			Ok(_) => Ok(()),
			Err(_) if self.exceeded => Err(ZstdRefusal::OutputLimitExceeded(self.max_output)),
			Err(_) => Err(ZstdRefusal::Malformed),
		}
	}

	fn len(&self) -> usize {
		self.output.len()
	}

	fn into_octets(self) -> Vec<u8> {
		self.output
	}
}

impl Write for Ceiling {
	fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
		let room = self.max_output - self.output.len();
		if buf.len() > room {
			self.exceeded = true;
			return Err(io::Error::other(ZstdRefusal::OutputLimitExceeded(self.max_output)));
		}

		let spare = self.output.capacity() - self.output.len();
		if spare < buf.len() {
			let step = buf.len().max(RESERVE_HINT).min(room);
			self.output.reserve_exact(step);
		}

		self.output.extend_from_slice(buf);
		Ok(buf.len())
	}

	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

/// Frames the tests of both targets craft.
#[cfg(test)]
mod fixtures {
	/// A frame whose header declares a window of `2^window_log` octets and
	/// whose one RLE block emits a single octet, as upstream's
	/// `frame_declaring_window` builds it (`tb:src/compress/mod.rs:336-346`).
	///
	/// The window descriptor holds the window log less 10 in its top five
	/// bits (RFC 8878 section 3.1.1.1.2).
	pub(super) fn frame_declaring_window(window_log: u8) -> Vec<u8> {
		let window_descriptor = (window_log - 10) << 3;
		vec![0x28, 0xb5, 0x2f, 0xfd, 0x00, window_descriptor, 0x0b, 0x00, 0x00, 0x41]
	}
}

// The tests run on the host, where upstream links libzstd as the reference.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
	use tightbeam::compress::{Compressor, Inflator, ZstdCompression as Upstream};
	use tightbeam::constants::DEFAULT_MAX_DECOMPRESSED_LEN;
	use tightbeam::der::Any;
	use tightbeam::error::CompressionError;
	use tightbeam::oids::DATA;
	use tightbeam::testing::vectors::patterned;
	use tightbeam::testing::TestMessage;
	use tightbeam::{compose, tb_cases, TightBeamError};

	use super::fixtures::frame_declaring_window;
	use super::{ZstdCompression, ZstdRefusal};

	type TestResult = core::result::Result<(), Box<dyn core::error::Error>>;
	type AnyResult<T> = core::result::Result<T, Box<dyn core::error::Error>>;

	/// The frame upstream compresses `len` zero octets into.
	fn upstream_zeros(len: usize) -> AnyResult<Vec<u8>> {
		let (compressed, _) = Upstream::default().compress(&vec![0u8; len], None)?;
		Ok(compressed)
	}

	/// The DER of the `INTEGER` level `level`, as compactness parameters.
	fn level(level: i32) -> AnyResult<Any> {
		Ok(Any::encode_from(&level)?)
	}

	/// One zstd frame followed by a skippable frame whose payload ends in
	/// the seekable-format magic number, upstream's `TRAILING_SEEK_TABLE`
	/// (`tb:src/compress/mod.rs:306-311`).
	const TRAILING_SEEK_TABLE: &[u8] = &[
		0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x54, 0x00, 0x00, 0x10, 0x00, 0x00, 0x01, 0x00, 0xfb, 0xff, 0x39, 0xc0, 0x02,
		0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10, 0x00, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10, 0x02, 0x00, 0x10, 0x00,
		0x02, 0x00, 0x10, 0x00, 0x03, 0x12, 0x0a, 0x00, 0x5e, 0x2a, 0x4d, 0x18, 0x11, 0x00, 0x00, 0x00, 0x2f, 0x00,
		0x00, 0x00, 0x40, 0x42, 0x0f, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xb1, 0xea, 0x92, 0x8f,
	];

	/// The skippable frame alone, taken from the octet stream above.
	const SKIPPABLE_TAIL: &[u8] = TRAILING_SEEK_TABLE.split_at(44).1;

	// A body of any size and pattern that upstream compresses inflates in the
	// engine to the octets it compressed.
	tb_cases! {
		fn a_frame_compressed_upstream_inflates_in_the_engine(data: Vec<u8>) -> TestResult {
			let (compressed, _) = Upstream::default().compress(&data, None)?;
			assert_eq!(ZstdCompression::default().inflate(&compressed)?, data);
			Ok(())
		}
		cases {
			empty => Vec::new(),
			one_octet => b"a".to_vec(),
			a_pangram => b"The quick brown fox jumps over the lazy dog".to_vec(),
			patterned => patterned(2048),
			repeated => vec![b'a'; 16 * 1024],
		}
	}

	// A body of any size and pattern that the engine compresses inflates
	// upstream to the octets it compressed.
	tb_cases! {
		fn a_frame_compressed_in_the_engine_inflates_upstream(data: Vec<u8>) -> TestResult {
			let (compressed, _) = ZstdCompression::default().compress(&data, None)?;
			assert_eq!(Upstream::default().decompress(&compressed)?, data);
			Ok(())
		}
		cases {
			empty => Vec::new(),
			one_octet => b"a".to_vec(),
			a_pangram => b"The quick brown fox jumps over the lazy dog".to_vec(),
			patterned => patterned(2048),
			repeated => vec![b'a'; 16 * 1024],
		}
	}

	/// A frame upstream compressed inflates in place with the engine
	/// inflator, the step `CleartextFrame::inflate` takes
	/// (`tb:src/router.rs:178`).
	#[test]
	fn an_upstream_frame_inflates_in_place_with_the_engine() -> TestResult {
		let message = TestMessage::sample(None);
		let mut frame = compose! {
			V1: id: "packed", order: 1u64, message: message.clone(), compactness: Upstream::default()
		}?;

		let _opened = frame.inflate_in_place(&ZstdCompression::default())?;
		assert_eq!(tightbeam::decode::<TestMessage>(frame.message())?, message);
		Ok(())
	}

	/// A frame the engine compressed inflates in place with upstream's
	/// inflator.
	#[test]
	fn an_engine_frame_inflates_in_place_upstream() -> TestResult {
		let message = TestMessage::sample(None);
		let mut frame = compose! {
			V1: id: "packed", order: 1u64, message: message.clone(), compactness: ZstdCompression::default()
		}?;

		let _opened = frame.inflate_in_place(&Upstream::default())?;
		assert_eq!(tightbeam::decode::<TestMessage>(frame.message())?, message);
		Ok(())
	}

	/// A refusal on the frame inflate path is a compression error, carried in
	/// the one variant that exists without upstream's `zstd` feature.
	#[test]
	fn a_refusal_on_the_inflate_path_is_a_compression_error() -> TestResult {
		let compressed = upstream_zeros(4096)?;
		let truncated = &compressed[..compressed.len() - 1];

		let refused = Inflator::decompress(&ZstdCompression::default(), truncated);
		assert!(matches!(
			refused,
			Err(TightBeamError::CompressionError(CompressionError::IO(_)))
		));
		Ok(())
	}

	/// The engine body declares `id-data` as the type of the content it
	/// compresses, as upstream's does (RFC 3274 section 1.1).
	#[test]
	fn the_engine_body_declares_id_data() -> TestResult {
		let (_, compressed_data) = ZstdCompression::default().compress(b"frame body", None)?;
		assert_eq!(compressed_data.encap_content_info.econtent_type, DATA);
		assert_eq!(compressed_data.compression_alg.parameters, None);
		Ok(())
	}

	/// A stream that lands exactly on the output ceiling inflates whole, as
	/// upstream's `decompress_within_limit_round_trips` pins.
	#[test]
	fn the_engine_inflates_a_stream_that_lands_on_the_ceiling() -> TestResult {
		let compressed = upstream_zeros(4096)?;
		let inflated = ZstdCompression::with_max_output(4096).inflate(&compressed)?;
		assert_eq!(inflated, vec![0u8; 4096]);
		Ok(())
	}

	/// A stream one octet past the ceiling is refused with that ceiling, as
	/// upstream's `decompress_over_limit_rejected` pins.
	#[test]
	fn the_engine_refuses_a_stream_one_octet_past_the_ceiling() -> TestResult {
		let compressed = upstream_zeros(4096)?;
		let refused = ZstdCompression::with_max_output(4095).inflate(&compressed);
		assert_eq!(refused, Err(ZstdRefusal::OutputLimitExceeded(4095)));
		Ok(())
	}

	/// A stream with a seek table after its frame ends in a refusal, so the
	/// decode of a hostile footer terminates, as upstream's
	/// `seekable_footer_input_terminates` pins. Its frame declares a 1 MiB
	/// window, past a 64 KiB ceiling.
	#[test]
	fn the_engine_refuses_a_seekable_footer() {
		let refused = ZstdCompression::with_max_output(65536).inflate(TRAILING_SEEK_TABLE);
		assert!(matches!(refused, Err(ZstdRefusal::WindowTooLarge { .. })));
	}

	/// The octets after the one frame of a stream are refused as trailing, as
	/// upstream's `octets_after_the_frame_are_rejected` pins.
	#[test]
	fn the_engine_refuses_octets_after_the_frame() -> TestResult {
		let mut framed = upstream_zeros(4096)?;
		framed.extend_from_slice(SKIPPABLE_TAIL);

		let refused = ZstdCompression::with_max_output(65536).inflate(&framed);
		assert_eq!(refused, Err(ZstdRefusal::TrailingBytes(SKIPPABLE_TAIL.len())));
		Ok(())
	}

	// A frame may declare a window up to the output ceiling rounded up to a
	// power of two, as upstream's
	// `a_window_within_the_rounded_output_ceiling_decodes` pins. The 31 log
	// is the clamp on the 64-bit host.
	tb_cases! {
		fn the_engine_inflates_a_window_within_the_rounded_ceiling((max_output, window_log): (usize, u8)) -> TestResult {
			let frame = frame_declaring_window(window_log);
			assert_eq!(ZstdCompression::with_max_output(max_output).inflate(&frame)?, vec![0x41]);
			Ok(())
		}
		cases {
			at_a_power_of_two_ceiling => (65536, 16),
			below_the_next_power_of_two => (49152, 16),
			below_the_smallest_window => (512, 10),
			at_an_unbounded_ceiling => (usize::MAX, 16),
			at_the_largest_window_log => (usize::MAX, 31),
		}
	}

	// A wider window is refused before the decoder reserves memory for it, as
	// upstream's `a_window_past_the_rounded_output_ceiling_is_refused` pins.
	// The 32 log passes the clamp on the 64-bit host.
	tb_cases! {
		fn the_engine_refuses_a_window_past_the_rounded_ceiling((max_output, window_log): (usize, u8)) {
			let frame = frame_declaring_window(window_log);
			let refused = ZstdCompression::with_max_output(max_output).inflate(&frame);
			assert!(matches!(refused, Err(ZstdRefusal::WindowTooLarge { .. })));
		}
		cases {
			past_a_power_of_two_ceiling => (65536, 17),
			past_the_next_power_of_two => (49152, 17),
			past_the_default_ceiling => (DEFAULT_MAX_DECOMPRESSED_LEN, 27),
			past_the_largest_window_log => (usize::MAX, 32),
		}
	}

	/// The default ceiling refuses a stream that inflates one octet past it,
	/// so a decompression bomb fails before it fills memory (CWE-409), as
	/// upstream's `decompression_bomb_rejected_by_default_cap` pins.
	#[test]
	fn the_engine_refuses_a_bomb_at_the_default_ceiling() -> TestResult {
		let compressed = upstream_zeros(DEFAULT_MAX_DECOMPRESSED_LEN + 1)?;
		let refused = ZstdCompression::default().inflate(&compressed);
		assert_eq!(refused, Err(ZstdRefusal::OutputLimitExceeded(DEFAULT_MAX_DECOMPRESSED_LEN)));
		Ok(())
	}

	/// Input that ends inside its frame is refused as truncated, as upstream
	/// reports libzstd waiting for more input.
	#[test]
	fn the_engine_refuses_a_truncated_frame() -> TestResult {
		let compressed = upstream_zeros(4096)?;
		let refused = ZstdCompression::default().inflate(&compressed[..compressed.len() - 1]);
		assert_eq!(refused, Err(ZstdRefusal::Truncated));
		Ok(())
	}

	/// No octets open no frame, so they are refused as truncated.
	#[test]
	fn the_engine_refuses_no_octets_as_truncated() {
		assert_eq!(ZstdCompression::default().inflate(&[]), Err(ZstdRefusal::Truncated));
	}

	/// A skippable frame alone carries no content, so it inflates to no
	/// octets, as upstream reads it.
	#[test]
	fn a_skippable_frame_alone_inflates_to_no_octets() -> TestResult {
		let inflated = ZstdCompression::default().inflate(SKIPPABLE_TAIL)?;
		assert_eq!(inflated, Upstream::default().decompress(SKIPPABLE_TAIL)?);
		assert!(inflated.is_empty());
		Ok(())
	}

	/// A skippable frame cut short is refused as truncated.
	#[test]
	fn the_engine_refuses_a_truncated_skippable_frame() {
		let cut = &SKIPPABLE_TAIL[..SKIPPABLE_TAIL.len() - 1];
		assert_eq!(ZstdCompression::default().inflate(cut), Err(ZstdRefusal::Truncated));
	}

	/// Octets that open with no zstd magic number are malformed.
	#[test]
	fn the_engine_refuses_a_bad_magic_number_as_malformed() {
		let refused = ZstdCompression::default().inflate(b"no zstd frame");
		assert_eq!(refused, Err(ZstdRefusal::Malformed));
	}

	/// A frame whose content checksum differs from its content is malformed,
	/// as libzstd refuses it.
	#[test]
	fn the_engine_refuses_a_wrong_checksum_as_malformed() -> TestResult {
		let (mut compressed, _) = ZstdCompression::default().compress(b"checked body", None)?;
		let last = compressed.len() - 1;
		compressed[last] ^= 0xff;

		assert!(Upstream::default().decompress(&compressed).is_err());
		assert_eq!(ZstdCompression::default().inflate(&compressed), Err(ZstdRefusal::Malformed));
		Ok(())
	}

	/// A frame descriptor with the reserved bit set is malformed, as libzstd
	/// refuses it.
	#[test]
	fn the_engine_refuses_the_reserved_descriptor_bit_as_malformed() {
		let mut frame = frame_declaring_window(16);
		frame[4] |= 0x08;

		assert!(Upstream::default().decompress(&frame).is_err());
		assert_eq!(ZstdCompression::default().inflate(&frame), Err(ZstdRefusal::Malformed));
	}

	/// A frame whose declared content size its blocks do not fill is
	/// malformed, as libzstd refuses it.
	#[test]
	fn the_engine_refuses_a_content_size_the_blocks_do_not_fill() {
		// A single-segment frame that declares two octets of content and
		// whose one RLE block emits one.
		let frame = [0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x02, 0x0b, 0x00, 0x00, 0x41];

		assert!(Upstream::default().decompress(&frame).is_err());
		assert_eq!(ZstdCompression::default().inflate(&frame), Err(ZstdRefusal::Malformed));
	}

	// The engine admits the parameters upstream admits at each bound of the
	// level range, and refuses the level one past each bound.
	tb_cases! {
		fn admits_parameters_matches_upstream_at_each_level_bound((parameters, admitted): (Option<i32>, bool)) -> TestResult {
			let parameters = parameters.map(level).transpose()?;
			let engine = ZstdCompression::default().admits_parameters(parameters.as_ref());
			assert_eq!(engine, Upstream::default().admits_parameters(parameters.as_ref()));
			assert_eq!(engine, admitted);
			Ok(())
		}
		cases {
			absent => (None, true),
			below_the_lowest_level => (Some(-131_073), false),
			the_lowest_level => (Some(-131_072), true),
			above_the_lowest_level => (Some(-131_071), true),
			below_the_highest_level => (Some(21), true),
			the_highest_level => (Some(22), true),
			above_the_highest_level => (Some(23), false),
		}
	}
}

// The runtime tests run on wasm32, where the window log clamps at 30 and the
// JavaScript surface exists.
#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
	use wasm_bindgen::JsValue;
	use wasm_bindgen_test::wasm_bindgen_test;

	use super::fixtures::frame_declaring_window;
	use super::{ZstdCompression, ZstdRefusal};
	use crate::fault::Refused;

	#[wasm_bindgen_test]
	fn a_32_bit_target_admits_a_window_log_of_30() {
		let frame = frame_declaring_window(30);
		assert_eq!(ZstdCompression::with_max_output(usize::MAX).inflate(&frame), Ok(vec![0x41]));
	}

	#[wasm_bindgen_test]
	fn a_32_bit_target_refuses_a_window_log_of_31() {
		let frame = frame_declaring_window(31);
		let refused = ZstdCompression::with_max_output(usize::MAX).inflate(&frame);
		assert!(matches!(refused, Err(ZstdRefusal::WindowTooLarge { .. })));
	}

	#[wasm_bindgen_test]
	fn a_ceiling_that_is_nan_negative_or_a_fraction_is_refused() {
		let realm = ZstdCompression::realm();
		let nan = realm.ceiling_js(JsValue::from_f64(f64::NAN)).code();
		let negative = realm.ceiling_js(JsValue::from_f64(-1.0)).code();
		let fraction = realm.ceiling_js(JsValue::from_f64(0.5)).code();

		let codes = [nan.as_deref(), negative.as_deref(), fraction.as_deref()];
		assert_eq!(codes, [Some("InvalidMaxOutput"); 3]);
	}
}
