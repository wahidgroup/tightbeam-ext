//! AES-128 one-block encrypt helpers.
//!
//! [`encrypt_block`] is the default LUT path: TinyTable-style `Sbox`
//! for SubBytes, with ShiftRows, MixColumns, and AddRoundKey on bit
//! planes. The Boyar-Peralta boolean circuit lives in
//! [`encrypt_block_boolean`] as a PlainBackend oracle cross-check only.
//!
//! # Sources
//!
//! - FIPS 197, Advanced Encryption Standard (AES)
//! - Damgård et al., TinyTable (ePrint 2016/695)
//! - Keller et al., multiparty TinyTable (ePrint 2017/378)
//! - Boyar and Peralta, "A depth-16 circuit for the AES S-box",
//!   IACR ePrint 2011/332

use crate::builder::{Bits, ProgramBuilder, Secret};

/// Bytes in an AES-128 block (and in the cipher key).
pub const BLOCK_LEN: u32 = 16;

/// FIPS 197 AES S-box (`§5.1.1`).
pub const AES_SBOX: [u8; 256] = [
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// Round constants for AES-128 key expansion (`rcon[1..=10]`).
const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// ShiftRows index map over the column-major 16-byte state
/// (FIPS 197 §5.1.2). `new[i]` reads `old[SHIFT_ROWS[i]]`.
const SHIFT_ROWS: [u8; 16] = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];

/// One AES byte as eight LSB-first bit wires (`bits[0]` is the LSB).
type Byte = [Bits; 8];

/// Bit-plane form of `n` bytes: `bits[i]` holds bit `i` (LSB-first) of
/// every byte, as one contiguous width-1 [`Bits`] of length `n`.
#[derive(Clone, Copy)]
struct Planes {
	bits: [Bits; 8],
}

/// Expand AES-128 encrypt of one block into `builder` on the LUT path.
///
/// `key` and `block` MUST each hold 16 byte-valued secret elements
/// (`0..=255`). SubBytes uses batched `Sbox` (TinyTable). Linear
/// layers run on bit planes so ShiftRows, MixColumns, and AddRoundKey
/// batch across the 16-byte state instead of paying a full byte-XOR
/// protocol per wire. The returned handle is 16 ciphertext bytes.
pub fn encrypt_block(builder: &mut ProgramBuilder, key: Secret, block: Secret) -> Secret {
	let key = key.slice(0, BLOCK_LEN);
	let block = block.slice(0, BLOCK_LEN);

	// Key-schedule SubWord and state SubBytes both use TinyTable `Sbox`
	// (200 lookups). The boolean Boyar-Peralta path is oracle-only.
	let key_planes = planes_from_secret(builder, key);
	let round_keys = expand_key(builder, key_planes);
	let block_planes = planes_from_secret(builder, block);
	let mut state = add_round_key(builder, block_planes, round_keys[0]);
	for round_key in round_keys.iter().take(10).skip(1) {
		state = planes_from_sbox(builder, state);
		state = shift_rows(builder, state);
		state = mix_columns(builder, state);
		state = add_round_key(builder, state, *round_key);
	}

	state = planes_from_sbox(builder, state);
	state = shift_rows(builder, state);
	state = add_round_key(builder, state, round_keys[10]);
	secret_from_planes(builder, state)
}

/// Boyar-Peralta boolean AES-128 encrypt for PlainBackend oracle
/// cross-checks. Prefer [`encrypt_block`] for product paths.
pub fn encrypt_block_boolean(builder: &mut ProgramBuilder, key: Secret, block: Secret) -> Secret {
	let key = key.slice(0, BLOCK_LEN);
	let block = block.slice(0, BLOCK_LEN);

	let key_planes = planes_from_secret(builder, key);
	let mut state = planes_from_secret(builder, block);
	let round_keys = expand_key(builder, key_planes);

	state = add_round_key(builder, state, round_keys[0]);
	for round_key in round_keys.iter().take(10).skip(1) {
		state = sbox_planes(builder, state);
		state = shift_rows(builder, state);
		state = mix_columns(builder, state);
		state = add_round_key(builder, state, *round_key);
	}

	state = sbox_planes(builder, state);
	state = shift_rows(builder, state);
	state = add_round_key(builder, state, round_keys[10]);

	secret_from_planes(builder, state)
}

/// TinyTable S-box over bit planes (no pack/`bit_dec` round trip).
fn planes_from_sbox(builder: &mut ProgramBuilder, state: Planes) -> Planes {
	let count = state.bits[0].len();
	let mut ordered = Vec::with_capacity(count as usize * 8);
	for element in 0..count {
		for position in 0..8u8 {
			ordered.push(state.bits[position as usize].bit(element, 0));
		}
	}
	let flat = builder.join_bits(ordered);
	let bits = builder.sbox(flat.regroup(8));
	let mut lanes = [bits.bit(0, 0); 8];
	for position in 0..8u8 {
		lanes[position as usize] = builder.bit_lane(bits, position);
	}
	Planes { bits: lanes }
}

fn planes_from_secret(builder: &mut ProgramBuilder, bytes: Secret) -> Planes {
	let packed = builder.bit_dec(bytes, 8);
	let mut bits = [packed.bit(0, 0); 8];
	for position in 0..8u8 {
		bits[position as usize] = builder.bit_lane(packed, position);
	}
	Planes { bits }
}

fn secret_from_planes(builder: &mut ProgramBuilder, planes: Planes) -> Secret {
	let count = planes.bits[0].len();
	let mut ordered = Vec::with_capacity(count as usize * 8);
	for element in 0..count {
		for position in 0..8u8 {
			ordered.push(planes.bits[position as usize].bit(element, 0));
		}
	}

	let flat = builder.join_bits(ordered);
	builder.pack(flat.regroup(8))
}

fn expand_key(builder: &mut ProgramBuilder, key: Planes) -> [Planes; 11] {
	let mut words: [[Byte; 4]; 44] = [[[key.bits[0]; 8]; 4]; 44];
	let key_bytes = planes_to_bytes(key);
	for (index, byte) in key_bytes.into_iter().enumerate() {
		words[index / 4][index % 4] = byte;
	}

	for index in 4..44 {
		let mut temp = words[index - 1];
		if index % 4 == 0 {
			temp = rot_word(temp);
			temp = sbox_bytes(builder, temp);
			temp[0] = xor_rcon(builder, temp[0], RCON[index / 4 - 1]);
		}

		words[index] = xor_word(builder, words[index - 4], temp);
	}

	let mut round_keys = [key; 11];
	for round in 0..11 {
		let mut block = [words[0][0]; 16];
		for byte_index in 0..16 {
			block[byte_index] = words[round * 4 + byte_index / 4][byte_index % 4];
		}

		round_keys[round] = bytes_to_planes(builder, block);
	}

	round_keys
}

fn planes_to_bytes(planes: Planes) -> [Byte; 16] {
	let mut bytes = [[planes.bits[0]; 8]; 16];
	for (element, byte) in bytes.iter_mut().enumerate() {
		for (position, bit) in byte.iter_mut().enumerate() {
			*bit = planes.bits[position].bit(element as u32, 0);
		}
	}

	bytes
}

fn bytes_to_planes(builder: &mut ProgramBuilder, bytes: [Byte; 16]) -> Planes {
	let mut bits = [bytes[0][0]; 8];
	for (position, lane_bits) in bits.iter_mut().enumerate() {
		let mut lane = Vec::with_capacity(16);
		for byte in &bytes {
			lane.push(byte[position]);
		}

		*lane_bits = builder.join_bits(lane);
	}

	Planes { bits }
}

fn rot_word(word: [Byte; 4]) -> [Byte; 4] {
	[word[1], word[2], word[3], word[0]]
}

fn xor_rcon(builder: &mut ProgramBuilder, byte: Byte, rcon: u8) -> Byte {
	let mut out = byte;
	for (position, bit) in out.iter_mut().enumerate() {
		if (rcon >> position) & 1 == 1 {
			*bit = builder.not(*bit);
		}
	}

	out
}

fn xor_word(builder: &mut ProgramBuilder, a: [Byte; 4], b: [Byte; 4]) -> [Byte; 4] {
	[
		xor_byte(builder, a[0], b[0]),
		xor_byte(builder, a[1], b[1]),
		xor_byte(builder, a[2], b[2]),
		xor_byte(builder, a[3], b[3]),
	]
}

fn xor_byte(builder: &mut ProgramBuilder, a: Byte, b: Byte) -> Byte {
	let results = builder.xor_many([
		(a[0], b[0]),
		(a[1], b[1]),
		(a[2], b[2]),
		(a[3], b[3]),
		(a[4], b[4]),
		(a[5], b[5]),
		(a[6], b[6]),
		(a[7], b[7]),
	]);
	[
		results[0], results[1], results[2], results[3], results[4], results[5], results[6], results[7],
	]
}

fn sbox_bytes(builder: &mut ProgramBuilder, word: [Byte; 4]) -> [Byte; 4] {
	let mut bits = [word[0][0]; 8];
	for (position, lane_bits) in bits.iter_mut().enumerate() {
		*lane_bits = builder.join_bits([word[0][position], word[1][position], word[2][position], word[3][position]]);
	}

	let substituted = planes_from_sbox(builder, Planes { bits });
	let mut out = [word[0]; 4];
	for (element, byte) in out.iter_mut().enumerate() {
		for (position, bit) in byte.iter_mut().enumerate() {
			*bit = substituted.bits[position].bit(element as u32, 0);
		}
	}

	out
}

fn add_round_key(builder: &mut ProgramBuilder, state: Planes, round_key: Planes) -> Planes {
	let mut bits = state.bits;
	for (position, lane) in bits.iter_mut().enumerate() {
		*lane = builder.xor(state.bits[position], round_key.bits[position]);
	}

	Planes { bits }
}

fn shift_rows(builder: &mut ProgramBuilder, state: Planes) -> Planes {
	let mut bits = state.bits;
	for (position, lane) in bits.iter_mut().enumerate() {
		let mut ordered = Vec::with_capacity(16);
		for &index in &SHIFT_ROWS {
			ordered.push(state.bits[position].bit(u32::from(index), 0));
		}

		*lane = builder.join_bits(ordered);
	}

	Planes { bits }
}

fn mix_columns(builder: &mut ProgramBuilder, state: Planes) -> Planes {
	let bytes = planes_to_bytes(state);
	let mixed = mix_columns_parallel(builder, bytes);
	bytes_to_planes(builder, mixed)
}

/// MixColumns for all four columns in lockstep so each XOR depth is
/// one batched `XorS` instead of four serial column walks.
fn mix_columns_parallel(builder: &mut ProgramBuilder, bytes: [Byte; 16]) -> [Byte; 16] {
	let a0 = [bytes[0], bytes[4], bytes[8], bytes[12]];
	let a1 = [bytes[1], bytes[5], bytes[9], bytes[13]];
	let a2 = [bytes[2], bytes[6], bytes[10], bytes[14]];
	let a3 = [bytes[3], bytes[7], bytes[11], bytes[15]];

	let t0 = xtime_many(builder, &a0);
	let t1 = xtime_many(builder, &a1);
	let t2 = xtime_many(builder, &a2);
	let t3 = xtime_many(builder, &a3);

	let a1x3 = xor_bytes_many(builder, &t1, &a1);
	let a2x3 = xor_bytes_many(builder, &t2, &a2);
	let a3x3 = xor_bytes_many(builder, &t3, &a3);
	let a0x3 = xor_bytes_many(builder, &t0, &a0);

	let b0_a = xor_bytes_many(builder, &t0, &a1x3);
	let b0_b = xor_bytes_many(builder, &b0_a, &a2);
	let b0 = xor_bytes_many(builder, &b0_b, &a3);
	let b1_a = xor_bytes_many(builder, &a0, &t1);
	let b1_b = xor_bytes_many(builder, &b1_a, &a2x3);
	let b1 = xor_bytes_many(builder, &b1_b, &a3);
	let b2_a = xor_bytes_many(builder, &a0, &a1);
	let b2_b = xor_bytes_many(builder, &b2_a, &t2);
	let b2 = xor_bytes_many(builder, &b2_b, &a3x3);
	let b3_a = xor_bytes_many(builder, &a0x3, &a1);
	let b3_b = xor_bytes_many(builder, &b3_a, &a2);
	let b3 = xor_bytes_many(builder, &b3_b, &t3);

	let mut out = bytes;
	for column in 0..4usize {
		out[column * 4] = b0[column];
		out[column * 4 + 1] = b1[column];
		out[column * 4 + 2] = b2[column];
		out[column * 4 + 3] = b3[column];
	}
	out
}

fn xor_bytes_many(builder: &mut ProgramBuilder, a: &[Byte], b: &[Byte]) -> Vec<Byte> {
	let mut pairs = Vec::with_capacity(a.len() * 8);
	for (left, right) in a.iter().zip(b) {
		for position in 0..8 {
			pairs.push((left[position], right[position]));
		}
	}
	let results = builder.xor_many(pairs);
	results
		.chunks_exact(8)
		.map(|chunk| [chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7]])
		.collect()
}

fn xtime_many(builder: &mut ProgramBuilder, bytes: &[Byte]) -> Vec<Byte> {
	let mut pairs = Vec::with_capacity(bytes.len() * 3);
	for byte in bytes {
		pairs.push((byte[0], byte[7]));
		pairs.push((byte[2], byte[7]));
		pairs.push((byte[3], byte[7]));
	}
	let results = builder.xor_many(pairs);
	let mut out = Vec::with_capacity(bytes.len());
	for (index, byte) in bytes.iter().enumerate() {
		let base = index * 3;
		out.push([
			byte[7],
			results[base],
			byte[1],
			results[base + 1],
			results[base + 2],
			byte[4],
			byte[5],
			byte[6],
		]);
	}
	out
}

/// Boyar-Peralta AES S-box over bit planes.
///
/// Input/output numbering matches the paper: `U0`/`S0` are the MSB
/// (bit 7) and `U7`/`S7` are the LSB (bit 0). The circuit's output
/// NOTs on `S1`, `S2`, `S6`, and `S7` embed the AES affine constant
/// `0x63`.
fn sbox_planes(builder: &mut ProgramBuilder, inp: Planes) -> Planes {
	let u0 = inp.bits[7];
	let u1 = inp.bits[6];
	let u2 = inp.bits[5];
	let u3 = inp.bits[4];
	let u4 = inp.bits[3];
	let u5 = inp.bits[2];
	let u6 = inp.bits[1];
	let u7 = inp.bits[0];

	let t1 = builder.xor(u0, u3);
	let t2 = builder.xor(u0, u5);
	let t3 = builder.xor(u0, u6);
	let t4 = builder.xor(u3, u5);
	let t5 = builder.xor(u4, u6);
	let t6 = builder.xor(t1, t5);
	let t7 = builder.xor(u1, u2);
	let t8 = builder.xor(u7, t6);
	let t9 = builder.xor(u7, t7);
	let t10 = builder.xor(t6, t7);
	let t11 = builder.xor(u1, u5);
	let t12 = builder.xor(u2, u5);
	let t13 = builder.xor(t3, t4);
	let t14 = builder.xor(t6, t11);
	let t15 = builder.xor(t5, t11);
	let t16 = builder.xor(t5, t12);
	let t17 = builder.xor(t9, t16);
	let t18 = builder.xor(u3, u7);
	let t19 = builder.xor(t7, t18);
	let t20 = builder.xor(t1, t19);
	let t21 = builder.xor(u6, u7);
	let t22 = builder.xor(t7, t21);
	let t23 = builder.xor(t2, t22);
	let t24 = builder.xor(t2, t10);
	let t25 = builder.xor(t20, t17);
	let t26 = builder.xor(t3, t16);
	let t27 = builder.xor(t1, t12);

	let m1 = builder.and(t13, t6);
	let m2 = builder.and(t23, t8);
	let m3 = builder.xor(t14, m1);
	let m4 = builder.and(t19, u7);
	let m5 = builder.xor(m4, m1);
	let m6 = builder.and(t3, t16);
	let m7 = builder.and(t22, t9);
	let m8 = builder.xor(t26, m6);
	let m9 = builder.and(t20, t17);
	let m10 = builder.xor(m9, m6);
	let m11 = builder.and(t1, t15);
	let m12 = builder.and(t4, t27);
	let m13 = builder.xor(m12, m11);
	let m14 = builder.and(t2, t10);
	let m15 = builder.xor(m14, m11);
	let m16 = builder.xor(m3, m2);
	let m17 = builder.xor(m5, t24);
	let m18 = builder.xor(m8, m7);
	let m19 = builder.xor(m10, m15);
	let m20 = builder.xor(m16, m13);
	let m21 = builder.xor(m17, m15);
	let m22 = builder.xor(m18, m13);
	let m23 = builder.xor(m19, t25);
	let m24 = builder.xor(m22, m23);
	let m25 = builder.and(m22, m20);
	let m26 = builder.xor(m21, m25);
	let m27 = builder.xor(m20, m21);
	let m28 = builder.xor(m23, m25);
	let m29 = builder.and(m28, m27);
	let m30 = builder.and(m26, m24);
	let m31 = builder.and(m20, m23);
	let m32 = builder.and(m27, m31);
	let m33 = builder.xor(m27, m25);
	let m34 = builder.and(m21, m22);
	let m35 = builder.and(m24, m34);
	let m36 = builder.xor(m24, m25);
	let m37 = builder.xor(m21, m29);
	let m38 = builder.xor(m32, m33);
	let m39 = builder.xor(m23, m30);
	let m40 = builder.xor(m35, m36);
	let m41 = builder.xor(m38, m40);
	let m42 = builder.xor(m37, m39);
	let m43 = builder.xor(m37, m38);
	let m44 = builder.xor(m39, m40);
	let m45 = builder.xor(m42, m41);

	let m46 = builder.and(m44, t6);
	let m47 = builder.and(m40, t8);
	let m48 = builder.and(m39, u7);
	let m49 = builder.and(m43, t16);
	let m50 = builder.and(m38, t9);
	let m51 = builder.and(m37, t17);
	let m52 = builder.and(m42, t15);
	let m53 = builder.and(m45, t27);
	let m54 = builder.and(m41, t10);
	let m55 = builder.and(m44, t13);
	let m56 = builder.and(m40, t23);
	let m57 = builder.and(m39, t19);
	let m58 = builder.and(m43, t3);
	let m59 = builder.and(m38, t22);
	let m60 = builder.and(m37, t20);
	let m61 = builder.and(m42, t1);
	let m62 = builder.and(m45, t4);
	let m63 = builder.and(m41, t2);

	let l0 = builder.xor(m61, m62);
	let l1 = builder.xor(m50, m56);
	let l2 = builder.xor(m46, m48);
	let l3 = builder.xor(m47, m55);
	let l4 = builder.xor(m54, m58);
	let l5 = builder.xor(m49, m61);
	let l6 = builder.xor(m62, l5);
	let l7 = builder.xor(m46, l3);
	let l8 = builder.xor(m51, m59);
	let l9 = builder.xor(m52, m53);
	let l10 = builder.xor(m53, l4);
	let l11 = builder.xor(m60, l2);
	let l12 = builder.xor(m48, m51);
	let l13 = builder.xor(m50, l0);
	let l14 = builder.xor(m52, m61);
	let l15 = builder.xor(m55, l1);
	let l16 = builder.xor(m56, l0);
	let l17 = builder.xor(m57, l1);
	let l18 = builder.xor(m58, l8);
	let l19 = builder.xor(m63, l4);
	let l20 = builder.xor(l0, l1);
	let l21 = builder.xor(l1, l7);
	let l22 = builder.xor(l3, l12);
	let l23 = builder.xor(l18, l2);
	let l24 = builder.xor(l15, l9);
	let l25 = builder.xor(l6, l10);
	let l26 = builder.xor(l7, l9);
	let l27 = builder.xor(l8, l10);
	let l28 = builder.xor(l11, l14);
	let l29 = builder.xor(l11, l17);

	let s0 = builder.xor(l6, l24);
	let s1_raw = builder.xor(l16, l26);
	let s1 = builder.not(s1_raw);
	let s2_raw = builder.xor(l19, l28);
	let s2 = builder.not(s2_raw);
	let s3 = builder.xor(l6, l21);
	let s4 = builder.xor(l20, l22);
	let s5 = builder.xor(l25, l29);
	let s6_raw = builder.xor(l13, l27);
	let s6 = builder.not(s6_raw);
	let s7_raw = builder.xor(l6, l23);
	let s7 = builder.not(s7_raw);

	Planes { bits: [s7, s6, s5, s4, s3, s2, s1, s0] }
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::isa::{Instruction, Program};
	use crate::validate::{BANK_SIZE, MAX_INSTRUCTIONS};
	use stoffelnet::network_utils::ClientId;

	const CLIENT: ClientId = 100;

	/// Pure Boyar-Peralta S-box for bit-order sanity checks against
	/// the FIPS 197 table samples.
	fn sbox_clear(input: u8) -> u8 {
		let u0 = (input >> 7) & 1;
		let u1 = (input >> 6) & 1;
		let u2 = (input >> 5) & 1;
		let u3 = (input >> 4) & 1;
		let u4 = (input >> 3) & 1;
		let u5 = (input >> 2) & 1;
		let u6 = (input >> 1) & 1;
		let u7 = input & 1;

		let t1 = u0 ^ u3;
		let t2 = u0 ^ u5;
		let t3 = u0 ^ u6;
		let t4 = u3 ^ u5;
		let t5 = u4 ^ u6;
		let t6 = t1 ^ t5;
		let t7 = u1 ^ u2;
		let t8 = u7 ^ t6;
		let t9 = u7 ^ t7;
		let t10 = t6 ^ t7;
		let t11 = u1 ^ u5;
		let t12 = u2 ^ u5;
		let t13 = t3 ^ t4;
		let t14 = t6 ^ t11;
		let t15 = t5 ^ t11;
		let t16 = t5 ^ t12;
		let t17 = t9 ^ t16;
		let t18 = u3 ^ u7;
		let t19 = t7 ^ t18;
		let t20 = t1 ^ t19;
		let t21 = u6 ^ u7;
		let t22 = t7 ^ t21;
		let t23 = t2 ^ t22;
		let t24 = t2 ^ t10;
		let t25 = t20 ^ t17;
		let t26 = t3 ^ t16;
		let t27 = t1 ^ t12;

		let m1 = t13 & t6;
		let m2 = t23 & t8;
		let m3 = t14 ^ m1;
		let m4 = t19 & u7;
		let m5 = m4 ^ m1;
		let m6 = t3 & t16;
		let m7 = t22 & t9;
		let m8 = t26 ^ m6;
		let m9 = t20 & t17;
		let m10 = m9 ^ m6;
		let m11 = t1 & t15;
		let m12 = t4 & t27;
		let m13 = m12 ^ m11;
		let m14 = t2 & t10;
		let m15 = m14 ^ m11;
		let m16 = m3 ^ m2;
		let m17 = m5 ^ t24;
		let m18 = m8 ^ m7;
		let m19 = m10 ^ m15;
		let m20 = m16 ^ m13;
		let m21 = m17 ^ m15;
		let m22 = m18 ^ m13;
		let m23 = m19 ^ t25;
		let m24 = m22 ^ m23;
		let m25 = m22 & m20;
		let m26 = m21 ^ m25;
		let m27 = m20 ^ m21;
		let m28 = m23 ^ m25;
		let m29 = m28 & m27;
		let m30 = m26 & m24;
		let m31 = m20 & m23;
		let m32 = m27 & m31;
		let m33 = m27 ^ m25;
		let m34 = m21 & m22;
		let m35 = m24 & m34;
		let m36 = m24 ^ m25;
		let m37 = m21 ^ m29;
		let m38 = m32 ^ m33;
		let m39 = m23 ^ m30;
		let m40 = m35 ^ m36;
		let m41 = m38 ^ m40;
		let m42 = m37 ^ m39;
		let m43 = m37 ^ m38;
		let m44 = m39 ^ m40;
		let m45 = m42 ^ m41;

		let m46 = m44 & t6;
		let m47 = m40 & t8;
		let m48 = m39 & u7;
		let m49 = m43 & t16;
		let m50 = m38 & t9;
		let m51 = m37 & t17;
		let m52 = m42 & t15;
		let m53 = m45 & t27;
		let m54 = m41 & t10;
		let m55 = m44 & t13;
		let m56 = m40 & t23;
		let m57 = m39 & t19;
		let m58 = m43 & t3;
		let m59 = m38 & t22;
		let m60 = m37 & t20;
		let m61 = m42 & t1;
		let m62 = m45 & t4;
		let m63 = m41 & t2;

		let l0 = m61 ^ m62;
		let l1 = m50 ^ m56;
		let l2 = m46 ^ m48;
		let l3 = m47 ^ m55;
		let l4 = m54 ^ m58;
		let l5 = m49 ^ m61;
		let l6 = m62 ^ l5;
		let l7 = m46 ^ l3;
		let l8 = m51 ^ m59;
		let l9 = m52 ^ m53;
		let l10 = m53 ^ l4;
		let l11 = m60 ^ l2;
		let l12 = m48 ^ m51;
		let l13 = m50 ^ l0;
		let l14 = m52 ^ m61;
		let l15 = m55 ^ l1;
		let l16 = m56 ^ l0;
		let l17 = m57 ^ l1;
		let l18 = m58 ^ l8;
		let l19 = m63 ^ l4;
		let l20 = l0 ^ l1;
		let l21 = l1 ^ l7;
		let l22 = l3 ^ l12;
		let l23 = l18 ^ l2;
		let l24 = l15 ^ l9;
		let l25 = l6 ^ l10;
		let l26 = l7 ^ l9;
		let l27 = l8 ^ l10;
		let l28 = l11 ^ l14;
		let l29 = l11 ^ l17;

		let s0 = l6 ^ l24;
		let s1 = 1 ^ (l16 ^ l26);
		let s2 = 1 ^ (l19 ^ l28);
		let s3 = l6 ^ l21;
		let s4 = l20 ^ l22;
		let s5 = l25 ^ l29;
		let s6 = 1 ^ (l13 ^ l27);
		let s7 = 1 ^ (l6 ^ l23);

		((s0 & 1) << 7)
			| ((s1 & 1) << 6)
			| ((s2 & 1) << 5)
			| ((s3 & 1) << 4)
			| ((s4 & 1) << 3)
			| ((s5 & 1) << 2)
			| ((s6 & 1) << 1)
			| (s7 & 1)
	}

	#[test]
	fn boyar_peralta_matches_fips_sbox_samples() {
		assert_eq!(sbox_clear(0x00), 0x63);
		assert_eq!(sbox_clear(0x01), 0x7c);
		assert_eq!(sbox_clear(0x53), 0xed);
		assert_eq!(sbox_clear(0xff), 0x16);
	}

	#[test]
	fn encrypt_block_program_validates_inside_raised_limits() {
		let mut builder = ProgramBuilder::default();
		let inputs = builder.input_bytes(CLIENT, BLOCK_LEN * 2);
		let key = inputs.slice(0, BLOCK_LEN);
		let block = inputs.slice(BLOCK_LEN, BLOCK_LEN);
		let ciphertext = encrypt_block(&mut builder, key, block);

		builder.output(CLIENT, ciphertext);

		let valid = match builder.build() {
			Ok(program) => program,
			Err(error) => panic!("AES program must validate: {error}"),
		};

		let instruction_count = valid.program().instructions.len();
		let secret_end = max_secret_end(valid.program());
		assert!(instruction_count <= MAX_INSTRUCTIONS);
		assert!(secret_end <= BANK_SIZE);
		assert!(ciphertext.len() == BLOCK_LEN);
		assert_eq!(valid.budget().sbox_tables, 200);
		assert!(valid.budget().triples > 0);
		assert!(valid.budget().prandbits >= 200 * 8);
	}

	#[test]
	fn boolean_oracle_program_validates_inside_raised_limits() {
		let mut builder = ProgramBuilder::default();
		let inputs = builder.input_bytes(CLIENT, BLOCK_LEN * 2);
		let key = inputs.slice(0, BLOCK_LEN);
		let block = inputs.slice(BLOCK_LEN, BLOCK_LEN);
		let ciphertext = encrypt_block_boolean(&mut builder, key, block);

		builder.output(CLIENT, ciphertext);

		let valid = match builder.build() {
			Ok(program) => program,
			Err(error) => panic!("boolean AES program must validate: {error}"),
		};

		assert!(valid.program().instructions.len() <= MAX_INSTRUCTIONS);
		assert!(max_secret_end(valid.program()) <= BANK_SIZE);
		assert!(valid.budget().triples > 10_000);
	}

	fn max_secret_end(program: &Program) -> u64 {
		let mut high = 0u64;
		for input in &program.inputs {
			high = high.max(input.dest.end());
		}

		for instruction in &program.instructions {
			let ends = match instruction {
				Instruction::AddS { dest, a, b } | Instruction::SubS { dest, a, b } => [dest.end(), a.end(), b.end()],
				Instruction::AddC { dest, a, .. }
				| Instruction::SubC { dest, a, .. }
				| Instruction::MulC { dest, a, .. } => [dest.end(), a.end(), 0],
				Instruction::MulS { pairs } | Instruction::AndS { pairs } | Instruction::XorS { pairs } => {
					let mut local = 0u64;
					for triple in pairs {
						local = local.max(triple.dest.end()).max(triple.a.end()).max(triple.b.end());
					}
					[local, 0, 0]
				}
				Instruction::NotS { dest, a } => [dest.end(), a.end(), 0],
				Instruction::Mux { dest, cond, t, f } => [dest.end().max(cond.end()), t.end(), f.end()],
				Instruction::Pack { dest, src, .. }
				| Instruction::BitDec { dest, src, .. }
				| Instruction::Sbox { dest, src } => [dest.end(), src.end(), 0],
				Instruction::ByteXor { dest, a, b } => [dest.end(), a.end(), b.end()],
				Instruction::Reveal { src, .. } | Instruction::Out { src, .. } => [src.end(), 0, 0],
				Instruction::LdC { .. } | Instruction::FpMulS { .. } | Instruction::FpDivC { .. } => [0, 0, 0],
			};
			high = high.max(ends[0]).max(ends[1]).max(ends[2]);
		}
		high
	}
}
