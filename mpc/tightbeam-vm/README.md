# tightbeam-vm

Bytecode VM for HoneyBadgerMPC programs over the [tightbeam](https://crates.io/crates/tightbeam-rs) messaging protocol.

Consumers build a straight-line program against two typed register banks (clear and secret), serialize it to ASN.1 DER, and submit it to every party over the [tightbeam-mpc](../tightbeam-mpc) control lane. Parties validate the bytes, agree on the SHA3-256 digest, execute the program against the HoneyBadgerMPC engine, and deliver result shares back to the consumer.

## Pipeline

```text
ProgramBuilder -> Program -> DER bytes -> digest agreement
    -> ValidProgram -> Executor (engine ops + control-lane reveals)
    -> output shares -> consumer reconstruction
```

Each stage owns its failure domain: `CodecError` for malformed bytes, `ValidationError` for static rejection, `VmError` for runtime faults. A program that fails validation at any party aborts the round at every party, because digest echoes carry the verdict.

## Instruction set

Register-based, version-tagged, straight line (no jumps, no recursion). Register indices are `u32`; vector operands are `(base, len)` ranges.

- `Input` - bind a client's secret input shares to a secret range.
- `LdC` - load public field constants into clear registers.
- `AddS` / `SubS` - secret plus/minus secret (local share arithmetic, zero rounds).
- `AddC` / `SubC` / `MulC` - secret against clear constant (local, zero rounds).
- `MulS` - vectorized secret multiplication: one Beaver round for the whole range.
- `AndS` / `XorS` / `NotS` - bit gates on `{0,1}` secret registers (`XorS` is `a + b - 2ab`). `AndS` and `XorS` batch like `MulS`.
- `Mux` - bit-selected choice: one condition bit broadcasts across a secret vector.
- `BitDec` - interactive mask-and-reveal bit decomposition into LSB-first `{0,1}` bits.
- `Pack` - local little-endian fold of bit groups back into secret field elements.
- `Sbox` - batched AES S-box on width-8 bit groups via TinyTable online (reveal masked index, mux-select, bit-decompose).
- `ByteXor` - element-wise XOR on byte-valued secrets.
- `FpMulS` / `FpDivC` - fixed-point multiplication (secret by secret) and division by a public constant, with probabilistic truncation by `2^f`. Register values are raw fixed-point integers (`real * 2^f`); every fixed-point instruction in one program must name the same `(k, f)` precision, because the engine pins one format per run.
- `Reveal` - open secret registers into clear registers over the control lane.
- `Out` - final instruction; names the secret range delivered to the consumer.

Static validation enforces instruction and bank limits, def-before-use, single trailing `Out`, non-overlapping client input declarations, and fixed-point rules (usable and uniform precision, non-zero divisors). The validator also prices the program: the `Budget` (Beaver triples, random shares, shared random bits and integers for truncation) drives party-side preprocessing before execution starts.

## Surface

- `ProgramBuilder` / `Secret` / `Clear` / `Bits` - fluent, infallible program construction with typed register handles. Bit ops mint `Bits`. `input_bytes` documents byte-valued secrets before `bit_dec(..., 8)`.
- `circuits::aes128::encrypt_block` - default AES-128 one-block encrypt on the TinyTable LUT path (`Sbox` + bit-plane linear layers).
- `circuits::aes128::encrypt_block_boolean` - Boyar-Peralta boolean oracle for PlainBackend cross-checks only.
- `Program` / `ValidProgram` - the raw instruction list and its validated, budgeted form (parse, don't validate).
- `ProgramDigest` - SHA3-256 identity of the DER bytes; doubles as the MPC instance id.
- `VmParty` / `VmPartyConfig` - party-side host: receive, validate, echo verdict, preprocess, collect inputs, execute, deliver.
- `VmConsumer` - consumer-side host: submit the program, verify every party echoes the same digest, provide inputs, reconstruct outputs.
- `SecretOps` / `HoneyBadgerBackend` - the execution backend trait; the interpreter is generic over it, so unit tests run against a plaintext backend.
- `execute` / `Output` - the interpreter entry point and its result.
- `TraceHandle` (re-exported from tightbeam-mpc) - program bytes carry no tracing of their own. Hosts record lifecycle events through injected handles instead. `VmPartyConfig::trace` observes the submission verdict (`admit` / `refuse` / `submit_timeout`), the session's round transitions, and the interpreter's execution events (`program_start`, `reveal`, `program_end`). `VmConsumer::with_trace` observes the submission flow (`submit`, `echo_ok`, `echo_lost`, `digest_mismatch`) and output reconstruction.

## Usage

Consumer side:

```rust
let mut builder = ProgramBuilder::default();
let x = builder.input(client_id, 2);       // two secret inputs from this client
let rates = builder.constants([3, 3]);     // public constants
let squared = builder.mul(x, x);           // one Beaver round
let scaled = builder.mul_clear(squared, rates);
builder.output(client_id, scaled);
let program = builder.build()?;            // static validation + budget

let network = Arc::new(TightbeamClient::establish(roster, identity, config).await?);
let mut consumer = VmConsumer::new(network)?;
consumer.submit(&program, deadline).await?; // every party echoes the digest
let mut session = consumer.open_session::<Fr, Avid<SessionId>>(&program, threshold, inputs)?;
let outputs = session.wait_output(deadline).await?;
```

Party side:

```rust
let network = Arc::new(TightbeamNetwork::establish(roster, identity, config).await?);
let mut party: VmParty<Fr, Avid<SessionId>> = VmParty::receive(network, config).await?;
party.run(&mut rng).await?; // preprocess, collect inputs, execute, deliver
```

### AES-128 (LUT default)

Declare sixteen key bytes and sixteen plaintext bytes, expand the encrypt circuit, then size preprocessing from the priced budget:

```rust
use tightbeam_vm::circuits::aes128::{encrypt_block, BLOCK_LEN};

let mut builder = ProgramBuilder::default();
let inputs = builder.input_bytes(client_id, BLOCK_LEN * 2);
let key = inputs.slice(0, BLOCK_LEN);
let block = inputs.slice(BLOCK_LEN, BLOCK_LEN);
let ciphertext = encrypt_block(&mut builder, key, block);
builder.output(client_id, ciphertext);
let program = builder.build()?;
// size party preprocessing from program.budget()
```

`encrypt_block` is the LUT path: TinyTable `Sbox` for SubBytes, with ShiftRows / MixColumns / AddRoundKey on bit planes. `encrypt_block_boolean` keeps the Boyar-Peralta circuit as a PlainBackend oracle only. The HoneyBadger mesh e2e (`an_aes128_block_encrypts_end_to_end`) targets preprocess plus online within 10 minutes on 5-party localhost. A reveal microbench on the same topology measured about 0.65 s for a 16-open batch and about 0.77 s for a 160-open batch in release.

## Roadmap

secp256k1 threshold ECDSA is a follow-on track on the [tightbeam-mpc](../tightbeam-mpc) `Network`, not more AES/LUT opcodes on HoneyBadger. Stoffel splits backends: HoneyBadger for field-arithmetic apps, and AVSS plus curve workflows (including `secp256k1`) for verifiable scalars and curve-oriented protocols ([Stoffel MPC architecture](https://docs.stoffelmpc.com/architecture/mpc)). A future signing product would host AVSS / threshold-ECDSA rounds as a sibling session type on the same mesh. Non-goals for the AES LUT wave: MtA, Paillier, secp256k1 scalar-mul opcodes, and AVSS integration.

## Related

The integration tests run submitted programs end-to-end over localhost TCP with five parties and a consumer, as `tb_scenario!` scenarios whose assertion specs count the live lifecycle events - including a fixed-point pipeline, bit-decomposed comparison, reveal-batch cost measurement, LUT AES mesh encrypt, and malformed-submission rejection: [tests/vm_e2e.rs](tests/vm_e2e.rs). AES-128 circuit correctness against the clear `aes` crate is also covered by a PlainBackend unit test. Shared fixture code lives in [tests/common](tests/common/mod.rs) over `tightbeam_mpc::testing::TestTopology`. Transport, roster, and session mechanics live in [tightbeam-mpc](../tightbeam-mpc).

Three suites use tightbeam's verification framework:

- [tests/submission_fmea.rs](tests/submission_fmea.rs) models the submission/agreement handshake as a CSP process, injects its enumerable failure modes (malformed program, echo loss, digest disagreement, lost submission) during FDR exploration, and checks the auto-generated FMEA report scores every mode with a risk priority number. The scenario runs the real handshake over localhost TCP with the collector injected into the consumer and one party, so the trace that refines the model is live.
- [tests/pipeline_spec.rs](tests/pipeline_spec.rs) runs the whole pipeline for real - submission, agreement, preprocessing, inputs, execution with a load-bearing reveal, delivery, reconstruction - and asserts the exact lifecycle event counts the hosts emitted while doing it.
- [fuzz/program_decode.rs](fuzz/program_decode.rs) is an AFL harness for the untrusted program decoder (`fuzz` feature): `ValidProgram::from_der` must never panic on arbitrary bytes, and any admitted program must re-validate from its own wire bytes to the identical digest. Build with `cargo afl build --bin fuzz_program_decode --features fuzz`.

## License

Licensed under either of [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE) at your option.
