//! CLI: scan AsnCodec wasm `.d.ts` and write MessageCodec TypeScript façades.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use tightbeam::Errorizable;
use tightbeam_asn::emit::{emit_from_paths, EmitError, EmitOptions};

#[derive(Debug, Errorizable)]
enum CliError {
	#[error("missing required --from-dts")]
	MissingFromDts,
	#[error("missing required --out")]
	MissingOut,
	#[error("unknown argument: {0}")]
	UnknownArg(String),
	#[error("missing value for {0}")]
	MissingValue(&'static str),
	#[error("{0}")]
	#[from]
	Emit(EmitError),
}

struct Args {
	from_dts: PathBuf,
	out: PathBuf,
	opts: EmitOptions,
}

enum Parsed {
	Help,
	Run(Args),
}

fn main() -> ExitCode {
	match run() {
		Ok(()) => ExitCode::SUCCESS,
		Err(err) => {
			eprintln!("tightbeam-asn-emit: {err}");
			ExitCode::FAILURE
		}
	}
}

fn run() -> Result<(), CliError> {
	match parse_args(env::args().skip(1))? {
		Parsed::Help => Ok(()),
		Parsed::Run(args) => {
			let names = emit_from_paths(&args.from_dts, &args.out, &args.opts)?;
			eprintln!("tightbeam-asn-emit: wrote {} codec(s) to {}", names.len(), args.out.display());
			Ok(())
		}
	}
}

fn parse_args(argv: impl IntoIterator<Item = String>) -> Result<Parsed, CliError> {
	let mut from_dts = None;
	let mut out = None;
	let mut opts = EmitOptions::default();
	let mut iter = argv.into_iter();
	while let Some(arg) = iter.next() {
		match arg.as_str() {
			"--from-dts" => {
				from_dts = Some(PathBuf::from(require_value(&mut iter, "--from-dts")?));
			}
			"--out" => {
				out = Some(PathBuf::from(require_value(&mut iter, "--out")?));
			}
			"--import" => {
				opts.import = require_value(&mut iter, "--import")?;
			}
			"--init-import" => {
				opts.init_import = Some(require_value(&mut iter, "--init-import")?);
			}
			"--message-codec-from" => {
				opts.message_codec_from = require_value(&mut iter, "--message-codec-from")?;
			}
			"--help" | "-h" => {
				print_usage();
				return Ok(Parsed::Help);
			}
			other => return Err(CliError::UnknownArg(other.to_owned())),
		}
	}

	let Some(from_dts) = from_dts else {
		return Err(CliError::MissingFromDts);
	};
	let Some(out) = out else {
		return Err(CliError::MissingOut);
	};

	Ok(Parsed::Run(Args { from_dts, out, opts }))
}

fn require_value(iter: &mut impl Iterator<Item = String>, flag: &'static str) -> Result<String, CliError> {
	iter.next().ok_or(CliError::MissingValue(flag))
}

fn print_usage() {
	eprintln!(
		"Usage: tightbeam-asn-emit --from-dts <file.d.ts> --out <codecs.ts> \\\n\
		\t[--import <spec>] [--init-import <spec>] [--message-codec-from <spec>]"
	);
}
