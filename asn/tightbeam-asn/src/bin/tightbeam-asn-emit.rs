//! CLI: scan AsnCodec wasm `.d.ts` and write MessageCodec TypeScript façades.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use tightbeam::Errorizable;
use tightbeam_asn::emit::{EmitError, EmitOptions};

#[derive(Debug, Errorizable)]
enum CliError {
	#[error("missing required --from-dts")]
	MissingFromDts,
	#[error("missing required --out")]
	MissingOut,
	#[error("missing required --import")]
	MissingImport,
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

/// The usage line `--help` prints.
const USAGE: &str = "Usage: tightbeam-asn-emit --from-dts <file.d.ts> --out <codecs.ts> --import <spec> \\\n\
	\t[--message-codec-from <spec>]";

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
	match Parsed::from_args(env::args().skip(1))? {
		Parsed::Help => {
			eprintln!("{USAGE}");
			Ok(())
		}
		Parsed::Run(args) => {
			let pairs = args.opts.emit(&args.from_dts, &args.out)?;
			let count = pairs.names().len();
			eprintln!("tightbeam-asn-emit: wrote {count} codec(s) to {}", args.out.display());
			Ok(())
		}
	}
}

impl Parsed {
	/// The command that the arguments `argv` give, after the program name.
	fn from_args(argv: impl IntoIterator<Item = String>) -> Result<Self, CliError> {
		let mut from_dts = None;
		let mut out = None;
		let mut import = None;
		let mut message_codec_from = None;
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
					import = Some(require_value(&mut iter, "--import")?);
				}
				"--message-codec-from" => {
					message_codec_from = Some(require_value(&mut iter, "--message-codec-from")?);
				}
				"--help" | "-h" => return Ok(Self::Help),
				other => return Err(CliError::UnknownArg(other.to_owned())),
			}
		}

		let Some(from_dts) = from_dts else {
			return Err(CliError::MissingFromDts);
		};
		let Some(out) = out else {
			return Err(CliError::MissingOut);
		};
		let Some(import) = import else {
			return Err(CliError::MissingImport);
		};

		let mut opts = EmitOptions::new(import);
		if let Some(message_codec_from) = message_codec_from {
			opts = opts.with_message_codec_from(message_codec_from);
		}

		Ok(Self::Run(Args { from_dts, out, opts }))
	}
}

fn require_value(iter: &mut impl Iterator<Item = String>, flag: &'static str) -> Result<String, CliError> {
	iter.next().ok_or(CliError::MissingValue(flag))
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The owned argument vector of `args`.
	fn argv(args: &[&str]) -> Vec<String> {
		args.iter().map(|arg| (*arg).to_owned()).collect()
	}

	#[test]
	fn a_missing_import_is_refused() {
		let parsed = Parsed::from_args(argv(&["--from-dts", "a.d.ts", "--out", "a.ts"]));
		assert!(matches!(parsed, Err(CliError::MissingImport)));
	}

	#[test]
	fn the_import_reaches_the_options() {
		let parsed = Parsed::from_args(argv(&["--from-dts", "a.d.ts", "--out", "a.ts", "--import", "#asn"]));
		assert!(matches!(parsed, Ok(Parsed::Run(args)) if args.opts == EmitOptions::new("#asn")));
	}
}
