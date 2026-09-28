//! Assemble a `.sot` listing into a `.sotb` program.

use clap::Parser;
use soteria_cli::{read_input, wrap, write_output};
use soteria_isa::asm::assemble;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    version,
    about = "Assemble a Soteria .sot listing into a .sotb program"
)]
struct Args {
    /// Source file, or - for stdin
    #[arg(default_value = "-")]
    input: PathBuf,
    /// Output file, or - for stdout [default: the input with a .sotb extension]
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Write bare program bytes, without the SOTB header and fingerprint
    #[arg(long)]
    raw: bool,
    /// Only check that the source assembles; write nothing
    #[arg(long)]
    check: bool,
}

fn run(args: Args) -> Result<(), String> {
    let src = read_input(&args.input)?;
    let src = String::from_utf8(src).map_err(|_| format!("{}: not UTF-8", args.input.display()))?;
    let prog = assemble(&src).map_err(|e| format!("{}: {e}", args.input.display()))?;
    if args.check {
        println!(
            "{}: ok, {} bundles",
            args.input.display(),
            prog.bundles().len()
        );
        return Ok(());
    }
    let output = match args.output {
        Some(o) => o,
        None if args.input.as_os_str() == "-" => {
            return Err("reading stdin needs -o (use -o - for stdout)".into())
        }
        None => args.input.with_extension("sotb"),
    };
    let bytes = if args.raw { prog.encode() } else { wrap(&prog) };
    write_output(&output, &bytes)
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("soteria-asm: {e}");
            ExitCode::FAILURE
        }
    }
}
