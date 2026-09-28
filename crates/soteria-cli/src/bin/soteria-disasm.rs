//! Print the listing of a `.sotb` program. The output assembles back to the
//! same program.

use clap::Parser;
use soteria_cli::{read_input, unwrap, write_output, MAGIC};
use soteria_isa::{disasm::listing, Program};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(version, about = "Disassemble a Soteria .sotb program into a listing")]
struct Args {
    /// Program file, or - for stdin
    #[arg(default_value = "-")]
    input: PathBuf,
    /// Output file, or - for stdout
    #[arg(short, long, default_value = "-")]
    output: PathBuf,
    /// Input is bare program bytes, without the SOTB header and fingerprint
    #[arg(long)]
    raw: bool,
}

fn run(args: Args) -> Result<(), String> {
    let bytes = read_input(&args.input)?;
    let prog = if args.raw && bytes.starts_with(MAGIC) {
        Err("has a SOTB header; drop --raw".into())
    } else if args.raw {
        Program::decode(&bytes).map_err(|e| e.to_string())
    } else {
        unwrap(&bytes)
    };
    let prog = prog.map_err(|e| format!("{}: {e}", args.input.display()))?;
    write_output(&args.output, listing(&prog).as_bytes())
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("soteria-disasm: {e}");
            ExitCode::FAILURE
        }
    }
}
