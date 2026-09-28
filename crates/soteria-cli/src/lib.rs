//! Shared pieces of the `soteria-asm` and `soteria-disasm` tools.
//!
//! Assembled programs are written as `.sotb` files: the magic `SOTB`, this
//! build's `opcodes::FINGERPRINT` (u64 little-endian), then the encoded
//! program. Opcode bytes depend on `SOTERIA_OPCODE_SEED`, so the fingerprint
//! stops a program from being decoded by a build that numbers opcodes
//! differently. `--raw` skips the header on both sides.

use soteria_isa::{opcodes::FINGERPRINT, Program};
use std::io::{Read, Write};
use std::path::Path;

pub const MAGIC: &[u8; 4] = b"SOTB";
pub const HEADER: usize = 12;

pub fn wrap(prog: &Program) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend(FINGERPRINT.to_le_bytes());
    out.extend(prog.encode());
    out
}

pub fn unwrap(bytes: &[u8]) -> Result<Program, String> {
    if bytes.len() < HEADER || &bytes[..4] != MAGIC {
        return Err("not a .sotb file (no SOTB header); pass --raw for bare program bytes".into());
    }
    let fp = u64::from_le_bytes(bytes[4..HEADER].try_into().unwrap());
    if fp != FINGERPRINT {
        return Err(format!(
            "assembled with a different opcode numbering (file {fp:#018x}, this build {FINGERPRINT:#018x}); rebuild with the same SOTERIA_OPCODE_SEED"
        ));
    }
    Program::decode(&bytes[HEADER..]).map_err(|e| e.to_string())
}

/// Read a file, or stdin for `-`.
pub fn read_input(path: &Path) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    let res = if path == Path::new("-") {
        std::io::stdin().read_to_end(&mut buf).map(|_| ())
    } else {
        std::fs::File::open(path)
            .and_then(|mut f| f.read_to_end(&mut buf))
            .map(|_| ())
    };
    res.map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(buf)
}

/// Write a file, or stdout for `-`.
pub fn write_output(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let res = if path == Path::new("-") {
        std::io::stdout().write_all(bytes)
    } else {
        std::fs::write(path, bytes)
    };
    res.map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use soteria_isa::asm::assemble;

    #[test]
    fn sotb_round_trips_and_checks_its_header() {
        let prog = assemble(include_str!("../../../programs/hashcash.sot")).unwrap();
        let file = wrap(&prog);
        assert_eq!(unwrap(&file), Ok(prog.clone()));
        assert!(unwrap(&prog.encode()).unwrap_err().contains("--raw"));
        let mut other = file.clone();
        other[4] ^= 1;
        assert!(unwrap(&other)
            .unwrap_err()
            .contains("different opcode numbering"));
        let mut ragged = file;
        ragged.pop();
        assert!(unwrap(&ragged).unwrap_err().contains("whole number"));
    }
}
