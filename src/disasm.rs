//! Disassembler, so blog listings come from the real program bytes.

use crate::{Op, Program, Slot};
use core::fmt;

struct Imm(i32);

impl fmt::Display for Imm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.0.unsigned_abs() >= 256 {
            write!(f, "{:#x}", self.0)
        } else {
            write!(f, "{}", self.0)
        }
    }
}

impl fmt::Display for Slot {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Op::*;
        let (d, a, b, i) = (self.d, self.a, self.b, Imm(self.imm));
        let name = format!("{:?}", self.op).to_lowercase();
        match self.op {
            Nop | Halt => write!(f, "{name}")?,
            Li => write!(f, "li r{d}, {i}")?,
            Addi => write!(f, "addi r{d}, r{a}, {i}")?,
            Add | Sub | Mul | Xor | And | Or => write!(f, "{name} r{d}, r{a}, r{b}")?,
            Shl | Shr | Rotr => write!(f, "{name} r{d}, r{a}, {}", self.imm & 31)?,
            Clz | Bswap | Popcnt => write!(f, "{name} r{d}, r{a}")?,
            Ld => write!(f, "ld r{d}, [r{a}+{i}]")?,
            St => write!(f, "st [r{a}+{i}], r{b}")?,
            Sha256 => write!(f, "sha256 [r{b}], [r{a}]")?,
            Fold => write!(f, "fold [r{b}], r{a}")?,
            Fill => write!(f, "fill r{a}, [r{b}]")?,
            CmpEq | CmpLt | CmpLtu => write!(f, "{name} p{d}, r{a}, r{b}")?,
            PAnd | POr | PXor => write!(f, "{name} p{d}, p{a}, p{b}")?,
            PNot | PAny => write!(f, "{name} p{d}, p{a}")?,
            FCvt => write!(f, "fcvt f{}, r{a}", d & 3)?,
            FAdd | FSub | FMul | FDiv => write!(f, "{name} f{}, f{}, f{}", d & 3, a & 3, b & 3)?,
            FSqrt => write!(f, "fsqrt f{}, f{}", d & 3, a & 3)?,
            FLt => write!(f, "flt p{d}, f{}, f{}", a & 3, b & 3)?,
            FTrunc | FBits => write!(f, "{name} r{d}, f{}", a & 3)?,
            FFrom => write!(f, "ffrom f{}, r{a}", d & 3)?,
            Subleq => write!(f, "subleq r{a}, r{b}, @{i}")?,
            Bp => write!(f, "bp p{a}, @{i}")?,
        }
        match self.guard {
            0 => Ok(()),
            g if g & 0x10 != 0 => write!(f, " ?!p{}", g & 15),
            g => write!(f, " ?p{g}"),
        }
    }
}

/// One line per bundle: `pc: slot | slot | ...`, NOPs elided.
pub fn listing(prog: &Program) -> String {
    let mut out = String::new();
    for (pc, b) in prog.bundles().iter().enumerate() {
        let slots: Vec<String> = b
            .iter()
            .filter(|s| s.op != Op::Nop)
            .map(|s| s.to_string())
            .collect();
        let body = if slots.is_empty() {
            "nop".to_string()
        } else {
            slots.join(" | ")
        };
        out += &format!("{pc:2}: {body}\n");
    }
    out
}
