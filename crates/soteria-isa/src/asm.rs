//! Two-pass assembler. The syntax is exactly what `disasm::listing` prints,
//! plus labels and comments, so any listing can be pasted back in.
//!
//! ```text
//! ; hashcash inner loop
//!         li r12, 64 | li r14, 1000
//! loop:   st [r0+32], r15 | addi r14, r14, -1
//!         sha256 [r12], [r0]
//!         addi r11, r15, 0 ?p15 | pany p7, p15
//!         bp p7, @done
//!         bp p3, @loop
//! done:   halt
//! ```
//!
//! - One bundle per line, slots separated by `|`, `nop` for an empty bundle.
//! - `name:` defines a label at the next bundle; `12:` (a number) is a pc
//!   prefix from the disassembler and is ignored.
//! - Branch targets are `@label` or `@12`. Guards are `?p3` or `?!p3`.
//! - Immediates are decimal (`-1`) or hex (`0xff00`, `0xffffffff` wraps).
//! - `;` starts a comment.

use crate::{Error, Op, Program, Slot, SLOTS};
use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsmError {
    pub line: usize,
    pub msg: String,
}

impl fmt::Display for AsmError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.msg)
    }
}

impl std::error::Error for AsmError {}

#[derive(Clone, Copy)]
enum Field {
    D,
    A,
    B,
}

/// What each operand position looks like, and which slot field it fills.
#[derive(Clone, Copy)]
enum Arg {
    R(Field),
    P(Field),
    F(Field),
    Imm,
    /// `[rN+imm]`: register into the field, offset into imm.
    Mem(Field),
    /// `[rN]`: register only.
    Ptr(Field),
    Target,
}

fn signature(op: Op) -> &'static [Arg] {
    use Arg::*;
    use Field::*;
    use Op::*;
    match op {
        Nop | Halt => &[],
        Li => &[R(D), Imm],
        Addi | Shl | Shr | Rotr => &[R(D), R(A), Imm],
        Add | Sub | Mul | Mulhu | Xor | And | Or => &[R(D), R(A), R(B)],
        Clz | Bswap | Popcnt => &[R(D), R(A)],
        Ld => &[R(D), Mem(A)],
        St => &[Mem(A), R(B)],
        Sha256 => &[Ptr(B), Ptr(A)],
        Fold => &[Ptr(B), R(A)],
        Fill => &[R(A), Ptr(B)],
        CmpEq | CmpLt | CmpLtu => &[P(D), R(A), R(B)],
        PAnd | POr | PXor => &[P(D), P(A), P(B)],
        PNot | PAny => &[P(D), P(A)],
        FCvt | FFrom => &[F(D), R(A)],
        FAdd | FSub | FMul | FDiv => &[F(D), F(A), F(B)],
        FSqrt => &[F(D), F(A)],
        FLt => &[P(D), F(A), F(B)],
        FTrunc | FBits => &[R(D), F(A)],
        PMov => &[R(D), P(A)],
        Subleq => &[R(A), R(B), Target],
        Bp => &[P(A), Target],
    }
}

fn mnemonic(name: &str) -> Option<Op> {
    Op::ALL
        .iter()
        .copied()
        .find(|op| format!("{op:?}").eq_ignore_ascii_case(name))
}

fn parse_imm(s: &str) -> Result<i32, String> {
    let (neg, body) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let v = match body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        Some(hex) => i64::from_str_radix(hex, 16),
        None => body.parse::<i64>(),
    }
    .map_err(|_| format!("bad immediate `{s}`"))?;
    let v = if neg { -v } else { v };
    if !(i32::MIN as i64..=u32::MAX as i64).contains(&v) {
        return Err(format!("immediate `{s}` doesn't fit in 32 bits"));
    }
    Ok(v as u32 as i32)
}

fn parse_reg(s: &str, prefix: char, max: u8) -> Result<u8, String> {
    let n = s
        .strip_prefix(prefix)
        .and_then(|n| n.parse::<u8>().ok())
        .ok_or_else(|| format!("expected {prefix}0..{prefix}{max}, got `{s}`"))?;
    if n > max {
        return Err(format!("`{s}` is out of range ({prefix}0..{prefix}{max})"));
    }
    Ok(n)
}

/// Split `[r3+0x40]` / `[r3-4]` / `[r3]` into (register, offset).
fn parse_mem(s: &str) -> Result<(u8, i32), String> {
    let inner = s
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(|| format!("expected `[rN+imm]`, got `{s}`"))?
        .trim();
    if inner.is_empty() {
        return Err("empty `[]`".into());
    }
    let split = inner[1..].find(['+', '-']).map(|i| i + 1);
    let (reg, off) = match split {
        Some(i) => (
            inner[..i].trim(),
            parse_imm(inner[i..].trim().trim_start_matches('+'))?,
        ),
        None => (inner, 0),
    };
    Ok((parse_reg(reg, 'r', 15)?, off))
}

fn parse_slot(text: &str, labels: &HashMap<String, usize>) -> Result<Slot, String> {
    // Guard suffix: `... ?p3` or `... ?!p3`
    let (body, guard) = match text.rsplit_once('?') {
        Some((body, g)) => {
            let (neg, p) = match g.trim().strip_prefix('!') {
                Some(p) => (true, p),
                None => (false, g.trim()),
            };
            (
                body.trim(),
                parse_reg(p, 'p', 15)? | if neg { 0x10 } else { 0 },
            )
        }
        None => (text.trim(), 0),
    };

    let (name, rest) = body.split_once(char::is_whitespace).unwrap_or((body, ""));
    let op = mnemonic(name).ok_or_else(|| format!("unknown instruction `{name}`"))?;
    let args: Vec<&str> = if rest.trim().is_empty() {
        vec![]
    } else {
        rest.split(',').map(str::trim).collect()
    };
    let sig = signature(op);
    if args.len() != sig.len() {
        return Err(format!(
            "`{name}` takes {} operands, got {}",
            sig.len(),
            args.len()
        ));
    }

    let mut slot = Slot::new(op, 0, 0, 0, 0);
    let mut set = |field: Field, v: u8| match field {
        Field::D => slot.d = v,
        Field::A => slot.a = v,
        Field::B => slot.b = v,
    };
    let mut imm = 0;
    for (&arg, &text) in sig.iter().zip(&args) {
        match arg {
            Arg::R(f) => set(f, parse_reg(text, 'r', 15)?),
            Arg::P(f) => set(f, parse_reg(text, 'p', 15)?),
            Arg::F(f) => set(f, parse_reg(text, 'f', 3)?),
            Arg::Imm => imm = parse_imm(text)?,
            Arg::Mem(f) => {
                let (r, off) = parse_mem(text)?;
                set(f, r);
                imm = off;
            }
            Arg::Ptr(f) => {
                let (r, off) = parse_mem(text)?;
                if off != 0 {
                    return Err(format!(
                        "`{name}` takes a bare pointer like `[r9]`, got `{text}`"
                    ));
                }
                set(f, r);
            }
            Arg::Target => {
                let t = text
                    .strip_prefix('@')
                    .ok_or_else(|| format!("branch target must start with `@`, got `{text}`"))?;
                imm = match t.parse::<usize>() {
                    Ok(pc) => pc as i32,
                    Err(_) => *labels
                        .get(t)
                        .ok_or_else(|| format!("undefined label `{t}`"))?
                        as i32,
                };
            }
        }
    }
    slot.imm = imm;
    slot.guard = guard;
    Ok(slot)
}

fn is_ident(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
}

/// Strip comments and leading `label:` / `12:` prefixes.
/// Returns (labels defined on this line, remaining bundle text).
fn split_line(raw: &str) -> Result<(Vec<&str>, &str), String> {
    let mut rest = raw.split(';').next().unwrap().trim();
    let mut labels = Vec::new();
    while let Some((head, tail)) = rest.split_once(':') {
        let head = head.trim();
        if head.chars().all(|c| c.is_ascii_digit()) && !head.is_empty() {
            // pc prefix from the disassembler
        } else if is_ident(head) {
            labels.push(head);
        } else {
            break;
        }
        rest = tail.trim();
    }
    Ok((labels, rest))
}

pub fn assemble(src: &str) -> Result<Program, AsmError> {
    let err = |line: usize, msg: String| AsmError {
        line: line + 1,
        msg,
    };

    // Pass 1: label addresses.
    let mut labels = HashMap::new();
    let mut pc = 0usize;
    for (n, raw) in src.lines().enumerate() {
        let (names, rest) = split_line(raw).map_err(|m| err(n, m))?;
        for name in names {
            if labels.insert(name.to_string(), pc).is_some() {
                return Err(err(n, format!("label `{name}` defined twice")));
            }
        }
        if !rest.is_empty() {
            pc += 1;
        }
    }

    // Pass 2: encode.
    let mut bundles = Vec::new();
    for (n, raw) in src.lines().enumerate() {
        let (_, rest) = split_line(raw).map_err(|m| err(n, m))?;
        if rest.is_empty() {
            continue;
        }
        let slots = rest
            .split('|')
            .map(|s| parse_slot(s, &labels))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|m| err(n, m))?;
        let slots: Vec<Slot> = slots.into_iter().filter(|s| s.op != Op::Nop).collect();
        if slots.len() > SLOTS {
            return Err(err(
                n,
                format!("{} slots in one bundle, max {SLOTS}", slots.len()),
            ));
        }
        if let Some(&target) = slots
            .iter()
            .find_map(|s| matches!(s.op, Op::Subleq | Op::Bp).then_some(&s.imm))
        {
            if target as usize >= pc {
                return Err(err(
                    n,
                    format!("branch target @{target} is past the end ({pc} bundles)"),
                ));
            }
        }
        bundles.push((n, crate::bundle(&slots)));
    }

    let lines: Vec<usize> = bundles.iter().map(|b| b.0).collect();
    Program::new(bundles.into_iter().map(|b| b.1).collect()).map_err(|e| match e {
        Error::MultipleControlOps { bundle } => {
            err(lines[bundle], "more than one control op in a bundle".into())
        }
        other => err(0, format!("{other:?}")),
    })
}
