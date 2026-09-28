//! List scheduler: turns a sequential list of steps into VLIW bundles.
//!
//! A step is 1..=4 slots that must issue together (so they share the
//! read-before-write semantics of one bundle, which is how `CondSwap` and
//! `WordRotate` get away with no temporaries). Between steps, the program
//! behaves as if steps ran one after another; the scheduler only hoists a step
//! into an earlier bundle when no register, predicate, float or memory hazard
//! forbids it.

use crate::{bundle, Bundle, Op, Slot, SLOTS};

pub type Step = Vec<Slot>;

const R: usize = 0;
const P: usize = 16;
const F: usize = 32;
const MEM: usize = 36;
const RESOURCES: usize = 37;

/// (reads, writes) of one slot, as resource indices.
fn hazards(s: &Slot) -> (Vec<usize>, Vec<usize>) {
    use Op::*;
    let (d, a, b) = (s.d as usize, s.a as usize, s.b as usize);
    let (mut r, w) = match s.op {
        Li => (vec![], vec![R + d]),
        Addi | Shl | Shr | Rotr | Clz | Bswap | Popcnt => (vec![R + a], vec![R + d]),
        Add | Sub | Mul | Xor | And | Or => (vec![R + a, R + b], vec![R + d]),
        Ld => (vec![R + a, MEM], vec![R + d]),
        St => (vec![R + a, R + b], vec![MEM]),
        Sha256 | Fold | Fill => (vec![R + a, R + b, MEM], vec![MEM]),
        CmpEq | CmpLt | CmpLtu => (vec![R + a, R + b], vec![P + d]),
        PAnd | POr | PXor => (vec![P + a, P + b], vec![P + d]),
        PNot | PAny => (vec![P + a], vec![P + d]),
        FCvt => (vec![R + a], vec![F + (d & 3)]),
        FAdd | FSub | FMul | FDiv => (vec![F + (a & 3), F + (b & 3)], vec![F + (d & 3)]),
        FSqrt => (vec![F + (a & 3)], vec![F + (d & 3)]),
        FLt => (vec![F + (a & 3), F + (b & 3)], vec![P + d]),
        FTrunc | FBits => (vec![F + (a & 3)], vec![R + d]),
        FFrom => (vec![R + a], vec![F + (d & 3)]),
        Nop => (vec![], vec![]),
        Halt | Subleq | Bp => panic!("control ops are not schedulable"),
    };
    if s.guard & 15 != 0 {
        r.push(P + (s.guard & 15) as usize);
    }
    (r, w)
}

/// Pack steps into as few bundles as the hazards allow.
pub fn schedule(steps: &[Step]) -> Vec<Bundle> {
    let mut bundles: Vec<Vec<Slot>> = Vec::new();
    let mut last_read = [-1i64; RESOURCES];
    let mut last_write = [-1i64; RESOURCES];

    for step in steps {
        assert!(!step.is_empty() && step.len() <= SLOTS);
        let (mut reads, mut writes) = (Vec::new(), Vec::new());
        for s in step {
            let (r, w) = hazards(s);
            reads.extend(r);
            writes.extend(w);
        }

        // RAW: after the last writer.
        // WAR: not before the last reader (same bundle is fine: reads see old values).
        // WAW: not before the last writer (same bundle is fine: this step is
        // appended after it, and writes commit in slot order).
        let mut at = 0i64;
        for &r in &reads {
            at = at.max(last_write[r] + 1);
        }
        for &w in &writes {
            at = at.max(last_write[w]).max(last_read[w]);
        }
        let mut j = at as usize;
        while j < bundles.len() && bundles[j].len() + step.len() > SLOTS {
            j += 1;
        }
        if j == bundles.len() {
            bundles.push(Vec::new());
        }
        bundles[j].extend_from_slice(step);

        for &r in &reads {
            last_read[r] = last_read[r].max(j as i64);
        }
        for &w in &writes {
            last_write[w] = last_write[w].max(j as i64);
        }
    }
    bundles.iter().map(|b| bundle(b)).collect()
}

/// One step per bundle: the reference semantics the scheduler must match.
pub fn sequential(steps: &[Step]) -> Vec<Bundle> {
    steps.iter().map(|s| bundle(s)).collect()
}
