//! Per-attempt puzzle generator. The server picks a fresh seed for every
//! challenge; the seed deterministically expands into a program whose loop
//! body is random VLIW bundles, so precomputed solvers don't carry over.
//!
//! Register conventions:
//!   r0 = 0 (never written), r1..r8 = hash state, r9..r11 = scratch,
//!   r12 = block pointer (64), r13 = 1, r14 = round counter, r15 = nonce.
//!   p1..p4 = scratch predicates, p15 = "solved".
//!
//! Memory: the challenge image sits at 0..32, the nonce is written at 32..36,
//! and the 64-byte block at 64..128 is hashed every round.

use crate::{bundle, Bundle, Op, Program, Slot, NOP, RESULT_PRED};

pub struct Puzzle {
    pub program: Program,
    /// Exact number of bundles an honest run executes.
    pub fuel: u64,
}

pub(crate) struct SplitMix(pub(crate) u64);

impl SplitMix {
    pub(crate) fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    pub(crate) fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    pub(crate) fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
        xs[self.below(xs.len() as u64) as usize]
    }
}

const BLOCK: u8 = 12;
const ONE: u8 = 13;
const COUNTER: u8 = 14;
const NONCE: u8 = 15;

fn random_slot(rng: &mut SplitMix) -> Slot {
    use Op::*;
    const OPS: &[Op] = &[
        Add, Sub, Mul, Xor, And, Or, Addi, Shl, Shr, Rotr, Clz, Bswap, Popcnt, Ld, St,
        CmpEq, CmpLt, CmpLtu, FCvt, FAdd, FSub, FMul, FDiv, FSqrt, FLt, FTrunc,
    ];
    let op = rng.pick(OPS);
    let dst = 1 + rng.below(11) as u8; // r1..r11
    let src = |rng: &mut SplitMix| rng.below(16) as u8; // any register, incl. nonce
    let freg = |rng: &mut SplitMix| rng.below(4) as u8;
    let pred = |rng: &mut SplitMix| 1 + rng.below(4) as u8; // p1..p4
    let imm = rng.next() as i32;

    let slot = match op {
        Add | Sub | Mul | Xor | And | Or => Slot::new(op, dst, src(rng), src(rng), 0),
        Addi => Slot::new(op, dst, src(rng), 0, imm),
        Shl | Shr | Rotr => Slot::new(op, dst, src(rng), 0, 1 + rng.below(31) as i32),
        Clz | Bswap | Popcnt => Slot::new(op, dst, src(rng), 0, 0),
        // Data-dependent addresses: the 64 KiB scratchpad becomes part of the state.
        Ld => Slot::new(op, dst, src(rng), 0, imm & 0xFFFF),
        St => Slot::new(op, 0, src(rng), src(rng), imm & 0xFFFF),
        CmpEq | CmpLt | CmpLtu => Slot::new(op, pred(rng), src(rng), src(rng), 0),
        FCvt => Slot::new(op, freg(rng), src(rng), 0, 0),
        FAdd | FSub | FMul | FDiv => Slot::new(op, freg(rng), freg(rng), freg(rng), 0),
        FSqrt => Slot::new(op, freg(rng), freg(rng), 0, 0),
        FLt => Slot::new(op, pred(rng), freg(rng), freg(rng), 0),
        FTrunc => Slot::new(op, dst, freg(rng), 0, 0),
        _ => unreachable!(),
    };

    // A quarter of slots are predicated on per-lane data. This is the SIMD
    // analogue of an `if`: both sides run, the guard picks which lanes commit.
    match rng.below(8) {
        0 => slot.when(pred(rng)),
        1 => slot.unless(pred(rng)),
        _ => slot,
    }
}

/// `rounds` iterations of (random body, write state into block, sha256 block).
/// Solved when the first little-endian word of the final digest has at least
/// `difficulty` leading zero bits.
pub fn generate(seed: u64, rounds: u32, body_bundles: usize, difficulty: u32) -> Puzzle {
    use Op::*;
    assert!(rounds >= 1 && difficulty <= 32);
    let mut rng = SplitMix(seed);
    let s = Slot::new;
    let mut p: Vec<Bundle> = vec![
        // Prologue: block = sha256(challenge || nonce || zeros)
        bundle(&[s(St, 0, 0, NONCE, 32), s(Li, BLOCK, 0, 0, 64), s(Li, ONE, 0, 0, 1), s(Li, COUNTER, 0, 0, rounds as i32)]),
        bundle(&[s(Sha256, 0, 0, BLOCK, 0)]),
    ];

    let top = p.len() as i32;
    p.push(core::array::from_fn(|i| s(Ld, 1 + i as u8, BLOCK, 0, 4 * i as i32)));
    p.push(core::array::from_fn(|i| s(Ld, 5 + i as u8, BLOCK, 0, 16 + 4 * i as i32)));
    for _ in 0..body_bundles {
        p.push(core::array::from_fn(|_| random_slot(&mut rng)));
    }
    // Fold r1..r8 into the second half of the block and rehash.
    p.push(core::array::from_fn(|i| s(St, 0, BLOCK, 1 + i as u8, 32 + 4 * i as i32)));
    p.push(core::array::from_fn(|i| s(St, 0, BLOCK, 5 + i as u8, 48 + 4 * i as i32)));

    // Loop control is pure subleq: counter -= 1, exit when it hits 0;
    // then `subleq r0, r0` computes 0 - 0 <= 0, i.e. an unconditional jump.
    let exit_pc = p.len() as i32 + 2;
    p.push(bundle(&[s(Sha256, 0, BLOCK, BLOCK, 0), s(Subleq, 0, ONE, COUNTER, exit_pc)]));
    p.push(bundle(&[s(Subleq, 0, 0, 0, top)]));

    // Epilogue: p15 = clz(block[0]) >= difficulty
    p.push(bundle(&[s(Ld, 1, BLOCK, 0, 0), s(Li, 9, 0, 0, difficulty as i32)]));
    p.push(bundle(&[s(Clz, 1, 1, 0, 0)]));
    p.push(bundle(&[s(CmpLtu, 1, 1, 9, 0)]));
    p.push(bundle(&[s(PNot, RESULT_PRED as u8, 1, 0, 0), s(Halt, 0, 0, 0, 0), NOP, NOP]));

    let body = (2 + body_bundles + 2 + 1) as u64;
    let fuel = 2 + rounds as u64 * body + (rounds as u64 - 1) + 4;
    Puzzle { program: Program::new(p).expect("generator emits valid bundles"), fuel }
}
