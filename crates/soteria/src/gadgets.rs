//! Gadget-composed challenges.
//!
//! Each challenge's hash function is
//!
//! ```text
//! state  = sha256(challenge || nonce)            // 8 words in r1..r8
//! state  = g_n(... g_2(g_1(state)))              // seed-chosen gadgets
//! digest = sha256(state || fold(scratchpad))
//! solved = be32(digest[0..4]) < threshold
//! ```
//!
//! With `Params::block` set, the gadget sequence is not fixed per challenge:
//! nonce n of sub-challenge `sub` runs the program built from
//! `block_seed(seed, sub, n >> block)`, so a program compiled ahead of time
//! is only good for 2^block nonces.
//!
//! Gadget rules: straight-line code, a fixed cost, and bijective on r1..r8
//! (except `ShaAnchor`, which is a random function). Bijectivity matters: if
//! the state could collapse, an attacker could memoize final hashes. Most
//! gadgets are Feistel taps, `x op= f(y, z, ...)` with x not among the
//! inputs to f, which is invertible whatever f is. That's what lets lossy ops
//! like clz, popcnt, float sqrt and memory loads feed the state safely.
//!
//! Registers: r0 = 0, r1..r8 = state, r9..r13 = temps, r14 = scratchpad
//! mask, r15 = nonce. p1..p6 = temps, p15 = solved. f0..f3 = temps.
//! Memory: 0..32 challenge, 32..36 nonce, 64..128 hash block,
//! 128..scratchpad the arena, expanded from sha256(challenge || nonce).

use crate::puzzle::SplitMix;
use crate::sched::{schedule, sequential, Step};
use crate::{lanes, sha4, Op::*, Program, Slot, Vm, ARENA_START, LANES, MEM_SIZE};
use core::cell::RefCell;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gadget {
    // ALU: cheap diffusion
    AddRot,
    XorRot,
    SubRot,
    MulOdd,
    AddBswap,
    BswapTap,
    XorShift,
    // Bit-counting taps
    PopcntTap,
    ClzTap,
    // Float taps
    SqrtTap,
    DivTap,
    // Memory
    MemLoad,
    MemScatter,
    // Lane-level data movement
    CondSwap,
    WordRotate,
    // Expensive, SIMD-friendly
    ShaAnchor,
    // ALU, SHA-2 style boolean functions and products
    ChTap,
    MajTap,
    SigmaTap,
    MulAddTap,
    // Multiply-high and predicate taps
    MulHiTap,
    CmpMaskTap,
    // Float taps
    FMulTap,
    FAddTap,
    HypotTap,
    // Memory
    MemChase,
    MemRmw,
    MemXorLoad,
    // Lane-level data movement
    CondNegate,
    CondWordRotate,
    // Expensive
    ShaFeistel,
    FoldTap,
    // Memory, latency-bound
    MemWalk,
}

pub const ALL: [Gadget; 33] = {
    use Gadget::*;
    [
        AddRot,
        XorRot,
        SubRot,
        MulOdd,
        AddBswap,
        BswapTap,
        XorShift,
        PopcntTap,
        ClzTap,
        SqrtTap,
        DivTap,
        MemLoad,
        MemScatter,
        CondSwap,
        WordRotate,
        ShaAnchor,
        ChTap,
        MajTap,
        SigmaTap,
        MulAddTap,
        MulHiTap,
        CmpMaskTap,
        FMulTap,
        FAddTap,
        HypotTap,
        MemChase,
        MemRmw,
        MemXorLoad,
        CondNegate,
        CondWordRotate,
        ShaFeistel,
        FoldTap,
        MemWalk,
    ]
};

/// Relative weights per gadget category. Shifting weight moves cost between
/// ALU latency, float units, memory, and SHA throughput.
#[derive(Clone, Copy, Debug)]
pub struct Mix {
    pub alu: u32,
    pub taps: u32,
    pub float: u32,
    pub memory: u32,
    pub lanes: u32,
    pub sha: u32,
}

impl Default for Mix {
    fn default() -> Self {
        Mix {
            alu: 8,
            taps: 3,
            float: 2,
            memory: 3,
            lanes: 2,
            sha: 1,
        }
    }
}

impl Mix {
    fn pick(&self, rng: &mut SplitMix) -> Gadget {
        use Gadget::*;
        let groups: [(u32, &[Gadget]); 6] = [
            (
                self.alu,
                &[
                    AddRot, XorRot, SubRot, MulOdd, AddBswap, BswapTap, XorShift, ChTap, MajTap,
                    SigmaTap, MulAddTap,
                ],
            ),
            (self.taps, &[PopcntTap, ClzTap, MulHiTap, CmpMaskTap]),
            (self.float, &[SqrtTap, DivTap, FMulTap, FAddTap, HypotTap]),
            (
                self.memory,
                &[MemLoad, MemScatter, MemChase, MemRmw, MemXorLoad, MemWalk],
            ),
            (
                self.lanes,
                &[CondSwap, WordRotate, CondNegate, CondWordRotate],
            ),
            (self.sha, &[ShaAnchor, ShaFeistel, FoldTap]),
        ];
        let total: u32 = groups.iter().map(|g| g.0).sum();
        assert!(total > 0, "mix needs at least one nonzero weight");
        let mut x = rng.below(total as u64) as u32;
        for (w, gs) in groups {
            if x < w {
                return rng.pick(gs);
            }
            x -= w;
        }
        unreachable!()
    }
}

/// The difficulty axes.
#[derive(Clone, Copy, Debug)]
pub struct Params {
    /// Number of gadgets: linear cost per attempt.
    pub gadgets: usize,
    pub mix: Mix,
    /// Scratchpad bytes, a power of two in 256..=MEM_SIZE (1 MiB): memory
    /// footprint. Past the CPU caches, `MemWalk` hops become cache misses.
    pub scratchpad: u32,
    /// Success iff the first digest word (big-endian) is below this:
    /// probability threshold / 2^32, so difficulty scales smoothly.
    pub threshold: u32,
    /// Nonces required. Same expected work at a higher threshold, less variance.
    pub solutions: u32,
    /// Each solution's digest becomes the next sub-challenge, so solutions
    /// can't be searched in parallel.
    pub chained: bool,
    /// Fold the whole scratchpad into the final hash block. Without this,
    /// stores that are never reloaded are dead code an attacker can skip.
    pub fold: bool,
    /// Expand sha256(challenge || nonce) into the arena before the gadgets
    /// run, so memory contents differ per challenge and per nonce.
    pub fill: bool,
    /// log2 of the nonces that share a program, 0 or 2..=31. 0 uses one
    /// program for the whole challenge. Otherwise each block of 2^block
    /// nonces (lane-aligned, since block >= 2) in each sub-challenge gets its
    /// own program, so compiling a program can't be amortized over the whole
    /// search.
    pub block: u32,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            gadgets: 32,
            mix: Mix::default(),
            scratchpad: 1 << 14,
            threshold: 1 << 24,
            solutions: 1,
            chained: false,
            fold: true,
            fill: true,
            block: 0,
        }
    }
}

/// One mix round (32 bytes in each of the 4 lanes, as `fill` and `fold` do)
/// in bundles. Measured by `calibrate_memory_cost` on the interpreter; it
/// will shift when the interpreter gets faster or challenges get compiled.
pub const ROUND_COST: f64 = 0.25;
/// One `sha256` (two 4-lane compressions) in bundles, measured the same way.
pub const SHA_COST: f64 = 13.0;

const STATE: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
/// Dependent loads in one `MemWalk`.
pub const WALK_HOPS: usize = 8;
const MASK: u8 = 14;

pub(crate) struct Temps {
    r: usize,
    p: usize,
    f: usize,
}

impl Temps {
    // Round-robin so neighbouring gadgets use different temps and can co-issue.
    fn r(&mut self) -> u8 {
        self.r += 1;
        9 + (self.r % 5) as u8
    }
    fn p(&mut self) -> u8 {
        self.p += 1;
        1 + (self.p % 6) as u8
    }
    fn f(&mut self) -> u8 {
        self.f += 1;
        (self.f % 4) as u8
    }
}

fn one(op: crate::Op, d: u8, a: u8, b: u8, imm: i32) -> Step {
    vec![Slot::new(op, d, a, b, imm)]
}

/// Store r1..r8 to the block, hash it in place, reload.
fn sha_block(t: u8, steps: &mut Vec<Step>, reload: bool) {
    for (i, &r) in STATE.iter().enumerate() {
        steps.push(one(St, 0, 0, r, 64 + 4 * i as i32));
    }
    steps.push(one(Li, t, 0, 0, 64));
    steps.push(one(Sha256, 0, t, t, 0));
    if reload {
        for (i, &r) in STATE.iter().enumerate() {
            steps.push(one(Ld, r, 0, 0, 64 + 4 * i as i32));
        }
    }
}

/// Emit one gadget as sequential steps.
pub(crate) fn emit(g: Gadget, rng: &mut SplitMix, tmp: &mut Temps, out: &mut Vec<Step>) {
    use Gadget::*;
    // Distinct state words: x is the target, y/z/w are inputs (never x).
    let mut regs = STATE;
    for i in (1..regs.len()).rev() {
        regs.swap(i, rng.below(i as u64 + 1) as usize);
    }
    let [x, y, z, w, u, v, ..] = regs;
    let k = 1 + rng.below(31) as i32;
    let odd = (rng.next() as i32) | 1;
    let imm = rng.next() as i32;

    match g {
        AddRot => out.extend([one(Add, x, x, y, 0), one(Rotr, x, x, 0, k)]),
        XorRot => out.extend([one(Xor, x, x, y, 0), one(Rotr, x, x, 0, k)]),
        SubRot => {
            let t = tmp.r();
            out.extend([one(Rotr, t, y, 0, k), one(Sub, x, x, t, 0)]);
        }
        MulOdd => {
            let t = tmp.r();
            out.extend([one(Li, t, 0, 0, odd), one(Mul, x, x, t, 0)]);
        }
        AddBswap => out.extend([one(Addi, x, x, 0, imm), one(Bswap, x, x, 0, 0)]),
        BswapTap => {
            let t = tmp.r();
            out.extend([one(Bswap, t, y, 0, 0), one(Xor, x, x, t, 0)]);
        }
        XorShift => {
            let t = tmp.r();
            out.extend([one(Shr, t, x, 0, k), one(Xor, x, x, t, 0)]);
        }
        PopcntTap => {
            let t = tmp.r();
            out.extend([
                one(Xor, t, y, z, 0),
                one(Popcnt, t, t, 0, 0),
                one(Rotr, t, t, 0, k),
                one(Add, x, x, t, 0),
            ]);
        }
        ClzTap => {
            // The count has 33 values, so offset it and take the high half
            // of a product with y: a full 32-bit tap.
            let t = tmp.r();
            out.extend([
                one(And, t, y, z, 0),
                one(Clz, t, t, 0, 0),
                one(Addi, t, t, 0, imm),
                one(Mulhu, t, t, y, 0),
                one(Add, x, x, t, 0),
            ]);
        }
        SqrtTap => {
            // Halve y so the root is never NaN, and tap the float's bits
            // rather than its truncated value.
            let (f, t) = (tmp.f(), tmp.r());
            out.extend([
                one(Shr, t, y, 0, 1),
                one(FCvt, f, t, 0, 0),
                one(FSqrt, f, f, 0, 0),
                one(FBits, t, f, 0, 0),
                one(Xor, x, x, t, 0),
            ]);
        }
        DivTap => {
            let (fa, fb, t) = (tmp.f(), tmp.f(), tmp.r());
            out.extend([
                one(FCvt, fa, y, 0, 0),
                one(FCvt, fb, z, 0, 0),
                one(FDiv, fa, fa, fb, 0),
                one(FBits, t, fa, 0, 0),
                one(Add, x, x, t, 0),
            ]);
        }
        MemLoad => {
            let t = tmp.r();
            out.extend([
                one(And, t, y, MASK, 0),
                one(Ld, t, t, 0, 0),
                one(Xor, x, x, t, 0),
            ]);
        }
        MemScatter => {
            // Store y, then add in a load. Even if the addresses alias, x += y
            // is still invertible, which x ^= x would not be.
            let (t1, t2) = (tmp.r(), tmp.r());
            out.extend([
                one(And, t1, z, MASK, 0),
                one(St, 0, t1, y, 0),
                one(And, t2, w, MASK, 0),
                one(Ld, t2, t2, 0, 0),
                one(Add, x, x, t2, 0),
            ]);
        }
        CondSwap => {
            // Swap x and y in lanes where z < w. Conditioning on words that
            // aren't swapped keeps it a bijection; `if x < y swap` would sort,
            // and sorting collapses (1,2) and (2,1) into one state.
            let p = tmp.p();
            out.push(one(CmpLtu, p, z, w, 0));
            out.push(vec![
                Slot::new(Addi, x, y, 0, 0).when(p),
                Slot::new(Addi, y, x, 0, 0).when(p),
            ]);
        }
        WordRotate => {
            // (x, y, z, w) <- (y, z, w, x) in one bundle, no temporaries.
            out.push(vec![
                Slot::new(Addi, x, y, 0, 0),
                Slot::new(Addi, y, z, 0, 0),
                Slot::new(Addi, z, w, 0, 0),
                Slot::new(Addi, w, x, 0, 0),
            ]);
        }
        ShaAnchor => sha_block(tmp.r(), out, true),
        ChTap => {
            // SHA-256 Ch: bits of z where y is set, else bits of w.
            let t = tmp.r();
            out.extend([
                one(Xor, t, z, w, 0),
                one(And, t, t, y, 0),
                one(Xor, t, t, w, 0),
                one(Add, x, x, t, 0),
            ]);
        }
        MajTap => {
            // SHA-256 Maj: bitwise majority of y, z, w.
            let (t1, t2) = (tmp.r(), tmp.r());
            out.extend([
                one(And, t1, y, z, 0),
                one(Or, t2, y, z, 0),
                one(And, t2, t2, w, 0),
                one(Or, t1, t1, t2, 0),
                one(Xor, x, x, t1, 0),
            ]);
        }
        SigmaTap => {
            // SHA-256 style Sigma: three rotations of y xored together.
            let (t1, t2) = (tmp.r(), tmp.r());
            let k2 = 1 + rng.below(31) as i32;
            let k3 = 1 + rng.below(31) as i32;
            out.extend([
                one(Rotr, t1, y, 0, k),
                one(Rotr, t2, y, 0, k2),
                one(Xor, t1, t1, t2, 0),
                one(Rotr, t2, y, 0, k3),
                one(Xor, t1, t1, t2, 0),
                one(Add, x, x, t1, 0),
            ]);
        }
        MulAddTap => {
            let t = tmp.r();
            out.extend([one(Mul, t, y, z, 0), one(Add, x, x, t, 0)]);
        }
        MulHiTap => {
            let t = tmp.r();
            out.extend([one(Mulhu, t, y, z, 0), one(Xor, x, x, t, 0)]);
        }
        CmpMaskTap => {
            // x += y < z ? w : 0
            let (p, t) = (tmp.p(), tmp.r());
            out.extend([
                one(CmpLtu, p, y, z, 0),
                one(PMov, t, p, 0, 0),
                one(And, t, t, w, 0),
                one(Add, x, x, t, 0),
            ]);
        }
        FMulTap => {
            let (fa, fb, t) = (tmp.f(), tmp.f(), tmp.r());
            out.extend([
                one(FCvt, fa, y, 0, 0),
                one(FCvt, fb, z, 0, 0),
                one(FMul, fa, fa, fb, 0),
                one(FBits, t, fa, 0, 0),
                one(Xor, x, x, t, 0),
            ]);
        }
        FAddTap => {
            // Raw bits as floats: every exponent, subnormals and NaNs
            // included. fadd canonicalizes any NaN it produces.
            let (fa, fb, t) = (tmp.f(), tmp.f(), tmp.r());
            out.extend([
                one(FFrom, fa, y, 0, 0),
                one(FFrom, fb, z, 0, 0),
                one(FAdd, fa, fa, fb, 0),
                one(FBits, t, fa, 0, 0),
                one(Sub, x, x, t, 0),
            ]);
        }
        HypotTap => {
            let (fa, fb, t) = (tmp.f(), tmp.f(), tmp.r());
            out.extend([
                one(FCvt, fa, y, 0, 0),
                one(FCvt, fb, z, 0, 0),
                one(FMul, fa, fa, fa, 0),
                one(FMul, fb, fb, fb, 0),
                one(FAdd, fa, fa, fb, 0),
                one(FSqrt, fa, fa, 0, 0),
                one(FBits, t, fa, 0, 0),
                one(Add, x, x, t, 0),
            ]);
        }
        MemChase => {
            // Two dependent loads: latency, not bandwidth.
            let t = tmp.r();
            out.extend([
                one(And, t, y, MASK, 0),
                one(Ld, t, t, 0, 0),
                one(And, t, t, MASK, 0),
                one(Ld, t, t, 0, 0),
                one(Xor, x, x, t, 0),
            ]);
        }
        MemRmw => {
            // mem[z] += y, then x ^= the new value.
            let (t1, t2) = (tmp.r(), tmp.r());
            out.extend([
                one(And, t1, z, MASK, 0),
                one(Ld, t2, t1, 0, 0),
                one(Add, t2, t2, y, 0),
                one(St, 0, t1, t2, 0),
                one(Xor, x, x, t2, 0),
            ]);
        }
        MemXorLoad => {
            let t = tmp.r();
            out.extend([
                one(Xor, t, y, z, 0),
                one(And, t, t, MASK, 0),
                one(Ld, t, t, 0, 0),
                one(Sub, x, x, t, 0),
            ]);
        }
        CondNegate => {
            // x = -x in lanes where y < z, as (x ^ m) - m with m = 0 or -1.
            let (p, t) = (tmp.p(), tmp.r());
            out.extend([
                one(CmpLtu, p, y, z, 0),
                one(PMov, t, p, 0, 0),
                one(Xor, x, x, t, 0),
                one(Sub, x, x, t, 0),
            ]);
        }
        CondWordRotate => {
            // WordRotate in lanes where u < v. u and v aren't rotated, so the
            // condition survives and the step can be undone.
            let p = tmp.p();
            out.push(one(CmpLtu, p, u, v, 0));
            out.push(vec![
                Slot::new(Addi, x, y, 0, 0).when(p),
                Slot::new(Addi, y, z, 0, 0).when(p),
                Slot::new(Addi, z, w, 0, 0).when(p),
                Slot::new(Addi, w, x, 0, 0).when(p),
            ]);
        }
        ShaFeistel => {
            // Hash every state word but x (zero in its place) and xor one
            // digest word into x: SHA-256 cost, still a bijection.
            let (t, i) = (tmp.r(), rng.below(8) as i32);
            for (j, &r) in STATE.iter().enumerate() {
                let r = if r == x { 0 } else { r };
                out.push(one(St, 0, 0, r, 64 + 4 * j as i32));
            }
            out.extend([
                one(Li, t, 0, 0, 64),
                one(Sha256, 0, t, t, 0),
                one(Ld, t, 0, 0, 64 + 4 * i),
                one(Xor, x, x, t, 0),
            ]);
        }
        MemWalk => {
            // A chain of dependent loads: each address comes from the last
            // loaded word, so the hops can't overlap and cost a memory
            // latency each, which varies far less between phones and
            // desktops than ALU throughput does. Adding z between hops means
            // two states that land on the same word don't share the rest of
            // the walk. Every loaded word goes into x.
            let t = tmp.r();
            out.push(one(Xor, t, y, z, 0));
            for hop in 0..WALK_HOPS {
                if hop > 0 {
                    out.push(one(Add, t, t, z, 0));
                }
                out.extend([
                    one(And, t, t, MASK, 0),
                    one(Ld, t, t, 0, 0),
                    one(Add, x, x, t, 0),
                ]);
            }
        }
        FoldTap => {
            // Fold the scratchpad mid-program, so stores before this point
            // matter twice and the fold can't be deferred to the end.
            let (t, i) = (tmp.r(), rng.below(8) as i32);
            out.extend([
                one(Li, t, 0, 0, 96),
                one(Fold, 0, MASK, t, 0),
                one(Ld, t, 0, 0, 96 + 4 * i),
                one(Add, x, x, t, 0),
            ]);
        }
    }
}

/// A compiled challenge family.
pub struct Challenge {
    pub seed: u64,
    pub params: Params,
    /// The program built from `seed`. With `params.block` = 0 every nonce
    /// runs it; otherwise it's a representative sample for `attempt_cost`,
    /// and nonces run `program_for` instead.
    pub gadgets: Vec<Gadget>,
    pub program: Program,
    unscheduled: bool,
    /// The last block program built, keyed by its seed. Callers walk nonces
    /// in order, so one entry is enough.
    cache: RefCell<Option<(u64, Program)>>,
    /// Reused between attempts: a fresh `Vm` would zero all of `MEM_SIZE`
    /// in every lane, `reset` only what the last run touched.
    vm: RefCell<Option<Vm>>,
}

/// Program seed for nonce block `block` of sub-challenge `sub`. Distinct
/// blocks of one sub-challenge always get distinct seeds.
pub fn block_seed(seed: u64, sub: &[u8; 32], block: u32) -> u64 {
    let s = u64::from_le_bytes(sub[..8].try_into().unwrap());
    SplitMix(seed ^ s ^ (block as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)).next()
}

impl Challenge {
    pub fn new(seed: u64, params: Params) -> Self {
        Self::build(seed, params, false)
    }

    /// Same program, one step per bundle. Reference semantics for tests.
    pub fn new_unscheduled(seed: u64, params: Params) -> Self {
        Self::build(seed, params, true)
    }

    /// Pick the threshold so that expected total work is `budget`
    /// bundle-equivalents (see `attempt_cost`). Every other axis is left as given.
    pub fn with_budget(seed: u64, mut params: Params, budget: f64) -> Self {
        let cost = Self::new(seed, params).attempt_cost();
        let attempts = budget / (cost * params.solutions as f64);
        params.threshold = (4_294_967_296.0 / attempts.max(1.0)).clamp(1.0, u32::MAX as f64) as u32;
        Self::new(seed, params)
    }

    fn build(seed: u64, params: Params, unscheduled: bool) -> Self {
        let s = params.scratchpad;
        assert!(s.is_power_of_two() && (256..=MEM_SIZE as u32).contains(&s));
        assert!(params.solutions >= 1 && params.threshold >= 1);
        assert!(params.block == 0 || (2..=31).contains(&params.block));
        let (gadgets, program) = compile(seed, &params, unscheduled);
        Challenge {
            seed,
            params,
            gadgets,
            program,
            unscheduled,
            cache: RefCell::new(None),
            vm: RefCell::new(None),
        }
    }

    /// Bundles per attempt. Straight-line code, so this is also the exact fuel.
    pub fn bundles(&self) -> usize {
        self.program.bundles().len()
    }

    /// Work per attempt in bundle-equivalents. `fill`, `fold` and `sha256`
    /// cost 1 fuel each but do far more work, so they're charged by what they
    /// compute: mix rounds over the scratchpad and SHA-256 compressions.
    pub fn attempt_cost(&self) -> f64 {
        let s = self.params.scratchpad as f64;
        let mem: f64 = self
            .program
            .bundles()
            .iter()
            .flatten()
            .map(|slot| match slot.op {
                Sha256 => SHA_COST,
                Fill => (s - ARENA_START as f64) / 32.0 * ROUND_COST,
                Fold => (s / 32.0 + 4.0) * ROUND_COST,
                _ => 0.0,
            })
            .sum();
        self.bundles() as f64 + mem
    }

    /// Expected bundle-equivalents to solve every sub-challenge: the single
    /// "work" number a policy can reason about.
    pub fn expected_work(&self) -> f64 {
        self.attempt_cost()
            * (4_294_967_296.0 / self.params.threshold as f64)
            * self.params.solutions as f64
    }

    /// The program nonce `nonce` of sub-challenge `sub` runs.
    pub fn program_for(&self, sub: &[u8; 32], nonce: u32) -> Program {
        match self.params.block {
            0 => self.program.clone(),
            b => {
                compile(
                    block_seed(self.seed, sub, nonce >> b),
                    &self.params,
                    self.unscheduled,
                )
                .1
            }
        }
    }

    /// Run one lane-aligned batch; returns (solved, final digest) per lane.
    pub fn attempt(&self, sub: &[u8; 32], base: u32) -> Option<[(bool, [u8; 32]); LANES]> {
        assert_eq!(base % LANES as u32, 0);
        if self.params.block == 0 {
            return self.run(&self.program, sub, base);
        }
        let key = block_seed(self.seed, sub, base >> self.params.block);
        let mut cache = self.cache.borrow_mut();
        if cache.as_ref().is_none_or(|c| c.0 != key) {
            *cache = Some((key, compile(key, &self.params, self.unscheduled).1));
        }
        self.run(&cache.as_ref().unwrap().1, sub, base)
    }

    fn run(
        &self,
        program: &Program,
        sub: &[u8; 32],
        base: u32,
    ) -> Option<[(bool, [u8; 32]); LANES]> {
        // The memory image is the sub-challenge, then zeros.
        let fuel = program.bundles().len() as u64;
        let mut slot = self.vm.borrow_mut();
        let vm = match slot.as_mut() {
            Some(vm) => {
                vm.reset(sub, base, fuel);
                vm
            }
            None => slot.insert(Vm::new(sub, base, fuel)),
        };
        vm.run(program).ok()?;
        let solved = lanes(vm.p[15]);
        Some(core::array::from_fn(|l| {
            let o = l * MEM_SIZE + 64;
            (solved[l] != 0, vm.mem[o..o + 32].try_into().unwrap())
        }))
    }

    pub(crate) fn first_sub(&self, challenge: &[u8; 32]) -> [u8; 32] {
        derive(challenge, 0)
    }

    fn next_sub(&self, challenge: &[u8; 32], i: u32, digest: &[u8; 32]) -> [u8; 32] {
        if self.params.chained {
            *digest
        } else {
            derive(challenge, i + 1)
        }
    }

    /// Client: find `solutions` nonces.
    pub fn solve(&self, challenge: &[u8; 32], max_batches: u32) -> Option<Vec<u32>> {
        let mut sub = self.first_sub(challenge);
        let mut nonces = Vec::new();
        for i in 0..self.params.solutions {
            let (nonce, digest) = (0..max_batches).find_map(|b| {
                let base = b * LANES as u32;
                let r = self.attempt(&sub, base)?;
                r.iter()
                    .position(|x| x.0)
                    .map(|l| (base + l as u32, r[l].1))
            })?;
            nonces.push(nonce);
            sub = self.next_sub(challenge, i, &digest);
        }
        Some(nonces)
    }

    /// Server: rerun one batch per nonce. Cost is `solutions` attempts.
    pub fn verify(&self, challenge: &[u8; 32], nonces: &[u32]) -> bool {
        if nonces.len() != self.params.solutions as usize {
            return false;
        }
        let mut sub = self.first_sub(challenge);
        for (i, &n) in nonces.iter().enumerate() {
            let lane = n as usize % LANES;
            let Some(r) = self.attempt(&sub, n - lane as u32) else {
                return false;
            };
            if !r[lane].0 {
                return false;
            }
            sub = self.next_sub(challenge, i as u32, &r[lane].1);
        }
        true
    }
}

/// Build the program for one seed: gadgets plus prologue and epilogue.
fn compile(seed: u64, params: &Params, unscheduled: bool) -> (Vec<Gadget>, Program) {
    let s = params.scratchpad;
    let mut rng = SplitMix(seed);
    let mut tmp = Temps { r: 0, p: 0, f: 0 };

    let mut steps: Vec<Step> = vec![
        one(St, 0, 0, 15, 32),
        one(Li, MASK, 0, 0, (s - 1) as i32),
        one(Li, 9, 0, 0, 64),
        one(Sha256, 0, 0, 9, 0),
    ];
    for (i, &r) in STATE.iter().enumerate() {
        steps.push(one(Ld, r, 0, 0, 64 + 4 * i as i32));
    }
    // After the loads in program order, so it can share their bundle
    // (the scheduler treats memory as one resource).
    if params.fill {
        steps.push(one(Fill, 0, MASK, 9, 0));
    }

    let gadgets: Vec<Gadget> = (0..params.gadgets)
        .map(|_| params.mix.pick(&mut rng))
        .collect();
    for &g in &gadgets {
        emit(g, &mut rng, &mut tmp, &mut steps);
    }

    // Epilogue: block = state (64..96) || fold(scratchpad) (96..128), then hash.
    for (i, &r) in STATE.iter().enumerate() {
        steps.push(one(St, 0, 0, r, 64 + 4 * i as i32));
    }
    if params.fold {
        steps.push(one(Li, 10, 0, 0, 96));
        steps.push(one(Fold, 0, MASK, 10, 0));
    }
    steps.push(one(Li, 9, 0, 0, 64));
    steps.push(one(Sha256, 0, 9, 9, 0));
    steps.extend([
        one(Ld, 9, 0, 0, 64),
        one(Bswap, 9, 9, 0, 0),
        one(Li, 10, 0, 0, params.threshold as i32),
        one(CmpLtu, 15, 9, 10, 0),
    ]);

    let mut bundles = if unscheduled {
        sequential(&steps)
    } else {
        schedule(&steps)
    };
    let halt = Slot::new(Halt, 0, 0, 0, 0);
    let last = bundles.last_mut().unwrap();
    match last.iter().position(|s| s.op == Nop) {
        Some(i) => last[i] = halt,
        None => bundles.push(crate::bundle(&[halt])),
    }

    (gadgets, Program::new(bundles).unwrap())
}

/// Batches in the nonce space: `batch * LANES` must fit in a u32.
pub const BATCHES: u32 = 1 << 30;

/// Outcome of `Solver::step`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    Working,
    Done,
    /// Ran out of nonces before finding every solution.
    Exhausted,
}

/// `Challenge::solve` in resumable steps, for callers that must yield, such
/// as a browser worker checking a deadline. Finds the same nonces as `solve`.
pub struct Solver {
    challenge: [u8; 32],
    sub: [u8; 32],
    batch: u32,
    nonces: Vec<u32>,
}

impl Solver {
    pub fn new(c: &Challenge, challenge: &[u8; 32]) -> Self {
        Solver {
            challenge: *challenge,
            sub: c.first_sub(challenge),
            batch: 0,
            nonces: Vec::new(),
        }
    }

    /// Run up to `batches` batches. `c` must be the challenge given to `new`.
    pub fn step(&mut self, c: &Challenge, batches: u32) -> Progress {
        for _ in 0..batches {
            if self.nonces.len() == c.params.solutions as usize {
                break;
            }
            if self.batch == BATCHES {
                return Progress::Exhausted;
            }
            let base = self.batch * LANES as u32;
            self.batch += 1;
            let Some(r) = c.attempt(&self.sub, base) else {
                continue;
            };
            if let Some(l) = r.iter().position(|x| x.0) {
                let i = self.nonces.len() as u32;
                self.nonces.push(base + l as u32);
                self.sub = c.next_sub(&self.challenge, i, &r[l].1);
                self.batch = 0;
            }
        }
        if self.nonces.len() == c.params.solutions as usize {
            Progress::Done
        } else {
            Progress::Working
        }
    }

    /// Solutions found so far, in order.
    pub fn nonces(&self) -> &[u32] {
        &self.nonces
    }
}

/// Independent sub-challenge i: sha256(challenge || i || zeros).
fn derive(challenge: &[u8; 32], i: u32) -> [u8; 32] {
    let mut b = [0u8; 64];
    b[..32].copy_from_slice(challenge);
    b[32..36].copy_from_slice(&i.to_le_bytes());
    sha4::sha256x4([&b; 4])[0]
}

/// Program with just gadget `g` (plus halt), for bijectivity tests.
#[cfg(test)]
pub(crate) fn solo(g: Gadget, seed: u64) -> Program {
    let mut rng = SplitMix(seed);
    let mut tmp = Temps { r: 0, p: 0, f: 0 };
    let mut steps = vec![one(Li, MASK, 0, 0, 0xFFFF)];
    emit(g, &mut rng, &mut tmp, &mut steps);
    let mut b = schedule(&steps);
    b.push(crate::bundle(&[Slot::new(Halt, 0, 0, 0, 0)]));
    Program::new(b).unwrap()
}
