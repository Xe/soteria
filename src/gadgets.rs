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
}

pub const ALL: [Gadget; 16] = {
    use Gadget::*;
    [
        AddRot, XorRot, SubRot, MulOdd, AddBswap, BswapTap, XorShift, PopcntTap, ClzTap, SqrtTap,
        DivTap, MemLoad, MemScatter, CondSwap, WordRotate, ShaAnchor,
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
                &[AddRot, XorRot, SubRot, MulOdd, AddBswap, BswapTap, XorShift],
            ),
            (self.taps, &[PopcntTap, ClzTap]),
            (self.float, &[SqrtTap, DivTap]),
            (self.memory, &[MemLoad, MemScatter]),
            (self.lanes, &[CondSwap, WordRotate]),
            (self.sha, &[ShaAnchor]),
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
    /// Scratchpad bytes, a power of two in 256..=65536: memory footprint.
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
    let [x, y, z, w, ..] = regs;
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
            let t = tmp.r();
            out.extend([
                one(And, t, y, z, 0),
                one(Clz, t, t, 0, 0),
                one(Mul, t, t, y, 0),
                one(Add, x, x, t, 0),
            ]);
        }
        SqrtTap => {
            let (f, t) = (tmp.f(), tmp.r());
            out.extend([
                one(FCvt, f, y, 0, 0),
                one(FSqrt, f, f, 0, 0),
                one(FTrunc, t, f, 0, 0),
                one(Xor, x, x, t, 0),
            ]);
        }
        DivTap => {
            let (fa, fb, t) = (tmp.f(), tmp.f(), tmp.r());
            out.extend([
                one(FCvt, fa, y, 0, 0),
                one(FCvt, fb, z, 0, 0),
                one(FDiv, fa, fa, fb, 0),
                one(FTrunc, t, fa, 0, 0),
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
    }
}

/// A compiled challenge family: one program, reused for every sub-challenge.
pub struct Challenge {
    pub params: Params,
    pub gadgets: Vec<Gadget>,
    pub program: Program,
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

        Challenge {
            params,
            gadgets,
            program: Program::new(bundles).unwrap(),
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

    pub(crate) fn image(&self, sub: &[u8; 32]) -> Vec<u8> {
        let mut m = vec![0u8; self.params.scratchpad as usize];
        m[..32].copy_from_slice(sub);
        m
    }

    /// Run one lane-aligned batch; returns (solved, final digest) per lane.
    pub fn attempt(&self, sub: &[u8; 32], base: u32) -> Option<[(bool, [u8; 32]); LANES]> {
        assert_eq!(base % LANES as u32, 0);
        let mut vm = Vm::new(&self.image(sub), base, self.bundles() as u64);
        vm.run(&self.program).ok()?;
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
