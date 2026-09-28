//! soteria: a 4-lane SPMD VLIW virtual machine for per-attempt proof-of-work puzzles.
//!
//! Every lane runs the same program on a different nonce. Registers are `v128`s
//! holding one 32-bit value per lane, so one bundle advances four attempts at once.
//!
//! Architectural state (per lane):
//! - 16 × i32 registers `r0..r15` (`r15` starts as the lane's nonce)
//! - 4 × f32 registers `f0..f3`
//! - 16 × predicate registers `p0..p15` (`p0` is hardwired true, `p15` is the result)
//! - 64 KiB of byte-addressed little-endian memory
//!
//! Bundle semantics: every slot reads the state as it was at the start of the
//! bundle, then all writes commit in slot order (later slots win on conflicts).

#![cfg(target_arch = "wasm32")]

use core::arch::wasm32::*;

pub use soteria_isa::*;

pub mod best;
pub mod gadgets;
pub mod hashcash;
pub mod puzzle;
pub mod sha4;
pub mod wire;

pub(crate) fn lanes(v: v128) -> [u32; LANES] {
    // SAFETY: v128 and [u32; 4] are both 16 bytes of plain data; lane 0 is the lowest address.
    unsafe { core::mem::transmute(v) }
}

pub(crate) fn from_lanes(a: [u32; LANES]) -> v128 {
    // SAFETY: see `lanes`.
    unsafe { core::mem::transmute(a) }
}

/// Count leading zeros in all four lanes. WASM SIMD has no i32x4 clz, so:
/// smear the top bit down, isolate it, convert to f32 (exact for a power of
/// two) and read the exponent.
pub fn clz32x4(x: v128) -> v128 {
    let mut y = x;
    for s in [1, 2, 4, 8, 16] {
        y = v128_or(y, u32x4_shr(y, s));
    }
    let top = v128_xor(y, u32x4_shr(y, 1));
    let exp = u32x4_shr(f32x4_convert_u32x4(top), 23);
    let clz = i32x4_sub(i32x4_splat(158), exp); // 31 - (exp - 127)
    v128_bitselect(i32x4_splat(32), clz, i32x4_eq(x, i32x4_splat(0)))
}

#[inline(always)]
fn rotl(x: v128, n: u32) -> v128 {
    v128_or(i32x4_shl(x, n), u32x4_shr(x, 32 - n))
}

const K0: u32 = 0x9E37_79B1;
const K1: u32 = 0x85EB_CA77;

/// One ARX-multiply round over the 256-bit state (s0, s1), absorbing (a, b).
#[inline(always)]
fn mix_round(a: v128, b: v128, s0: &mut v128, s1: &mut v128) {
    *s0 = i32x4_mul(rotl(v128_xor(*s0, a), 11), u32x4_splat(K0));
    *s1 = i32x4_mul(rotl(v128_xor(*s1, b), 17), u32x4_splat(K1));
    // Cross the halves so every word depends on every other word.
    *s0 = i32x4_add(*s0, i32x4_shuffle::<1, 2, 3, 0>(*s1, *s1));
    *s1 = v128_xor(*s1, i32x4_shuffle::<2, 3, 0, 1>(*s0, *s0));
}

/// Order-dependent fold of one lane's memory into 32 bytes. Not a
/// cryptographic hash (the final SHA-256 handles that); it only needs every
/// input byte to affect the output and to be impossible to update
/// incrementally from the end.
pub fn fold_lane(mem: &[u8]) -> [u8; 32] {
    assert!(mem.len() % 32 == 0);
    let mut s0 = u32x4(0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A);
    let mut s1 = u32x4(0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19);
    for c in mem.chunks_exact(32) {
        // SAFETY: the chunk is exactly 32 bytes; v128_load has no alignment requirement.
        let (a, b) = unsafe {
            (
                v128_load(c.as_ptr() as *const v128),
                v128_load(c[16..].as_ptr() as *const v128),
            )
        };
        mix_round(a, b, &mut s0, &mut s1);
    }
    let len = u32x4_splat(mem.len() as u32);
    for _ in 0..4 {
        mix_round(len, len, &mut s0, &mut s1);
    }
    let mut out = [0u8; 32];
    // SAFETY: out is 32 bytes; v128_store has no alignment requirement.
    unsafe {
        v128_store(out.as_mut_ptr() as *mut v128, s0);
        v128_store(out[16..].as_mut_ptr() as *mut v128, s1);
    }
    out
}

/// Expand a 32-byte key into `out` (a multiple of 32 bytes). Sequential by
/// construction: byte N can't be produced without producing everything
/// before it.
pub fn fill_lane(key: &[u8; 32], out: &mut [u8]) {
    assert!(out.len() % 32 == 0);
    // SAFETY: key is 32 bytes; v128_load has no alignment requirement.
    let (mut s0, mut s1) = unsafe {
        (
            v128_load(key.as_ptr() as *const v128),
            v128_load(key[16..].as_ptr() as *const v128),
        )
    };
    let mut ctr = u32x4(0, 1, 2, 3);
    for c in out.chunks_exact_mut(32) {
        mix_round(ctr, rotl(ctr, 16), &mut s0, &mut s1);
        // SAFETY: the chunk is exactly 32 bytes.
        unsafe {
            v128_store(c.as_mut_ptr() as *mut v128, s0);
            v128_store(c[16..].as_mut_ptr() as *mut v128, s1);
        }
        ctr = i32x4_add(ctr, u32x4_splat(4));
    }
}

/// First byte `fill` writes: below it live the challenge, nonce and hash block.
pub const ARENA_START: usize = 128;

/// Population count in all four lanes: WASM SIMD only has a per-byte popcnt,
/// so count bytes, then sum adjacent pairs twice (u8 -> u16 -> u32).
pub fn popcnt32x4(x: v128) -> v128 {
    i32x4_extadd_pairwise_u16x8(i16x8_extadd_pairwise_u8x16(i8x16_popcnt(x)))
}

/// WASM leaves NaN payloads from SIMD float ops nondeterministic. A puzzle has
/// to be bit-exact between client and server, so every NaN becomes 0x7FC00000.
fn canon(v: v128) -> v128 {
    v128_bitselect(v, u32x4_splat(0x7FC0_0000), f32x4_eq(v, v))
}

enum Write {
    None,
    R(usize, v128),
    F(usize, v128),
    P(usize, v128),
    St(v128, v128),
    Sha(v128, [[u8; 32]; LANES]),
    Fill([[u8; 32]; LANES], [usize; LANES]),
}

pub struct Vm {
    pub r: [v128; 16],
    pub f: [v128; 4],
    pub p: [v128; 16],
    /// Lane-major: lane L owns `mem[L * MEM_SIZE..][..MEM_SIZE]`.
    pub mem: Vec<u8>,
    pub pc: u32,
    pub fuel: u64,
    pub halted: bool,
}

impl Vm {
    /// Fresh machine: every lane gets a copy of `image`, and `r15` holds
    /// `nonce_base + lane`.
    pub fn new(image: &[u8], nonce_base: u32, fuel: u64) -> Self {
        assert!(image.len() <= MEM_SIZE);
        let mut mem = vec![0u8; LANES * MEM_SIZE];
        for lane in mem.chunks_exact_mut(MEM_SIZE) {
            lane[..image.len()].copy_from_slice(image);
        }
        let mut r = [u32x4_splat(0); 16];
        r[NONCE_REG] = from_lanes(core::array::from_fn(|l| nonce_base.wrapping_add(l as u32)));
        let mut p = [u32x4_splat(0); 16];
        p[0] = u32x4_splat(!0);
        Vm {
            r,
            f: [f32x4_splat(0.0); 4],
            p,
            mem,
            pc: 0,
            fuel,
            halted: false,
        }
    }

    fn guard(&self, g: u8) -> v128 {
        let m = self.p[(g & 15) as usize];
        if g & 0x10 != 0 {
            v128_not(m)
        } else {
            m
        }
    }

    /// Control flow must agree across lanes: all true, or all false.
    fn uniform(&self, cond: v128) -> Result<bool, Error> {
        if i32x4_all_true(cond) {
            Ok(true)
        } else if !v128_any_true(cond) {
            Ok(false)
        } else {
            Err(Error::DivergentControl { pc: self.pc })
        }
    }

    // WASM SIMD has no gather, so per-lane addresses mean four scalar loads.
    fn load32(&self, addr: v128) -> v128 {
        let a = lanes(addr);
        from_lanes(core::array::from_fn(|l| {
            let o = l * MEM_SIZE + (a[l] as usize & 0xFFFC);
            u32::from_le_bytes(self.mem[o..o + 4].try_into().unwrap())
        }))
    }

    fn fold(&self, len_mask: v128) -> [[u8; 32]; LANES] {
        let m = lanes(len_mask);
        core::array::from_fn(|l| {
            let len = (((m[l] & 0xFFFF) + 1) & !31).max(32) as usize;
            fold_lane(&self.mem[l * MEM_SIZE..][..len])
        })
    }

    fn sha(&self, src: v128) -> [[u8; 32]; LANES] {
        let a = lanes(src);
        let blocks: [&[u8; 64]; LANES] = core::array::from_fn(|l| {
            let o = l * MEM_SIZE + (a[l] as usize & 0xFFC0);
            self.mem[o..o + 64].try_into().unwrap()
        });
        sha4::sha256x4(blocks)
    }

    fn store(&mut self, addr: v128, mask: v128, align: u32, bytes: impl Fn(usize) -> Vec<u8>) {
        let (a, m) = (lanes(addr), lanes(mask));
        for l in 0..LANES {
            if m[l] != 0 {
                let data = bytes(l);
                let o = l * MEM_SIZE + (a[l] & (0xFFFF & !(align - 1))) as usize;
                self.mem[o..o + data.len()].copy_from_slice(&data);
            }
        }
    }

    /// Execute one bundle.
    pub fn step(&mut self, prog: &Program) -> Result<(), Error> {
        use Op::*;
        let bundle = *prog
            .bundles()
            .get(self.pc as usize)
            .ok_or(Error::PcOutOfRange(self.pc))?;
        self.fuel = self.fuel.checked_sub(1).ok_or(Error::OutOfFuel)?;

        let zero = i32x4_splat(0);
        let mut next_pc = self.pc.wrapping_add(1);
        let mut halt = false;
        let mut writes: [(v128, Write); SLOTS] = core::array::from_fn(|_| (zero, Write::None));

        // Phase 1: every slot reads pre-bundle state.
        for (i, s) in bundle.iter().enumerate() {
            let mask = self.guard(s.guard);
            let (d, a, b) = (s.d as usize, s.a as usize, s.b as usize);
            let (ra, rb) = (self.r[a], self.r[b]);
            let (fa, fb) = (self.f[a & 3], self.f[b & 3]);
            let (pa, pb) = (self.p[a], self.p[b]);
            let imm = i32x4_splat(s.imm);
            let sh = s.imm as u32 & 31;
            let w = match s.op {
                Nop => Write::None,
                Halt => {
                    halt = self.uniform(mask)?;
                    Write::None
                }
                Li => Write::R(d, imm),
                Addi => Write::R(d, i32x4_add(ra, imm)),
                Add => Write::R(d, i32x4_add(ra, rb)),
                Sub => Write::R(d, i32x4_sub(ra, rb)),
                Mul => Write::R(d, i32x4_mul(ra, rb)),
                Xor => Write::R(d, v128_xor(ra, rb)),
                And => Write::R(d, v128_and(ra, rb)),
                Or => Write::R(d, v128_or(ra, rb)),
                Shl => Write::R(d, i32x4_shl(ra, sh)),
                Shr => Write::R(d, u32x4_shr(ra, sh)),
                // Shift counts are taken mod 32, so sh = 0 gives ra | ra = ra.
                Rotr => Write::R(d, v128_or(u32x4_shr(ra, sh), i32x4_shl(ra, 32 - sh))),
                Clz => Write::R(d, clz32x4(ra)),
                Ld => Write::R(d, self.load32(i32x4_add(ra, imm))),
                St => Write::St(i32x4_add(ra, imm), rb),
                Sha256 => Write::Sha(rb, self.sha(ra)),
                CmpEq => Write::P(d, i32x4_eq(ra, rb)),
                CmpLt => Write::P(d, i32x4_lt(ra, rb)),
                CmpLtu => Write::P(d, u32x4_lt(ra, rb)),
                PAnd => Write::P(d, v128_and(pa, pb)),
                POr => Write::P(d, v128_or(pa, pb)),
                PXor => Write::P(d, v128_xor(pa, pb)),
                PNot => Write::P(d, v128_not(pa)),
                FCvt => Write::F(d & 3, f32x4_convert_i32x4(ra)),
                FAdd => Write::F(d & 3, canon(f32x4_add(fa, fb))),
                FSub => Write::F(d & 3, canon(f32x4_sub(fa, fb))),
                FMul => Write::F(d & 3, canon(f32x4_mul(fa, fb))),
                FDiv => Write::F(d & 3, canon(f32x4_div(fa, fb))),
                FSqrt => Write::F(d & 3, canon(f32x4_sqrt(fa))),
                FLt => Write::P(d, f32x4_lt(fa, fb)),
                FTrunc => Write::R(d, i32x4_trunc_sat_f32x4(fa)),
                Subleq => {
                    let nb = i32x4_sub(rb, ra);
                    if self.uniform(v128_and(mask, i32x4_le(nb, zero)))? {
                        next_pc = s.imm as u32;
                    }
                    Write::R(b, nb)
                }
                Bp => {
                    if self.uniform(v128_and(mask, pa))? {
                        next_pc = s.imm as u32;
                    }
                    Write::None
                }
                PAny => Write::P(
                    d,
                    if v128_any_true(pa) {
                        u32x4_splat(!0)
                    } else {
                        zero
                    },
                ),
                Bswap => Write::R(
                    d,
                    i8x16_swizzle(
                        ra,
                        i8x16(3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12),
                    ),
                ),
                Popcnt => Write::R(d, popcnt32x4(ra)),
                FBits => Write::R(d, fa),
                FFrom => Write::F(d & 3, ra),
                Mulhu => Write::R(
                    d,
                    i32x4_shuffle::<1, 3, 5, 7>(
                        u64x2_extmul_low_u32x4(ra, rb),
                        u64x2_extmul_high_u32x4(ra, rb),
                    ),
                ),
                // Predicates are always all-ones or all-zero per lane.
                PMov => Write::R(d, pa),
                Fold => Write::Sha(rb, self.fold(ra)),
                Fill => {
                    let (m, k) = (lanes(ra), lanes(rb));
                    Write::Fill(
                        core::array::from_fn(|l| {
                            let o = l * MEM_SIZE + (k[l] as usize & 0xFFE0);
                            self.mem[o..o + 32].try_into().unwrap()
                        }),
                        core::array::from_fn(|l| (((m[l] & 0xFFFF) + 1) & !31) as usize),
                    )
                }
            };
            writes[i] = (mask, w);
        }

        // Phase 2: commit in slot order, only in lanes the guard allows.
        for (mask, w) in writes {
            match w {
                Write::None => {}
                Write::R(d, v) => self.r[d] = v128_bitselect(v, self.r[d], mask),
                Write::F(d, v) => self.f[d] = v128_bitselect(v, self.f[d], mask),
                Write::P(0, _) => {} // p0 is hardwired true
                Write::P(d, v) => self.p[d] = v128_bitselect(v, self.p[d], mask),
                Write::St(addr, v) => {
                    let v = lanes(v);
                    self.store(addr, mask, 4, |l| v[l].to_le_bytes().to_vec());
                }
                Write::Sha(addr, digests) => self.store(addr, mask, 32, |l| digests[l].to_vec()),
                Write::Fill(keys, lens) => {
                    let m = lanes(mask);
                    for l in 0..LANES {
                        if m[l] != 0 && lens[l] > ARENA_START {
                            fill_lane(
                                &keys[l],
                                &mut self.mem[l * MEM_SIZE..][ARENA_START..lens[l]],
                            );
                        }
                    }
                }
            }
        }

        self.pc = next_pc;
        self.halted = halt;
        Ok(())
    }

    pub fn run(&mut self, prog: &Program) -> Result<(), Error> {
        while !self.halted {
            self.step(prog)?;
        }
        Ok(())
    }
}

/// Run one batch of LANES nonces. `nonce_base` must be a multiple of LANES so
/// client and server always group nonces identically, which keeps traps
/// (divergence, fuel) reproducible. Returns which lanes solved the puzzle.
pub fn attempt(
    prog: &Program,
    image: &[u8],
    nonce_base: u32,
    fuel: u64,
) -> Result<[bool; LANES], Error> {
    assert_eq!(
        nonce_base % LANES as u32,
        0,
        "nonce_base must be lane-aligned"
    );
    let mut vm = Vm::new(image, nonce_base, fuel);
    vm.run(prog)?;
    Ok(lanes(vm.p[RESULT_PRED]).map(|x| x != 0))
}

/// Client side: search batches until a lane solves. Trapping batches are skipped.
pub fn solve(prog: &Program, image: &[u8], fuel: u64, max_batches: u32) -> Option<u32> {
    (0..max_batches).find_map(|batch| {
        let base = batch * LANES as u32;
        let solved = attempt(prog, image, base, fuel).ok()?;
        solved.iter().position(|&s| s).map(|l| base + l as u32)
    })
}

/// Server side: rerun the nonce's batch and check its lane.
pub fn verify(prog: &Program, image: &[u8], nonce: u32, fuel: u64) -> bool {
    let lane = nonce as usize % LANES;
    attempt(prog, image, nonce - lane as u32, fuel).is_ok_and(|s| s[lane])
}

#[cfg(test)]
mod tests;
