//! The interpreter as it was before roadmap item 9, frozen as a reference.
//! `interpreter_matches_reference` steps it alongside `Vm::step` bundle by
//! bundle, so optimizations to the real interpreter can't change semantics.

use super::*;

enum Write {
    None,
    R(usize, v128),
    F(usize, v128),
    P(usize, v128),
    St(v128, v128),
    Sha(v128, [[u8; 32]; LANES]),
    Fill([[u8; 32]; LANES], [usize; LANES]),
}

fn guard(vm: &Vm, g: u8) -> v128 {
    let m = vm.p[(g & 15) as usize];
    if g & 0x10 != 0 {
        v128_not(m)
    } else {
        m
    }
}

/// Control flow must agree across lanes: all true, or all false.
fn uniform(vm: &Vm, cond: v128) -> Result<bool, Error> {
    if i32x4_all_true(cond) {
        Ok(true)
    } else if !v128_any_true(cond) {
        Ok(false)
    } else {
        Err(Error::DivergentControl { pc: vm.pc })
    }
}

// WASM SIMD has no gather, so per-lane addresses mean four scalar loads.
fn load32(vm: &Vm, addr: v128) -> v128 {
    let a = lanes(addr);
    from_lanes(core::array::from_fn(|l| {
        let o = l * MEM_SIZE + (a[l] & ADDR & !3) as usize;
        u32::from_le_bytes(vm.mem[o..o + 4].try_into().unwrap())
    }))
}

fn fold(vm: &Vm, len_mask: v128) -> [[u8; 32]; LANES] {
    let m = lanes(len_mask);
    core::array::from_fn(|l| {
        let len = (((m[l] & ADDR) + 1) & !31).max(32) as usize;
        fold_lane(&vm.mem[l * MEM_SIZE..][..len])
    })
}

fn sha(vm: &Vm, src: v128) -> [[u8; 32]; LANES] {
    let a = lanes(src);
    let blocks: [&[u8; 64]; LANES] = core::array::from_fn(|l| {
        let o = l * MEM_SIZE + (a[l] & ADDR & !63) as usize;
        vm.mem[o..o + 64].try_into().unwrap()
    });
    sha4::sha256x4(blocks)
}

fn store(vm: &mut Vm, addr: v128, mask: v128, align: u32, bytes: impl Fn(usize) -> Vec<u8>) {
    let (a, m) = (lanes(addr), lanes(mask));
    for l in 0..LANES {
        if m[l] != 0 {
            let data = bytes(l);
            let o = (a[l] & ADDR & !(align - 1)) as usize;
            vm.mem[l * MEM_SIZE + o..][..data.len()].copy_from_slice(&data);
            vm.dirty = vm.dirty.max(o + data.len());
        }
    }
}

/// Execute one bundle.
pub(crate) fn step(vm: &mut Vm, prog: &Program) -> Result<(), Error> {
    use Op::*;
    let bundle = *prog
        .bundles()
        .get(vm.pc as usize)
        .ok_or(Error::PcOutOfRange(vm.pc))?;
    vm.fuel = vm.fuel.checked_sub(1).ok_or(Error::OutOfFuel)?;

    let zero = i32x4_splat(0);
    let mut next_pc = vm.pc.wrapping_add(1);
    let mut halt = false;
    let mut writes: [(v128, Write); SLOTS] = core::array::from_fn(|_| (zero, Write::None));

    // Phase 1: every slot reads pre-bundle state.
    for (i, s) in bundle.iter().enumerate() {
        let mask = guard(vm, s.guard);
        let (d, a, b) = (s.d as usize, s.a as usize, s.b as usize);
        let (ra, rb) = (vm.r[a], vm.r[b]);
        let (fa, fb) = (vm.f[a & 3], vm.f[b & 3]);
        let (pa, pb) = (vm.p[a], vm.p[b]);
        let imm = i32x4_splat(s.imm);
        let sh = s.imm as u32 & 31;
        let w = match s.op {
            Nop => Write::None,
            Halt => {
                halt = uniform(vm, mask)?;
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
            Ld => Write::R(d, load32(vm, i32x4_add(ra, imm))),
            St => Write::St(i32x4_add(ra, imm), rb),
            Sha256 => Write::Sha(rb, sha(vm, ra)),
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
                if uniform(vm, v128_and(mask, i32x4_le(nb, zero)))? {
                    next_pc = s.imm as u32;
                }
                Write::R(b, nb)
            }
            Bp => {
                if uniform(vm, v128_and(mask, pa))? {
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
            Fold => Write::Sha(rb, fold(vm, ra)),
            Fill => {
                let (m, k) = (lanes(ra), lanes(rb));
                Write::Fill(
                    core::array::from_fn(|l| {
                        let o = l * MEM_SIZE + (k[l] & ADDR & !31) as usize;
                        vm.mem[o..o + 32].try_into().unwrap()
                    }),
                    core::array::from_fn(|l| (((m[l] & ADDR) + 1) & !31) as usize),
                )
            }
        };
        writes[i] = (mask, w);
    }

    // Phase 2: commit in slot order, only in lanes the guard allows.
    for (mask, w) in writes {
        match w {
            Write::None => {}
            Write::R(d, v) => vm.r[d] = v128_bitselect(v, vm.r[d], mask),
            Write::F(d, v) => vm.f[d] = v128_bitselect(v, vm.f[d], mask),
            Write::P(0, _) => {} // p0 is hardwired true
            Write::P(d, v) => vm.p[d] = v128_bitselect(v, vm.p[d], mask),
            Write::St(addr, v) => {
                let v = lanes(v);
                store(vm, addr, mask, 4, |l| v[l].to_le_bytes().to_vec());
            }
            Write::Sha(addr, digests) => store(vm, addr, mask, 32, |l| digests[l].to_vec()),
            Write::Fill(keys, lens) => {
                let m = lanes(mask);
                for l in 0..LANES {
                    if m[l] != 0 && lens[l] > ARENA_START {
                        fill_lane(&keys[l], &mut vm.mem[l * MEM_SIZE..][ARENA_START..lens[l]]);
                        vm.dirty = vm.dirty.max(lens[l]);
                    }
                }
            }
        }
    }

    vm.pc = next_pc;
    vm.halted = halt;
    Ok(())
}
