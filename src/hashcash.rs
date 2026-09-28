//! Hashcash on the VLIW VM: find the smallest nonce such that
//! sha256(challenge[32] || nonce_le[4] || zeros[28]) starts with
//! `difficulty` zero bits (1..=32).
//!
//! Lane L tries nonces base+L, base+L+4, base+L+8, ... and the loop exits as
//! soon as any lane hits, so the first hit in the lowest lane is the globally
//! smallest nonce. Verification needs no VM: it's one native SHA-256.
//!
//! Registers: r1 digest word, r3 byteswapped word,
//! r10 = difficulty - 1, r11 = found nonce, r12 = 64 (digest address),
//! r14 = iterations left, r15 = current nonce.
//! Predicates: p3 = iterations remain, p7 = some lane solved, p15 = solved.

use crate::{bundle, lanes, sha4, Op::*, Program, Slot, Vm, LANES};

const DONE: i32 = 10;
const LOOP: i32 = 1;

pub fn program(difficulty: u32, iterations: u32) -> Program {
    assert!((1..=32).contains(&difficulty) && iterations >= 1);
    let s = Slot::new;
    Program::new(vec![
        /*  0 */ bundle(&[s(Li, 12, 0, 0, 64), s(Li, 14, 0, 0, iterations as i32), s(Li, 10, 0, 0, difficulty as i32 - 1)]),
        // LOOP: write the nonce after the challenge, hash the 64-byte block.
        /*  1 */ bundle(&[s(St, 0, 0, 15, 32), s(Addi, 14, 14, 0, -1)]),
        /*  2 */ bundle(&[s(Sha256, 0, 0, 12, 0)]),
        /*  3 */ bundle(&[s(Ld, 1, 12, 0, 0)]),
        // Loads are little-endian but the digest is big-endian.
        /*  4 */ bundle(&[s(Bswap, 3, 1, 0, 0)]),
        /*  5 */ bundle(&[s(Clz, 3, 3, 0, 0)]),
        // p15 = difficulty-1 < clz, i.e. clz >= difficulty. p3 = iterations remain.
        /*  6 */ bundle(&[s(CmpLtu, 15, 10, 3, 0), s(CmpLt, 3, 0, 14, 0)]),
        // Latch the nonce where solved, advance every lane, reduce across lanes.
        // All three read r15/p15 from before this bundle.
        /*  7 */ bundle(&[s(Addi, 11, 15, 0, 0).when(15), s(Addi, 15, 15, 0, LANES as i32), s(PAny, 7, 15, 0, 0)]),
        /*  8 */ bundle(&[s(Bp, 0, 7, 0, DONE)]),
        /*  9 */ bundle(&[s(Bp, 0, 3, 0, LOOP)]),
        /* 10 */ bundle(&[s(Halt, 0, 0, 0, 0)]),
    ])
    .unwrap()
}

/// Upper bound on bundles executed: prologue + 9 per iteration + halt.
pub fn fuel(iterations: u32) -> u64 {
    2 + 9 * iterations as u64
}

/// Client: run the VM in chunks of `iterations` rounds until a lane solves.
pub fn search(challenge: &[u8; 32], difficulty: u32, iterations: u32, max_runs: u32) -> Option<u32> {
    let prog = program(difficulty, iterations);
    (0..max_runs).find_map(|run| {
        let base = run * iterations * LANES as u32;
        let mut vm = Vm::new(challenge, base, fuel(iterations));
        vm.run(&prog).ok()?;
        let (solved, nonce) = (lanes(vm.p[15]), lanes(vm.r[11]));
        solved.iter().position(|&x| x != 0).map(|l| nonce[l])
    })
}

/// Server: one hash, no VM.
pub fn verify(challenge: &[u8; 32], nonce: u32, difficulty: u32) -> bool {
    let mut block = [0u8; 64];
    block[..32].copy_from_slice(challenge);
    block[32..36].copy_from_slice(&nonce.to_le_bytes());
    let digest = sha4::sha256x4([&block; 4])[0];
    u32::from_be_bytes(digest[..4].try_into().unwrap()).leading_zeros() >= difficulty
}
