//! 4-way multi-buffer SHA-256: lane L of every v128 belongs to message L.
//! SHA-256 is all 32-bit add/xor/rotate, so it maps 1:1 onto i32x4.

use core::arch::wasm32::*;

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[inline(always)]
fn rotr(x: v128, n: u32) -> v128 {
    v128_or(u32x4_shr(x, n), i32x4_shl(x, 32 - n))
}

#[inline(always)]
fn xor3(a: v128, b: v128, c: v128) -> v128 {
    v128_xor(v128_xor(a, b), c)
}

fn compress4(s: &mut [v128; 8], block: &[v128; 16]) {
    let mut w = [u32x4_splat(0); 64];
    w[..16].copy_from_slice(block);
    for t in 16..64 {
        let s0 = xor3(
            rotr(w[t - 15], 7),
            rotr(w[t - 15], 18),
            u32x4_shr(w[t - 15], 3),
        );
        let s1 = xor3(
            rotr(w[t - 2], 17),
            rotr(w[t - 2], 19),
            u32x4_shr(w[t - 2], 10),
        );
        w[t] = i32x4_add(i32x4_add(w[t - 16], s0), i32x4_add(w[t - 7], s1));
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *s;
    for t in 0..64 {
        let s1 = xor3(rotr(e, 6), rotr(e, 11), rotr(e, 25));
        let ch = v128_xor(v128_and(e, f), v128_andnot(g, e)); // (e & f) ^ (!e & g)
        let t1 = i32x4_add(
            i32x4_add(h, s1),
            i32x4_add(ch, i32x4_add(u32x4_splat(K[t]), w[t])),
        );
        let s0 = xor3(rotr(a, 2), rotr(a, 13), rotr(a, 22));
        let maj = xor3(v128_and(a, b), v128_and(a, c), v128_and(b, c));
        let t2 = i32x4_add(s0, maj);
        h = g;
        g = f;
        f = e;
        e = i32x4_add(d, t1);
        d = c;
        c = b;
        b = a;
        a = i32x4_add(t1, t2);
    }
    for (x, y) in s.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *x = i32x4_add(*x, y);
    }
}

/// SHA-256 of four independent 64-byte messages at once.
pub fn sha256x4(msgs: [&[u8; 64]; 4]) -> [[u8; 32]; 4] {
    // Transpose: word i of every message goes into one v128 (big-endian words, per the spec).
    let mut block = [u32x4_splat(0); 16];
    for (i, w) in block.iter_mut().enumerate() {
        let word = |m: &[u8; 64]| u32::from_be_bytes(m[4 * i..4 * i + 4].try_into().unwrap());
        *w = u32x4(word(msgs[0]), word(msgs[1]), word(msgs[2]), word(msgs[3]));
    }
    let mut state = IV.map(|x| u32x4_splat(x));
    compress4(&mut state, &block);

    // A 64-byte message always has the same padding block: 0x80, zeros, bit length 512.
    let mut pad = [u32x4_splat(0); 16];
    pad[0] = u32x4_splat(0x8000_0000);
    pad[15] = u32x4_splat(512);
    compress4(&mut state, &pad);

    let mut out = [[0u8; 32]; 4];
    for (i, w) in state.iter().enumerate() {
        let w = crate::lanes(*w);
        for (lane, digest) in out.iter_mut().enumerate() {
            digest[4 * i..4 * i + 4].copy_from_slice(&w[lane].to_be_bytes());
        }
    }
    out
}
