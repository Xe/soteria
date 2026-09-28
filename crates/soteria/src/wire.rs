//! Request format shared by the client and server modules (`soteria-client`,
//! `soteria-server`). The host calls `soteria_alloc(len)`, writes a request
//! into the buffer, and passes it to an export, which frees it. All integers
//! are little-endian:
//!
//! ```text
//!  0  seed        u64
//!  8  gadgets     u32   <= MAX_GADGETS
//! 12  mix         u32 x 6: alu, taps, float, memory, lanes, sha (each <= 65536, sum > 0)
//! 36  scratchpad  u32   power of two in 256..=65536
//! 40  threshold   u32   > 0
//! 44  solutions   u32   1..=MAX_SOLUTIONS
//! 48  flags       u32   bit 0 chained, bit 1 fold, bit 2 fill,
//!                         bits 8..16 block (0 or 2..=31)
//! 52  challenge   [u8; 32]
//! 84  nonces      u32 x n, the rest of the buffer
//! ```
//!
//! Solver requests carry no nonces. Params are validated here so bad input
//! comes back as an error code instead of a trap.

use crate::gadgets::{Mix, Params};
use crate::MEM_SIZE;

pub const HEADER: usize = 84;
pub const MAX_GADGETS: u32 = 4096;
pub const MAX_SOLUTIONS: u32 = 256;
const MAX_WEIGHT: u32 = 1 << 16;

/// Buffer shorter than the header, or nonces not a whole number of u32s.
pub const ERR_LENGTH: i32 = -1;
/// Params out of range or unknown flag bits.
pub const ERR_PARAMS: i32 = -2;

/// A parsed, validated request.
pub struct Request {
    pub seed: u64,
    pub params: Params,
    pub challenge: [u8; 32],
    pub nonces: Vec<u32>,
}

/// Parse and validate a request. Errors are `ERR_LENGTH` or `ERR_PARAMS`.
pub fn parse(buf: &[u8]) -> Result<Request, i32> {
    if buf.len() < HEADER || (buf.len() - HEADER) % 4 != 0 {
        return Err(ERR_LENGTH);
    }
    let u = |i: usize| u32::from_le_bytes(buf[i..i + 4].try_into().unwrap());
    let w = [u(12), u(16), u(20), u(24), u(28), u(32)];
    let (gadgets, scratchpad, threshold, solutions, flags) = (u(8), u(36), u(40), u(44), u(48));
    let ok = gadgets <= MAX_GADGETS
        && w.iter().all(|&x| x <= MAX_WEIGHT)
        && w.iter().sum::<u32>() > 0
        && scratchpad.is_power_of_two()
        && (256..=MEM_SIZE as u32).contains(&scratchpad)
        && threshold > 0
        && (1..=MAX_SOLUTIONS).contains(&solutions)
        && flags & !0xFF07 == 0
        && matches!(flags >> 8, 0 | 2..=31);
    if !ok {
        return Err(ERR_PARAMS);
    }
    let [alu, taps, float, memory, lanes, sha] = w;
    Ok(Request {
        seed: u64::from_le_bytes(buf[..8].try_into().unwrap()),
        params: Params {
            gadgets: gadgets as usize,
            mix: Mix {
                alu,
                taps,
                float,
                memory,
                lanes,
                sha,
            },
            scratchpad,
            threshold,
            solutions,
            chained: flags & 1 != 0,
            fold: flags & 2 != 0,
            fill: flags & 4 != 0,
            block: flags >> 8,
        },
        challenge: buf[52..84].try_into().unwrap(),
        nonces: buf[HEADER..]
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect(),
    })
}

/// Encode a request. The reference for the layout above; hosts write the
/// same bytes themselves.
pub fn request(seed: u64, p: &Params, challenge: &[u8; 32], nonces: &[u32]) -> Vec<u8> {
    let m = p.mix;
    let flags = p.chained as u32 | (p.fold as u32) << 1 | (p.fill as u32) << 2 | p.block << 8;
    let mut b = seed.to_le_bytes().to_vec();
    for x in [
        p.gadgets as u32,
        m.alu,
        m.taps,
        m.float,
        m.memory,
        m.lanes,
        m.sha,
    ] {
        b.extend(x.to_le_bytes());
    }
    for x in [p.scratchpad, p.threshold, p.solutions, flags] {
        b.extend(x.to_le_bytes());
    }
    b.extend(challenge);
    for n in nonces {
        b.extend(n.to_le_bytes());
    }
    b
}

/// A zeroed buffer of `len` bytes for the host to fill. Backs each module's
/// `soteria_alloc` export.
pub fn alloc(len: usize) -> *mut u8 {
    Box::into_raw(vec![0u8; len].into_boxed_slice()) as *mut u8
}

/// Take back a buffer from `alloc`.
///
/// # Safety
/// `ptr` and `len` must come from one `alloc` call, used once.
pub unsafe fn take(ptr: *mut u8, len: usize) -> Box<[u8]> {
    Box::from_raw(core::ptr::slice_from_raw_parts_mut(ptr, len))
}
