//! C ABI for hosts that run core WASM modules, such as wazero. Build with
//!
//! ```sh
//! cargo build --release -p soteria-ffi --target wasm32-unknown-unknown
//! ```
//!
//! The host calls `soteria_alloc(len)`, writes a request into the returned
//! buffer, and passes it to `soteria_verify` or `soteria_verify_best`, which
//! free it. Request layout, all integers little-endian:
//!
//! ```text
//!  0  seed        u64
//!  8  gadgets     u32   <= MAX_GADGETS
//! 12  mix         u32 x 6: alu, taps, float, memory, lanes, sha (each <= 65536, sum > 0)
//! 36  scratchpad  u32   power of two in 256..=65536
//! 40  threshold   u32   > 0
//! 44  solutions   u32   1..=MAX_SOLUTIONS
//! 48  flags       u32   bit 0 chained, bit 1 fold, bit 2 fill
//! 52  challenge   [u8; 32]
//! 84  nonces      u32 x n, the rest of the buffer
//! ```

#![cfg(target_arch = "wasm32")]

use soteria::gadgets::{Challenge, Mix, Params};
use soteria::MEM_SIZE;

pub const HEADER: usize = 84;
pub const MAX_GADGETS: u32 = 4096;
pub const MAX_SOLUTIONS: u32 = 256;
const MAX_WEIGHT: u32 = 1 << 16;

/// Buffer shorter than the header, or nonces not a whole number of u32s.
pub const ERR_LENGTH: i32 = -1;
/// Params out of range or unknown flag bits.
pub const ERR_PARAMS: i32 = -2;

struct Request {
    seed: u64,
    params: Params,
    challenge: [u8; 32],
    nonces: Vec<u32>,
}

fn parse(buf: &[u8]) -> Result<Request, i32> {
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
        && flags & !7 == 0;
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
    let flags = p.chained as u32 | (p.fold as u32) << 1 | (p.fill as u32) << 2;
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

/// A zeroed buffer of `len` bytes for the host to fill.
#[no_mangle]
pub extern "C" fn soteria_alloc(len: usize) -> *mut u8 {
    Box::into_raw(vec![0u8; len].into_boxed_slice()) as *mut u8
}

/// # Safety
/// `ptr` and `len` must come from one `soteria_alloc` call, used once.
unsafe fn take(ptr: *mut u8, len: usize) -> Box<[u8]> {
    Box::from_raw(core::ptr::slice_from_raw_parts_mut(ptr, len))
}

/// Threshold mode: 1 if the nonces solve the challenge, 0 if not, or a
/// negative `ERR_*`. Frees the buffer.
///
/// # Safety
/// `ptr` and `len` must come from one `soteria_alloc` call, used once.
#[no_mangle]
pub unsafe extern "C" fn soteria_verify(ptr: *mut u8, len: usize) -> i32 {
    match parse(&take(ptr, len)) {
        Ok(r) => Challenge::new(r.seed, r.params).verify(&r.challenge, &r.nonces) as i32,
        Err(e) => e,
    }
}

/// Best-effort mode: estimated attempts (see `best.rs`), 0 if the nonces
/// are rejected, or a negative `ERR_*`. Frees the buffer.
///
/// # Safety
/// `ptr` and `len` must come from one `soteria_alloc` call, used once.
#[no_mangle]
pub unsafe extern "C" fn soteria_verify_best(ptr: *mut u8, len: usize) -> f64 {
    match parse(&take(ptr, len)) {
        Ok(r) => Challenge::new(r.seed, r.params)
            .verify_best(&r.challenge, &r.nonces)
            .unwrap_or(0.0),
        Err(e) => e as f64,
    }
}

/// This build's opcode numbering, to check against the client's.
#[no_mangle]
pub extern "C" fn soteria_fingerprint() -> u64 {
    soteria::opcodes::FINGERPRINT
}

#[cfg(test)]
mod tests {
    use super::*;
    use soteria::best::Best;

    /// Through the exported functions, as a host would call them.
    fn call<T>(req: &[u8], f: unsafe extern "C" fn(*mut u8, usize) -> T) -> T {
        let ptr = soteria_alloc(req.len());
        // SAFETY: ptr is a fresh req.len()-byte buffer, used once.
        unsafe {
            core::ptr::copy_nonoverlapping(req.as_ptr(), ptr, req.len());
            f(ptr, req.len())
        }
    }

    #[test]
    fn verify_through_abi() {
        let p = Params {
            threshold: 1 << 26,
            solutions: 2,
            ..Default::default()
        };
        let challenge = [4u8; 32];
        let nonces = Challenge::new(11, p).solve(&challenge, 10_000).unwrap();
        let req = request(11, &p, &challenge, &nonces);
        assert_eq!(call(&req, soteria_verify), 1);
        let bad = request(11, &p, &challenge, &[nonces[0], nonces[1] + 1]);
        assert_eq!(call(&bad, soteria_verify), 0);
        let other_seed = request(12, &p, &challenge, &nonces);
        assert_eq!(call(&other_seed, soteria_verify), 0);
    }

    #[test]
    fn verify_best_through_abi() {
        let p = Params {
            gadgets: 8,
            scratchpad: 256,
            ..Default::default()
        };
        let (c, challenge) = (Challenge::new(3, p), [6u8; 32]);
        let mut best = Best::new(16);
        c.search_best(&challenge, &mut best, 0..64);
        let req = request(3, &p, &challenge, &best.nonces());
        assert_eq!(Some(call(&req, soteria_verify_best)), best.estimate());
        let dup = request(3, &p, &challenge, &[1, 1]);
        assert_eq!(call(&dup, soteria_verify_best), 0.0);
    }

    /// Pins the byte layout the Go side writes.
    #[test]
    fn request_layout_is_stable() {
        let p = Params {
            gadgets: 3,
            threshold: 0x0102_0304,
            chained: true,
            ..Default::default()
        };
        let req = request(0x1122_3344_5566_7788, &p, &[0xAA; 32], &[5, 0xDEAD_BEEF]);
        let hex: String = req.iter().map(|b| format!("{b:02x}")).collect();
        let want = [
            "8877665544332211",                                   // seed
            "03000000",                                           // gadgets
            "08000000030000000200000003000000020000000100000000", // mix (+ first byte of scratchpad)
        ];
        assert!(hex.starts_with(&want.concat()), "{hex}");
        assert_eq!(req.len(), HEADER + 8);
        assert_eq!(
            &req[36..52],
            [0, 0x40, 0, 0, 4, 3, 2, 1, 1, 0, 0, 0, 7, 0, 0, 0]
        );
        assert_eq!(&req[52..84], [0xAA; 32]);
        assert_eq!(&req[84..], [5, 0, 0, 0, 0xEF, 0xBE, 0xAD, 0xDE]);
    }

    #[test]
    fn malformed_requests_are_errors_not_traps() {
        let ok = Params::default();
        let ch = [0u8; 32];
        assert_eq!(call(&[0u8; HEADER - 1], soteria_verify), ERR_LENGTH);
        let mut ragged = request(1, &ok, &ch, &[1]);
        ragged.pop();
        assert_eq!(call(&ragged, soteria_verify), ERR_LENGTH);
        let mut flags = request(1, &ok, &ch, &[1]);
        flags[48] |= 8;
        assert_eq!(call(&flags, soteria_verify), ERR_PARAMS);
        let zero_mix = Params {
            mix: Mix {
                alu: 0,
                taps: 0,
                float: 0,
                memory: 0,
                lanes: 0,
                sha: 0,
            },
            ..ok
        };
        let bad = [
            Params {
                scratchpad: 300,
                ..ok
            },
            Params {
                scratchpad: 128,
                ..ok
            },
            Params { threshold: 0, ..ok },
            Params { solutions: 0, ..ok },
            Params {
                solutions: MAX_SOLUTIONS + 1,
                ..ok
            },
            Params {
                gadgets: MAX_GADGETS as usize + 1,
                ..ok
            },
            zero_mix,
        ];
        for p in bad {
            let req = request(1, &p, &ch, &[1]);
            assert_eq!(call(&req, soteria_verify), ERR_PARAMS, "{p:?}");
            assert_eq!(call(&req, soteria_verify_best), ERR_PARAMS as f64, "{p:?}");
        }
        // Wrong nonce count is a failed proof, not a malformed request.
        assert_eq!(call(&request(1, &ok, &ch, &[]), soteria_verify), 0);
    }

    #[test]
    fn fingerprint_is_exported() {
        assert_eq!(soteria_fingerprint(), soteria::opcodes::FINGERPRINT);
    }
}
