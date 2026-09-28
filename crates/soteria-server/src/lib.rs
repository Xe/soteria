//! Server module: verifies client proofs, and nothing else. Build with
//!
//! ```sh
//! cargo build --release -p soteria-server --target wasm32-unknown-unknown
//! ```
//!
//! for a core module with no imports, suitable for wazero. Requests use the
//! layout in `soteria::wire`; both verify calls free the request buffer, so a
//! pooled instance doesn't leak.

#![cfg(target_arch = "wasm32")]

use soteria::gadgets::Challenge;
use soteria::wire::{self, parse};
pub use soteria::wire::{ERR_LENGTH, ERR_PARAMS};

/// A zeroed buffer of `len` bytes for the host to fill.
#[no_mangle]
pub extern "C" fn soteria_alloc(len: usize) -> *mut u8 {
    wire::alloc(len)
}

/// Threshold mode: 1 if the nonces solve the challenge, 0 if not, or a
/// negative `ERR_*`. Frees the buffer.
///
/// # Safety
/// `ptr` and `len` must come from one `soteria_alloc` call, used once.
#[no_mangle]
pub unsafe extern "C" fn soteria_verify(ptr: *mut u8, len: usize) -> i32 {
    match parse(&wire::take(ptr, len)) {
        Ok(r) => Challenge::new(r.seed, r.params).verify(&r.challenge, &r.nonces) as i32,
        Err(e) => e,
    }
}

/// Best-effort mode: estimated attempts (see `soteria::best`), 0 if the
/// nonces are rejected, or a negative `ERR_*`. Frees the buffer.
///
/// # Safety
/// `ptr` and `len` must come from one `soteria_alloc` call, used once.
#[no_mangle]
pub unsafe extern "C" fn soteria_verify_best(ptr: *mut u8, len: usize) -> f64 {
    match parse(&wire::take(ptr, len)) {
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
    use soteria::gadgets::{Challenge, Mix, Params};
    use soteria::wire::{request, HEADER, MAX_GADGETS, MAX_SOLUTIONS};

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
            Params { block: 1, ..ok },
            Params { block: 32, ..ok },
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
