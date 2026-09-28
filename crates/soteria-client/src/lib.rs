//! Client module: solves challenges, and nothing else. Build with
//!
//! ```sh
//! cargo build --release -p soteria-client --target wasm32-unknown-unknown
//! ```
//!
//! for a core module with no imports that a browser can instantiate
//! directly. A search can take seconds, so it runs in steps: start a job,
//! call `soteria_step` with a small batch count until it reports done or the
//! deadline passes, then read the nonces. Run it in a Web Worker; each
//! instance holds one job at a time.
//!
//! - `soteria_solve(ptr, len)`: threshold mode, find `params.solutions` nonces.
//! - `soteria_search(ptr, len, k)`: best-effort mode, keep the K lowest digests.
//!
//! Requests use the layout in `soteria::wire`, with no nonces; both start
//! calls free the request buffer.

#![cfg(target_arch = "wasm32")]

use soteria::best::{Best, MAX_BEST};
use soteria::gadgets::{Challenge, Progress, Solver, BATCHES};
use soteria::wire::{self, parse, Request};
use std::cell::RefCell;

pub use soteria::wire::{ERR_LENGTH, ERR_PARAMS};
/// `soteria_step` was called with no job started.
pub const ERR_NO_JOB: i32 = -3;
/// Threshold mode ran out of nonces before finding every solution.
pub const ERR_EXHAUSTED: i32 = -4;

enum Job {
    Solve(Challenge, Solver),
    Search(Challenge, [u8; 32], Best, u32),
}

struct State {
    job: Option<Job>,
    /// What `soteria_nonces` points at, refreshed after every step.
    nonces: Vec<u32>,
}

thread_local! {
    static STATE: RefCell<State> = const { RefCell::new(State { job: None, nonces: Vec::new() }) };
}

/// Parse a solver request: no nonces allowed.
unsafe fn start(ptr: *mut u8, len: usize) -> Result<(Challenge, Request), i32> {
    let r = parse(&wire::take(ptr, len))?;
    if !r.nonces.is_empty() {
        return Err(ERR_LENGTH);
    }
    Ok((Challenge::new(r.seed, r.params), r))
}

fn set(job: Option<Job>) {
    STATE.with_borrow_mut(|s| {
        s.job = job;
        s.nonces.clear();
    });
}

/// A zeroed buffer of `len` bytes for the host to fill.
#[no_mangle]
pub extern "C" fn soteria_alloc(len: usize) -> *mut u8 {
    wire::alloc(len)
}

/// Start a threshold-mode job, replacing any current one. 0 or a negative
/// `ERR_*`. Frees the buffer.
///
/// # Safety
/// `ptr` and `len` must come from one `soteria_alloc` call, used once.
#[no_mangle]
pub unsafe extern "C" fn soteria_solve(ptr: *mut u8, len: usize) -> i32 {
    match start(ptr, len) {
        Ok((c, r)) => {
            let solver = Solver::new(&c, &r.challenge);
            set(Some(Job::Solve(c, solver)));
            0
        }
        Err(e) => {
            set(None);
            e
        }
    }
}

/// Start a best-effort job keeping the `k` lowest digests (1..=32),
/// replacing any current one. 0 or a negative `ERR_*`. Frees the buffer.
///
/// # Safety
/// `ptr` and `len` must come from one `soteria_alloc` call, used once.
#[no_mangle]
pub unsafe extern "C" fn soteria_search(ptr: *mut u8, len: usize, k: u32) -> i32 {
    let started = start(ptr, len).and_then(|j| match (1..=MAX_BEST as u32).contains(&k) {
        true => Ok(j),
        false => Err(ERR_PARAMS),
    });
    match started {
        Ok((c, r)) => {
            set(Some(Job::Search(c, r.challenge, Best::new(k as usize), 0)));
            0
        }
        Err(e) => {
            set(None);
            e
        }
    }
}

/// Run up to `batches` batches (4 nonces each) of the current job. Returns 1
/// when there's nothing left to do (all solutions found, or the best-effort
/// search covered every nonce), 0 to keep going, or a negative `ERR_*`.
/// Best-effort jobs never finish on their own: stop at the deadline.
#[no_mangle]
pub extern "C" fn soteria_step(batches: u32) -> i32 {
    STATE.with_borrow_mut(|s| {
        let (code, nonces) = match s.job.as_mut() {
            None => return ERR_NO_JOB,
            Some(Job::Solve(c, solver)) => {
                let code = match solver.step(c, batches) {
                    Progress::Working => 0,
                    Progress::Done => 1,
                    Progress::Exhausted => ERR_EXHAUSTED,
                };
                (code, solver.nonces().to_vec())
            }
            Some(Job::Search(c, challenge, best, next)) => {
                let end = next.saturating_add(batches).min(BATCHES);
                c.search_best(challenge, best, *next..end);
                *next = end;
                ((end == BATCHES) as i32, best.nonces())
            }
        };
        s.nonces = nonces;
        code
    })
}

/// Pointer to the current nonces as little-endian u32s: solutions found so
/// far, or the K best so far. Valid until the next `soteria_*` call.
#[no_mangle]
pub extern "C" fn soteria_nonces() -> *const u32 {
    STATE.with_borrow(|s| s.nonces.as_ptr())
}

/// Number of u32s at `soteria_nonces`.
#[no_mangle]
pub extern "C" fn soteria_nonces_len() -> usize {
    STATE.with_borrow(|s| s.nonces.len())
}

/// Best-effort mode: the attempts the server will credit for the current
/// nonces, once K digests have been seen. 0 otherwise.
#[no_mangle]
pub extern "C" fn soteria_estimate() -> f64 {
    STATE.with_borrow(|s| match &s.job {
        Some(Job::Search(_, _, best, _)) => best.estimate().unwrap_or(0.0),
        _ => 0.0,
    })
}

/// This build's opcode numbering, sent with the proof so the server can
/// reject a mismatched client.
#[no_mangle]
pub extern "C" fn soteria_fingerprint() -> u64 {
    soteria::opcodes::FINGERPRINT
}

#[cfg(test)]
mod tests {
    use super::*;
    use soteria::gadgets::Params;
    use soteria::wire::request;

    fn submit(req: &[u8]) -> (*mut u8, usize) {
        let ptr = soteria_alloc(req.len());
        // SAFETY: ptr is a fresh req.len()-byte buffer.
        unsafe { core::ptr::copy_nonoverlapping(req.as_ptr(), ptr, req.len()) };
        (ptr, req.len())
    }

    fn nonces() -> Vec<u32> {
        // SAFETY: the pointer and length describe the module's current nonce buffer.
        unsafe { core::slice::from_raw_parts(soteria_nonces(), soteria_nonces_len()).to_vec() }
    }

    /// Stepping in small chunks finds exactly what `Challenge::solve` finds,
    /// and the server accepts it.
    #[test]
    fn solve_in_steps_matches_solve() {
        for chained in [false, true] {
            let p = Params {
                threshold: 1 << 27,
                solutions: 3,
                chained,
                ..Default::default()
            };
            let challenge = [8u8; 32];
            let (ptr, len) = submit(&request(21, &p, &challenge, &[]));
            // SAFETY: from soteria_alloc, used once.
            assert_eq!(unsafe { soteria_solve(ptr, len) }, 0);
            let mut steps = 0;
            // One batch per step: a lucky seed can finish in a few batches.
            while soteria_step(1) == 0 {
                steps += 1;
                assert!(nonces().len() < 3);
            }
            let c = Challenge::new(21, p);
            assert_eq!(
                Some(nonces()),
                c.solve(&challenge, 100_000),
                "chained={chained}"
            );
            assert!(c.verify(&challenge, &nonces()));
            assert!(steps > 1, "should have taken several steps");
            assert_eq!(soteria_step(3), 1, "stays done");
        }
    }

    #[test]
    fn search_in_steps_matches_best() {
        let p = Params {
            gadgets: 8,
            scratchpad: 256,
            ..Default::default()
        };
        let challenge = [5u8; 32];
        let (ptr, len) = submit(&request(4, &p, &challenge, &[]));
        // SAFETY: from soteria_alloc, used once.
        assert_eq!(unsafe { soteria_search(ptr, len, 16) }, 0);
        assert_eq!(soteria_estimate(), 0.0, "no estimate before K digests");
        for _ in 0..10 {
            assert_eq!(soteria_step(10), 0);
        }
        let c = Challenge::new(4, p);
        let mut best = Best::new(16);
        c.search_best(&challenge, &mut best, 0..100);
        assert_eq!(nonces(), best.nonces());
        assert_eq!(Some(soteria_estimate()), best.estimate());
        assert_eq!(c.verify_best(&challenge, &nonces()), best.estimate());
    }

    #[test]
    fn bad_calls_are_errors() {
        let p = Params::default();
        let start = |req: Vec<u8>, k: Option<u32>| {
            let (ptr, len) = submit(&req);
            // SAFETY: from soteria_alloc, used once.
            unsafe {
                match k {
                    None => soteria_solve(ptr, len),
                    Some(k) => soteria_search(ptr, len, k),
                }
            }
        };
        set(None);
        assert_eq!(soteria_step(1), ERR_NO_JOB);
        assert_eq!(start(request(1, &p, &[0; 32], &[7]), None), ERR_LENGTH);
        assert_eq!(start(request(1, &p, &[0; 32], &[]), Some(0)), ERR_PARAMS);
        assert_eq!(start(request(1, &p, &[0; 32], &[]), Some(33)), ERR_PARAMS);
        let bad = Params {
            scratchpad: 100,
            ..p
        };
        assert_eq!(start(request(1, &bad, &[0; 32], &[]), None), ERR_PARAMS);
        // A failed start leaves no job behind, even if one was running.
        assert_eq!(start(request(1, &p, &[0; 32], &[]), None), 0);
        assert_eq!(start(request(1, &bad, &[0; 32], &[]), None), ERR_PARAMS);
        assert_eq!(soteria_step(1), ERR_NO_JOB);
        assert_eq!(soteria_nonces_len(), 0);
    }

    #[test]
    fn fingerprint_matches_server_side() {
        assert_eq!(soteria_fingerprint(), soteria::opcodes::FINGERPRINT);
    }
}
