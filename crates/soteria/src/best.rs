//! Best-effort solving: instead of searching until one digest falls under a
//! threshold, the client hashes until a deadline and submits the nonces of
//! the K lowest digests. The server reruns them and credits an estimate of
//! how many attempts the client made.
//!
//! With N attempts, digest prefixes are N uniform draws on [0, 1), so the
//! K-th smallest, u_(K), is Beta(K, N - K + 1) and
//!
//! ```text
//! N^ = (K - 1) / u_(K)
//! ```
//!
//! is an unbiased estimate of N with variance N(N - K + 1) / (K - 2), a
//! relative error of about 1 / sqrt(K - 2) (18% at K = 32). A client can only
//! lose credit by lying: any set other than its true K lowest has a larger
//! maximum. `threshold`, `solutions` and `chained` don't apply in this mode.

use crate::gadgets::Challenge;
use crate::LANES;
use core::ops::Range;

/// Most nonces a server accepts, which bounds verification to this many
/// batch reruns.
pub const MAX_BEST: usize = 32;

/// First 8 digest bytes, big-endian: the value that gets ranked.
fn prefix(digest: &[u8; 32]) -> u64 {
    u64::from_be_bytes(digest[..8].try_into().unwrap())
}

/// N^ from K and the largest of the K lowest prefixes. The +1 keeps a zero
/// prefix finite; the bias it adds is 2^-64.
pub fn estimate(k: usize, kth: u64) -> f64 {
    (k - 1) as f64 / ((kth as f64 + 1.0) / 18_446_744_073_709_551_616.0)
}

/// Client-side accumulator of the K lowest (prefix, nonce) pairs.
pub struct Best {
    k: usize,
    kept: Vec<(u64, u32)>,
}

impl Best {
    pub fn new(k: usize) -> Self {
        assert!((1..=MAX_BEST).contains(&k));
        Best {
            k,
            kept: Vec::with_capacity(k + 1),
        }
    }

    pub(crate) fn offer(&mut self, p: u64, nonce: u32) {
        if self.kept.len() == self.k && p >= self.kept[self.k - 1].0 {
            return;
        }
        let i = self.kept.partition_point(|&(q, _)| q <= p);
        self.kept.insert(i, (p, nonce));
        self.kept.truncate(self.k);
    }

    /// What to submit.
    pub fn nonces(&self) -> Vec<u32> {
        self.kept.iter().map(|&(_, n)| n).collect()
    }

    /// The credit the server will give, once K digests have been seen.
    pub fn estimate(&self) -> Option<f64> {
        (self.kept.len() == self.k).then(|| estimate(self.k, self.kept[self.k - 1].0))
    }
}

impl Challenge {
    /// Client: run `batches` (each is LANES nonces starting at batch * LANES)
    /// and fold the digests into `best`. Call repeatedly with fresh ranges
    /// until the deadline.
    pub fn search_best(&self, challenge: &[u8; 32], best: &mut Best, batches: Range<u32>) {
        let sub = self.first_sub(challenge);
        for b in batches {
            let base = b * LANES as u32;
            let Some(r) = self.attempt(&sub, base) else {
                continue;
            };
            for (l, (_, d)) in r.iter().enumerate() {
                best.offer(prefix(d), base + l as u32);
            }
        }
    }

    /// Server: estimated attempts behind `nonces`, or None if the submission
    /// is malformed. Multiply by `attempt_cost` for bundle-equivalents.
    /// Nonces sharing a batch are verified by one rerun.
    pub fn verify_best(&self, challenge: &[u8; 32], nonces: &[u32]) -> Option<f64> {
        if !(1..=MAX_BEST).contains(&nonces.len()) {
            return None;
        }
        let mut sorted = nonces.to_vec();
        sorted.sort_unstable();
        if sorted.windows(2).any(|w| w[0] == w[1]) {
            return None;
        }
        let sub = self.first_sub(challenge);
        let lanes = LANES as u32;
        let mut kth = 0;
        for batch in sorted.chunk_by(|a, b| a / lanes == b / lanes) {
            let base = batch[0] - batch[0] % lanes;
            let r = self.attempt(&sub, base)?;
            for &n in batch {
                kth = kth.max(prefix(&r[(n - base) as usize].1));
            }
        }
        Some(estimate(nonces.len(), kth))
    }
}
