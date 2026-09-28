//! Per-build opcode numbering. Set SOTERIA_OPCODE_SEED (decimal or 0x-hex)
//! to shuffle which byte encodes which opcode; leave it unset for the
//! identity mapping, which keeps dev builds and hexdumps readable.
//!
//! CI should derive the seed from something reproducible, e.g.
//!   SOTERIA_OPCODE_SEED=0x$(git rev-parse HEAD | cut -c1-16)
//! so the same commit always yields the same numbering.

use std::{env, fs, path::Path};

struct SplitMix(u64);

impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in 0..n. Plain `next() % n` is slightly biased toward small
    /// values; rejecting the ragged top of the range removes the bias.
    fn below(&mut self, n: u64) -> u64 {
        let zone = u64::MAX - (u64::MAX % n);
        loop {
            let r = self.next();
            if r < zone {
                return r % n;
            }
        }
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=SOTERIA_OPCODE_SEED");
    println!("cargo:rerun-if-changed=build.rs");

    let seed = env::var("SOTERIA_OPCODE_SEED").ok().map(|s| {
        let s = s.trim();
        match s.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16),
            None => s.parse(),
        }
        .expect("SOTERIA_OPCODE_SEED must be a u64 (decimal or 0x-hex)")
    });

    // Fisher-Yates over all 256 byte values. Opcode i is encoded as perm[i],
    // so the opcodes land on scattered bytes and the rest decode as invalid.
    let mut perm: [u8; 256] = std::array::from_fn(|i| i as u8);
    if let Some(seed) = seed {
        let mut rng = SplitMix(seed);
        for i in (1..perm.len()).rev() {
            let j = rng.below(i as u64 + 1) as usize;
            perm.swap(i, j);
        }
    }

    let out = Path::new(&env::var("OUT_DIR").unwrap()).join("opcodes.rs");
    fs::write(
        out,
        format!(
            "/// Seed used for this build's opcode numbering (None = identity).\n\
             pub const OPCODE_SEED: Option<u64> = {seed:?};\n\
             /// Opcode index -> encoded byte.\n\
             pub const PERM: [u8; 256] = {perm:?};\n"
        ),
    )
    .unwrap();
}
