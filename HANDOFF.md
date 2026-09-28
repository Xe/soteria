# Soteria handoff

Soteria is a 4-lane SPMD VLIW virtual machine written in Rust against WASM
SIMD (`simd128`). It exists to generate per-challenge proof-of-work puzzles
for [Anubis](https://github.com/TecharoHQ/anubis) and is the subject of a
planned blog post on xeiaso.net. Xe (the owner) writes Go and Rust, prefers
direct, code-forward answers, and wants tradeoffs stated honestly.

Status: working prototype, 2,257 lines, 29 tests passing. Nothing is wired
into Anubis yet.

## Build and test

Everything targets `wasm32-wasip1`; `.cargo/config.toml` sets the target,
`+simd128`, and `wasmtime` as the test runner. The crate is
`#![cfg(target_arch = "wasm32")]`, so a native build compiles to nothing.

```sh
rustup target add wasm32-wasip1
curl https://wasmtime.dev/install.sh -sSf | bash
cargo test --release                       # 29 tests, ~1 s
cargo test --release <name> -- --nocapture # to see printed listings
SOTERIA_OPCODE_SEED=42 cargo test --release # shuffled opcode numbering
```

Last verified with rustc 1.98.1 and wasmtime 49.0.1.

WASI builds use `panic = abort`, so the first panicking test kills the whole
test binary and the summary line is missing. Search the output for
`panicked at` to find which test failed.

## Layout

| File | What it is |
|---|---|
| `src/lib.rs` | ISA (`Op`), encoding (`Slot`, `Program`), the VM (`Vm::step`/`run`), `attempt`/`solve`/`verify`, `clz32x4`, `popcnt32x4`, `fold_lane`, `fill_lane`, opcode tables |
| `src/sha4.rs` | 4-way multi-buffer SHA-256 over `i32x4` (64-byte messages only) |
| `src/sched.rs` | List scheduler: sequential steps → bundles, respecting hazards |
| `src/gadgets.rs` | The 16 gadgets, `Params`/`Mix`, `Challenge` (build, solve, verify, budget) |
| `src/hashcash.rs` | Hand-written hashcash program + host search/verify |
| `src/puzzle.rs` | **Older** random-bundle generator; superseded by `gadgets.rs`, still tested |
| `src/asm.rs` | Two-pass assembler; accepts disassembler output plus labels and `;` comments |
| `src/disasm.rs` | `Display` for `Slot`, `listing(&Program)` |
| `src/tests.rs` | All tests |
| `build.rs` | Per-build Fisher-Yates opcode numbering from `SOTERIA_OPCODE_SEED` |
| `README.md` | ISA reference table and feature summaries |

## Machine model (the spec)

Per lane: 16 × i32 `r0..r15`, 4 × f32 `f0..f3`, 16 predicates `p0..p15`,
64 KiB little-endian memory. Each register is a `v128` holding all 4 lanes.
`r15` starts as `nonce_base + lane`; `p0` is hardwired true; `p15` is
"solved" by convention.

Bundle = 4 slots × 8 bytes: `op, guard, d, a<<4|b, imm:i32le`. Guard bits
0–3 select a predicate, bit 4 negates it.

`Vm::step`:
1. Program counter out of range → `PcOutOfRange`; fuel exhausted → `OutOfFuel`.
2. **Read phase:** every slot computes from pre-bundle state into a pending write. Branch conditions are decided here.
3. **Commit phase:** writes apply in slot order (later slot wins), masked per lane by the guard via `v128_bitselect`. Writes to `p0` are dropped.
4. Program counter advances, or jumps.

Control (`subleq`, `bp`, `halt`) must be lane-uniform: the condition ANDed
with the guard must be all-true or all-false across the 4 lanes, otherwise
`DivergentControl`. At most one control op per bundle, enforced by
`Program::new`.

41 opcodes. The README table is the reference; edge cases that matter:

- Shifts and `rotr` use `imm & 31`. There are no per-lane shift counts because WASM SIMD shifts take a scalar amount.
- `ld`/`st` mask the address with `& 0xFFFC`. `sha256` masks its source with `& 0xFFC0` (64 bytes) and its destination with `& 0xFFE0` (32 bytes).
- `fill r_len, [r_key]` writes `mem[128 .. (len & 0xFFFF)+1]` from a 32-byte key. `fold [r_dst], r_len` folds `mem[0 .. (len & 0xFFFF)+1]` into 32 bytes. Both lengths round down to a multiple of 32.
- Every float arithmetic result is canonicalized to NaN `0x7FC00000`. `fcvt`, `ffrom` and `fbits` are not canonicalized. `ftrunc` saturates and maps NaN to 0.
- `subleq a, b, @t` always writes `rb -= ra`; it jumps if `rb <= 0` (signed).
- `pany` is the only cross-lane op: any lane true, broadcast to all lanes.

## Invariants — do not break these

1. **Determinism is bit-exact.** Client (browser) and server must agree on every bit. Never reassociate float ops, never introduce FMA, never let a non-canonical NaN reach a float arithmetic result. The fast inverse square root test exists because `(x2·y)·y` and `(y·y)·x2` round differently.
2. **Lane-aligned batches.** Nonces are grouped as `nonce & !3`. The server verifies by rerunning the whole batch, which is what makes traps reproducible. Don't add cross-lane ops beyond `pany`.
3. **Gadgets are bijective on `r1..r8`** (except `ShaAnchor`). Write them in Feistel form, `x op= f(y, z, …)` where `x` is not an input to `f`. `every_gadget_is_injective` catches structural collapse such as sorting, but not a gadget that computes `x ^= f(x)`. Treat Feistel form as a review rule.
4. **The scheduler never reorders semantics.** `scheduler_matches_sequential` must pass: scheduled and one-step-per-bundle execution must match exactly.
5. **New opcodes go at the end of the `ops!` list.** Existing encodings depend on the order (modulo the per-build permutation).

### Checklist for a new opcode

`ops!` list (at the end) → VM match arm in `step` → `sched::hazards` →
`disasm` format → `asm::signature` → README table → a test against a scalar
reference. `listings_round_trip` will fail if disasm and asm disagree.

### Checklist for a new gadget

Add to `Gadget`, `ALL`, a `Mix` group, and `emit`. Take temps from `Temps`.
Never read the target register inside `f`. Run `every_gadget_is_injective`
and `scheduler_matches_sequential`.

## Gadget challenges (`gadgets.rs`)

```
sha256(challenge ‖ nonce) → r1..r8
fill arena[128..scratchpad) from that digest
32 seed-chosen gadgets (default)
digest = sha256(state ‖ fold(scratchpad))
solved = be32(digest[0..4]) < threshold
```

`Params` defaults: 32 gadgets, `Mix { alu 8, taps 3, float 2, memory 3,
lanes 2, sha 1 }`, 16 KiB scratchpad, threshold `1 << 24`, 1 solution, not
chained, fold on, fill on. The default challenge is about 63 bundles and packs
about 2.8 slots per bundle. `Challenge::with_budget` sets the threshold so
expected bundles equal a target.

Registers: r0 = 0, r1..r8 state, r9..r13 temps (round-robin), r14 scratchpad
mask, r15 nonce. Memory: 0..32 challenge, 32..36 nonce, 64..128 hash block,
128.. arena.

## Known issues

- **Fuel ≠ work.** `fill`, `fold` and `sha256` each cost 1 fuel but do far more (about 500 mixing rounds per lane each at 16 KiB). `expected_bundles` undercounts; it needs a memory term.
- **`Vm::store` allocates a `Vec` per store** through its closure. Easy performance fix.
- **The read phase loads every operand for every slot**, needed or not.
- `Write::Sha` is also used for `fold` output; it should be renamed to something like `Write::Mem32`.
- `hashcash` only checks the first digest word, so difficulty is capped at 32 bits.
- `puzzle.rs` is legacy. Keep it working, but build new features on `gadgets.rs`.

## Roadmap (suggested order)

1. **Work metric memory term.** Add a per-attempt cost for `fill`/`fold`/`sha256` to `expected_bundles` and `with_budget`. Done when a budget test accounts for scratchpad size.
2. **Best-effort solving.**
   - Client: hash until a deadline, keep the K lowest 64-bit digest prefixes, and submit only the nonces.
   - Server: rejects duplicates, caps K (≈32), dedupes batches, recomputes the digests, and credits `N̂ = (K−1) / u_(K)` where `u` is the K-th smallest digest as a fraction of 2⁶⁴.
   - Done when a statistical test shows N̂ within the expected error of the true attempt count.
3. **C-ABI exports for Go/wazero.** Build a `cdylib` for `wasm32-unknown-unknown` (+simd128) with `soteria_alloc(len) -> ptr` and `soteria_verify(ptr, len) -> i32`. Request layout: `seed u64 | params | challenge[32] | nonces[u32]`. wazero runs core modules only, not components.
4. **Go verifier.** Embed the `.wasm`, compile once, use an anonymous instance per call (or a `sync.Pool`), plus a context timeout. Benchmark per-call versus pooled.
5. **Compile challenges to WASM (the main weakness fix).** Browsers currently interpret while attackers can compile each seed's program once. Translate each bundle to WASM SIMD locals (read into temps, then commit), guards to `v128.bitselect`, and memory ops to lane extracts plus loads. Import `sha256x4` rather than embedding it, and export `search(base, batches) -> i64`. Done when differential tests of interpreter versus compiled module agree on random seeds.
6. **Program blocks from `nonce >> k`.** Derive the program from `H(seed, nonce >> k)`, with blocks aligned to batches, so compilation can't be amortized across a whole challenge.
7. **Proposed ops, not yet added:** `mulhu` (high 32 bits of a 32×32 multiply) and `pmov` (predicate → -1/0 int). Then upgrade `SqrtTap`/`DivTap`/`ClzTap` to use `fbits` for full-entropy taps.
8. **Latency-bound pointer-chase gadget** plus a larger arena (256 KiB–1 MiB per lane) to narrow the phone/desktop gap. This means raising `MEM_SIZE` and address masks from 16 bits.
9. **Interpreter performance:** pre-decode, fixed-size pending writes, no allocation in the hot path. Protect it with a bundle-by-bundle differential test against the current `Vm`.
10. **Later:** a lane visualizer for the Anubis challenge page, the WIT `compiler`/`verifier` interfaces (`jco transpile` for browsers), and the Techaro datasheet.

## Decisions already made (don't relitigate without a reason)

- **SPMD, not slot-per-lane.** Four lanes run four nonces.
- **Keep `subleq` for the story; `bp` exists for sanity.**
- **No per-nonce programs (full RandomX style).** They break SIMD uniformity and browser compilation. `nonce >> k` blocks are the compromise.
- **No integer divide, no cross-lane ops beyond `pany`, no rounding modes.** WASM has no rounding modes anyway.
- **The per-build opcode shuffle is a speed bump, not security.** Seed it from the commit hash for reproducible builds, and ship `opcodes::FINGERPRINT` with challenges.
- **Ship threshold difficulty and k-solutions to plain SHA-256 Anubis first.** They give most of the fairness benefit for phones without the VM. Soteria is an opt-in challenge that CEL policy selects for suspicious traffic.

## Blog context

Working title: "Soteria: I made a VLIW CPU for proof-of-work and I'm only a
little sorry". It uses Xe's Conv-block dialogue style (Cadey, Aoi, Mara,
Numa). The sections roughly follow the history above:

1. Hashcash's problems
2. Machine design
3. `subleq` / `bp` / `pany`
4. WASM SIMD gaps
5. Fast inverse square root
6. Hashcash listing
7. Gadgets and Feistel taps
8. The `CondSwap` sort bug
9. Scheduler, 84 → 63 bundles
10. The dead-store hole, fixed by `fold`, and `fill`
11. Difficulty axes
12. wazero
13. The main weakness and compile-to-WASM
14. RandomX comparison
15. An honest ledger

Tests produce the listings used in the post (`--nocapture` on
`hashcash_listing`, `gadget_listing`, `fast_inverse_sqrt`), so regenerate
them rather than hand-editing.
