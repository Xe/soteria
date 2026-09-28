# Soteria handoff

Soteria is a 4-lane SPMD VLIW virtual machine written in Rust against WASM
SIMD (`simd128`). It exists to generate per-challenge proof-of-work puzzles
for [Anubis](https://github.com/TecharoHQ/anubis) and is the subject of a
planned blog post on xeiaso.net. Xe (the owner) writes Go and Rust, prefers
direct, code-forward answers, and wants tradeoffs stated honestly.

Status: working prototype, about 3,900 lines across 5 crates, 61 tests passing (plus 3 ignored benchmarks). `challenge/soteria` is an Anubis challenge
method (Go) built on the two modules; Anubis itself doesn't import it yet.

## Build and test

The workspace defaults to `wasm32-wasip1`; `.cargo/config.toml` sets the
target, `+simd128`, and `wasmtime` as the test runner. `soteria`,
`soteria-client` and `soteria-server` are `#![cfg(target_arch = "wasm32")]`, so a native build of them
compiles to nothing. `soteria-isa` and `soteria-cli` build anywhere; the CLI
aliases pass `--target host-tuple` to run natively.

```sh
rustup target add wasm32-wasip1
curl https://wasmtime.dev/install.sh -sSf | bash
cargo test --release                       # 61 tests across the workspace, ~1.5 s
cargo test --release <name> -- --nocapture # to see printed listings
SOTERIA_OPCODE_SEED=42 cargo test --release # shuffled opcode numbering
cargo test --release bench_solve -- --ignored --nocapture # solve time per Anubis difficulty, 4..=12
cargo test --release bench_scratchpad -- --ignored --nocapture # cost and nonces/s, 16 KiB..1 MiB
cargo build --release -p soteria-client -p soteria-server --target wasm32-unknown-unknown # browser and wazero modules
cargo soteria-asm programs/hashcash.sot     # -> programs/hashcash.sotb (native)
cargo soteria-disasm programs/hashcash.sotb # listing to stdout
go generate ./challenge/soteria             # rebuild and copy the modules, regenerate templ
go test ./...                               # Anubis challenge method
go run ./cmd/soteriabench --difficulty 18   # endless challenge loop on :8923, to watch the lane visualizer
```

Last verified with rustc 1.98.1 and wasmtime 48.0.0. If `cargo test` reports
"running 0 tests", `.cargo/config.toml` is missing and the build went native.

WASI builds use `panic = abort`, so the first panicking test kills its
crate's test binary and that summary line is missing. Search the output for
`panicked at` to find which test failed.

## Layout

A Cargo workspace. The dependency order is `soteria-isa <- soteria <-
{soteria-client, soteria-server}`, plus `soteria-isa <- soteria-cli`.

| Path | What it is |
|---|---|
| `crates/soteria-isa/src/lib.rs` | ISA (`Op`, `ops!`), encoding (`Slot`, `Bundle`, `Program`), `Error`, opcode tables. Target-independent |
| `crates/soteria-isa/build.rs` | Per-build Fisher-Yates opcode numbering from `SOTERIA_OPCODE_SEED` |
| `crates/soteria-isa/src/asm.rs` | Two-pass assembler; accepts disassembler output plus labels and `;` comments |
| `crates/soteria-isa/src/disasm.rs` | `Display` for `Slot`, `listing(&Program)` |
| `crates/soteria-isa/src/sched.rs` | List scheduler: sequential steps to bundles, respecting hazards |
| `crates/soteria/src/lib.rs` | Re-exports the ISA. The VM (`Vm::step`/`run`), `attempt`/`solve`/`verify`, `clz32x4`, `popcnt32x4`, `fold_lane`, `fill_lane`. wasm32 only |
| `crates/soteria/src/sha4.rs` | 4-way multi-buffer SHA-256 over `i32x4` (64-byte messages only) |
| `crates/soteria/src/gadgets.rs` | The 40 gadgets, `Params`/`Mix`, `Challenge` (build, solve, verify, budget) |
| `crates/soteria/src/best.rs` | Best-effort mode: `Best` (client K-lowest accumulator), `search_best`, `verify_best`, `estimate` |
| `crates/soteria/src/hashcash.rs` | Hand-written hashcash program + host search/verify |
| `crates/soteria/src/puzzle.rs` | **Older** random-bundle generator; superseded by `gadgets.rs`, still tested. Also home of `SplitMix`, which `gadgets` uses |
| `crates/soteria/src/tests.rs` | VM, gadget, best-effort and assembler tests |
| `crates/soteria/src/reference.rs` | Test-only copy of the interpreter from before roadmap item 9; `interpreter_matches_reference` steps it alongside `Vm::step` |
| `crates/soteria/src/wire.rs` | Request layout shared by both modules: `parse`, `request` encoder, `ERR_*`, caps, `alloc`/`take` |
| `crates/soteria-client/src/lib.rs` | Browser module (cdylib): stepped solver, `soteria_solve`/`search`/`step`/`nonces`/`lanes`/`estimate` |
| `crates/soteria-server/src/lib.rs` | Server module (cdylib) for wazero: `soteria_verify`/`verify_best` |
| `challenge/soteria/` | Anubis challenge method `soteria` (Go): embeds both modules, verifies under wazero, serves the client module and `js/` (minified into `static/` by esbuild), `page.templ`. `static/*.wasm` are gitignored, so run `go generate` before building a fresh clone |
| `cmd/soteriabench/` | Go server that loops the Anubis page through the method's real `Issue` and `Validate` (fresh challenge, solve, verify, redirect, repeat) in Anubis' base page, logging each round |
| `crates/soteria-cli/` | Native `soteria-asm` / `soteria-disasm` (clap) and the `.sotb` container (magic + opcode fingerprint + program) |
| `programs/hashcash.sot` | Annotated hashcash source; `hashcash_from_source` checks it equals `hashcash::program(16, 1000)` |
| `README.md` | ISA reference table and feature summaries |

## Machine model (the spec)

Per lane: 16 × i32 `r0..r15`, 4 × f32 `f0..f3`, 16 predicates `p0..p15`,
1 MiB little-endian memory (20-bit addresses). Each register is a `v128` holding all 4 lanes.
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

43 opcodes. The README table is the reference; edge cases that matter:

- Shifts and `rotr` use `imm & 31`. There are no per-lane shift counts because WASM SIMD shifts take a scalar amount.
- `ld`/`st` mask the address with `& 0xFFFFC`. `sha256` masks its source with `& 0xFFFC0` (64 bytes) and its destination with `& 0xFFFE0` (32 bytes).
- `fill r_len, [r_key]` writes `mem[128 .. (len & 0xFFFFF)+1]` from a 32-byte key. `fold [r_dst], r_len` folds `mem[0 .. (len & 0xFFFFF)+1]` into 32 bytes. Both lengths round down to a multiple of 32.
- Memory is architecturally zero outside the image, but zeroing 4 MiB per attempt would cost more than the attempt. `Vm::reset` reuses a machine and clears only below `Vm::dirty`, the high-water mark of stores and fills (`reset_matches_new` checks it against a fresh `Vm`). `Challenge` keeps one `Vm` for this. Code that writes `vm.mem` directly must raise `dirty`.
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

`ops!` list (at the end) → VM match arm in `step` (`soteria`) →
`sched::hazards`, `disasm` format, `asm::signature` (all `soteria-isa`) → README table → a test against a scalar
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

With `Params::block = k` (0 or 2..=31; wire flags bits 8..16), the gadgets
and program for nonce n of sub-challenge `sub` come from
`block_seed(seed, sub, n >> k)` rather than `seed`. `Challenge` caches the
last block program it built, so callers should walk nonces in order (all of
them do). `Challenge::program`/`gadgets` stay the `seed` program, which
`attempt_cost`, `expected_work` and `with_budget` use as a representative of
the family; block programs vary in cost around it. Keying on `sub` as well as
the block means chained and multi-solution searches, which restart at nonce 0
per sub-challenge, can't reuse compiled blocks either.

`Params` defaults: 32 gadgets, `Mix { alu 8, taps 3, float 2, memory 3,
lanes 2, sha 1 }`, 16 KiB scratchpad (up to 1 MiB), threshold `1 << 24`, 1 solution, not
chained, fold on, fill on, block 0 (one program). The default challenge is
about 102 bundles and packs about 2.4 slots per bundle, but costs about 556
bundle-equivalents per attempt once `fill`, `fold` and `sha256` are charged
for their real work and loops for their expected iterations. `packing_stats`
prints these. Under the old weights it was 361 before the 16 gadgets of
roadmap item 7, 439 before `MemWalk`, 458 before `CondRepeat` and 533 after
float state; the reweighting in item 9 alone took 533 to 556.
`Challenge::attempt_cost` is, per bundle, 1 + `ROUND_COST` per 32-byte mix
round (`fill`, `fold`) + `SHA_COST` per `sha256`, times `expected_repeats()`
(about 6.86) inside a loop. `expected_work` and `with_budget` use it. The
two weights (0.26 and 16.0, from 0.25 and 13.0 before item 9) were measured
by the ignored `calibrate_memory_cost` test; rerun it and update the
constants after interpreter changes or roadmap item 5, since a faster
interpreter makes memory relatively more expensive.

`CondRepeat` is the only control flow in gadget programs. Each lane's count is
`c = 1 + 3 bits of z` (1..=`REPEAT_MAX` = 8), kept in r13, which leaves the
temp rotation while the body runs. The body is `REPEAT_BODY` = 2 gadgets drawn
from the mix, excluding the SHA group (a repeated `FoldTap` would swamp the
program) and `CondRepeat` itself, so loops never nest. Body gadgets draw their
state words from a pool without z, so the count survives and the loop can be
undone; `cond_repeat_runs_the_batch_maximum` checks this, since
`every_gadget_is_injective` didn't notice when z was writable. The loop is
`do { body; c -= 1 } while pany(c > 0)`, unguarded, so every lane runs the batch
maximum. Guarding the body per lane would let a scalar or GPU solver skip about
40% of the loop work SIMD lanes pay for. `Code` in `gadgets.rs` schedules the
straight-line segments on either side of the loop separately, since the
scheduler can't move code across a branch. Fuel is no longer the bundle count:
`gadgets::fuel` counts every loop at `REPEAT_MAX` iterations, and
`Challenge::fuel` is that for the seed program.

Registers: r0 = 0, r1..r8 state, r9..r13 temps (round-robin; r13 is the
`CondRepeat` counter inside a loop), r14 scratchpad mask, r15 nonce. Memory: 0..32 challenge, 32..36 nonce, 40..48 float state,
64..128 hash block, 128.. arena.

Float state (`FSTATE`, two f32 words at 40..48) plays RandomX's F registers.
It lives in memory because every float register is a temp (`RsqrtTap` needs
three). `FStateMix` does `F_i ^= fbits(F_j op y)` with op in fadd/fsub/fmul:
float arithmetic on the other word, xored in, so it can be undone and leaves
r1..r8 alone. `FStateTap` does `x += fbits(F_i op y)`. `fold` covers the
words. With the default mix a program has about 0.4 of each, so the rounding
chain is short; raise `mix.float` to lengthen it.

## Known issues

- **Fuel is not work.** `fill`, `fold` and `sha256` still cost 1 fuel each. Fuel only bounds execution; the work metric is `attempt_cost`. Its weights are interpreter-specific (see above).
- **`CondRepeat` makes work per batch vary.** A batch's loop runs 1 to 8 times (mean about 6.86), so `attempt_cost` is an expectation, not an exact count. Verification is unaffected because the server reruns the batch, but a fixed-time solver budget sees more spread.
- **The VM always takes 4 MiB**, whatever the scratchpad. The browser pays it once per worker. The Go verifier pays it per call because it makes a fresh instance each time: verify went from about 1.1 to 1.4 ms and from 4.3 to 8.0 MB allocated per call when `MEM_SIZE` went to 1 MiB (`BenchmarkVerify`). Pooling instances would fix both.
- **Tiered masks are unmeasured where they matter.** Memory taps other than `MemWalk` use `tier_mask`: `L1_WINDOW` (16 KiB) half the time, `L2_WINDOW` (256 KiB) a quarter, the whole scratchpad otherwise, all clamped by `MASK`. `bench_scratchpad` on the M-series Mac shows no change in nonces/s at any size, as expected with large caches and interpreter overhead dominating. A phone with a small L2 is where it could show up.
- **The work metric doesn't model cache misses.** A `MemWalk` hop costs 1 bundle in `attempt_cost` whether it hits L1 or DRAM. On the M-series Mac, ns per bundle-equivalent stays flat (12-15) from 16 KiB to 1 MiB, but a phone with a small L2 may not.
- `hashcash` only checks the first digest word, so difficulty is capped at 32 bits.
- **Bijectivity is per gadget, not across gadgets.** Memory can hold a copy of a state word's current value (after `ShaAnchor`, `mem[64..96]` equals r1..r8; `MemScatter` stores a state word as is; `MemBlock` stores its loaded block ^ `rotr(k, r)`, so a later tap on k's register before k changes computes `x ^= f(x)` if it lands there; the float state depends on the y words that fed it, so `FStateTap` on such a y's register is the same risk). A later memory tap whose address lands there computes `x ^= f(x)`. `every_gadget_is_injective` tests gadgets alone, so it can't see this. `ShaFeistel` zeroes x's word in the block for this reason. The odds per load are small (8 words of a 4096-word scratchpad), but a fix would mean keeping memory taps away from state copies.
- `puzzle.rs` is legacy. Keep it working, but build new features on `gadgets.rs`.

## Roadmap (suggested order)

1. ~~**Work metric memory term.**~~ Done: `attempt_cost`, `expected_work` (was `expected_bundles`), `budget_accounts_for_scratchpad`.
2. ~~**Best-effort solving.**~~ Done in `best.rs`. The client feeds batch ranges into `Best` (call `search_best` repeatedly between deadline checks) and submits `Best::nonces`. `verify_best` rejects empty, duplicate or more than `MAX_BEST` (32) nonces, reruns each distinct batch once, and returns `N^ = (K-1) / u_(K)` attempts (multiply by `attempt_cost` for bundle-equivalents). N^ is exactly unbiased with relative error about `1/sqrt(K-2)` (18% at K = 32); `estimator_is_unbiased` and `best_effort_estimates_attempts` check the mean and spread. Uses the first sub-challenge only; `threshold`, `solutions` and `chained` don't apply. Open question for the policy layer: what minimum credit to require, given the 18% spread.
3. ~~**C-ABI exports.**~~ Done as two modules, each about 68 KB with no imports (sizes are close because the VM and SHA-256 dominate). Both export `memory`, `soteria_alloc(len) -> ptr` and `soteria_fingerprint() -> i64`, and take requests in the `soteria::wire` layout (pinned by `request_layout_is_stable`).
   - **Server** (`soteria_server.wasm`, for wazero): `soteria_verify(ptr, len) -> i32` (1, 0, or negative `ERR_*`), `soteria_verify_best(ptr, len) -> f64` (attempts, 0 if rejected, or negative `ERR_*`). Both free the buffer, so a pooled instance doesn't leak.
   - **Client** (`soteria_client.wasm`, for a browser Web Worker): one job per instance. `soteria_solve(ptr, len)` or `soteria_search(ptr, len, k)` starts a job (0 or `ERR_*`); `soteria_step(batches)` returns 1 when done, 0 to continue, `ERR_NO_JOB` (-3) or `ERR_EXHAUSTED` (-4); `soteria_nonces()`/`soteria_nonces_len()` point at the current nonces; `soteria_estimate()` is the best-effort credit. Built on `gadgets::Solver`, which `solver_steps_match_solve` checks against `Challenge::solve`. Verified end to end in V8 (Node 26): client solves and searches, server verifies, estimates agree. `ERR_EXHAUSTED` (2^30 batches) is not covered by a test. Params are validated at the boundary (caps: 4096 gadgets, 256 solutions, mix weights <= 65536), so bad params return `ERR_PARAMS` instead of trapping. Passing a pointer that didn't come from `soteria_alloc` traps in the allocator.
4. ~~**Go verifier.**~~ Done in `challenge/soteria` as an Anubis method. One shared wazero runtime (concurrent `NewRuntime` calls race inside wazero), a fresh anonymous instance per call, 5 s timeout; about 1.4 ms per verify at difficulty 16 (M-series; 1.1 ms before item 8). No `sync.Pool` yet. Anubis `difficulty` d is in bits, not the sha256 method's hex digits: 2^d expected attempts (4 chained solutions, `threshold = 2^(34-d)`, 256-nonce program blocks), max 33. Difficulty 4n asks for as many attempts as sha256 difficulty n, so an Anubis policy written for sha256 needs its difficulty multiplied by 4. On an M-series Mac under wasmtime, `bench_solve` puts difficulty 12 (4096 attempts) at about 127k nonces/s (116k before item 9, 129k before `CondRepeat`), about 32 to 37 ms mean depending on the run; each extra bit doubles it. Seed and challenge are sha512(RandomData)[0..8] and [32..64]. The browser solves in one worker because `soteria_solve` always starts at nonce 0; parallel workers need a start/stride export.
5. **Compile challenges to WASM. Paused 2026-09-28; groundwork on branch `compile-to-wasm`.** The branch has a working compiler (`soteria::compile`: each bundle becomes a read phase into v128 locals and commits through `v128.bitselect`, basic blocks behind a `br_table`, traps with the interpreter's error and pc; generated modules import memory, the function table and `sha256`/`fold`/`fill` helpers from the client and install themselves into its table), a test-only `soteria-testkit` cdylib, and differential tests under wazero (`go test`) and V8 (`node scripts/compile-check.mjs`) that agree on thousands of random and challenge programs. It is not merged because it barely pays at default parameters. In V8, per 4-nonce batch: default 16 KiB challenges go from 37 to 32 us (about 12%), 18.8 to 14.2 us with fill and fold off, and a gadget-heavy case from 20 to 8.4 us (2.4x). Compiled bundles are about 5x faster, but `fill`, `fold`, `sha256`, `FoldTap` and the per-attempt reset dominate an attempt and run the same helpers either way. So interpreting versus compiling is a 10-25% gap at defaults; the larger attacker advantage is probably native SHA-NI/AVX2 against WASM SIMD in those helpers, which compiling doesn't touch. Merging would also add a codegen arm to the new-opcode checklist and still needs the client side (async compile of about 16 blocks per module in `worker.js`, a table-slot ring, solver routing). V8 compiles and instantiates a 16-program module (about 220 KB) in about 0.7 ms, so compile cost is not the obstacle. Revisit if defaults shift toward gadget-heavy programs (more gadgets, smaller scratchpad), where the gain is 2.4x or more; rebase the branch onto the current ISA first.
6. ~~**Program blocks from `nonce >> k`.**~~ Done: `Params::block`, `block_seed(seed, sub, nonce >> k)`, `Challenge::program_for`, tested by `blocks_get_their_own_programs` plus block variants of `scheduler_matches_sequential`, `solver_steps_match_solve` and `solve_verify_chained_and_not`. A default program builds in about 27 us, 0.77 batch attempts (`calibrate_memory_cost` prints it; it was 16 us and 0.62 before the gadgets added after item 8). The Anubis method uses k = 8 (about 1.2% client overhead); verify went from about 0.9 to 1.1 ms since the server builds one program per solution. Item 5's compiled `search(base, batches)` export should work per block.
7. ~~**`mulhu`, `pmov`, full-entropy taps.**~~ Done: `mulhu` (high half of an unsigned 32×32 multiply) and `pmov` (predicate → -1/0), tested by `mulhu_and_pmov_match_scalar`. `SqrtTap` (on `y >> 1`, so never NaN) and `DivTap` xor in `fbits` of the result. `ClzTap` uses `mulhu(clz + imm, y)` instead, since `fbits` of a 0..32 count is still 33 values. Also added 16 gadgets, all in the existing six `Mix` groups so the wire layout is unchanged: `ChTap`, `MajTap`, `SigmaTap`, `MulAddTap` (alu); `MulHiTap`, `CmpMaskTap` (taps); `FMulTap`, `FAddTap` (raw bits via `ffrom`), `HypotTap` (float); `MemChase`, `MemRmw`, `MemXorLoad` (memory); `CondNegate`, `CondWordRotate` (lanes); `ShaFeistel` (SHA of every word but x, xored into x: a bijective SHA gadget), `FoldTap` (a mid-program `fold`) (sha). `scheduler_matches_sequential` now asserts every gadget ran. Adding gadgets changed which program each seed builds.
8. ~~**Latency-bound pointer-chase gadget and a larger arena.**~~ Done: `MEM_SIZE` is 1 MiB per lane with 20-bit address masks, `Params::scratchpad` (and the wire field) goes up to 1 MiB, and `MemWalk` (memory group) walks `WALK_HOPS` = 8 dependent loads, `t = ld((t + z) & mask)`, adding each loaded word into x. Tested by `memory_addresses_are_twenty_bits`, `reset_matches_new`, `mem_walk_is_a_dependent_chain` and `megabyte_scratchpad_solves_and_verifies`. Reusing the `Vm` (see the spec) made default solves about 25% faster, since `Vm::new` used to zero 256 KiB per attempt. The Go host's memory cap went from 64 to 128 pages. Defaults are unchanged (16 KiB scratchpad in `Params` and the Anubis method); `bench_scratchpad` on an M-series Mac:

   | scratchpad | attempt cost | nonces/s | us/nonce |
   |---|---|---|---|
   | 16 KiB | 538 | 127k | 7.8 |
   | 64 KiB | 1690 | 39k | 25 |
   | 256 KiB | 6298 | 12k | 82 |
   | 1 MiB | 24730 | 3.5k | 288 |

   Past 64 KiB, `fill` and `fold` (sequential, bandwidth-bound) are most of the cost, not the `MemWalk` hops. Anubis difficulty counts attempts, so a bigger default arena means lowering difficulty by about log2 of the cost ratio (3.5 bits for 256 KiB) to keep solve times. Whether that narrows the phone/desktop gap needs measuring on phones.
9. ~~**Interpreter performance.**~~ Done: pending writes are small and `Copy` (`Write::Mem32`, formerly `Write::Sha`, and `Write::Fill` keep their 32-byte payloads in `Vm::pending`), stores write directly instead of through a `Vec`, operands are read only by the arms that use them, and NOP slots are skipped. `calibrate_memory_cost` went from about 88 to 62 ns per bundle, and 16 KiB solves from 113k to 127k nonces/s. Pre-decoding was skipped: `Program` already holds decoded `Slot`s, so it would save only an immediate splat and a guard branch per slot. `interpreter_matches_reference` runs 300 random programs over every opcode (random guards, immediates, NaN floats, branches) and 8 challenge programs through both `Vm::step` and `reference::step`, comparing registers, pc, fuel, halt, dirty and errors after every bundle and memory at the end. `ROUND_COST` and `SHA_COST` were recalibrated.
10. ~~**Lane visualizer.**~~ Done: `Solver::lanes` keeps each lane's latest nonce and digest head (`be32(digest[0..4])`, the word compared with the threshold) and its lowest head since the previous solution, kept after the final one so the last frame still has it; `solver_lanes_track_attempts` checks it against `Challenge::attempt`. The client exports it as `soteria_lanes()` (4 lanes of nonce, head, best nonce, best head; `lanes_match_solver`), `worker.js` posts it with each progress message and with the result, and `main.js` draws it as ASCII in `#lanes` (`aria-hidden`, which `TestIssue` checks; the progress bar already reports status) and leaves the final frame up while the page redirects. It sits folded inside the page's `<details>` expando, above the simplified explanation; the page no longer shows Anubis' long-form explanation paragraphs. The header says only "zero bits"; the bar's full width is the `clz32(threshold - 1)` bits a solution needs. `page.templ` styles it with Xe design system tokens (dark Gruvbox surface, 1px border, `--radius-md`, two-step shadow; purple bar cells, yellow bests, green solved heads) with fallbacks for the older xess that Anubis ships. Each row shows per lane the nonce, head, a bar of leading zero bits against the `clz32(threshold - 1)` a solution needs (scaled to at most 16 cells), the lowest head, and solutions and nonces so far. Labels are English only, not localized. Progress messages are 100 ms apart, so a fast solve (difficulty 12 on a desktop, about 45 ms) may show only the final frame. `cmd/soteriabench` loops the page for watching it, serving the newer xess CSS and fonts from design.within.website (copied into `cmd/soteriabench/static/`) in place of the Anubis module's copy.
11. **Later:** the WIT `compiler`/`verifier` interfaces (`jco transpile` for browsers), and the Techaro datasheet.

## Decisions already made (don't relitigate without a reason)

- **SPMD, not slot-per-lane.** Four lanes run four nonces.
- **Keep `subleq` for the story; `bp` exists for sanity.**
- **No per-nonce programs (full RandomX style).** They break SIMD uniformity and browser compilation. `nonce >> k` blocks are the compromise.
- **No integer divide, no cross-lane ops beyond `pany`, no rounding modes.** WASM has no rounding modes anyway.
- **The per-build opcode shuffle is a speed bump, not security.** Seed it from the commit hash for reproducible builds, and ship `opcodes::FINGERPRINT` with challenges.
- **No shared dataset (RandomX's 2 GiB dataset or light-mode cache).** Dropped 2026-09-28. A dataset gives memory hardness only once its build cost is spread over many attempts. RandomX miners hash nonstop, so everyone amortizes it. An Anubis visitor solves about one challenge per site per cookie lifetime and would pay the whole build (about 250 ms for 16 MiB of 1 us items) every time, or use light mode at about 1 us per lookup, roughly doubling a difficulty 12 solve. A scraper solving many challenges per epoch builds once and then pays DRAM latency per lookup. Keyed per epoch, it favors the scraper; keyed per challenge, a solve's lookups (about 33k at difficulty 12) are far fewer than the items (256K), so nobody builds it and it reduces to extra compute. For more memory hardness, grow the per-attempt scratchpad instead: everyone refills it every nonce, so nobody can amortize it.
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
