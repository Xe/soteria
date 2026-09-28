# soteria

soteria is a 4-lane SPMD VLIW virtual machine in WASM SIMD, built for proof-of-work
challenges where every solve attempt gets a freshly generated program.

```sh
cargo test --release   # builds for wasm32-wasip1 with +simd128, runs under wasmtime
```

## Machine

| State | Count | Notes |
|---|---|---|
| i32 registers | 16 | `r15` starts as the lane's nonce |
| f32 registers | 4 | NaNs canonicalized to `0x7FC00000` |
| predicates | 16 | `p0` hardwired true, `p15` = solved |
| memory | 64 KiB per lane | little-endian, addresses masked to 16 bits |

Each `v128` register holds one value per lane, so one bundle runs four nonces.
A bundle is 4 slots × 8 bytes: `op, guard, d, a<<4|b, imm:i32le`. The guard
byte picks a predicate (bit 4 negates); a slot only commits in lanes where its
guard is true.

All slots read pre-bundle state, then writes commit in slot order. That means
`add r1, r2, r0 | add r2, r1, r0` swaps registers.

## Instructions

| Op | Effect |
|---|---|
| `li d, imm` / `addi d, a, imm` | `rd = imm` / `rd = ra + imm` |
| `add sub mul xor and or d, a, b` | `rd = ra OP rb` |
| `shl shr rotr d, a, imm` | shift by immediate (WASM SIMD has no per-lane shifts) |
| `clz d, a` | count leading zeros (via the f32 exponent trick) |
| `bswap d, a` | reverse byte order (one `i8x16.swizzle`) |
| `popcnt d, a` | count set bits (`i8x16.popcnt` + two pairwise adds) |
| `ld d, [a + imm]` / `st [a + imm], b` | 32-bit, 4-byte aligned |
| `sha256 a, b` | `mem[rb..+32] = sha256(mem[ra..+64])`, 64/32-byte aligned |
| `fill a, [b]` | `mem[128..(ra & 0xFFFF)+1] = expand(mem[rb..+32])`, sequential keyed stream |
| `fold a, b` | `mem[rb..+32] = fold(mem[0..(ra & 0xFFFF)+1])`, ordered ARX-multiply fold of the scratchpad |
| `cmpeq cmplt cmpltu pd, a, b` | integer compares into predicates |
| `pand por pxor pd, pa, pb` / `pnot pd, pa` | predicate logic |
| `fcvt fd, a` / `ftrunc d, fa` | int to float / saturating float to int |
| `fbits d, fa` / `ffrom fd, a` | bitcast float to int / int to float |
| `fadd fsub fmul fdiv fd, fa, fb` / `fsqrt fd, fa` | float math |
| `flt pd, fa, fb` | float compare |
| `subleq a, b, imm` | `rb -= ra; if rb <= 0 { pc = imm }` |
| `bp pa, imm` | `if pa { pc = imm }` |
| `pany pd, pa` | `pd` = any lane of `pa`, broadcast (the only cross-lane op) |
| `halt` | stop after this bundle commits |

At most one of `subleq`, `bp` or `halt` per bundle. Control flow must be
lane-uniform (its guard and condition all-true or all-false), otherwise the
batch traps with `DivergentControl`.

## Verification

Nonces are grouped into lane-aligned batches (`nonce & !3`). The server
verifies by rerunning the whole batch, so client and server agree on traps
bit-for-bit. Generated puzzles carry an exact fuel budget; an honest run ends
with exactly zero fuel left.

## Gadget challenges (`gadgets.rs`, `sched.rs`)

A challenge's hash is `sha256(challenge ‖ nonce)` → a seed-chosen chain of
gadgets over the state `r1..r8` → `sha256(state ‖ fold(scratchpad))` →
compare the first word to a threshold. The fold means every store reaches the
digest, so an attacker's compiler can't delete stores as dead code. Before the
gadgets run, `fill` expands `sha256(challenge ‖ nonce)` into the arena, so
memory is different for every challenge and every nonce. There are 16 gadgets:

| Group | Gadgets |
|---|---|
| ALU | `AddRot`, `XorRot`, `SubRot`, `MulOdd`, `AddBswap`, `BswapTap`, `XorShift` |
| Bit-count taps | `PopcntTap`, `ClzTap` |
| Float taps | `SqrtTap`, `DivTap` |
| Memory | `MemLoad`, `MemScatter` |
| Lane movement | `CondSwap`, `WordRotate` |
| Anchor | `ShaAnchor` |

Every gadget except `ShaAnchor` is a bijection on the state, mostly in
Feistel form (`x op= f(y, z, …)` with `x` not an input to `f`), so lossy ops
can't collapse the state space. Gadgets emit sequential steps; the list
scheduler packs them into bundles around register, predicate, float and
memory hazards (about 2.8 slots per bundle on the default mix).

Difficulty axes (`Params`): gadget count, category mix, scratchpad size,
threshold (smooth success probability), number of solutions (less variance),
and chaining (solutions can't be searched in parallel).
`Challenge::with_budget` picks the threshold so expected work equals a given
number of bundle-equivalents: bundles plus the real cost of `fill`, `fold`
and `sha256`, which take 1 fuel each but do far more work (`attempt_cost`).

## Best-effort solving (`best.rs`)

Instead of searching until a digest falls under a threshold, the client hashes
until a deadline, keeps the K lowest 64-bit digest prefixes (`Best`) and
submits only their nonces. The server reruns each distinct batch once and
credits `N^ = (K - 1) / u_(K)` attempts, where `u_(K)` is the largest
submitted prefix as a fraction of 2^64. That estimate is unbiased with a
relative error of about `1 / sqrt(K - 2)`, 18% at the maximum K of 32.
Submitting anything but the true K lowest only lowers the credit. Slow
devices earn partial credit instead of nothing.

## Assembler (`asm.rs`)

`asm::assemble` accepts exactly what `disasm::listing` prints, plus labels
(`loop:`), symbolic targets (`@loop`) and `;` comments, so any listing
round-trips. It's two passes: the first records which bundle each label
points at, the second parses slots against a per-opcode operand signature.

## Per-build opcode numbering (`build.rs`)

Set `SOTERIA_OPCODE_SEED` at build time to Fisher-Yates shuffle all 256 byte
values; opcode *i* is encoded as `PERM[i]`, and every other byte decodes as
`BadOpcode`. Unset means the identity mapping. Derive the seed from the
commit (`0x$(git rev-parse HEAD | cut -c1-16)`) so builds stay reproducible,
and ship `opcodes::FINGERPRINT` with challenges so mismatched clients fail
fast. Only the wire format changes: the assembler, disassembler and VM
semantics are untouched.
