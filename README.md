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
| memory | 1 MiB per lane | little-endian, addresses masked to 20 bits |

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
| `mulhu d, a, b` | high 32 bits of the unsigned 64-bit product (`u64x2.extmul` + shuffle) |
| `shl shr rotr d, a, imm` | shift by immediate (WASM SIMD has no per-lane shifts) |
| `clz d, a` | count leading zeros (via the f32 exponent trick) |
| `bswap d, a` | reverse byte order (one `i8x16.swizzle`) |
| `popcnt d, a` | count set bits (`i8x16.popcnt` + two pairwise adds) |
| `ld d, [a + imm]` / `st [a + imm], b` | 32-bit, 4-byte aligned |
| `sha256 a, b` | `mem[rb..+32] = sha256(mem[ra..+64])`, 64/32-byte aligned |
| `fill a, [b]` | `mem[128..(ra & 0xFFFFF)+1] = expand(mem[rb..+32])`, sequential keyed stream |
| `fold a, b` | `mem[rb..+32] = fold(mem[0..(ra & 0xFFFFF)+1])`, ordered ARX-multiply fold of the scratchpad |
| `cmpeq cmplt cmpltu pd, a, b` | integer compares into predicates |
| `pand por pxor pd, pa, pb` / `pnot pd, pa` | predicate logic |
| `pmov d, pa` | `rd = pa ? -1 : 0` |
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
memory is different for every challenge and every nonce. There are 38 gadgets:

| Group | Gadgets |
|---|---|
| ALU | `AddRot`, `XorRot`, `SubRot`, `MulOdd`, `AddBswap`, `BswapTap`, `XorShift`, `ChTap`, `MajTap`, `SigmaTap`, `MulAddTap`, `VarRot`, `CondRepeat` |
| Taps | `PopcntTap`, `ClzTap`, `MulHiTap`, `CmpMaskTap`, `SMulHiTap` |
| Float taps | `SqrtTap`, `DivTap`, `FMulTap`, `FAddTap`, `HypotTap`, `RsqrtTap` |
| Memory | `MemLoad`, `MemScatter`, `MemChase`, `MemRmw`, `MemXorLoad`, `MemWalk`, `MemBlock` |
| Lane movement | `CondSwap`, `WordRotate`, `CondNegate`, `CondWordRotate` |
| Expensive | `ShaAnchor`, `ShaFeistel`, `FoldTap` |

Every gadget except `ShaAnchor` is a bijection on the state, mostly in
Feistel form (`x op= f(y, z, …)` with `x` not an input to `f`), so lossy ops
can't collapse the state space. Gadgets emit sequential steps; the list
scheduler packs them into bundles around register, predicate, float and
memory hazards (about 2.7 slots per bundle on the default mix). Float taps
xor in the result's bits (`fbits`), not its truncated value, so they carry
full 32-bit entropy. `MemWalk` is an 8-hop pointer chase: each address comes
from the previous load, so it costs memory latency rather than throughput.
The other memory taps address a 16 KiB window half the time, a 256 KiB
window a quarter of the time and the whole scratchpad otherwise, like
RandomX's L1/L2/L3 scratchpad levels. `MemBlock` is RandomX's register-file
exchange cut down to stay invertible: the 32-byte block at key word `k` is
xored into the other seven words, then written back elsewhere as
`m ^ rotr(k, r)`.
`VarRot` rotates by `y & 31` per lane, a barrel of five guarded fixed
rotates, since WASM SIMD only shifts by a scalar. `CondRepeat` is the only
loop: it runs two gadgets `1 + (3 bits of z)` times per lane, and the batch
keeps going while `pany` says some lane wants more, so every lane pays for
the largest count (about 6.9 iterations on average). `RsqrtTap` is the
fast inverse square root as a tap: the `0x5F3759DF` integer guess, then one
Newton step in a fixed float order.

Difficulty axes (`Params`): gadget count, category mix, scratchpad size,
threshold (smooth success probability), number of solutions (less variance),
chaining (solutions can't be searched in parallel), and program blocks.
With `block = k`, nonce `n` of each sub-challenge runs the program built from
`block_seed(seed, sub, n >> k)` instead of one program per challenge, so an
attacker who compiles programs pays for a compile every 2^k nonces. Building a
default program costs about half a batch attempt in the interpreter.
`cargo test --release bench_solve -- --ignored --nocapture` times solves
under wasmtime for Anubis difficulties 4 through 12, where difficulty d is
2^d expected attempts (about 129k nonces/s, 32 ms at difficulty 12, on an
M-series Mac). `bench_scratchpad` does the same for scratchpads of 16 KiB to
1 MiB, where `fill` and `fold` dominate the cost.
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

## Client and server modules (`soteria-client`, `soteria-server`)

`cargo build --release -p soteria-client -p soteria-server --target wasm32-unknown-unknown`
produces two core modules with no imports: `soteria_client.wasm` solves (for
browsers) and `soteria_server.wasm` verifies (for wazero). In both, the host
gets a buffer from `soteria_alloc(len)` and writes a request in the
`soteria::wire` layout (seed, params, challenge, then nonces for the server).
Negative results mean a malformed request, and `soteria_fingerprint` returns
the opcode numbering so the server can reject a client from another build.

The server's `soteria_verify` returns 1 or 0, and `soteria_verify_best`
returns the credited attempts. The client runs in steps so a Web Worker can
check its deadline:

```js
client.soteria_search(ptr, len, 32);               // or soteria_solve(ptr, len)
while (performance.now() < deadline && client.soteria_step(16) === 0) {}
const nonces = new Uint32Array(client.memory.buffer,
  client.soteria_nonces(), client.soteria_nonces_len());
```

## Tools (`soteria-cli`)

`soteria-asm` assembles a `.sot` listing into a `.sotb` file, and
`soteria-disasm` prints the listing back; the round trip is byte-exact. A
`.sotb` file is the magic `SOTB`, the build's opcode fingerprint, then the
encoded program, so a build with a different `SOTERIA_OPCODE_SEED` refuses it
instead of decoding garbage. `--raw` reads or writes bare program bytes.
Both run natively through cargo aliases:

```sh
cargo soteria-asm programs/hashcash.sot       # writes programs/hashcash.sotb
cargo soteria-disasm programs/hashcash.sotb
cargo soteria-asm programs/hashcash.sot --check
```

## Per-build opcode numbering (`build.rs`)

Set `SOTERIA_OPCODE_SEED` at build time to Fisher-Yates shuffle all 256 byte
values; opcode *i* is encoded as `PERM[i]`, and every other byte decodes as
`BadOpcode`. Unset means the identity mapping. Derive the seed from the
commit (`0x$(git rev-parse HEAD | cut -c1-16)`) so builds stay reproducible,
and ship `opcodes::FINGERPRINT` with challenges so mismatched clients fail
fast. Only the wire format changes: the assembler, disassembler and VM
semantics are untouched.
