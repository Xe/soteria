# Soteria

Read `HANDOFF.md` first: it has the spec, invariants, known issues and roadmap.

- Test: `cargo test --release` (workspace; targets wasm32-wasip1 with simd128, runs under wasmtime).
- A failing test aborts its crate's test binary; search output for `panicked at`.
- Determinism is bit-exact between browser and server: never reassociate float ops or add FMA.
- New opcodes go at the end of the `ops!` list (`soteria-isa`) and need the VM arm (`soteria`), `sched::hazards`, `disasm`, `asm::signature`, README and a test.
- New gadgets must be Feistel-shaped (`x op= f(others)`), and must pass `every_gadget_is_injective` and `scheduler_matches_sequential`.
