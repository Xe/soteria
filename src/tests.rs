use super::*;
use sha2::{Digest, Sha256};

const CHALLENGE: &[u8; 32] = b"xeiaso.net anubis challenge 1234";

#[test]
fn sha256x4_matches_reference() {
    let msgs: [[u8; 64]; 4] = core::array::from_fn(|l| core::array::from_fn(|i| (i * 7 + l * 31) as u8));
    let got = sha4::sha256x4([&msgs[0], &msgs[1], &msgs[2], &msgs[3]]);
    for l in 0..4 {
        assert_eq!(got[l][..], Sha256::digest(msgs[l])[..], "lane {l}");
    }
}

#[test]
fn clz_matches_scalar() {
    let cases = [0u32, 1, 2, 3, 0x7FFF_FFFF, 0x8000_0000, 0xFFFF_FFFF, 0x00FF_FFFF, 0x0100_0000, 12345];
    for c in cases.chunks(4) {
        let mut v = [0u32; 4];
        v[..c.len()].copy_from_slice(c);
        let got = lanes(clz32x4(from_lanes(v)));
        for l in 0..4 {
            assert_eq!(got[l], v[l].leading_zeros(), "clz({:#x})", v[l]);
        }
    }
}

#[test]
fn bswap_and_popcnt_match_scalar() {
    let v = [0u32, 0x0102_0304, 0xFFFF_FFFF, 0x8000_0001];
    let prog = Program::new(vec![
        bundle(&[Slot::new(Op::Bswap, 1, 2, 0, 0), Slot::new(Op::Popcnt, 3, 2, 0, 0)]),
        bundle(&[Slot::new(Op::Halt, 0, 0, 0, 0)]),
    ])
    .unwrap();
    let mut vm = Vm::new(&[], 0, 10);
    vm.r[2] = from_lanes(v);
    vm.run(&prog).unwrap();
    assert_eq!(lanes(vm.r[1]), v.map(u32::swap_bytes));
    assert_eq!(lanes(vm.r[3]), v.map(u32::count_ones));
}

#[test]
fn bundle_reads_before_writes() {
    // swap r1 and r2 in one bundle
    let prog = Program::new(vec![
        bundle(&[Slot::new(Op::Li, 1, 0, 0, 10), Slot::new(Op::Li, 2, 0, 0, 20)]),
        bundle(&[Slot::new(Op::Add, 1, 2, 0, 0), Slot::new(Op::Add, 2, 1, 0, 0)]),
        bundle(&[Slot::new(Op::Halt, 0, 0, 0, 0)]),
    ])
    .unwrap();
    let mut vm = Vm::new(&[], 0, 10);
    vm.run(&prog).unwrap();
    assert_eq!(lanes(vm.r[1]), [20; 4]);
    assert_eq!(lanes(vm.r[2]), [10; 4]);
}

#[test]
fn predication_is_per_lane() {
    // p1 = nonce < 2; r1 = 7 only where p1, r1 = 9 where !p1
    let prog = Program::new(vec![
        bundle(&[Slot::new(Op::Li, 2, 0, 0, 2)]),
        bundle(&[Slot::new(Op::CmpLt, 1, 15, 2, 0)]),
        bundle(&[Slot::new(Op::Li, 1, 0, 0, 7).when(1), Slot::new(Op::Li, 1, 0, 0, 9).unless(1)]),
        bundle(&[Slot::new(Op::Halt, 0, 0, 0, 0)]),
    ])
    .unwrap();
    let mut vm = Vm::new(&[], 0, 10);
    vm.run(&prog).unwrap();
    assert_eq!(lanes(vm.r[1]), [7, 7, 9, 9]);
}

#[test]
fn divergent_subleq_traps() {
    // r15 - r0 = nonce lanes 0,1,2,3: only lane 0 is <= 0
    let prog = Program::new(vec![
        bundle(&[Slot::new(Op::Subleq, 0, 0, 15, 0)]),
        bundle(&[Slot::new(Op::Halt, 0, 0, 0, 0)]),
    ])
    .unwrap();
    let mut vm = Vm::new(&[], 0, 10);
    assert_eq!(vm.run(&prog), Err(Error::DivergentControl { pc: 0 }));
}

#[test]
fn two_control_ops_rejected() {
    let b = bundle(&[Slot::new(Op::Halt, 0, 0, 0, 0), Slot::new(Op::Subleq, 0, 0, 0, 0)]);
    assert_eq!(Program::new(vec![b]), Err(Error::MultipleControlOps { bundle: 0 }));
}

#[test]
fn nan_is_canonical() {
    // f0 = 0/0 from a fresh machine
    let prog = Program::new(vec![
        bundle(&[Slot::new(Op::FDiv, 0, 0, 0, 0)]),
        bundle(&[Slot::new(Op::Halt, 0, 0, 0, 0)]),
    ])
    .unwrap();
    let mut vm = Vm::new(&[], 0, 10);
    vm.run(&prog).unwrap();
    assert_eq!(lanes(vm.f[0]), [0x7FC0_0000; 4]);
}

#[test]
fn generated_puzzle_roundtrips_and_is_deterministic() {
    let a = puzzle::generate(42, 4, 6, 8);
    let b = puzzle::generate(42, 4, 6, 8);
    let c = puzzle::generate(43, 4, 6, 8);
    assert_eq!(a.program, b.program);
    assert_ne!(a.program, c.program);
    assert_eq!(Program::decode(&a.program.encode()).unwrap(), a.program);
}

#[test]
fn fuel_is_exact() {
    let pz = puzzle::generate(7, 5, 8, 1);
    let mut vm = Vm::new(CHALLENGE, 0, pz.fuel);
    vm.run(&pz.program).unwrap();
    assert_eq!(vm.fuel, 0);
    let mut vm = Vm::new(CHALLENGE, 0, pz.fuel - 1);
    assert_eq!(vm.run(&pz.program), Err(Error::OutOfFuel));
}

#[test]
fn solve_then_verify() {
    for seed in 0..8 {
        let pz = puzzle::generate(seed, 4, 6, 8);
        let nonce = solve(&pz.program, CHALLENGE, pz.fuel, 1 << 14).expect("found a nonce");
        assert!(verify(&pz.program, CHALLENGE, nonce, pz.fuel), "seed {seed} nonce {nonce}");
        // Every nonce before the first solution must be rejected.
        for bad in nonce.saturating_sub(8)..nonce {
            assert!(!verify(&pz.program, CHALLENGE, bad, pz.fuel), "seed {seed} accepted {bad}");
        }
        println!("seed {seed}: nonce {nonce}");
    }
}

#[test]
fn lanes_solve_at_equal_rates() {
    // difficulty 4 => p = 1/16, so ~125 hits per lane over 2000 batches
    let pz = puzzle::generate(99, 3, 6, 4);
    let mut hits = [0u32; 4];
    for batch in 0..2000u32 {
        let r = attempt(&pz.program, CHALLENGE, batch * 4, pz.fuel).unwrap();
        for l in 0..4 { hits[l] += r[l] as u32; }
    }
    assert!(hits.iter().all(|&h| (80..=170).contains(&h)), "{hits:?}");
}

#[test]
fn hashcash_finds_smallest_nonce() {
    for difficulty in [1, 4, 8, 12] {
        let expected = (0u32..).find(|&n| hashcash::verify(CHALLENGE, n, difficulty)).unwrap();
        // Small chunks so the search crosses several VM runs.
        let got = hashcash::search(CHALLENGE, difficulty, 16, 1 << 16).unwrap();
        assert_eq!(got, expected, "difficulty {difficulty}");
    }
}

#[test]
fn hashcash_listing() {
    let prog = hashcash::program(16, 1000);
    assert_eq!(Program::decode(&prog.encode()).unwrap(), prog);
    println!("{}", disasm::listing(&prog));
}

mod gadget_tests {
    use super::*;
    use crate::gadgets::{self, Challenge, Mix, Params};
    use std::collections::HashSet;

    fn state(vm: &Vm) -> Vec<[u32; 8]> {
        (0..LANES).map(|l| core::array::from_fn(|i| lanes(vm.r[1 + i])[l])).collect()
    }

    /// Sanity net for bijectivity (which gadgets get by construction, mostly
    /// Feistel form). Each batch feeds a base state, the base with two words
    /// swapped (catches sort-like collapse), the base with one word nudged,
    /// and a random state, over random memory.
    #[test]
    fn every_gadget_is_injective() {
        let mut rng = puzzle::SplitMix(0xABCD);
        let image: Vec<u8> = (0..MEM_SIZE).map(|_| rng.next() as u8).collect();
        for &g in &gadgets::ALL {
            for seed in 0..8 {
                let prog = gadgets::solo(g, seed);
                let mut seen = std::collections::HashMap::new();
                for run in 0..512usize {
                    let (i, j) = (run % 8, (run / 8) % 8);
                    let base: [u32; 8] = core::array::from_fn(|_| rng.next() as u32);
                    let mut swapped = base;
                    swapped.swap(i, j);
                    let mut nudged = base;
                    nudged[j] = nudged[j].wrapping_add(1 + (run as u32 & 7));
                    let random: [u32; 8] = core::array::from_fn(|_| rng.next() as u32);
                    let inputs = [base, swapped, nudged, random];
                    let mut vm = Vm::new(&image, 0, 64);
                    for w in 0..8 {
                        vm.r[1 + w] = from_lanes(core::array::from_fn(|l| inputs[l][w]));
                    }
                    vm.run(&prog).unwrap();
                    for (inp, out) in inputs.into_iter().zip(state(&vm)) {
                        if let Some(prev) = seen.insert(out, inp) {
                            assert_eq!(prev, inp, "{g:?} (seed {seed}) collapsed two states");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn scheduler_matches_sequential() {
        for seed in 0..20 {
            let p = Params { gadgets: 48, mix: Mix { alu: 1, taps: 1, float: 1, memory: 1, lanes: 1, sha: 1 }, ..Default::default() };
            let packed = Challenge::new(seed, p);
            let serial = Challenge::new_unscheduled(seed, p);
            assert_eq!(packed.gadgets, serial.gadgets);
            let sub = [seed as u8; 32];
            for base in [0, 400, 8000] {
                assert_eq!(packed.attempt(&sub, base), serial.attempt(&sub, base), "seed {seed} base {base}");
            }
        }
    }

    #[test]
    fn packing_stats() {
        let (mut ratios, mut costs) = (vec![], vec![]);
        for seed in 0..50 {
            let c = Challenge::new(seed, Params::default());
            let slots: usize = c.program.bundles().iter().flatten().filter(|s| s.op != Op::Nop).count();
            ratios.push(slots as f64 / c.bundles() as f64);
            costs.push(c.attempt_cost());
            let serial = Challenge::new_unscheduled(seed, Params::default()).bundles();
            if seed == 0 {
                println!("seed 0: {} steps -> {} bundles, gadgets {:?}", serial, c.bundles(), c.gadgets);
            }
        }
        let avg = ratios.iter().sum::<f64>() / ratios.len() as f64;
        println!("average slots per bundle: {avg:.2}");
        println!("average attempt cost: {:.0} bundle-equivalents", costs.iter().sum::<f64>() / costs.len() as f64);
        assert!(avg > 1.5);
    }

    /// Measures the weights behind `gadgets::ROUND_COST` and `SHA_COST` on
    /// this interpreter. Rerun after interpreter or compiler changes:
    /// `cargo test --release calibrate_memory_cost -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn calibrate_memory_cost() {
        use std::hint::black_box;
        use std::time::Instant;
        let per = |reps: u32, mut f: Box<dyn FnMut()>| {
            f();
            let t = Instant::now();
            for _ in 0..reps {
                f();
            }
            t.elapsed().as_secs_f64() / reps as f64
        };

        let p = Params { gadgets: 4000, mix: Mix { sha: 0, ..Default::default() }, scratchpad: 256, fill: false, fold: false, ..Default::default() };
        let c = Challenge::new(1, p);
        let n = c.bundles() as f64;
        let bundle = per(50, Box::new(move || { black_box(c.attempt(black_box(&[1; 32]), 0)); })) / n;

        // One VM mix round = one 32-byte chunk in each of the 4 lanes.
        let mut buf = vec![0u8; 1 << 16];
        let chunks = (buf.len() / 32) as f64;
        let fill = per(200, Box::new(move || fill_lane(black_box(&[3; 32]), black_box(&mut buf)))) * LANES as f64 / chunks;
        let mem = vec![5u8; 1 << 16];
        let fold = per(200, Box::new(move || { black_box(fold_lane(black_box(&mem))); })) * LANES as f64 / chunks;
        let block = [9u8; 64];
        let sha = per(20000, Box::new(move || { black_box(sha4::sha256x4(black_box([&block; 4]))); }));

        println!("bundle {:.1} ns", bundle * 1e9);
        println!("fill round {:.2} bundles, fold round {:.2} bundles", fill / bundle, fold / bundle);
        println!("sha256x4 {:.2} bundles", sha / bundle);
    }

    #[test]
    fn fuel_is_exact_and_budget_hits_target() {
        let c = Challenge::with_budget(3, Params { solutions: 4, ..Default::default() }, 2e6);
        let rel = c.expected_work() / 2e6;
        assert!((0.99..1.01).contains(&rel), "{rel}");
        let mut vm = Vm::new(&[], 0, c.bundles() as u64);
        vm.run(&c.program).unwrap();
        assert_eq!(vm.fuel, 0);
    }

    /// Same seed and budget at different scratchpad sizes: the memory term
    /// grows with the scratchpad, so the budget buys fewer attempts and the
    /// threshold rises to compensate.
    #[test]
    fn budget_accounts_for_scratchpad() {
        let mut prev: Option<Challenge> = None;
        for shift in [8, 10, 12, 14, 16] {
            let c = Challenge::with_budget(5, Params { scratchpad: 1 << shift, ..Default::default() }, 1e8);
            let rel = c.expected_work() / 1e8;
            assert!((0.99..1.01).contains(&rel), "scratchpad 2^{shift}: {rel}");
            if let Some(p) = prev {
                assert_eq!(p.program.bundles().len(), c.program.bundles().len());
                // fill and fold each charge one round per 32 bytes.
                let rounds = 2.0 * (c.params.scratchpad - p.params.scratchpad) as f64 / 32.0;
                let grew = c.attempt_cost() - p.attempt_cost();
                assert!((grew - rounds * gadgets::ROUND_COST).abs() < 1e-9, "{grew}");
                assert!(c.params.threshold > p.params.threshold);
            }
            prev = Some(c);
        }
        // Without fill and fold the scratchpad size costs nothing.
        let small = Challenge::new(5, Params { scratchpad: 256, fill: false, fold: false, ..Default::default() });
        let big = Challenge::new(5, Params { scratchpad: 1 << 16, fill: false, fold: false, ..Default::default() });
        assert_eq!(small.attempt_cost(), big.attempt_cost());
    }

    /// With no gadgets there are no loads, so the scratchpad can only reach
    /// the digest through the fold.
    #[test]
    fn scratchpad_reaches_digest_only_with_fold() {
        for fold in [false, true] {
            let c = Challenge::new(1, Params { gadgets: 0, fold, fill: false, ..Default::default() });
            let sub = [7u8; 32];
            let digest = |image: &[u8]| {
                let mut vm = Vm::new(image, 0, c.bundles() as u64);
                vm.run(&c.program).unwrap();
                vm.mem[64..96].to_vec()
            };
            let a = c.image(&sub);
            let mut b = a.clone();
            b[0x3000] ^= 1;
            assert_eq!(digest(&a) != digest(&b), fold, "fold={fold}");
        }
    }

    #[test]
    fn arena_depends_on_challenge_and_nonce() {
        let c = Challenge::new(2, Params::default());
        let arena = |sub: &[u8; 32], base: u32| {
            let mut vm = Vm::new(&c.image(sub), base, c.bundles() as u64);
            vm.run(&c.program).unwrap();
            (0..LANES).map(|l| vm.mem[l * MEM_SIZE + 4096..][..64].to_vec()).collect::<Vec<_>>()
        };
        let a = arena(b"challenge text number one.......", 0);
        let b = arena(b"challenge text number two.......", 0);
        let c2 = arena(b"challenge text number one.......", 4);
        let set: HashSet<_> = a.iter().chain(&b).chain(&c2).collect();
        assert_eq!(set.len(), 12, "every (challenge, nonce) gets its own arena");
        assert!(a.iter().all(|x| x.iter().any(|&b| b != 0)));
    }

    #[test]
    fn fill_is_sequential_and_keyed() {
        let mut x = [0u8; 256];
        let mut y = [0u8; 256];
        fill_lane(&[1; 32], &mut x);
        fill_lane(&[2; 32], &mut y);
        assert_ne!(x, y);
        let mut short = [0u8; 64];
        fill_lane(&[1; 32], &mut short);
        assert_eq!(short, x[..64], "prefix is stable, so the arena is a stream");
    }

    #[test]
    fn fold_is_order_dependent() {
        let mut m = [0u8; 64];
        m[0] = 1;
        let mut swapped = [0u8; 64];
        swapped[32] = 1;
        assert_ne!(fold_lane(&m), fold_lane(&swapped));
    }

    #[test]
    fn solve_verify_chained_and_not() {
        let challenge = *b"anubis says hi to every phone :3";
        for chained in [false, true] {
            let p = Params { solutions: 3, chained, threshold: 1 << 26, ..Default::default() };
            let c = Challenge::new(11, p);
            let nonces = c.solve(&challenge, 1 << 12).expect("solved");
            assert!(c.verify(&challenge, &nonces), "chained={chained} {nonces:?}");
            // Same nonces against a different challenge: ~2^-18 chance to pass.
            assert!(!c.verify(b"a different challenge, same seed", &nonces));
            assert!(!c.verify(&challenge, &nonces[..2]));
            println!("chained={chained}: {nonces:?}");
        }
    }
}

#[test]
fn gadget_listing() {
    let c = gadgets::Challenge::new(5, gadgets::Params { gadgets: 5, ..Default::default() });
    println!("{:?}\n{}", c.gadgets, disasm::listing(&c.program));
}

/// Quake III's fast inverse square root, four lanes at once, two Newton steps.
/// f0 = x on entry, f1 = 1/sqrt(x) on exit.
fn rsqrt_program() -> Program {
    use Op::*;
    let s = Slot::new;
    Program::new(vec![
        bundle(&[s(Li, 1, 0, 0, 0x3F00_0000), s(Li, 2, 0, 0, 0x3FC0_0000), s(FBits, 3, 0, 0, 0), s(Li, 4, 0, 0, 0x5F37_59DF)]),
        bundle(&[s(FFrom, 2, 1, 0, 0), s(FFrom, 3, 2, 0, 0), s(Shr, 3, 3, 0, 1)]),
        bundle(&[s(Sub, 3, 4, 3, 0), s(FMul, 0, 0, 2, 0)]),
        bundle(&[s(FFrom, 1, 3, 0, 0)]),
        // Newton step 1: y = y * (1.5 - x2 * y * y)
        bundle(&[s(FMul, 2, 1, 1, 0)]),
        bundle(&[s(FMul, 2, 2, 0, 0)]),
        bundle(&[s(FSub, 2, 3, 2, 0)]),
        bundle(&[s(FMul, 1, 1, 2, 0)]),
        // Newton step 2
        bundle(&[s(FMul, 2, 1, 1, 0)]),
        bundle(&[s(FMul, 2, 2, 0, 0)]),
        bundle(&[s(FSub, 2, 3, 2, 0)]),
        bundle(&[s(FMul, 1, 1, 2, 0), s(Halt, 0, 0, 0, 0)]),
    ])
    .unwrap()
}

fn rsqrt_scalar(x: f32) -> f32 {
    let x2 = x * 0.5;
    let mut y = f32::from_bits(0x5F37_59DF - (x.to_bits() >> 1));
    for _ in 0..2 {
        // Same association as the VM: (y * y) * x2, not (x2 * y) * y.
        y = y * (1.5 - (y * y) * x2);
    }
    y
}

#[test]
fn fast_inverse_sqrt() {
    let prog = rsqrt_program();
    println!("{}", disasm::listing(&prog));
    for xs in [[1.0f32, 2.0, 4.0, 10.0], [0.01, 123.456, 1e6, 3.0e-7]] {
        let mut vm = Vm::new(&[], 0, 20);
        vm.f[0] = f32x4(xs[0], xs[1], xs[2], xs[3]);
        vm.run(&prog).unwrap();
        let got = lanes(vm.f[1]).map(f32::from_bits);
        for l in 0..4 {
            // Bit-exact with the scalar version: same IEEE ops, same order, no FMA.
            assert_eq!(got[l].to_bits(), rsqrt_scalar(xs[l]).to_bits());
            let rel = (got[l] - 1.0 / xs[l].sqrt()).abs() * xs[l].sqrt();
            assert!(rel < 1e-5, "x={} got {} rel {rel}", xs[l], got[l]);
            println!("1/sqrt({}) = {} (rel err {rel:.1e})", xs[l], got[l]);
        }
    }
}

mod asm_tests {
    use super::*;
    use crate::asm::assemble;
    use crate::gadgets::{Challenge, Params};

    #[test]
    fn listings_round_trip() {
        let mut progs = vec![hashcash::program(16, 1000), rsqrt_program()];
        for seed in 0..20 {
            progs.push(puzzle::generate(seed, 4, 8, 8).program);
            progs.push(Challenge::new(seed, Params::default()).program);
        }
        for p in progs {
            let text = disasm::listing(&p);
            assert_eq!(assemble(&text).unwrap_or_else(|e| panic!("{e}\n{text}")), p);
        }
    }

    #[test]
    fn hashcash_from_source() {
        let src = r#"
            ; sha256(challenge || nonce) with 16 leading zero bits
                    li r12, 64 | li r14, 1000 | li r10, 15
            loop:   st [r0+32], r15 | addi r14, r14, -1
                    sha256 [r12], [r0]
                    ld r1, [r12]
                    bswap r3, r1
                    clz r3, r3
                    cmpltu p15, r10, r3 | cmplt p3, r0, r14
                    addi r11, r15, 0 ?p15 | addi r15, r15, 4 | pany p7, p15
                    bp p7, @done
                    bp p3, @loop
            done:   halt
        "#;
        assert_eq!(assemble(src).unwrap(), hashcash::program(16, 1000));
    }

    #[test]
    fn errors_point_at_the_line() {
        let cases = [
            ("halt\nadd r1, r2", "line 2: `add` takes 3 operands, got 2"),
            ("li r16, 1", "line 1: `r16` is out of range (r0..r15)"),
            ("fadd f0, f1, f4", "line 1: `f4` is out of range (f0..f3)"),
            ("bp p1, @nowhere", "line 1: undefined label `nowhere`"),
            ("frobnicate r1", "line 1: unknown instruction `frobnicate`"),
            ("nop\nbp p1, @0 | halt", "line 2: more than one control op in a bundle"),
            ("x:\nx: halt", "line 2: label `x` defined twice"),
            ("add r1, r1, r1 | add r1, r1, r1 | add r1, r1, r1 | add r1, r1, r1 | halt", "line 1: 5 slots in one bundle, max 4"),
            ("bp p1, @5\nhalt", "line 1: branch target @5 is past the end (2 bundles)"),
        ];
        for (src, want) in cases {
            assert_eq!(assemble(src).unwrap_err().to_string(), want, "{src}");
        }
    }
}

#[test]
fn opcode_numbering_is_a_permutation() {
    let bytes: std::collections::HashSet<u8> = Op::ALL.iter().map(|op| op.encode()).collect();
    assert_eq!(bytes.len(), Op::ALL.len(), "two opcodes share a byte");
    for &op in Op::ALL {
        assert_eq!(Op::decode(op.encode()), Some(op));
    }
    let unused = (0..=255u8).filter(|b| Op::decode(*b).is_none()).count();
    assert_eq!(unused, 256 - Op::ALL.len());
    println!("seed {:?}, fingerprint {:#018x}, halt = {:#04x}, subleq = {:#04x}",
        opcodes::OPCODE_SEED, opcodes::FINGERPRINT, Op::Halt.encode(), Op::Subleq.encode());
}
