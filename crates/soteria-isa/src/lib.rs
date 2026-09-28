//! Soteria's instruction set: opcodes, the 8-byte slot encoding, bundles and
//! validated programs, plus the assembler, disassembler and list scheduler.
//! Target-independent, so tools can run natively; the VM that executes
//! programs lives in the `soteria` crate.

pub mod asm;
pub mod disasm;
pub mod sched;

pub const LANES: usize = 4;
/// Bytes of memory per lane. Addresses are masked to 20 bits.
pub const MEM_SIZE: usize = 1 << 20;
pub const NONCE_REG: usize = 15;
pub const RESULT_PRED: usize = 15;
pub const SLOTS: usize = 4;
pub const SLOT_BYTES: usize = 8;
pub const BUNDLE_BYTES: usize = SLOTS * SLOT_BYTES;

macro_rules! ops {
    ($($(#[$doc:meta])* $name:ident),* $(,)?) => {
        #[repr(u8)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Op { $($(#[$doc])* $name),* }
        impl Op {
            pub const ALL: &'static [Op] = &[$(Op::$name),*];
        }
    };
}

ops! {
    Nop,
    /// Stop the machine after this bundle commits. Must be lane-uniform.
    Halt,
    /// rd = imm
    Li,
    /// rd = ra + imm
    Addi,
    /// rd = ra OP rb
    Add, Sub, Mul, Xor, And, Or,
    /// rd = ra OP (imm & 31). Shift amounts are immediates because WASM SIMD
    /// only shifts all lanes by the same scalar amount.
    Shl, Shr, Rotr,
    /// rd = count_leading_zeros(ra)
    Clz,
    /// rd = mem32[(ra + imm) & 0xFFFFC]
    Ld,
    /// mem32[(ra + imm) & 0xFFFFC] = rb
    St,
    /// mem[rb & 0xFFFE0 ..][..32] = sha256(mem[ra & 0xFFFC0 ..][..64])
    Sha256,
    /// pd = ra OP rb (signed, signed, unsigned)
    CmpEq, CmpLt, CmpLtu,
    /// pd = pa OP pb
    PAnd, POr, PXor,
    /// pd = !pa
    PNot,
    /// fd = ra as f32
    FCvt,
    /// fd = fa OP fb (NaNs are canonicalized)
    FAdd, FSub, FMul, FDiv,
    /// fd = sqrt(fa)
    FSqrt,
    /// pd = fa < fb
    FLt,
    /// rd = fa as i32 (saturating, NaN -> 0)
    FTrunc,
    /// rb -= ra; if rb <= 0 { pc = imm }. The only branch. Must be lane-uniform.
    Subleq,
    /// if pa { pc = imm }. Must be lane-uniform.
    Bp,
    /// pd = any lane of pa is true, broadcast to every lane. The only
    /// cross-lane op; it makes a per-lane result safe to branch on.
    PAny,
    /// rd = byte-reversed ra (one i8x16 shuffle)
    Bswap,
    /// rd = number of set bits in ra
    Popcnt,
    /// rd = bits of fa. Deterministic because float writes are canonicalized.
    FBits,
    /// fd = ra reinterpreted as f32. Any odd NaN payload is canonicalized by
    /// the next float arithmetic op that consumes it.
    FFrom,
    /// mem[rb & 0xFFFE0 ..][..32] = fold(mem[0 .. (ra & 0xFFFFF) + 1]).
    /// Makes every byte of the scratchpad reach the digest, so stores that
    /// are never loaded again can't be deleted as dead code.
    Fold,
    /// mem[128 .. (ra & 0xFFFFF) + 1] = expand(mem[rb & 0xFFFE0 ..][..32]).
    /// Fills the arena from a per-attempt key, so memory differs per nonce.
    Fill,
    /// rd = (ra as u64 * rb as u64) >> 32, the high half of an unsigned
    /// multiply (two `u64x2.extmul` and a shuffle).
    Mulhu,
    /// rd = pa ? -1 : 0
    PMov,
}

/// This build's opcode numbering (see build.rs).
pub mod opcodes {
    include!(concat!(env!("OUT_DIR"), "/opcodes.rs"));

    /// Encoded byte -> opcode index: the inverse permutation.
    pub const INV: [u8; 256] = {
        let mut inv = [0u8; 256];
        let mut i = 0;
        while i < 256 {
            inv[PERM[i] as usize] = i as u8;
            i += 1;
        }
        inv
    };

    /// FNV-1a over the bytes actually used by opcodes. Put this in the
    /// challenge so a client from another build fails fast instead of
    /// producing garbage.
    pub const FINGERPRINT: u64 = {
        let mut h: u64 = 0xCBF2_9CE4_8422_2325;
        let mut i = 0;
        while i < super::Op::ALL.len() {
            h ^= PERM[i] as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01B3);
            i += 1;
        }
        h
    };
}

impl Op {
    /// This build's byte for the opcode.
    pub fn encode(self) -> u8 {
        opcodes::PERM[self as usize]
    }

    /// Bytes not assigned to an opcode in this build decode to None.
    pub fn decode(b: u8) -> Option<Op> {
        Op::ALL.get(opcodes::INV[b as usize] as usize).copied()
    }

    fn is_control(self) -> bool {
        matches!(self, Op::Halt | Op::Subleq | Op::Bp)
    }
}

/// One slot. Wire format (8 bytes): `op, guard, d, a<<4 | b, imm (i32 LE)`.
/// `guard` bits 0-3 pick a predicate register, bit 4 negates it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot {
    pub op: Op,
    pub guard: u8,
    pub d: u8,
    pub a: u8,
    pub b: u8,
    pub imm: i32,
}

pub const NOP: Slot = Slot {
    op: Op::Nop,
    guard: 0,
    d: 0,
    a: 0,
    b: 0,
    imm: 0,
};

impl Slot {
    pub const fn new(op: Op, d: u8, a: u8, b: u8, imm: i32) -> Self {
        Slot {
            op,
            guard: 0,
            d: d & 15,
            a: a & 15,
            b: b & 15,
            imm,
        }
    }
    /// Only commit in lanes where `p` is true.
    pub const fn when(mut self, p: u8) -> Self {
        self.guard = p & 15;
        self
    }
    /// Only commit in lanes where `p` is false.
    pub const fn unless(mut self, p: u8) -> Self {
        self.guard = (p & 15) | 0x10;
        self
    }
}

pub type Bundle = [Slot; SLOTS];

/// Pad a partial bundle with NOPs.
pub fn bundle(slots: &[Slot]) -> Bundle {
    assert!(slots.len() <= SLOTS);
    core::array::from_fn(|i| slots.get(i).copied().unwrap_or(NOP))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    BadLength,
    BadOpcode(u8),
    BadGuard(u8),
    MultipleControlOps { bundle: usize },
    PcOutOfRange(u32),
    DivergentControl { pc: u32 },
    OutOfFuel,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Error::BadLength => write!(
                f,
                "length is not a whole number of {BUNDLE_BYTES}-byte bundles"
            ),
            Error::BadOpcode(b) => write!(f, "byte {b:#04x} is not an opcode in this build"),
            Error::BadGuard(g) => write!(f, "guard byte {g:#04x} has bits above 4 set"),
            Error::MultipleControlOps { bundle } => {
                write!(f, "bundle {bundle} has more than one control op")
            }
            Error::PcOutOfRange(pc) => write!(f, "pc {pc} is past the end of the program"),
            Error::DivergentControl { pc } => {
                write!(f, "lanes disagree on control flow at pc {pc}")
            }
            Error::OutOfFuel => write!(f, "out of fuel"),
        }
    }
}

impl std::error::Error for Error {}

/// A validated program: at most one control op per bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program(Vec<Bundle>);

impl Program {
    pub fn new(bundles: Vec<Bundle>) -> Result<Self, Error> {
        for (i, b) in bundles.iter().enumerate() {
            if b.iter().filter(|s| s.op.is_control()).count() > 1 {
                return Err(Error::MultipleControlOps { bundle: i });
            }
        }
        Ok(Program(bundles))
    }

    pub fn bundles(&self) -> &[Bundle] {
        &self.0
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.0.len() * BUNDLE_BYTES);
        for s in self.0.iter().flatten() {
            out.extend_from_slice(&[s.op.encode(), s.guard, s.d, s.a << 4 | s.b]);
            out.extend_from_slice(&s.imm.to_le_bytes());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() % BUNDLE_BYTES != 0 {
            return Err(Error::BadLength);
        }
        let slot = |c: &[u8]| -> Result<Slot, Error> {
            let op = Op::decode(c[0]).ok_or(Error::BadOpcode(c[0]))?;
            if c[1] & !0x1F != 0 {
                return Err(Error::BadGuard(c[1]));
            }
            Ok(Slot {
                op,
                guard: c[1],
                d: c[2] & 15,
                a: c[3] >> 4,
                b: c[3] & 15,
                imm: i32::from_le_bytes(c[4..8].try_into().unwrap()),
            })
        };
        let bundles = bytes
            .chunks_exact(BUNDLE_BYTES)
            .map(|b| {
                let s: Vec<Slot> = b
                    .chunks_exact(SLOT_BYTES)
                    .map(slot)
                    .collect::<Result<_, _>>()?;
                Ok(bundle(&s))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Program::new(bundles)
    }
}
