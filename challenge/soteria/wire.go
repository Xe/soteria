package soteria

import (
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
)

// These mirror soteria::wire. The layout is pinned by request_layout_is_stable
// on the Rust side.
const (
	headerSize = 84

	flagChained = 1 << 0
	flagFold    = 1 << 1
	flagFill    = 1 << 2

	// flagBlockShift positions Params::block (log2 nonces per program)
	// in bits 8..16 of the flags.
	flagBlockShift = 8
)

// blockBits is log2 of the nonces that share a program. Building a program
// costs about half a batch (2 attempts), so 256-nonce blocks add about 1% to
// an honest client, while an attacker who compiles programs has to compile
// one every 256 nonces instead of once per challenge.
const blockBits = 8

// Solutions per challenge. More solutions at a higher threshold is the same
// expected work with less variance, which matters for slow phones.
const (
	solutions    = 4
	solutionBits = 2 // log2(solutions)
)

// MaxDifficulty is the highest difficulty whose per-solution threshold keeps
// at least one bit, so a solution is expected well inside the nonce space.
const MaxDifficulty = 31 + solutionBits

var (
	ErrDifficulty = errors.New("soteria: difficulty out of range")
	ErrRandomData = errors.New("soteria: random data is too short")
)

// minRandomData is the least random data NewParams accepts: 128 bits.
const minRandomData = 16

// Params are the per-challenge knobs sent to the modules. Everything but
// Threshold and the block size uses the Rust defaults
// (gadgets::Params::default).
type Params struct {
	Seed       uint64
	Gadgets    uint32
	Mix        [6]uint32 // alu, taps, float, memory, lanes, sha
	Scratchpad uint32
	Threshold  uint32
	Solutions  uint32
	Flags      uint32
	Challenge  [32]byte
}

// threshold maps an Anubis difficulty to a per-solution threshold so that
// the expected attempts over all solutions is 2^difficulty. Difficulty is in
// bits, not the sha256 method's hex digits (16^difficulty): one attempt is
// far more work than one SHA-256, so a factor of 16 per step is too coarse.
// Difficulty 4n asks for as many attempts as sha256 difficulty n.
func threshold(difficulty int) (uint32, error) {
	if difficulty < 0 || difficulty > MaxDifficulty {
		return 0, fmt.Errorf("%w: %d not in 0..%d", ErrDifficulty, difficulty, MaxDifficulty)
	}
	bits := difficulty - solutionBits
	if bits <= 0 {
		return ^uint32(0), nil
	}
	return 1 << (32 - bits), nil
}

// NewParams derives a challenge from Anubis' random data (64 bytes from
// issueChallenge). With h = sha512(randomData), the program seed is h[0..8]
// little-endian and the challenge bytes are h[32..64].
func NewParams(randomData []byte, difficulty int) (*Params, error) {
	if len(randomData) < minRandomData {
		return nil, fmt.Errorf("%w: got %d bytes, want at least %d", ErrRandomData, len(randomData), minRandomData)
	}

	t, err := threshold(difficulty)
	if err != nil {
		return nil, err
	}

	h := sha512.Sum512(randomData)

	p := &Params{
		Seed:       binary.LittleEndian.Uint64(h[:8]),
		Gadgets:    32,
		Mix:        [6]uint32{8, 3, 2, 3, 2, 1},
		Scratchpad: 1 << 14,
		Threshold:  t,
		Solutions:  solutions,
		Flags:      flagChained | flagFold | flagFill | blockBits<<flagBlockShift,
	}
	copy(p.Challenge[:], h[32:64])

	return p, nil
}

// Request encodes p and nonces in the soteria::wire layout.
func (p *Params) Request(nonces []uint32) []byte {
	b := make([]byte, headerSize, headerSize+4*len(nonces))
	le := binary.LittleEndian

	le.PutUint64(b[0:], p.Seed)
	le.PutUint32(b[8:], p.Gadgets)
	for i, w := range p.Mix {
		le.PutUint32(b[12+4*i:], w)
	}
	le.PutUint32(b[36:], p.Scratchpad)
	le.PutUint32(b[40:], p.Threshold)
	le.PutUint32(b[44:], p.Solutions)
	le.PutUint32(b[48:], p.Flags)
	copy(b[52:], p.Challenge[:])

	for _, n := range nonces {
		b = le.AppendUint32(b, n)
	}

	return b
}
