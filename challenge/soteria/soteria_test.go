package soteria

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/TecharoHQ/anubis/lib/challenge"
	"github.com/TecharoHQ/anubis/lib/config"
	"github.com/TecharoHQ/anubis/lib/policy"
)

// difficulty is small so solving in tests is effectively instant.
const difficulty = 2

func setup(t testing.TB) *Impl {
	t.Helper()

	i := &Impl{}
	if err := i.Setup(http.NewServeMux()); err != nil {
		t.Fatalf("can't set up: %v", err)
	}
	return i
}

// solve finds nonces with the same client module browsers run.
func solve(t testing.TB, randomData []byte, difficulty int) []uint32 {
	t.Helper()

	client, err := newModule(t.Context(), clientWasm, "soteria_solve")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close(t.Context()) //nolint:errcheck

	p, err := NewParams(randomData, difficulty)
	if err != nil {
		t.Fatal(err)
	}

	nonces, err := client.Solve(t.Context(), p.Request(nil))
	if err != nil {
		t.Fatalf("can't solve: %v", err)
	}
	return nonces
}

func joinNonces(nonces []uint32) string {
	s := make([]string, len(nonces))
	for j, n := range nonces {
		s[j] = strconv.FormatUint(uint64(n), 10)
	}
	return strings.Join(s, ",")
}

func mkRequest(t *testing.T, values map[string]string) *http.Request {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	q := req.URL.Query()
	for k, v := range values {
		q.Set(k, v)
	}
	req.URL.RawQuery = q.Encode()
	return req
}

func bot(difficulty int) *policy.Bot {
	return &policy.Bot{
		Challenge: &config.ChallengeRules{
			Algorithm:  Method,
			Difficulty: difficulty,
		},
	}
}

func TestThreshold(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name       string
		difficulty int
		want       uint32
		err        error
	}{
		{name: "zero is free", difficulty: 0, want: 0xFFFFFFFF},
		{name: "one", difficulty: 1, want: 1 << 30},
		{name: "default", difficulty: 4, want: 1 << 18},
		{name: "max", difficulty: MaxDifficulty, want: 1 << 2},
		{name: "negative", difficulty: -1, err: ErrDifficulty},
		{name: "too high", difficulty: MaxDifficulty + 1, err: ErrDifficulty},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := threshold(tt.difficulty)
			if !errors.Is(err, tt.err) {
				t.Logf("want: %v", tt.err)
				t.Logf("got:  %v", err)
				t.Fatal("wrong error")
			}
			if got != tt.want {
				t.Errorf("threshold(%d) = %#x, want %#x", tt.difficulty, got, tt.want)
			}
		})
	}
}

// TestRequestLayout pins the encoder to the soteria::wire layout.
func TestRequestLayout(t *testing.T) {
	t.Parallel()

	p := &Params{
		Seed:       0x0102030405060708,
		Gadgets:    32,
		Mix:        [6]uint32{8, 3, 2, 3, 2, 1},
		Scratchpad: 1 << 14,
		Threshold:  1 << 24,
		Solutions:  4,
		Flags:      7,
	}
	for j := range p.Challenge {
		p.Challenge[j] = byte(j)
	}

	want, _ := hex.DecodeString("" +
		"0807060504030201" + // seed
		"20000000" + // gadgets
		"08000000" + "03000000" + "02000000" + "03000000" + "02000000" + "01000000" + // mix
		"00400000" + // scratchpad
		"00000001" + // threshold
		"04000000" + // solutions
		"07000000" + // flags
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" + // challenge
		"2a000000" + "ffffffff") // nonces

	got := p.Request([]uint32{42, 0xFFFFFFFF})
	if !bytes.Equal(got, want) {
		t.Logf("want: %x", want)
		t.Logf("got:  %x", got)
		t.Fatal("request layout changed")
	}
}

func TestNewParams(t *testing.T) {
	t.Parallel()

	if _, err := NewParams(make([]byte, minRandomData-1), 1); !errors.Is(err, ErrRandomData) {
		t.Errorf("short random data: got %v, want %v", err, ErrRandomData)
	}

	a, _ := NewParams(bytes.Repeat([]byte{1}, 64), 1)
	b, _ := NewParams(bytes.Repeat([]byte{2}, 64), 1)
	if a.Seed == b.Seed || a.Challenge == b.Challenge {
		t.Error("different random data gave the same seed or challenge")
	}
}

func TestSetupServesAssets(t *testing.T) {
	t.Parallel()

	i := &Impl{}
	mux := http.NewServeMux()
	if err := i.Setup(mux); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	for _, tt := range []struct {
		name        string
		file        string
		status      int
		contentType string
	}{
		{name: "client module", file: "soteria_client.wasm", status: http.StatusOK, contentType: "application/wasm"},
		{name: "page script", file: "main.js", status: http.StatusOK, contentType: "text/javascript; charset=utf-8"},
		{name: "worker", file: "worker.js", status: http.StatusOK, contentType: "text/javascript; charset=utf-8"},
		{name: "server module is private", file: "soteria_server.wasm", status: http.StatusNotFound},
		{name: "no directory listing", file: "", status: http.StatusNotFound},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := http.Get(srv.URL + assetPath() + tt.file)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()        //nolint:errcheck
			io.Copy(io.Discard, resp.Body) //nolint:errcheck

			if resp.StatusCode != tt.status {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.status)
			}
			if tt.contentType != "" && resp.Header.Get("Content-Type") != tt.contentType {
				t.Errorf("Content-Type = %q, want %q", resp.Header.Get("Content-Type"), tt.contentType)
			}
		})
	}
}

func TestIssue(t *testing.T) {
	t.Parallel()

	i := setup(t)
	randomData := sha256.Sum256([]byte(t.Name()))
	c := &challenge.Challenge{ID: "abc", RandomData: hex.EncodeToString(randomData[:])}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	comp, err := i.Issue(httptest.NewRecorder(), req, slog.New(slog.DiscardHandler), &challenge.IssueInput{
		Rule:      bot(4),
		Challenge: c,
	})
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := comp.Render(t.Context(), &buf); err != nil {
		t.Fatal(err)
	}

	p, _ := NewParams(randomData[:], 4)
	for _, want := range []string{
		`id="soteria_info"`,
		hex.EncodeToString(p.Request(nil)),
		i.fingerprint,
		"main.js?cacheBuster=" + i.cacheBuster,
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("page is missing %q", want)
		}
	}

	if _, err := i.Issue(httptest.NewRecorder(), req, slog.New(slog.DiscardHandler), &challenge.IssueInput{
		Rule:      bot(MaxDifficulty + 1),
		Challenge: c,
	}); !errors.Is(err, ErrDifficulty) {
		t.Errorf("too-high difficulty: got %v, want %v", err, ErrDifficulty)
	}
}

// TestValidateAdversarial feeds Validate malformed and hostile input. Anubis
// accepts a challenge when Validate's error wraps none of ErrFailed,
// ErrInvalidFormat or ErrMissingField, so every failure is checked for one.
func TestValidateAdversarial(t *testing.T) {
	t.Parallel()

	i := setup(t)
	lg := slog.New(slog.DiscardHandler)

	randomData := sha256.Sum256([]byte(t.Name()))
	randomHex := hex.EncodeToString(randomData[:])
	nonces := solve(t, randomData[:], difficulty)
	good := joinNonces(nonces)

	wrong := append([]uint32(nil), nonces...)
	wrong[len(wrong)-1]++

	goodInput := func() *challenge.ValidateInput {
		return &challenge.ValidateInput{
			Rule:      bot(difficulty),
			Challenge: &challenge.Challenge{RandomData: randomHex},
		}
	}

	values := func(overrides ...string) map[string]string {
		v := map[string]string{
			"nonces":      good,
			"fingerprint": i.fingerprint,
			"elapsedTime": "42",
		}
		for j := 0; j < len(overrides); j += 2 {
			if overrides[j+1] == "" {
				delete(v, overrides[j])
			} else {
				v[overrides[j]] = overrides[j+1]
			}
		}
		return v
	}

	for _, tt := range []struct {
		name   string
		values map[string]string
		input  *challenge.ValidateInput
		err    error // nil means the solution must pass
	}{
		{name: "valid solution passes", values: values(), input: goodInput()},
		{name: "no fields", values: map[string]string{}, input: goodInput(), err: challenge.ErrMissingField},
		{name: "missing nonces", values: values("nonces", ""), input: goodInput(), err: challenge.ErrMissingField},
		{name: "missing fingerprint", values: values("fingerprint", ""), input: goodInput(), err: challenge.ErrMissingField},
		{name: "missing elapsedTime", values: values("elapsedTime", ""), input: goodInput(), err: challenge.ErrMissingField},
		{name: "elapsedTime not a number", values: values("elapsedTime", "taco"), input: goodInput(), err: challenge.ErrInvalidFormat},
		{name: "nonce not an integer", values: values("nonces", "1,2,3,taco"), input: goodInput(), err: challenge.ErrInvalidFormat},
		{name: "nonce overflows u32", values: values("nonces", "1,2,3,4294967296"), input: goodInput(), err: challenge.ErrInvalidFormat},
		{name: "negative nonce", values: values("nonces", "1,2,3,-4"), input: goodInput(), err: challenge.ErrInvalidFormat},
		{name: "too few nonces", values: values("nonces", joinNonces(nonces[:len(nonces)-1])), input: goodInput(), err: challenge.ErrInvalidFormat},
		{name: "too many nonces", values: values("nonces", good+",0"), input: goodInput(), err: challenge.ErrInvalidFormat},
		{name: "wrong nonce", values: values("nonces", joinNonces(wrong)), input: goodInput(), err: challenge.ErrFailed},
		{name: "reordered nonces", values: values("nonces", joinNonces([]uint32{nonces[1], nonces[0], nonces[2], nonces[3]})), input: goodInput(), err: challenge.ErrFailed},
		{name: "stale fingerprint", values: values("fingerprint", "0000000000000000"), input: goodInput(), err: challenge.ErrFailed},
		{
			name:   "solved at a lower difficulty",
			values: values(),
			input: &challenge.ValidateInput{
				Rule:      bot(MaxDifficulty),
				Challenge: &challenge.Challenge{RandomData: randomHex},
			},
			err: challenge.ErrFailed,
		},
		{
			name:   "difficulty out of range",
			values: values(),
			input: &challenge.ValidateInput{
				Rule:      bot(MaxDifficulty + 1),
				Challenge: &challenge.Challenge{RandomData: randomHex},
			},
			err: challenge.ErrInvalidFormat,
		},
		{
			name:   "random data not hex",
			values: values(),
			input: &challenge.ValidateInput{
				Rule:      bot(difficulty),
				Challenge: &challenge.Challenge{RandomData: "zz"},
			},
			err: challenge.ErrInvalidFormat,
		},
		{
			name:   "different challenge",
			values: values(),
			input: &challenge.ValidateInput{
				Rule:      bot(difficulty),
				Challenge: &challenge.Challenge{RandomData: strings.Repeat("00", 32)},
			},
			err: challenge.ErrFailed,
		},
		{name: "nil input", values: values(), input: nil, err: challenge.ErrInvalidInput},
		{name: "nil rule", values: values(), input: &challenge.ValidateInput{Challenge: &challenge.Challenge{RandomData: randomHex}}, err: challenge.ErrInvalidInput},
		{name: "nil rule challenge", values: values(), input: &challenge.ValidateInput{Rule: &policy.Bot{}, Challenge: &challenge.Challenge{RandomData: randomHex}}, err: challenge.ErrInvalidInput},
		{name: "nil challenge", values: values(), input: &challenge.ValidateInput{Rule: bot(difficulty)}, err: challenge.ErrInvalidInput},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := i.Validate(mkRequest(t, tt.values), lg, tt.input)

			if tt.err == nil {
				if err != nil {
					t.Fatalf("valid solution rejected: %v", err)
				}
				return
			}

			if !errors.Is(err, tt.err) {
				t.Logf("want: %v", tt.err)
				t.Logf("got:  %v", err)
				t.Fatal("wrong error")
			}

			var cerr *challenge.Error
			if !errors.As(err, &cerr) {
				t.Errorf("error is not a *challenge.Error: %v", err)
			}
			if !errors.Is(err, challenge.ErrFailed) && !errors.Is(err, challenge.ErrInvalidFormat) && !errors.Is(err, challenge.ErrMissingField) {
				t.Errorf("Anubis would accept this failure: %v", err)
			}
		})
	}
}

// TestSolveVerifyManyChallenges runs many random challenges through the
// client module and Validate, across program seeds.
func TestSolveVerifyManyChallenges(t *testing.T) {
	t.Parallel()

	n := 100
	if testing.Short() {
		n = 10
	}

	i := setup(t)
	lg := slog.New(slog.DiscardHandler)

	for j := range n {
		randomData := sha256.Sum256(fmt.Appendf(nil, "%s-%d", t.Name(), j))
		nonces := solve(t, randomData[:], difficulty)

		req := mkRequest(t, map[string]string{
			"nonces":      joinNonces(nonces),
			"fingerprint": i.fingerprint,
			"elapsedTime": "42",
		})
		in := &challenge.ValidateInput{
			Rule:      bot(difficulty),
			Challenge: &challenge.Challenge{RandomData: hex.EncodeToString(randomData[:])},
		}

		if err := i.Validate(req, lg, in); err != nil {
			t.Fatalf("challenge %d failed to validate: %v", j, err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	i := setup(b)

	randomData := sha256.Sum256([]byte(b.Name()))
	p, _ := NewParams(randomData[:], 4)
	req := p.Request(solve(b, randomData[:], 4))

	for b.Loop() {
		ok, err := i.server.Verify(b.Context(), req)
		if err != nil || !ok {
			b.Fatalf("verify = %v, %v", ok, err)
		}
	}
}
