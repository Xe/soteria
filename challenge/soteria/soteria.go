// Package soteria is an Anubis challenge method backed by the Soteria VM.
//
// Import it for its side effect of registering the "soteria" method:
//
//	import _ "github.com/Xe/soteria/challenge/soteria"
//
// The browser runs soteria_client.wasm in a Web Worker to find nonces, and
// the server checks them with soteria_server.wasm under wazero. Both modules
// are embedded, and are rebuilt with go generate.
package soteria

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TecharoHQ/anubis"
	chall "github.com/TecharoHQ/anubis/lib/challenge"
	"github.com/TecharoHQ/anubis/lib/localization"
	mrc "github.com/TecharoHQ/mobile-request-classifier"
	"github.com/a-h/templ"
)

//go:generate ./build.sh
//go:generate go tool github.com/a-h/templ/cmd/templ generate --log-level=error

// Method is the algorithm name to use in Anubis policy files.
const Method = "soteria"

// verifyTimeout bounds one verification. A valid proof takes a few
// milliseconds; this only stops a pathological one from pinning a core.
const verifyTimeout = 5 * time.Second

var (
	//go:embed static
	staticFS embed.FS

	//go:embed static/soteria_client.wasm
	clientWasm []byte

	//go:embed static/soteria_server.wasm
	serverWasm []byte
)

func init() {
	chall.Register(Method, &Impl{})
}

// Impl implements chall.Impl.
type Impl struct {
	once     sync.Once
	setupErr error

	server      *module
	classifier  *mrc.Middleware
	fingerprint string
	cacheBuster string
}

// assetPath is where Setup mounts the worker, page script and client module.
func assetPath() string {
	return strings.TrimSuffix(anubis.BasePrefix, "/") + anubis.StaticPath + "soteria/"
}

// init compiles the server module once. Anubis calls Setup for every mux it
// builds, so this must be idempotent.
func (i *Impl) init(ctx context.Context) error {
	i.once.Do(func() {
		i.setupErr = i.load(ctx)
	})
	return i.setupErr
}

func (i *Impl) load(ctx context.Context) error {
	server, err := newModule(ctx, serverWasm, "soteria_verify")
	if err != nil {
		return fmt.Errorf("server module: %w", err)
	}

	client, err := newModule(ctx, clientWasm, "soteria_solve", "soteria_step", "soteria_nonces", "soteria_nonces_len")
	if err != nil {
		server.Close(ctx) //nolint:errcheck
		return fmt.Errorf("client module: %w", err)
	}
	defer client.Close(ctx) //nolint:errcheck

	// The opcode numbering is shuffled per build. Modules from different
	// builds would disagree on every program, so refuse to start.
	sfp, err := server.Fingerprint(ctx)
	if err != nil {
		server.Close(ctx) //nolint:errcheck
		return err
	}
	cfp, err := client.Fingerprint(ctx)
	if err != nil {
		server.Close(ctx) //nolint:errcheck
		return err
	}
	if sfp != cfp {
		server.Close(ctx) //nolint:errcheck
		return fmt.Errorf("soteria: client fingerprint %016x != server fingerprint %016x, rerun go generate", cfp, sfp)
	}

	h := sha256.New()
	for _, name := range []string{"static/soteria_client.wasm", "static/main.js", "static/worker.js"} {
		data, err := staticFS.ReadFile(name)
		if err != nil {
			server.Close(ctx) //nolint:errcheck
			return fmt.Errorf("soteria: can't read %s: %w", name, err)
		}
		h.Write(data)
	}

	// Its own wazero runtime; this runs once, so it can't race ours.
	classifier, err := newClassifier(ctx)
	if err != nil {
		server.Close(ctx) //nolint:errcheck
		return fmt.Errorf("soteria: can't load the mobile request classifier: %w", err)
	}

	i.server = server
	i.classifier = classifier
	i.fingerprint = fmt.Sprintf("%016x", sfp)
	i.cacheBuster = hex.EncodeToString(h.Sum(nil))[:16]
	return nil
}

func (i *Impl) Setup(mux *http.ServeMux) error {
	if err := i.init(context.Background()); err != nil {
		return err
	}

	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return err
	}

	files := http.StripPrefix(assetPath(), http.FileServerFS(sub))
	mux.Handle("GET "+assetPath(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimPrefix(r.URL.Path, assetPath()) {
		case "main.js", "worker.js", "soteria_client.wasm":
		default:
			// Don't serve the server module or directory listings.
			http.NotFound(w, r)
			return
		}
		// Asset URLs carry a content hash, so they can be cached forever.
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		files.ServeHTTP(w, r)
	}))

	return nil
}

// info is what the page script needs, rendered as JSON into the page.
type info struct {
	Request     string            `json:"request"` // hex soteria::wire header
	Difficulty  int               `json:"difficulty"`
	Threshold   uint32            `json:"threshold"`
	Solutions   uint32            `json:"solutions"`
	Fingerprint string            `json:"fingerprint"`
	WorkerURL   string            `json:"workerURL"`
	WasmURL     string            `json:"wasmURL"`
	PassURL     string            `json:"passURL"`
	Strings     map[string]string `json:"strings"`
}

func (i *Impl) Issue(w http.ResponseWriter, r *http.Request, lg *slog.Logger, in *chall.IssueInput) (templ.Component, error) {
	if err := in.Valid(); err != nil {
		return nil, err
	}
	if err := i.init(r.Context()); err != nil {
		return nil, err
	}

	difficulty := in.Rule.Challenge.Difficulty
	phone := i.isPhone(r, lg, in)
	p, err := paramsFor(in.Challenge, difficulty, phone)
	if err != nil {
		return nil, err
	}
	if phone {
		difficulty = PhoneDifficulty(difficulty)
	}

	loc := localization.GetLocalizer(r)
	asset := func(name string) string {
		return assetPath() + name + "?cacheBuster=" + i.cacheBuster
	}

	data := info{
		Request:     hex.EncodeToString(p.Request(nil)),
		Difficulty:  difficulty,
		Threshold:   p.Threshold,
		Solutions:   p.Solutions,
		Fingerprint: i.fingerprint,
		WorkerURL:   asset("worker.js"),
		WasmURL:     asset("soteria_client.wasm"),
		PassURL:     strings.TrimSuffix(anubis.BasePrefix, "/") + anubis.APIPrefix + "pass-challenge",
		Strings: map[string]string{
			"calculating":           loc.T("js_calculating_difficulty"),
			"verification_longer":   loc.T("js_verification_longer"),
			"calculation_error":     loc.T("js_calculation_error"),
			"calculation_error_msg": loc.T("js_calculation_error_msg"),
			"missing_feature":       loc.T("js_missing_feature"),
			"web_workers_error":     loc.T("js_web_workers_error"),
		},
	}

	return page(loc, data, asset("main.js")), nil
}

func (i *Impl) Validate(r *http.Request, lg *slog.Logger, in *chall.ValidateInput) error {
	// XXX(Xe): Anubis' PassChallenge only rejects errors that wrap ErrFailed,
	// ErrInvalidFormat or ErrMissingField. Anything else falls through to a
	// pass, so every error returned here must wrap one of those three.
	if err := in.Valid(); err != nil {
		return chall.NewError("validate", "invalid input", fmt.Errorf("%w: %w", chall.ErrInvalidFormat, err))
	}
	if err := i.init(r.Context()); err != nil {
		return chall.NewError("validate", "internal error", fmt.Errorf("%w: %w", chall.ErrFailed, err))
	}

	noncesStr := r.FormValue("nonces")
	if noncesStr == "" {
		return chall.NewError("validate", "invalid response", fmt.Errorf("%w nonces", chall.ErrMissingField))
	}

	fingerprint := r.FormValue("fingerprint")
	if fingerprint == "" {
		return chall.NewError("validate", "invalid response", fmt.Errorf("%w fingerprint", chall.ErrMissingField))
	}

	elapsedTimeStr := r.FormValue("elapsedTime")
	if elapsedTimeStr == "" {
		return chall.NewError("validate", "invalid response", fmt.Errorf("%w elapsedTime", chall.ErrMissingField))
	}

	elapsedTime, err := strconv.ParseFloat(elapsedTimeStr, 64)
	if err != nil {
		return chall.NewError("validate", "invalid response", fmt.Errorf("%w: elapsedTime: %w", chall.ErrInvalidFormat, err))
	}

	phone := wasPhone(r.Context(), lg, in.Store, in.Challenge.ID)
	p, err := paramsFor(in.Challenge, in.Rule.Challenge.Difficulty, phone)
	if err != nil {
		return chall.NewError("validate", "invalid challenge", fmt.Errorf("%w: %w", chall.ErrInvalidFormat, err))
	}

	fields := strings.Split(noncesStr, ",")
	if len(fields) != int(p.Solutions) {
		return chall.NewError("validate", "invalid response", fmt.Errorf("%w: got %d nonces, want %d", chall.ErrInvalidFormat, len(fields), p.Solutions))
	}

	nonces := make([]uint32, len(fields))
	for j, f := range fields {
		n, err := strconv.ParseUint(f, 10, 32)
		if err != nil {
			return chall.NewError("validate", "invalid response", fmt.Errorf("%w: nonce %d: %w", chall.ErrInvalidFormat, j, err))
		}
		nonces[j] = uint32(n)
	}

	// A cached client module from an older build: its nonces are for
	// different programs and can't verify.
	if fingerprint != i.fingerprint {
		return chall.NewError("validate", "outdated client, reload the page", fmt.Errorf("%w: client fingerprint %q, want %q", chall.ErrFailed, fingerprint, i.fingerprint))
	}

	ctx, cancel := context.WithTimeout(r.Context(), verifyTimeout)
	defer cancel()

	ok, err := i.server.Verify(ctx, p.Request(nonces))
	if err != nil {
		return chall.NewError("validate", "internal error", fmt.Errorf("%w: can't run verifier: %w", chall.ErrFailed, err))
	}

	if !ok {
		return chall.NewError("verify", "client calculated wrong data", fmt.Errorf("%w: nonces %v rejected", chall.ErrFailed, nonces))
	}

	lg.DebugContext(r.Context(), "challenge took", "elapsedTime", elapsedTime)
	chall.TimeTaken.WithLabelValues(Method).Observe(elapsedTime)

	return nil
}

// paramsFor derives c's params, with the phone discount if phone.
func paramsFor(c *chall.Challenge, difficulty int, phone bool) (*Params, error) {
	randomData, err := hex.DecodeString(c.RandomData)
	if err != nil {
		return nil, fmt.Errorf("soteria: can't decode random data: %w", err)
	}
	if phone {
		return NewPhoneParams(randomData, difficulty)
	}
	return NewParams(randomData, difficulty)
}
