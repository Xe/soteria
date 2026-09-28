package soteria

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

var (
	ErrMissingExport = errors.New("soteria: module is missing an export")
	ErrModule        = errors.New("soteria: module returned an error code")
)

// module is one compiled Soteria core module (client or server). Every call
// gets a fresh anonymous instance, so no state leaks between requests and
// calls can run concurrently.
type module struct {
	code wazero.CompiledModule
}

// wasmRuntime is shared by every module. It lives for the whole process:
// wazero.NewRuntime lazily sets a package global without locking, so
// creating runtimes concurrently is a data race.
var wasmRuntime = sync.OnceValue(func() wazero.Runtime {
	// CloseOnContextDone makes a context deadline interrupt a running call.
	// The modules need well under 1 MiB; 64 pages is a cap, not a reservation.
	cfg := wazero.NewRuntimeConfig().
		WithCloseOnContextDone(true).
		WithMemoryLimitPages(64)

	return wazero.NewRuntimeWithConfig(context.Background(), cfg)
})

func newModule(ctx context.Context, wasm []byte, exports ...string) (*module, error) {
	code, err := wasmRuntime().CompileModule(ctx, wasm)
	if err != nil {
		return nil, fmt.Errorf("soteria: can't compile module: %w", err)
	}

	defined := code.ExportedFunctions()
	for _, name := range append([]string{"soteria_alloc", "soteria_fingerprint"}, exports...) {
		if _, ok := defined[name]; !ok {
			code.Close(ctx) //nolint:errcheck
			return nil, fmt.Errorf("%w: %s", ErrMissingExport, name)
		}
	}

	return &module{code: code}, nil
}

func (m *module) Close(ctx context.Context) error {
	return m.code.Close(ctx)
}

// with runs fn against a fresh instance and closes it afterwards.
func (m *module) with(ctx context.Context, fn func(api.Module) error) error {
	inst, err := wasmRuntime().InstantiateModule(ctx, m.code, wazero.NewModuleConfig().WithName(""))
	if err != nil {
		return fmt.Errorf("soteria: can't instantiate module: %w", err)
	}
	defer inst.Close(ctx) //nolint:errcheck

	return fn(inst)
}

// Fingerprint is the opcode numbering the module was built with.
func (m *module) Fingerprint(ctx context.Context) (uint64, error) {
	var fp uint64
	err := m.with(ctx, func(inst api.Module) error {
		res, err := inst.ExportedFunction("soteria_fingerprint").Call(ctx)
		if err != nil {
			return fmt.Errorf("soteria: soteria_fingerprint: %w", err)
		}
		fp = res[0]
		return nil
	})
	return fp, err
}

// submit copies req into a buffer from soteria_alloc and returns its
// address. The export it is passed to frees it.
func submit(ctx context.Context, inst api.Module, req []byte) (uint32, error) {
	res, err := inst.ExportedFunction("soteria_alloc").Call(ctx, uint64(len(req)))
	if err != nil {
		return 0, fmt.Errorf("soteria: soteria_alloc: %w", err)
	}
	ptr := uint32(res[0])
	if !inst.Memory().Write(ptr, req) {
		return 0, fmt.Errorf("soteria: request buffer at %d is out of range", ptr)
	}
	return ptr, nil
}

// Verify runs soteria_verify on a request that carries nonces.
func (m *module) Verify(ctx context.Context, req []byte) (bool, error) {
	var ok bool
	err := m.with(ctx, func(inst api.Module) error {
		ptr, err := submit(ctx, inst, req)
		if err != nil {
			return err
		}
		res, err := inst.ExportedFunction("soteria_verify").Call(ctx, uint64(ptr), uint64(len(req)))
		if err != nil {
			return fmt.Errorf("soteria: soteria_verify: %w", err)
		}
		switch code := int32(res[0]); code {
		case 0, 1:
			ok = code == 1
			return nil
		default:
			return fmt.Errorf("%w: soteria_verify: %d", ErrModule, code)
		}
	})
	return ok, err
}

// Solve runs a threshold-mode job to completion with the client module. The
// server never calls this; it exists so tests and tools can produce proofs
// with the same code browsers run.
func (m *module) Solve(ctx context.Context, req []byte) ([]uint32, error) {
	var nonces []uint32
	err := m.with(ctx, func(inst api.Module) error {
		ptr, err := submit(ctx, inst, req)
		if err != nil {
			return err
		}
		res, err := inst.ExportedFunction("soteria_solve").Call(ctx, uint64(ptr), uint64(len(req)))
		if err != nil {
			return fmt.Errorf("soteria: soteria_solve: %w", err)
		}
		if code := int32(res[0]); code != 0 {
			return fmt.Errorf("%w: soteria_solve: %d", ErrModule, code)
		}

		step := inst.ExportedFunction("soteria_step")
		for {
			res, err := step.Call(ctx, 256)
			if err != nil {
				return fmt.Errorf("soteria: soteria_step: %w", err)
			}
			code := int32(res[0])
			if code == 1 {
				break
			}
			if code != 0 {
				return fmt.Errorf("%w: soteria_step: %d", ErrModule, code)
			}
		}

		res, err = inst.ExportedFunction("soteria_nonces").Call(ctx)
		if err != nil {
			return fmt.Errorf("soteria: soteria_nonces: %w", err)
		}
		ptr = uint32(res[0])
		res, err = inst.ExportedFunction("soteria_nonces_len").Call(ctx)
		if err != nil {
			return fmt.Errorf("soteria: soteria_nonces_len: %w", err)
		}
		n := uint32(res[0])
		buf, ok := inst.Memory().Read(ptr, n*4)
		if !ok {
			return fmt.Errorf("soteria: nonce buffer at %d is out of range", ptr)
		}
		for i := range n {
			nonces = append(nonces, binary.LittleEndian.Uint32(buf[i*4:]))
		}
		return nil
	})
	return nonces, err
}
