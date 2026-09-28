// Soteria solver worker. The page posts {module, request}: a compiled
// soteria_client.wasm and the soteria::wire request header. The worker posts
// {attempts} while it runs, then {nonces, fingerprint} or {error}.

// Batches (4 nonces each) per soteria_step call. Small enough that progress
// messages stay frequent on slow phones.
const STEP = 32;

// Minimum milliseconds between progress messages.
const PROGRESS_INTERVAL = 100;

const errors = {
  "-1": "malformed request (ERR_LENGTH)",
  "-2": "bad parameters (ERR_PARAMS)",
  "-3": "no job (ERR_NO_JOB)",
  "-4": "ran out of nonces (ERR_EXHAUSTED)",
};

const describe = (code) => errors[String(code)] || `error ${code}`;

self.onmessage = async (event) => {
  try {
    const { module, request } = event.data;
    const instance = await WebAssembly.instantiate(module, {});
    const e = instance.exports;

    const ptr = e.soteria_alloc(request.length);
    new Uint8Array(e.memory.buffer, ptr, request.length).set(request);

    let code = e.soteria_solve(ptr, request.length);
    if (code !== 0) {
      throw new Error(`soteria_solve: ${describe(code)}`);
    }

    let attempts = 0;
    let lastPost = 0;
    for (;;) {
      code = e.soteria_step(STEP);
      attempts += STEP * 4;
      if (code === 1) {
        break;
      }
      if (code !== 0) {
        throw new Error(`soteria_step: ${describe(code)}`);
      }
      const now = Date.now();
      if (now - lastPost >= PROGRESS_INTERVAL) {
        lastPost = now;
        postMessage({ attempts });
      }
    }

    // Copy out before anything else can touch the module's memory.
    const nonces = Array.from(
      new Uint32Array(e.memory.buffer, e.soteria_nonces(), e.soteria_nonces_len()),
    );
    // u64 export arrives as a signed BigInt.
    const fingerprint = BigInt.asUintN(64, e.soteria_fingerprint())
      .toString(16)
      .padStart(16, "0");

    postMessage({ nonces, fingerprint, attempts });
  } catch (err) {
    postMessage({ error: String(err) });
  }
};
