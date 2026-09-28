// Soteria challenge page script. Reads #soteria_info (rendered by Issue) plus
// the base page's anubis_* JSON, solves in a Web Worker, and redirects to
// pass-challenge with the nonces.

const json = (id) => {
  const el = document.getElementById(id);
  return el === null ? null : JSON.parse(el.textContent);
};

const info = json("soteria_info");
const { challenge } = json("anubis_challenge");
const basePrefix = json("anubis_base_prefix") ?? "";
const publicUrl = json("anubis_public_url");

const status = document.getElementById("status");
const image = document.getElementById("image");
const title = document.getElementById("title");
const progress = document.getElementById("progress");
const lanesView = document.getElementById("lanes");

const imageURL = (mood) =>
  `${basePrefix}/.within.website/x/cmd/anubis/static/img/${mood}.webp`;

const fail = (titleMsg, statusMsg) => {
  if (title !== null) {
    title.textContent = titleMsg;
  }
  status.textContent = statusMsg;
  image.src = imageURL("reject");
  progress.style.display = "none";
};

// Same rules as Anubis' main.ts getRedirectUrl.
const redirectURL = () => {
  if (publicUrl === null) {
    return "/";
  }
  if (publicUrl && window.location.href.startsWith(publicUrl)) {
    return new URLSearchParams(window.location.search).get("redir") ?? "/";
  }
  return window.location.href;
};

const compile = async (url) => {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`fetching ${url}: HTTP ${response.status}`);
  }
  try {
    return await WebAssembly.compileStreaming(response.clone());
  } catch (err) {
    // A proxy may have rewritten the application/wasm Content-Type.
    console.warn("soteria: streaming compile failed, buffering", err);
    return await WebAssembly.compile(await response.arrayBuffer());
  }
};

const hexToBytes = (hex) => {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
};

const hex = (n) => n.toString(16).padStart(8, "0");

// Widest zero-bit bar, so difficulty 33 still fits a phone screen.
const BAR = 16;

const span = (cls, text) => {
  const el = document.createElement("span");
  el.className = cls;
  el.textContent = text;
  return el;
};

// Draws soteria_lanes: each lane's latest nonce and digest head, how many of
// the leading zero bits a solution needs that head has, and the lane's lowest
// head since the last solution. A head below the threshold solves. Classes
// (dim, hit, best, solved) are styled in page.templ.
const drawLanes = ({ attempts, found, lanes }) => {
  const need = Math.clz32(info.threshold - 1);
  const cells = Math.min(need, BAR);
  const header = "lane nonce    digest   zero bits";
  // Column where "best" starts: past both the bar and its header.
  const width = Math.max(header.length, 25 + cells) + 2;
  const nodes = [span("dim", header.padEnd(width) + "best\n")];
  for (let l = 0; l < 4; l++) {
    const [nonce, head, , bestHead] = lanes.slice(l * 4, l * 4 + 4);
    const filled = need === 0 ? cells : Math.round((Math.min(Math.clz32(head), need) * cells) / need);
    const solved = head < info.threshold;
    nodes.push(
      `${l}    ${hex(nonce)} `,
      solved ? span("solved", hex(head) + "*") : hex(head) + " ",
      "[",
      span("hit", "#".repeat(filled)),
      ".".repeat(cells - filled) + "]" + " ".repeat(width - 25 - cells),
      bestHead === 0xffffffff ? "-" : span("best", hex(bestHead)),
      "\n",
    );
  }
  nodes.push(span("dim", `solutions ${found}/${info.solutions}, ${attempts} nonces tried`));
  lanesView.replaceChildren(...nodes);
  lanesView.style.display = "inline-block";
};

const solve = (module, request, onProgress) =>
  new Promise((resolve, reject) => {
    const worker = new Worker(info.workerURL);
    worker.onmessage = ({ data }) => {
      if (data.error !== undefined) {
        worker.terminate();
        reject(new Error(data.error));
      } else if (data.nonces !== undefined) {
        worker.terminate();
        resolve(data);
      } else {
        onProgress(data);
      }
    };
    worker.onerror = (event) => {
      worker.terminate();
      reject(new Error(event.message || "worker failed to start"));
    };
    worker.postMessage({ module, request });
  });

(async () => {
  const s = info.strings;

  if (typeof Worker === "undefined") {
    fail(`${s.missing_feature} Web Workers`, s.web_workers_error);
    return;
  }
  if (typeof WebAssembly === "undefined") {
    fail(`${s.missing_feature} WebAssembly`, "");
    return;
  }

  status.innerHTML = `${s.calculating} ${info.difficulty}`;
  progress.style.display = "inline-block";
  const bar = progress.firstElementChild;

  // Chance that one attempt succeeds, and attempts expected for all solutions.
  const p = info.threshold / 2 ** 32;
  const expected = info.solutions / p;
  let apologized = false;

  try {
    const module = await compile(info.wasmURL);
    const t0 = Date.now();

    const result = await solve(module, hexToBytes(info.request), (data) => {
      drawLanes(data);
      const { attempts } = data;
      // Same ease-out as main.ts: fast at first, slower as it gets unlikely.
      const remaining = Math.exp(-attempts / expected);
      const distance = (1 - remaining * remaining) * 100;
      progress.ariaValueNow = `${distance}`;
      bar.style.width = `${distance}%`;
      if (remaining < 0.1 && !apologized) {
        apologized = true;
        status.append(document.createElement("br"), s.verification_longer);
      }
    });

    const t1 = Date.now();
    // The final frame stays up while the browser navigates away.
    drawLanes(result);
    const u = new URL(info.passURL, window.location.href);
    u.searchParams.set("id", challenge.id);
    u.searchParams.set("nonces", result.nonces.join(","));
    u.searchParams.set("fingerprint", result.fingerprint);
    u.searchParams.set("redir", redirectURL());
    u.searchParams.set("elapsedTime", `${t1 - t0}`);

    image.src = imageURL("happy");
    window.location.replace(u.toString());
  } catch (err) {
    fail(s.calculation_error, `${s.calculation_error_msg} ${err.message}`);
  }
})();
