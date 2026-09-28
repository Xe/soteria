package soteria

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	chall "github.com/TecharoHQ/anubis/lib/challenge"
	"github.com/TecharoHQ/anubis/lib/store"
	mrc "github.com/TecharoHQ/mobile-request-classifier"
)

// classifierWasm is github.com/TecharoHQ/mobile-request-classifier, fetched
// and hash-checked by build.sh.
//
//go:embed static/mobile_request_classifier.wasm
var classifierWasm []byte

// phoneTTL matches how long Anubis keeps a challenge.
const phoneTTL = 30 * time.Minute

func phoneKey(id string) string {
	return "soteria:phone:" + id
}

func newClassifier(ctx context.Context) (*mrc.Middleware, error) {
	// Only Classify is used, so there is no next handler.
	return mrc.New(ctx, slog.Default(), nil, classifierWasm)
}

// classifyHeaders are every header mrc.Classify reads. It also passes the
// method, path and query to the module, but the pinned module ignores them,
// so results depend on these alone. Recheck when bumping the pin in
// build.sh.
var classifyHeaders = []string{
	"User-Agent",
	"Sec-Ch-Ua",
	"Sec-Ch-Ua-Mobile",
	"Sec-Ch-Ua-Platform",
	"Sec-Ch-Ua-Arch",
	"Sec-Ch-Ua-Bitness",
	"X-Http-Protocol",
}

// classifyCacheSize bounds each of the cache's two generations. Real traffic
// has far fewer distinct header sets; rotating them only causes misses.
const classifyCacheSize = 4096

// classifyCache remembers classifications by a hash of classifyHeaders, so
// the classifier (a fresh WASM instance per call, about 0.35 ms and 2.7 MB)
// runs once per distinct client rather than once per challenge. When cur
// fills it becomes prev, and a hit in prev moves back to cur, so entries in
// use survive and memory stays under 2*classifyCacheSize entries.
type classifyCache struct {
	mu        sync.Mutex
	cur, prev map[[32]byte]mrc.RequestLikelihood
}

// classifyKey hashes the headers the classifier reads, length-prefixed so
// different header sets can't collide by concatenation.
func classifyKey(r *http.Request) [32]byte {
	h := sha256.New()
	for _, name := range classifyHeaders {
		values := r.Header.Values(name)
		h.Write(binary.LittleEndian.AppendUint32(nil, uint32(len(values))))
		for _, v := range values {
			h.Write(binary.LittleEndian.AppendUint32(nil, uint32(len(v))))
			h.Write([]byte(v))
		}
	}
	var k [32]byte
	h.Sum(k[:0])
	return k
}

func (c *classifyCache) get(k [32]byte) (mrc.RequestLikelihood, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.cur[k]; ok {
		return v, true
	}
	v, ok := c.prev[k]
	if ok {
		c.putLocked(k, v)
	}
	return v, ok
}

func (c *classifyCache) put(k [32]byte, v mrc.RequestLikelihood) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.putLocked(k, v)
}

func (c *classifyCache) putLocked(k [32]byte, v mrc.RequestLikelihood) {
	if len(c.cur) >= classifyCacheSize {
		c.prev, c.cur = c.cur, nil
	}
	if c.cur == nil {
		c.cur = make(map[[32]byte]mrc.RequestLikelihood, classifyCacheSize)
	}
	c.cur[k] = v
}

// classify is i.classifier.Classify through the cache. Errors aren't cached.
func (i *Impl) classify(r *http.Request) (mrc.RequestLikelihood, error) {
	k := classifyKey(r)
	if v, ok := i.classified.get(k); ok {
		return v, nil
	}
	got, err := i.classifier.Classify(r)
	if err != nil {
		return mrc.RequestLikelihood{}, err
	}
	i.classified.put(k, *got)
	return *got, nil
}

// isPhone decides at issue time whether a challenge gets phone parameters,
// and records the decision so Validate checks against the same ones.
//
// The classifier only sees headers the client chooses (User-Agent and
// Sec-CH-UA-Mobile), so anyone can claim to be a phone; the discount is
// sized with that in mind. is_slow is ignored because every HTTP/1.1 client
// counts as slow, which covers most scrapers. Anything that goes wrong means
// no discount.
func (i *Impl) isPhone(r *http.Request, lg *slog.Logger, in *chall.IssueInput) bool {
	if in.Store == nil {
		// Validate couldn't find the decision, so it would reject a phone's
		// nonces.
		return false
	}

	got, err := i.classify(r)
	if err != nil {
		lg.WarnContext(r.Context(), "can't classify request, using full difficulty", "err", err)
		return false
	}
	phone := got.IsPhone && !got.IsBot
	lg.DebugContext(r.Context(), "classified request", "is_phone", got.IsPhone, "is_bot", got.IsBot, "is_slow", got.IsSlow, "phone_params", phone)
	if !phone {
		return false
	}

	if err := in.Store.Set(r.Context(), phoneKey(in.Challenge.ID), []byte{1}, phoneTTL); err != nil {
		lg.WarnContext(r.Context(), "can't record phone classification, using full difficulty", "err", err)
		return false
	}
	return true
}

// wasPhone reports whether isPhone recorded challenge id as a phone's. A
// missing record, or no store, means full difficulty.
func wasPhone(ctx context.Context, lg *slog.Logger, st store.Interface, id string) bool {
	if st == nil {
		return false
	}
	if _, err := st.Get(ctx, phoneKey(id)); err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			lg.WarnContext(ctx, "can't read phone classification, using full difficulty", "err", err)
		}
		return false
	}
	return true
}
