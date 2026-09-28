package soteria

import (
	"context"
	_ "embed"
	"errors"
	"log/slog"
	"net/http"
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

	got, err := i.classifier.Classify(r)
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
