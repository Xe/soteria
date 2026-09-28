// Command soteriabench serves the Soteria challenge page in an endless loop,
// for watching the lane visualizer. Each solve goes through the challenge
// method's real Issue and Validate, then redirects back for a new challenge.
package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/TecharoHQ/anubis"
	chall "github.com/TecharoHQ/anubis/lib/challenge"
	"github.com/TecharoHQ/anubis/lib/config"
	"github.com/TecharoHQ/anubis/lib/localization"
	"github.com/TecharoHQ/anubis/lib/policy"
	"github.com/TecharoHQ/anubis/lib/store"
	"github.com/TecharoHQ/anubis/lib/store/memory"
	"github.com/TecharoHQ/anubis/web"
	"github.com/TecharoHQ/anubis/xess"
	"github.com/facebookgo/flagenv"

	"github.com/Xe/soteria/challenge/soteria"
)

var (
	bind       = flag.String("bind", ":8923", "HTTP bind address")
	difficulty = flag.Int("difficulty", 18, "challenge difficulty in bits (2^difficulty expected attempts)")
	slogLevel  = flag.String("slog-level", "INFO", "log level")
)

// xessFS is xess.css and its fonts from
// https://design.within.website/.within.website/x/xess/, copied verbatim. The
// Anubis module's xess is older and lacks the Schibsted Grotesk fonts.
//
//go:embed static
var xessFS embed.FS

// maxPending bounds challenges issued but never solved, such as from
// reloading the page mid-solve.
const maxPending = 64

type bench struct {
	impl *soteria.Impl
	rule *policy.Bot
	// store holds the challenge method's phone classifications, as Anubis'
	// store would.
	store store.Interface

	mu       sync.Mutex
	pending  map[string]*chall.Challenge
	rounds   int
	failures int
	total    time.Duration
}

func main() {
	flagenv.Parse()
	flag.Parse()

	var level slog.Level
	if err := level.UnmarshalText([]byte(*slogLevel)); err != nil {
		slog.Error("invalid --slog-level", "err", err)
		os.Exit(2)
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	if _, err := soteria.NewParams(make([]byte, 64), *difficulty); err != nil {
		slog.Error("invalid --difficulty", "difficulty", *difficulty, "max", soteria.MaxDifficulty, "err", err)
		os.Exit(2)
	}

	b := &bench{
		impl: &soteria.Impl{},
		rule: &policy.Bot{
			Name: "soteriabench",
			Challenge: &config.ChallengeRules{
				Algorithm:  soteria.Method,
				Difficulty: *difficulty,
			},
		},
		store:   memory.New(context.Background()),
		pending: map[string]*chall.Challenge{},
	}

	mux := http.NewServeMux()
	if err := b.impl.Setup(mux); err != nil {
		slog.Error("can't set up the soteria challenge method", "err", err)
		os.Exit(1)
	}
	mountXess(mux)
	mux.Handle("GET "+anubis.StaticPath+"static/", http.StripPrefix(anubis.StaticPath, http.FileServerFS(web.Static)))
	mux.HandleFunc("GET /{$}", b.issue)
	mux.HandleFunc("GET "+anubis.APIPrefix+"pass-challenge", b.pass)

	slog.Info("listening", "bind", *bind, "difficulty", *difficulty)
	if err := http.ListenAndServe(*bind, mux); err != nil {
		slog.Error("can't serve", "err", err)
		os.Exit(1)
	}
}

// mountXess serves xessFS where the base page looks for xess. The page links
// xess.min.css outside devel builds, so both names get the same file, and the
// CSS loads fonts from static/ next to itself.
func mountXess(mux *http.ServeMux) {
	prefix := anubis.BasePrefix + xess.BasePrefix
	css := func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, xessFS, "static/xess.css")
	}
	mux.HandleFunc("GET "+prefix+"xess.css", css)
	mux.HandleFunc("GET "+prefix+"xess.min.css", css)
	mux.Handle("GET "+prefix+"static/", http.StripPrefix(prefix, http.FileServerFS(xessFS)))
}

// issue renders a fresh challenge in Anubis' base page.
func (b *bench) issue(w http.ResponseWriter, r *http.Request) {
	randomData := make([]byte, 64)
	rand.Read(randomData)
	c := &chall.Challenge{
		IssuedAt:   time.Now(),
		ID:         rand.Text(),
		Method:     soteria.Method,
		RandomData: hex.EncodeToString(randomData),
		Difficulty: *difficulty,
	}

	b.mu.Lock()
	if len(b.pending) >= maxPending {
		clear(b.pending)
	}
	b.pending[c.ID] = c
	round := b.rounds + 1
	b.mu.Unlock()

	body, err := b.impl.Issue(w, r, slog.Default(), &chall.IssueInput{Rule: b.rule, Challenge: c, Store: b.store})
	if err != nil {
		slog.Error("can't issue challenge", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	title := fmt.Sprintf("Soteria bench, round %d", round)
	page := web.BaseWithChallengeAndOGTags(title, body, nil, nil, c, b.rule.Challenge, nil, localization.GetLocalizer(r))
	if err := page.Render(r.Context(), w); err != nil {
		slog.Error("can't render page", "err", err)
	}
}

// pass verifies a solution like Anubis would, logs it and starts the next
// round.
func (b *bench) pass(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	b.mu.Lock()
	c, ok := b.pending[id]
	delete(b.pending, id)
	b.mu.Unlock()
	if !ok {
		slog.Warn("unknown or already solved challenge", "id", id)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	err := b.impl.Validate(r, slog.Default(), &chall.ValidateInput{Rule: b.rule, Challenge: c, Store: b.store})
	elapsed, _ := time.ParseDuration(r.FormValue("elapsedTime") + "ms")

	b.mu.Lock()
	b.rounds++
	if err != nil {
		b.failures++
	}
	b.total += elapsed
	rounds, failures, mean := b.rounds, b.failures, b.total/time.Duration(b.rounds)
	b.mu.Unlock()

	lg := slog.With("round", rounds, "elapsed", elapsed.String(), "mean", mean.Round(time.Millisecond).String(), "failures", failures, "nonces", r.FormValue("nonces"))
	if err != nil {
		lg.Error("solution rejected", "err", err)
	} else {
		lg.Info("solution verified")
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}
