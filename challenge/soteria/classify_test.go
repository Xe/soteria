package soteria

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/TecharoHQ/anubis/lib/challenge"
	"github.com/TecharoHQ/anubis/lib/store"
	"github.com/TecharoHQ/anubis/lib/store/memory"
	mrc "github.com/TecharoHQ/mobile-request-classifier"
)

func mrcLikelihood(phone bool) mrc.RequestLikelihood {
	return mrc.RequestLikelihood{IsPhone: phone}
}

const (
	iPhoneUA  = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1"
	androidUA = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36"
	desktopUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
	botUA     = "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
)

func TestNewPhoneParams(t *testing.T) {
	t.Parallel()

	randomData := bytes.Repeat([]byte{7}, 64)
	full, _ := NewParams(randomData, 16)
	phone, err := NewPhoneParams(randomData, 16)
	if err != nil {
		t.Fatal(err)
	}

	if phone.Solutions != 2 {
		t.Errorf("solutions = %d, want 2", phone.Solutions)
	}
	// Expected attempts are solutions * 2^32 / threshold.
	attempts := func(p *Params) float64 { return float64(p.Solutions) * (1 << 32) / float64(p.Threshold) }
	if got, want := attempts(phone), attempts(full)/16; got != want {
		t.Errorf("phone attempts = %v, want a sixteenth of %v", got, attempts(full))
	}
	if phone.Seed != full.Seed || phone.Challenge != full.Challenge {
		t.Error("phone params should only change the threshold and solution count")
	}

	for _, tt := range []struct {
		name       string
		difficulty int
		threshold  uint32
		err        error
	}{
		{name: "low difficulty is free", difficulty: 1, threshold: 0xFFFFFFFF},
		{name: "max", difficulty: MaxDifficulty, threshold: 1 << 4},
		{name: "too high", difficulty: MaxDifficulty + 1, err: ErrDifficulty},
		{name: "negative", difficulty: -1, threshold: 0xFFFFFFFF},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewPhoneParams(randomData, tt.difficulty)
			if !errors.Is(err, tt.err) {
				t.Logf("want: %v", tt.err)
				t.Logf("got:  %v", err)
				t.Fatal("wrong error")
			}
			if err == nil && p.Threshold != tt.threshold {
				t.Errorf("threshold = %#x, want %#x", p.Threshold, tt.threshold)
			}
		})
	}
}

// issue runs Issue for a request with the given headers and returns the
// soteria::wire request the page carries.
func issue(t *testing.T, i *Impl, st store.Interface, c *challenge.Challenge, difficulty int, headers map[string]string) string {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	comp, err := i.Issue(httptest.NewRecorder(), req, slog.New(slog.DiscardHandler), &challenge.IssueInput{
		Rule:      bot(difficulty),
		Challenge: c,
		Store:     st,
	})
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := comp.Render(t.Context(), &buf); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// TestPhoneGrace checks who gets phone params at issue time, and that
// Validate holds each challenge to the params it was issued with.
func TestPhoneGrace(t *testing.T) {
	t.Parallel()

	const difficulty = 10
	i := setup(t)
	lg := slog.New(slog.DiscardHandler)

	for _, tt := range []struct {
		name    string
		headers map[string]string
		noStore bool
		phone   bool
	}{
		{name: "iPhone Safari", headers: map[string]string{"User-Agent": iPhoneUA}, phone: true},
		{name: "Android Chrome with client hints", headers: map[string]string{
			"User-Agent":         androidUA,
			"Sec-CH-UA":          `"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"`,
			"Sec-CH-UA-Mobile":   "?1",
			"Sec-CH-UA-Platform": `"Android"`,
		}, phone: true},
		{name: "mobile UA, client hints say desktop", headers: map[string]string{
			"User-Agent":         androidUA,
			"Sec-CH-UA":          `"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"`,
			"Sec-CH-UA-Mobile":   "?0",
			"Sec-CH-UA-Platform": `"Android"`,
		}},
		{name: "desktop Chrome", headers: map[string]string{"User-Agent": desktopUA}},
		{name: "self-declared bot on a phone", headers: map[string]string{"User-Agent": botUA}},
		{name: "no user agent", headers: map[string]string{}},
		{name: "phone without a store", headers: map[string]string{"User-Agent": iPhoneUA}, noStore: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var st store.Interface
			if !tt.noStore {
				st = memory.New(t.Context())
			}
			randomData := sha256.Sum256([]byte(t.Name()))
			c := &challenge.Challenge{ID: t.Name(), RandomData: hex.EncodeToString(randomData[:])}

			page := issue(t, i, st, c, difficulty, tt.headers)

			want, _ := NewParams(randomData[:], difficulty)
			wantDifficulty := difficulty
			if tt.phone {
				want, _ = NewPhoneParams(randomData[:], difficulty)
				wantDifficulty = PhoneDifficulty(difficulty)
			}
			if !strings.Contains(page, hex.EncodeToString(want.Request(nil))) {
				t.Fatalf("page doesn't carry the expected params (phone=%v)", tt.phone)
			}
			if !strings.Contains(page, fmt.Sprintf(`"difficulty":%d`, wantDifficulty)) {
				t.Errorf("page doesn't show difficulty %d", wantDifficulty)
			}

			req := mkRequest(t, map[string]string{
				"nonces":      joinNonces(solveParams(t, want)),
				"fingerprint": i.fingerprint,
				"elapsedTime": "42",
			})
			if err := i.Validate(req, lg, &challenge.ValidateInput{Rule: bot(difficulty), Challenge: c, Store: st}); err != nil {
				t.Errorf("solution for the issued params failed: %v", err)
			}
		})
	}
}

// TestPhoneGraceFailsClosed: phone params only validate for a challenge that
// was issued as a phone's, in this store.
func TestPhoneGraceFailsClosed(t *testing.T) {
	t.Parallel()

	const difficulty = 10
	i := setup(t)
	lg := slog.New(slog.DiscardHandler)

	randomData := sha256.Sum256([]byte(t.Name()))
	c := &challenge.Challenge{ID: "desktop", RandomData: hex.EncodeToString(randomData[:])}
	phone, _ := NewPhoneParams(randomData[:], difficulty)
	nonces := joinNonces(solveParams(t, phone))

	for _, tt := range []struct {
		name  string
		store func() store.Interface
	}{
		{name: "issued to a desktop", store: func() store.Interface {
			st := memory.New(t.Context())
			issue(t, i, st, c, difficulty, map[string]string{"User-Agent": desktopUA})
			return st
		}},
		{name: "record missing", store: func() store.Interface { return memory.New(t.Context()) }},
		{name: "no store", store: func() store.Interface { return nil }},
		{name: "another challenge was a phone's", store: func() store.Interface {
			st := memory.New(t.Context())
			other := &challenge.Challenge{ID: "phone", RandomData: c.RandomData}
			issue(t, i, st, other, difficulty, map[string]string{"User-Agent": iPhoneUA})
			return st
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := mkRequest(t, map[string]string{
				"nonces":      nonces,
				"fingerprint": i.fingerprint,
				"elapsedTime": "42",
			})
			err := i.Validate(req, lg, &challenge.ValidateInput{Rule: bot(difficulty), Challenge: c, Store: tt.store()})
			if !errors.Is(err, challenge.ErrInvalidFormat) && !errors.Is(err, challenge.ErrFailed) {
				t.Errorf("phone solution for a non-phone challenge: got %v, want a rejection", err)
			}
		})
	}
}

// TestPhoneGraceConcurrent classifies from many goroutines; run with -race.
func TestPhoneGraceConcurrent(t *testing.T) {
	t.Parallel()

	i := setup(t)
	st := memory.New(t.Context())
	var wg sync.WaitGroup
	for j := range 32 {
		wg.Go(func() {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			req.Header.Set("User-Agent", iPhoneUA)
			in := &challenge.IssueInput{
				Rule:      bot(10),
				Challenge: &challenge.Challenge{ID: fmt.Sprint(j), RandomData: hex.EncodeToString(make([]byte, 64))},
				Store:     st,
			}
			if !i.isPhone(req, slog.New(slog.DiscardHandler), in) {
				t.Errorf("goroutine %d: iPhone not classified as a phone", j)
			}
		})
	}
	wg.Wait()
}

func BenchmarkClassify(b *testing.B) {
	i := setup(b)
	req := httptest.NewRequestWithContext(b.Context(), http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", iPhoneUA)

	for b.Loop() {
		if _, err := i.classifier.Classify(req); err != nil {
			b.Fatal(err)
		}
	}
}

// TestClassifyCacheMatchesClassifier: a cached answer is the classifier's
// answer, both on the miss and on the hit.
func TestClassifyCacheMatchesClassifier(t *testing.T) {
	t.Parallel()

	i := setup(t)
	for _, headers := range []map[string]string{
		{"User-Agent": iPhoneUA},
		{"User-Agent": desktopUA},
		{"User-Agent": botUA},
		{"User-Agent": androidUA, "Sec-CH-UA": `"Chromium";v="140"`, "Sec-CH-UA-Mobile": "?1", "Sec-CH-UA-Platform": `"Android"`},
		{"User-Agent": androidUA, "Sec-CH-UA": `"Chromium";v="140"`, "Sec-CH-UA-Mobile": "?0", "Sec-CH-UA-Platform": `"Android"`},
		{"User-Agent": desktopUA, "X-Http-Protocol": "HTTP/1.1"},
		{},
	} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		want, err := i.classifier.Classify(req)
		if err != nil {
			t.Fatal(err)
		}
		for try := range 2 {
			got, err := i.classify(req)
			if err != nil {
				t.Fatal(err)
			}
			if got != *want {
				t.Errorf("%v try %d: got %+v, want %+v", headers, try, got, *want)
			}
		}
	}
}

func TestClassifyKey(t *testing.T) {
	t.Parallel()

	key := func(method, target string, headers ...[2]string) [32]byte {
		req := httptest.NewRequest(method, target, nil)
		for _, h := range headers {
			req.Header.Add(h[0], h[1])
		}
		return classifyKey(req)
	}
	ua := [2]string{"User-Agent", iPhoneUA}

	if key("GET", "/a?x=1", ua) != key("POST", "/b?y=2", ua) {
		t.Error("method, path and query changed the key; the classifier doesn't read them")
	}
	for _, tt := range []struct {
		name string
		a, b [][2]string
	}{
		{name: "user agent", a: [][2]string{ua}, b: [][2]string{{"User-Agent", desktopUA}}},
		{name: "mobile hint", a: [][2]string{ua, {"Sec-Ch-Ua-Mobile", "?1"}}, b: [][2]string{ua, {"Sec-Ch-Ua-Mobile", "?0"}}},
		{name: "hint present or not", a: [][2]string{ua}, b: [][2]string{ua, {"Sec-Ch-Ua-Bitness", "64"}}},
		{name: "protocol", a: [][2]string{ua, {"X-Http-Protocol", "HTTP/1.1"}}, b: [][2]string{ua, {"X-Http-Protocol", "HTTP/2.0"}}},
		{name: "value boundaries", a: [][2]string{{"Sec-Ch-Ua", "ab"}, {"Sec-Ch-Ua", "c"}}, b: [][2]string{{"Sec-Ch-Ua", "a"}, {"Sec-Ch-Ua", "bc"}}},
		{name: "header boundaries", a: [][2]string{{"Sec-Ch-Ua-Arch", "x"}}, b: [][2]string{{"Sec-Ch-Ua-Platform", "x"}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if key("GET", "/", tt.a...) == key("GET", "/", tt.b...) {
				t.Error("different classifier inputs gave the same key")
			}
		})
	}
}

// TestClassifyCacheBounded: memory stays under two generations, and an entry
// that keeps being used survives rotations.
func TestClassifyCacheBounded(t *testing.T) {
	t.Parallel()

	var c classifyCache
	k := func(n int) [32]byte { return sha256.Sum256(fmt.Append(nil, n)) }
	hot := k(-1)
	c.put(hot, mrcLikelihood(true))

	for n := range 5 * classifyCacheSize {
		c.put(k(n), mrcLikelihood(false))
		if n%(classifyCacheSize/2) == 0 {
			if _, ok := c.get(hot); !ok {
				t.Fatalf("hot entry evicted after %d puts", n)
			}
		}
	}
	if got := len(c.cur) + len(c.prev); got > 2*classifyCacheSize {
		t.Errorf("cache holds %d entries, want at most %d", got, 2*classifyCacheSize)
	}
	if _, ok := c.get(k(0)); ok {
		t.Error("oldest entry should have been evicted")
	}
	if v, ok := c.get(k(5*classifyCacheSize - 1)); !ok || v.IsPhone {
		t.Errorf("newest entry = %+v, %v", v, ok)
	}
}

func BenchmarkClassifyCached(b *testing.B) {
	i := setup(b)
	req := httptest.NewRequestWithContext(b.Context(), http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", iPhoneUA)

	for b.Loop() {
		if _, err := i.classify(req); err != nil {
			b.Fatal(err)
		}
	}
}
