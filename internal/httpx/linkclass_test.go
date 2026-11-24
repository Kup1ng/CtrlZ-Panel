package httpx_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
)

// P3 7.1: a route that carries a share or download link value is charged to the row the value names, never to the network, and a
// value that does not screen is answered at once and charges nothing.
const linkDoc = `openapi: 3.1.0
info: {title: t, version: "1"}
paths:
  /public/share:
    post:
      operationId: openShare
      x-ctrlz-auth: none
      x-ctrlz-rate: public-link
      requestBody:
        content:
          application/json:
            schema:
              type: object
              additionalProperties: false
              properties:
                token: {type: string, maxLength: 64}
      responses: {"200": {description: ok}}
`

type linkRigT struct {
	h       http.Handler
	reached *atomic.Int32
	screens *atomic.Int32
}

func newLinkPipeline(t *testing.T, bearer func(*http.Request, apispec.Operation) (string, bool)) linkRigT {
	t.Helper()
	ops, err := apispec.Parse([]byte(linkDoc), ratelimit.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	pl := &httpx.Pipeline{
		Log: slog.New(slog.DiscardHandler), Service: ratelimit.Tenant, Ops: ops, Doc: []byte(linkDoc), BaseURL: "/api/v1",
		Limiter:  ratelimit.New(ratelimit.Config{Service: ratelimit.Tenant, LocalOnly: true, Now: func() time.Time { return now }}),
		Resolver: refusing{t}, Host: want, Bearer: bearer,
	}
	built, err := pl.Build()
	if err != nil {
		t.Fatal(err)
	}
	reached := new(atomic.Int32)
	built.Router.With(built.PerOp).Post("/v1/public/share", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(raw), "token") {
			t.Errorf("the handler found the body gone: %q", raw)
		}
		reached.Add(1)
		if strings.Contains(string(raw), "dead") {
			httpx.MarkLinkDead(r.Context())
			httpx.Write(w, r, httpx.NotFound())
		}
	}))
	root := chi.NewRouter()
	root.Mount("/api", built.Router)
	return linkRigT{h: root, reached: reached}
}

func openFrom(h http.Handler, ip, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/api/v1/public/share", strings.NewReader(`{"token":"`+token+`"}`))
	r.Host = host
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Forwarded-For", ip)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// keyOf reads the token of the body the way the api's hook does: a value "row-<id>" screens as row <id>.
func keyOf(r *http.Request, _ apispec.Operation) (string, bool) {
	raw, ok := httpx.PeekBody(r)
	if !ok {
		return "", false
	}
	_, after, found := strings.Cut(string(raw), `"row-`)
	if !found {
		return "", false
	}
	id, _, _ := strings.Cut(after, `"`)
	return "s:" + id, true
}

func TestAValueThatDoesNotScreenIsRefusedAtTheDoorAndChargesNothing(t *testing.T) {
	rig := newLinkPipeline(t, keyOf)
	for i := 0; i < 200; i++ {
		w := openFrom(rig.h, "198.51.100.7", "junk")
		if w.Code != 404 || code(t, w) != "not_found" {
			t.Fatalf("junk answered %d %s", w.Code, w.Body)
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Robots-Tag") != "noindex" || w.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Fatalf("headers %v", w.Header())
		}
	}
	if rig.reached.Load() != 0 {
		t.Errorf("the handler ran %d times for junk", rig.reached.Load())
	}
	// Junk spent nothing: the first honest value of the same network is served.
	if w := openFrom(rig.h, "198.51.100.7", "row-1"); w.Code != 200 {
		t.Errorf("an honest value after 200 junk ones: %d", w.Code)
	}
}

func TestAValueIsChargedToItsRowAndNotToTheNetwork(t *testing.T) {
	rig := newLinkPipeline(t, keyOf)
	served, refused := 0, 0
	for i := 0; i < 40; i++ {
		switch openFrom(rig.h, "198.51.100.7", "row-1").Code {
		case 200:
			served++
		case 429:
			refused++
		}
	}
	if served != 30 || refused != 10 {
		t.Errorf("one row served %d and refused %d of 40, want 30 and 10 (public-link is 30 a minute)", served, refused)
	}
	// Another row on the same network is not that row's bucket, and the same row from another network is.
	if w := openFrom(rig.h, "198.51.100.7", "row-2"); w.Code != 200 {
		t.Errorf("another row of the same network: %d", w.Code)
	}
	if w := openFrom(rig.h, "203.0.113.9", "row-1"); w.Code != 429 {
		t.Errorf("the same row from another network: %d, want 429", w.Code)
	}
}

func TestAValueTheHandlerFoundDeadIsRefusedWithNoHandler(t *testing.T) {
	rig := newLinkPipeline(t, keyOf)
	if w := openFrom(rig.h, "198.51.100.7", "row-dead"); w.Code != 404 {
		t.Fatalf("first: %d", w.Code)
	}
	if rig.reached.Load() != 1 {
		t.Fatalf("the handler ran %d times", rig.reached.Load())
	}
	for i := 0; i < 5; i++ {
		if w := openFrom(rig.h, "198.51.100.7", "row-dead"); w.Code != 404 {
			t.Fatalf("again: %d", w.Code)
		}
	}
	if rig.reached.Load() != 1 {
		t.Errorf("the handler ran %d times for a value it had marked dead", rig.reached.Load())
	}
}

func TestALinkClassWithNoBearerReaderIsRefusedAtBuild(t *testing.T) {
	ops, err := apispec.Parse([]byte(linkDoc), ratelimit.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	pl := &httpx.Pipeline{Log: slog.New(slog.DiscardHandler), Service: ratelimit.Tenant, Ops: ops, Doc: []byte(linkDoc), BaseURL: "/api/v1",
		Limiter: ratelimit.New(ratelimit.Config{Service: ratelimit.Tenant, LocalOnly: true}), Resolver: refusing{t}, Host: want}
	if _, err := pl.Build(); err == nil {
		t.Error("a document with a link-keyed route and no Bearer reader was built")
	}
}
