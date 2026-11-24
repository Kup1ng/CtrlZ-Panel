package httpx_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
)

// tenant-r19-1 (D64 nat-proof-tag): a request whose bearer value checks (Pipeline.TokenProof) is charged to that value's
// bucket and not to the network, and its body is still whole for the schema check and the handler that read it.
const tokenDoc = `openapi: 3.1.0
info: {title: t, version: "1"}
paths:
  /step:
    post:
      operationId: step
      x-ctrlz-auth: none
      x-ctrlz-rate: auth
      requestBody:
        content:
          application/json:
            schema:
              type: object
              additionalProperties: false
              properties:
                ticket: {type: string, maxLength: 64}
      responses: {"200": {description: ok}}
`

func tokenRig(t *testing.T) (http.Handler, *int) {
	t.Helper()
	ops, err := apispec.Parse([]byte(tokenDoc), ratelimit.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	pl := &httpx.Pipeline{
		Log: slog.New(slog.DiscardHandler), Service: ratelimit.Tenant, Ops: ops, Doc: []byte(tokenDoc), BaseURL: "/api/v1",
		Limiter:  ratelimit.New(ratelimit.Config{Service: ratelimit.Tenant, LocalOnly: true, Now: func() time.Time { return now }}),
		Resolver: refusing{t}, Host: want,
		// A value "good-<account>" is a ticket whose tag checks. The body is read through PeekBody, as the api's hook does.
		TokenProof: func(r *http.Request, _ apispec.Operation) (string, string, bool) {
			raw, ok := httpx.PeekBody(r)
			if !ok {
				return "", "", false
			}
			var b struct {
				Ticket string `json:"ticket"`
			}
			if json.Unmarshal(raw, &b) != nil || !strings.HasPrefix(b.Ticket, "good-") {
				return "", "", false
			}
			return "u:" + b.Ticket, "u:" + b.Ticket, true
		},
	}
	built, err := pl.Build()
	if err != nil {
		t.Fatal(err)
	}
	reached := new(int)
	built.Router.With(built.PerOp).Post("/v1/step", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The handler still reads the whole body the hook read.
		raw, err := io.ReadAll(r.Body)
		if err != nil || !strings.Contains(string(raw), "ticket") {
			t.Errorf("the handler found the body gone: %q %v", raw, err)
		}
		*reached++
	}))
	root := chi.NewRouter()
	root.Mount("/api", built.Router)
	return root, reached
}

func stepFrom(h http.Handler, ip, ticket string) int {
	r := httptest.NewRequest("POST", "/api/v1/step", strings.NewReader(`{"ticket":"`+ticket+`"}`))
	r.Host = host
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Forwarded-For", ip)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

func TestARequestWithACheckedValueIsNotChargedToTheNetwork(t *testing.T) {
	h, reached := tokenRig(t)
	const shared = "203.0.113.9"
	// Strangers on the block spend the plain network bucket (20 a minute) and are then refused.
	refused := false
	for i := 0; i < 40; i++ {
		if stepFrom(h, shared, "junk") == http.StatusTooManyRequests {
			refused = true
			break
		}
	}
	if !refused {
		t.Fatal("the control did not hold: strangers on one network were never refused")
	}
	// Two accounts on that very network, each holding a value that checks, are answered.
	for _, acct := range []string{"good-a", "good-b"} {
		if got := stepFrom(h, shared, acct); got != http.StatusOK {
			t.Fatalf("%s on the flooded network: status %d, want 200", acct, got)
		}
	}
	// One account's own bucket is its own: it ends in a 429 after its 20 and leaves the other account's alone.
	got429 := false
	for i := 0; i < 30; i++ {
		if stepFrom(h, shared, "good-a") == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatal("an account that kept sending was never refused by its own bucket")
	}
	if got := stepFrom(h, shared, "good-b"); got != http.StatusOK {
		t.Fatalf("another account was refused with the first one's bucket: %d", got)
	}
	if *reached == 0 {
		t.Fatal("no request reached the handler")
	}
}

func TestPeekBodyLeavesTheBodyForTheNextReaderAndKeepsItsError(t *testing.T) {
	r := httptest.NewRequest("POST", "/", strings.NewReader("hello"))
	raw, ok := httpx.PeekBody(r)
	if !ok || string(raw) != "hello" {
		t.Fatalf("PeekBody = %q %v", raw, ok)
	}
	again, _ := io.ReadAll(r.Body)
	if string(again) != "hello" {
		t.Fatalf("the body after PeekBody is %q", again)
	}
	// A body over its limit: the next reader sees the same refusal, not an empty body.
	big := httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat("x", httpx.DefaultBodyLimit+10)))
	var h http.Handler = httpx.BodyLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := httpx.PeekBody(r); ok {
			t.Error("an over-limit body was reported readable")
		}
		if _, err := io.ReadAll(r.Body); err == nil {
			t.Error("the error of an over-limit body was lost for the next reader")
		}
	}))
	h.ServeHTTP(httptest.NewRecorder(), big)
}
