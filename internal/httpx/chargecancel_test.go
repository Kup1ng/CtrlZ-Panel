package httpx_test

import (
	"context"
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

// tenant-r12-2: Limiter.Allow turns every backend failure into ErrUnavailable for a fail-closed class, so a client
// that left while the limiter was being asked was answered 503 sms_unavailable and the bare 499 of the other branch
// could not be reached. The status count of the access log is how an outage of the SMS path is seen; clients that
// close a tab must not be in it.
const sendDoc = `openapi: 3.1.0
info: {title: t, version: "1"}
paths:
  /send:
    post:
      operationId: send
      x-ctrlz-auth: none
      x-ctrlz-rate: otp-send
      requestBody:
        content:
          application/json:
            schema: {type: object, additionalProperties: false}
      responses: {"200": {description: ok}}
`

func TestAClientThatLeavesDuringAFailClosedChargeIsNot503(t *testing.T) {
	ops, err := apispec.Parse([]byte(sendDoc), ratelimit.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	// No backend and not local-only: every fail-closed class answers ErrUnavailable, the state of Valkey being down.
	lim := ratelimit.New(ratelimit.Config{Service: ratelimit.Tenant, Now: time.Now})
	pl := &httpx.Pipeline{
		Log: slog.New(slog.DiscardHandler), Limiter: lim, Service: ratelimit.Tenant, Ops: ops, Doc: []byte(sendDoc),
		Resolver: refusing{t}, BaseURL: "/api/v1", Host: want,
	}
	built, err := pl.Build()
	if err != nil {
		t.Fatal(err)
	}
	reached := 0
	g := built.Router.With(built.PerOp)
	g.Post("/v1/send", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached++ }))
	root := chi.NewRouter()
	root.Mount("/api", built.Router)

	post := func(ctx context.Context) int {
		r := httptest.NewRequest("POST", "/api/v1/send", strings.NewReader("{}")).WithContext(ctx)
		r.Host = host
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Forwarded-For", "198.51.100.7")
		w := httptest.NewRecorder()
		root.ServeHTTP(w, r)
		return w.Code
	}
	if got := post(context.Background()); got != http.StatusServiceUnavailable {
		t.Fatalf("a live client with the limiter down: status %d, want 503 (the outage must still show)", got)
	}
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	if got := post(gone); got != httpx.StatusClientClosedRequest {
		t.Errorf("a client that left: status %d, want %d", got, httpx.StatusClientClosedRequest)
	}
	if reached != 0 {
		t.Errorf("the handler ran %d times behind a refused charge", reached)
	}
}
