package httpx_test

import (
	"context"
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

// The pipeline half of rule boundary-input (spec 2.3 step 8a): a request is checked
// against the schemas of its operation before the session lookup and before the
// handler, a bad one is 400 with no detail, an oversize one is 413, and a pipeline
// cannot be built without its document.

const validateDoc = `openapi: 3.1.0
info: {title: t, version: "1"}
paths:
  /open:
    post:
      operationId: open
      x-ctrlz-auth: none
      x-ctrlz-rate: auth
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [name]
              properties:
                name: {type: string, maxLength: 8, pattern: '^[^\p{C}]*$'}
                n: {type: integer, minimum: 0, maximum: 10}
      responses: {"200": {description: ok}}
  /secret/{id}:
    post:
      operationId: secret
      x-ctrlz-auth: session
      x-ctrlz-rate: user-write
      parameters:
        - {name: id, in: path, required: true, schema: {type: string, maxLength: 4, pattern: '^[a-z]+$'}}
        - {name: q, in: query, schema: {type: string, maxLength: 4, pattern: '^[a-z]*$'}}
      requestBody:
        content:
          application/json:
            schema: {type: object, additionalProperties: false}
      responses: {"200": {description: ok}}
`

// refusing is a resolver that fails the test when the session is resolved: the check of
// the request comes before the lookup. Screen is in process and comes first by design
// (tenant-r5-2: a cookie that cannot be ours is a 401 before the body is read), so it
// accepts any cookie that is not empty and counts how often it was asked.
type refusing struct{ t *testing.T }

func (refusing) CookieName() string { return "sess" }
func (r refusing) Screen(c string) (string, string, bool) {
	return "lookup-" + c, "", c != ""
}
func (r refusing) Resolve(context.Context, string, apispec.Operation) (httpx.Resolved, error) {
	r.t.Error("the session was resolved before the request was checked")
	return httpx.Resolved{}, nil
}

func validateRig(t *testing.T, doc string) (http.Handler, *int) {
	t.Helper()
	ops, err := apispec.Parse([]byte(doc), ratelimit.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	lim := ratelimit.New(ratelimit.Config{Service: ratelimit.Tenant, LocalOnly: true, Now: time.Now})
	pl := &httpx.Pipeline{
		Log: slog.New(slog.DiscardHandler), Limiter: lim, Service: ratelimit.Tenant, Ops: ops, Doc: []byte(doc),
		Resolver: refusing{t}, BaseURL: "/api/v1", Host: want,
	}
	built, err := pl.Build()
	if err != nil {
		t.Fatal(err)
	}
	reached := new(int)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*reached++
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	})
	g := built.Router.With(built.PerOp)
	g.Post("/v1/open", h)
	g.Post("/v1/secret/{id}", h)
	root := chi.NewRouter()
	root.Mount("/api", built.Router)
	return root, reached
}

func TestRequestsAreCheckedBeforeAnyHandlerOrSession(t *testing.T) {
	h, reached := validateRig(t, validateDoc)
	post := func(path, body string, hdr map[string]string) *httptest.ResponseRecorder {
		if hdr == nil {
			hdr = map[string]string{}
		}
		hdr["Content-Type"] = "application/json"
		hdr["X-Forwarded-For"] = "198.51.100.7"
		hdr["Cookie"] = "sess=abc" // a session route looks at the cookie first (tenant-r5-2)
		return do(h, "POST", path, hdr, strings.NewReader(body))
	}
	for name, c := range map[string]struct {
		path, body string
		status     int
	}{
		"a request that satisfies it":     {"/api/v1/open", `{"name":"abc","n":3}`, 204},
		"a NUL":                           {"/api/v1/open", `{"name":"a\u0000b"}`, 400},
		"a bidi override":                 {"/api/v1/open", `{"name":"a\u202eb"}`, 400},
		"a zero width joiner":             {"/api/v1/open", `{"name":"a\u200db"}`, 400},
		"one over the length":             {"/api/v1/open", `{"name":"abcdefghi"}`, 400},
		"invalid UTF-8":                   {"/api/v1/open", "{\"name\":\"a\xffb\"}", 400},
		"an integer past 64 bits":         {"/api/v1/open", `{"name":"a","n":99999999999999999999}`, 400},
		"a fraction for an integer":       {"/api/v1/open", `{"name":"a","n":1.5}`, 400},
		"a missing required member":       {"/api/v1/open", `{"n":1}`, 400},
		"a body that is not JSON":         {"/api/v1/open", `{"name":`, 400},
		"a path parameter with a NUL":     {"/api/v1/secret/ab%00", `{}`, 400},
		"a path parameter out of bounds":  {"/api/v1/secret/abcdef", `{}`, 400},
		"a path parameter, invalid UTF-8": {"/api/v1/secret/%ff", `{}`, 400},
		"a query parameter with a NUL":    {"/api/v1/secret/ab?q=a%00", `{}`, 400},
		"a query parameter, bad UTF-8":    {"/api/v1/secret/ab?q=%ff%fe", `{}`, 400},
	} {
		before := *reached
		w := post(c.path, c.body, nil)
		if w.Code != c.status {
			t.Errorf("%s: status %d (%s), want %d", name, w.Code, strings.TrimSpace(w.Body.String()), c.status)
		}
		if c.status != 204 && *reached != before {
			t.Errorf("%s: the handler ran", name)
		}
		if c.status == 400 && code(t, w) != "bad_request" {
			t.Errorf("%s: code %q, want bad_request", name, code(t, w))
		}
		// The error text of the library repeats the value that failed; none of it may leave.
		if strings.Contains(w.Body.String(), "abcdefghi") || strings.Contains(w.Body.String(), "schema") {
			t.Errorf("%s: the answer carries detail: %s", name, w.Body)
		}
	}
	if *reached != 1 {
		t.Errorf("the handler ran %d times, want once (the valid request)", *reached)
	}

	// A body over the limit is 413, not a schema failure.
	big := `{"name":"a","pad":"` + strings.Repeat("x", 17<<10) + `"}`
	if w := post("/api/v1/open", big, nil); w.Code != http.StatusRequestEntityTooLarge || code(t, w) != "too_large" {
		t.Errorf("an oversize body: %d %s, want 413 too_large", w.Code, w.Body)
	}
	// A wrong content type is refused as well.
	if w := do(h, "POST", "/api/v1/open", map[string]string{"Content-Type": "text/plain", "X-Forwarded-For": "198.51.100.8"}, strings.NewReader(`{"name":"a"}`)); w.Code != 400 {
		t.Errorf("text/plain: %d, want 400", w.Code)
	}
}

func TestAPipelineHasToHaveItsDocument(t *testing.T) {
	ops, err := apispec.Parse([]byte(validateDoc), ratelimit.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	lim := ratelimit.New(ratelimit.Config{Service: ratelimit.Tenant, LocalOnly: true, Now: time.Now})
	if _, err := (&httpx.Pipeline{Log: slog.New(slog.DiscardHandler), Limiter: lim, Service: ratelimit.Tenant, Ops: ops, BaseURL: "/api/v1"}).Build(); err == nil {
		t.Error("a pipeline with no document was built: its requests would not be checked")
	}
	if _, err := (&httpx.Pipeline{Log: slog.New(slog.DiscardHandler), Limiter: lim, Service: ratelimit.Tenant, Ops: ops, Doc: []byte("not: [a document"), BaseURL: "/api/v1"}).Build(); err == nil {
		t.Error("a document that does not load was accepted")
	}
}

// countingBody counts what the pipeline reads from a body.
type countingBody struct {
	r io.Reader
	n int
}

func (c *countingBody) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// TestASessionRouteWithoutAUsableCookieReadsNoBody is tenant-r5-2 at the pipeline: a session route
// has no network bucket, so a request with no cookie that could be ours used to pay a body read and a
// schema check before its 401 and was charged to nothing. No cookie, or one the resolver's Screen
// refuses, is 401 session_expired and the body is not touched; a cookie it accepts reaches the schema.
func TestASessionRouteWithoutAUsableCookieReadsNoBody(t *testing.T) {
	h, reached := validateRig(t, validateDoc)
	send := func(cookie string) (int, int) {
		cb := &countingBody{r: strings.NewReader(`{"unknown":1}`)}
		hdr := map[string]string{"Content-Type": "application/json", "X-Forwarded-For": "198.51.100.9"}
		if cookie != "" {
			hdr["Cookie"] = cookie
		}
		w := do(h, "POST", "/api/v1/secret/ab", hdr, cb)
		return w.Code, cb.n
	}
	if code, read := send(""); code != 401 || read != 0 {
		t.Errorf("no cookie: status %d after reading %d bytes, want 401 and none", code, read)
	}
	if code, read := send("sess="); code != 401 || read != 0 {
		t.Errorf("an empty cookie: status %d after reading %d bytes, want 401 and none", code, read)
	}
	if code, read := send("sess=abc"); code != 400 || read == 0 {
		t.Errorf("a cookie that screens: status %d, body read %d bytes, want the schema to refuse the body (400)", code, read)
	}
	if *reached != 0 {
		t.Errorf("the handler ran %d times", *reached)
	}
}
