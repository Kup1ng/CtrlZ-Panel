package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/bearer"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/pwstrength"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest/oracle"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/netkey"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/classify"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/senders"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/smsir"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testtls"
	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/smssend"
	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/sweep"
)

// The known-or-unknown oracle of the tenant API (P1 auth review round 5, rule
// known-unknown-oracle, spec 5.3, 5.4, 18.5).
//
// Rule: whether a phone has an account may change only the sealed SMS payload and
// the final session or ticket. This test enforces it for every route of
// api/openapi.yaml that needs no session. For each route (several variants where
// the purpose or the mode changes the branch) it asks as a phone with an account
// and as one without, under every registered fault state, and compares everything
// the rule names: status, body, headers, cookies, the movement of every SMS and
// throttle counter after the worker drained, the Argon2 and scoring runs, the gate
// acquisitions. A difference fails unless the declared exception list covers it.
//
// A route added to the OpenAPI document without a variant here fails
// TestOracleCoversEveryNoneOperation, and a state added to oracle.AllStates
// without an action fails TestOracleHandlesEveryState.

// oracleExceptions is the declared list. Each entry names the section of
// p1-auth.md that accepts it (spec 18.5 table "Known and unknown subject").
var oracleExceptions = func() oracle.Exceptions {
	ex := oracle.Exceptions{
		// A code the gateway accepted was sent and paid for; a decoy never is. The
		// money and the global slot are the payload's own consequences (5.3).
		{Op: "*", State: oracle.StateNone, Subject: "*", Dim: "sms.global", Spec: "5.3 the global counter and the cost follow a message that was sent"},
		{Op: "*", State: oracle.StateGateHeld, Subject: "*", Dim: "sms.global", Spec: "5.3 same; the gate holds Argon2, and the worker still delivers"},
		// Only a real row reaches a gateway, so only a real row can fail one. Three failures open a
		// breaker, which is the router's own state (sms-r6-4). Since round 18 (sms-r18-2) no public
		// output reads it: sms_available is computed from configuration alone, so the dimension
		// "gateways.public_sms_available" is held to equality in every state, and these two rows are
		// internal state that no stranger can read. The other states that end a real row (a refused
		// number, a template problem, a worker that cannot open the payload) do not touch a breaker,
		// so only the state that fails every send is listed.
		{Op: "*", State: oracle.StateProvider404, Subject: "*", Dim: "gateways.failures", Spec: "18.5 the breaker: three failed sends of a real row open it; internal state (sms-r6-4, sms-r18-2)"},
		{Op: "*", State: oracle.StateProvider404, Subject: "*", Dim: "gateways.open", Spec: "18.5 the breaker (sms-r6-4)"},
	}
	// The hold of a refused login (sms-r15-5). Only a real delivery reaches a gateway, so only a real
	// row can be refused its login, and one refused send holds the gateway. That is internal state:
	// before round 18 it also turned the public flag false, a bit of the user list for anyone who could
	// ask for a code and read GET /auth/config (sms-r18-2), and the public flag is now held to equality
	// like every other dimension, so a change that couples it to the hold again fails here. The
	// dimensions the hold moves are listed one by one, so every other dimension of this state is held
	// to equality, and a change that moved a counter, a refund or the answer with the hold would fail
	// here.
	for _, dim := range []string{"gateways.failures", "gateways.open", "gateways.held", "gateways.blocked"} {
		ex = append(ex, &oracle.Exception{Op: "*", State: oracle.StateProviderRefusedLogin, Subject: "*", Dim: dim,
			Spec: "18.5 the hold of a refused login and the breaker behind it; internal state (sms-r15-5, sms-r6-4, sms-r18-2)"})
	}
	// The failed-login trail row: a wrong password for a phone with an account is recorded, and an
	// unknown phone has no account to record it for. The row is written AFTER the answer, off the
	// request (afterwork, tenant-r13-2), so no wait for it is in the answer's time; this is the one
	// difference of the pool meter, and it exists only in the states where the verify ran and said no.
	// A mutant that writes the row inside the floor moves the other dimension, "pool", which has no
	// entry.
	for _, state := range []string{
		oracle.StateNone, oracle.StateTemplateUnmapped, oracle.StateProvider404, oracle.StateProviderFlapping,
		oracle.StateWorkerFailing, oracle.StateRecipientRefused, oracle.StateBlacklisted,
		oracle.StateProviderRefusedLogin,
		oracle.StateBreakerOpensMidRow, oracle.StateWorkerDown, oracle.StateGlobalCounterHeld,
	} {
		for _, op := range []string{"loginPassword", "loginPassword/marker"} {
			ex = append(ex, &oracle.Exception{Op: op, State: state, Subject: "*", Dim: "pool.after_floor",
				Spec: "18.5 the failed-login row of a phone with an account, written after the floor (tenant-r13-2)"})
		}
	}
	return ex
}

// oracleWho is the subject of one run.
type oracleWho struct {
	name  string // "known" or "unknown"
	known bool
	phone string
}

// oracleVariant is one request shape of one operation.
type oracleVariant struct {
	name  string // unique; operationId, with /purpose when one operation has several
	op    string // operationId in api/openapi.yaml
	floor time.Duration
	mode  string // registration mode to run under; "" is the default (closed)
	// noSubject marks a route that takes no phone: the two runs ask the same
	// question with different made-up values, and must still look the same.
	noSubject bool
	// spendClass names a network rate class whose plain bucket is spent for the address of the measured request before it
	// is sent (round 9, tenant-r9-3): the branches that exist only for a request carrying a device marker are the ones a
	// spent class makes the handler take.
	spendClass string
	// prepare makes what the request needs (a challenge, an invite) and returns it.
	prepare func(w *oracleWorld, who oracleWho) oracle.Request
}

const (
	oracleWrongPW   = "Wrong-Guess-Heron-4412-x"
	oracleUnknown   = "+989129990001"
	oracleCodeWrong = "000000"
)

// oracleTicket is a ticket of the canonical shape that no ticket row matches. The last character
// of a token carries 2 spare bits that must be zero (token.Valid), so only those characters are
// used: a ticket of another spelling is refused before any lookup, and the known and the unknown
// request would then differ in what they reach.
func oracleTicket(n int) string {
	return strings.Repeat(string("AEIMQUYcgkosw048"[n%16]), 43)
}

func oracleVariants() []oracleVariant {
	post := func(path string, body any) oracle.Request {
		return oracle.Request{Method: "POST", Path: path, Body: body}
	}
	otp := func(phone, purpose string, extra map[string]any) oracle.Request {
		body := map[string]any{"phone": phone, "purpose": purpose, "locale": "fa"}
		for k, v := range extra {
			body[k] = v
		}
		return post("/auth/otp/request", body)
	}
	// challenge asks for a code the way a browser does and returns its id.
	challenge := func(w *oracleWorld, phone, purpose string) string {
		var iss issued
		r, err := oracle.Fire(w.f.h, host, w.f.freshIP(), otp(phone, purpose, nil))
		if err != nil || r.Status != 202 {
			w.t.Fatalf("setup: otp request for %s: %v %d %s", purpose, err, r.Status, r.Body)
		}
		w.mustJSON(r.Body, &iss)
		return iss.ID
	}
	return []oracleVariant{
		{name: "getAuthConfig", op: "getAuthConfig", noSubject: true, prepare: func(*oracleWorld, oracleWho) oracle.Request {
			return oracle.Request{Method: "GET", Path: "/auth/config"}
		}},
		{name: "getPublicFreeDns", op: "getPublicFreeDns", noSubject: true, prepare: func(*oracleWorld, oracleWho) oracle.Request {
			return oracle.Request{Method: "GET", Path: "/public/free-dns"}
		}},
		{name: "loginPassword", op: "loginPassword", floor: floorLogin, prepare: func(w *oracleWorld, who oracleWho) oracle.Request {
			return post("/auth/login/password", map[string]any{"phone": who.phone, "password": oracleWrongPW})
		}},
		{name: "requestOtp/login", op: "requestOtp", floor: floorOTPReq, prepare: func(w *oracleWorld, who oracleWho) oracle.Request {
			return otp(who.phone, "login", nil)
		}},
		{name: "requestOtp/reset", op: "requestOtp", floor: floorOTPReq, prepare: func(w *oracleWorld, who oracleWho) oracle.Request {
			return otp(who.phone, "reset", nil)
		}},
		{name: "requestOtp/signup", op: "requestOtp", floor: floorOTPReq, mode: "open", prepare: func(w *oracleWorld, who oracleWho) oracle.Request {
			return otp(who.phone, "signup", nil)
		}},
		{name: "requestOtp/invite", op: "requestOtp", floor: floorOTPReq, prepare: func(w *oracleWorld, who oracleWho) oracle.Request {
			// The phone of an invite is the invite's own; the request's is ignored.
			tok := w.f.plantInvite(who.phone, time.Hour, false)
			return otp("09120000001", "invite", map[string]any{"invite_token": tok})
		}},
		// A request that carries a device marker minted for a THIRD account (round 9, tenant-r9-3). Rounds 5 and 8 gave the
		// public routes branches that exist only when a marker came (loginPassword reads the account inside the charge,
		// requestOtp asks whether the marker holds and charges the marker's buckets once the plain one is spent), so a
		// walk with no marker never reached them. A marker that holds for the asked account is the declared exception
		// (the owner on a known device) and is the one request that is allowed to differ; every other marker must look
		// the same for a phone with an account and one without, under every state.
		{name: "loginPassword/marker", op: "loginPassword", floor: floorLogin, prepare: func(w *oracleWorld, who oracleWho) oracle.Request {
			r := post("/auth/login/password", map[string]any{"phone": who.phone, "password": oracleWrongPW})
			r.Cookies = w.thirdMarker()
			return r
		}},
		{name: "requestOtp/login/marker", op: "requestOtp", floor: floorOTPReq, prepare: func(w *oracleWorld, who oracleWho) oracle.Request {
			r := otp(who.phone, "login", nil)
			r.Cookies = w.thirdMarker()
			return r
		}},
		{name: "requestOtp/reset/marker", op: "requestOtp", floor: floorOTPReq, prepare: func(w *oracleWorld, who oracleWho) oracle.Request {
			r := otp(who.phone, "reset", nil)
			r.Cookies = w.thirdMarker()
			return r
		}},
		{name: "requestOtp/login/marker/spent", op: "requestOtp", floor: floorOTPReq, spendClass: "otp-send", prepare: func(w *oracleWorld, who oracleWho) oracle.Request {
			r := otp(who.phone, "login", nil)
			r.Cookies = w.thirdMarker()
			return r
		}},
		{name: "requestOtp/reset/marker/spent", op: "requestOtp", floor: floorOTPReq, spendClass: "otp-send", prepare: func(w *oracleWorld, who oracleWho) oracle.Request {
			r := otp(who.phone, "reset", nil)
			r.Cookies = w.thirdMarker()
			return r
		}},
		// No marker, a spent bucket: the refusal is answered at once, with no floor, exactly as the pipeline answered it before
		// the class was deferred (a refused request must not cost the floor, round 8, admin-r8-1). It is the same for both
		// subjects, which is what is compared.
		{name: "requestOtp/login/spent", op: "requestOtp", spendClass: "otp-send", prepare: func(w *oracleWorld, who oracleWho) oracle.Request {
			return otp(who.phone, "login", nil)
		}},
		{name: "resetVerify/marker", op: "resetVerify", floor: floorVerify, prepare: func(w *oracleWorld, who oracleWho) oracle.Request {
			r := post("/auth/password/reset/verify", map[string]any{"phone": who.phone, "challenge_id": challenge(w, who.phone, "reset"), "code": oracleCodeWrong})
			r.Cookies = w.thirdMarker()
			return r
		}},
		{name: "loginOtp", op: "loginOtp", floor: floorVerify, prepare: func(w *oracleWorld, who oracleWho) oracle.Request {
			return post("/auth/login/otp", map[string]any{"phone": who.phone, "challenge_id": challenge(w, who.phone, "login"), "code": oracleCodeWrong})
		}},
		{name: "loginTotp", op: "loginTotp", noSubject: true, prepare: func(w *oracleWorld, who oracleWho) oracle.Request {
			return post("/auth/login/totp", map[string]any{"ticket": oracleTicket(w.seq()), "totp_code": "123456"})
		}},
		{name: "passkeyLoginBegin", op: "passkeyLoginBegin", noSubject: true, prepare: func(*oracleWorld, oracleWho) oracle.Request {
			return post("/auth/passkey/login/begin", map[string]any{})
		}},
		{name: "passkeyLoginFinish", op: "passkeyLoginFinish", noSubject: true, floor: floorVerify, prepare: func(w *oracleWorld, who oracleWho) oracle.Request {
			r := post("/auth/passkey/login/finish", []byte(`{"id":"AAAA","rawId":"AAAA","type":"public-key","response":{"clientDataJSON":"AAAA"}}`))
			r.Header = map[string]string{"X-Ctrlz-Ticket": oracleTicket(w.seq()), "Content-Type": "application/json"}
			return r
		}},
		{name: "refreshSession", op: "refreshSession", noSubject: true, prepare: func(*oracleWorld, oracleWho) oracle.Request {
			return post("/auth/refresh", nil)
		}},
		{name: "register/open", op: "register", floor: floorVerify, mode: "open", prepare: func(w *oracleWorld, who oracleWho) oracle.Request {
			return post("/auth/register", map[string]any{
				"phone": who.phone, "challenge_id": challenge(w, who.phone, "signup"), "code": oracleCodeWrong, "password": pwA,
			})
		}},
		{name: "lookupInvite", op: "lookupInvite", noSubject: true, prepare: func(w *oracleWorld, who oracleWho) oracle.Request {
			return post("/auth/invites/lookup", map[string]any{"token": oracleTicket(w.seq())})
		}},
		{name: "resetVerify", op: "resetVerify", floor: floorVerify, prepare: func(w *oracleWorld, who oracleWho) oracle.Request {
			return post("/auth/password/reset/verify", map[string]any{"phone": who.phone, "challenge_id": challenge(w, who.phone, "reset"), "code": oracleCodeWrong})
		}},
		{name: "resetPasskeyBegin", op: "resetPasskeyBegin", noSubject: true, prepare: func(w *oracleWorld, who oracleWho) oracle.Request {
			return post("/auth/password/reset/passkey/begin", map[string]any{"ticket": oracleTicket(w.seq())})
		}},
		{name: "resetPasskeyFinish", op: "resetPasskeyFinish", noSubject: true, floor: floorVerify, prepare: func(w *oracleWorld, who oracleWho) oracle.Request {
			r := post("/auth/password/reset/passkey/finish", []byte(`{"id":"AAAA","rawId":"AAAA","type":"public-key","response":{"clientDataJSON":"AAAA"}}`))
			r.Header = map[string]string{"X-Ctrlz-Ticket": oracleTicket(w.seq()), "Content-Type": "application/json"}
			return r
		}},
		{name: "resetComplete", op: "resetComplete", noSubject: true, prepare: func(w *oracleWorld, who oracleWho) oracle.Request {
			return post("/auth/password/reset/complete", map[string]any{"ticket": oracleTicket(w.seq()), "new_password": pwB})
		}},
		// The three public routes of P3 7.1. They take no phone, so the two runs ask with made-up values; each value is one this
		// service could have issued (its tag checks) for a row that does not exist, so the request goes through the pipeline's
		// screen, the lookup and the 404 that every refusal of these routes shares.
		{name: "openShare", op: "openShare", noSubject: true, prepare: func(w *oracleWorld, who oracleWho) oracle.Request {
			return post("/public/share", map[string]any{"link": w.ghostLink(bearer.ShareLink)})
		}},
		{name: "createShareAppleProfile", op: "createShareAppleProfile", noSubject: true, prepare: func(w *oracleWorld, who oracleWho) oracle.Request {
			return post("/public/share/apple-profile", map[string]any{"link": w.ghostLink(bearer.ShareLink), "params": map[string]any{"protocol": "doh"}})
		}},
		{name: "downloadAppleProfile", op: "downloadAppleProfile", noSubject: true, prepare: func(w *oracleWorld, who oracleWho) oracle.Request {
			return oracle.Request{Method: "GET", Path: "/public/apple-profile/" + w.ghostLink(bearer.DownloadLink)}
		}},
	}
}

// oracleWorld is the tenant API over real Postgres with a worker that drains the
// SMS queue into a fake gateway, and the handles every fault state needs.
type oracleWorld struct {
	t      *testing.T
	f      *frig
	ring   *keyring.Ring
	gate   *password.Gate
	hasher *password.Hasher
	strong *pwstrength.Checker
	anon   *pwstrength.Checker
	router *sms.Router
	good   *smssend.Worker
	bad    *smssend.Worker // cannot open the sealed payload
	sweep  *sweep.Sweeper  // the fast sweep, for the worker_down state
	src    *smssend.Source // the gateways the worker reads; a test may replace its Build
	gwURL  string          // the fake gateway, for a test that adds a second provider pointing at it
	gwID   uuid.UUID
	work   *heldWork // what the handlers owe after their floor, held until the meters of the request are read

	mu    sync.Mutex
	reply string // ok, 404, 500, recipient or blacklisted
	n     int
	held  []func()
}

func (w *oracleWorld) seq() int { w.mu.Lock(); defer w.mu.Unlock(); w.n++; return w.n }

// ghostLink is a link value of the kind that checks (this service made it) and names no row.
func (w *oracleWorld) ghostLink(k bearer.Kind) string {
	v, err := w.f.srv.bearer.Mint(k, uuid.New(), w.f.ck.now().Add(time.Hour))
	if err != nil {
		w.t.Fatal(err)
	}
	return v.Reveal()
}

func (w *oracleWorld) mustJSON(b []byte, v any) {
	w.t.Helper()
	if err := json.Unmarshal(b, v); err != nil {
		w.t.Fatalf("not JSON: %q", b)
	}
}

func newOracleWorld(t *testing.T) *oracleWorld {
	t.Helper()
	f := newFrig(t, frigOpts{})
	w := &oracleWorld{t: t, f: f, reply: "ok"}
	var err error
	// One ring for the API (which seals the payload) and the worker (which opens
	// it), with every domain either needs.
	w.ring, err = keyring.NewEphemeral(keyring.DomainUserTOTP, keyring.DomainOTPDelivery, keyring.DomainAuthMAC, keyring.DomainSMSCred, keyring.DomainDOHToken)
	if err != nil {
		t.Fatal(err)
	}
	// Gates the test can fill: one Argon2 slot and one slot of each scoring gate,
	// with a short wait so a refused request does not sit for two seconds.
	w.gate = password.NewGate(1, 100*time.Millisecond)
	w.hasher, err = password.NewHasher(password.Params{MemoryKiB: 64, Time: 1, Threads: 1}, w.gate)
	if err != nil {
		t.Fatal(err)
	}
	w.strong, w.anon = pwstrength.NewWithLimit(1, 100*time.Millisecond), pwstrength.NewWithLimit(1, 100*time.Millisecond)
	f.deps.Keys, f.deps.Hasher, f.deps.Strength, f.deps.StrengthUnauthenticated = w.ring, w.hasher, w.strong, w.anon
	w.work = &heldWork{}
	f.deps.After = w.work
	f.setLimiter(f.deps.Limiter)

	// The gateway: one sms.ir primary pointing at a server whose reply the test
	// sets. One gateway keeps "the breaker never opens" in the flapping state
	// independent of a second route.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.mu.Lock()
		mode := w.reply
		w.mu.Unlock()
		switch mode {
		case "recipient":
			_, _ = io.WriteString(rw, `{"status":104,"message":"x"}`)
		case "blacklisted":
			_, _ = io.WriteString(rw, `{"status":115,"message":"x"}`)
		case "refused":
			// sms.ir status 10: the API key is refused. The classification reads it as a refused login, which holds the gateway.
			_, _ = io.WriteString(rw, `{"status":10,"message":"x"}`)
		case "404":
			rw.WriteHeader(404)
		case "500":
			rw.WriteHeader(500)
		default:
			_, _ = io.WriteString(rw, `{"status":1,"message":"ok","data":{"messageId":42,"cost":1}}`)
		}
	}))
	t.Cleanup(srv.Close)
	f.env.ResetSMS(t)
	w.gwID = f.env.AddGateway(t, w.ring, authtest.Gateway{Provider: "sms_ir", Role: "primary", Credentials: `{"api_key":"oracle-key-1234"}`, Price: "10"})

	wlog := slog.New(slog.NewJSONHandler(io.Discard, nil))
	wst := f.env.Worker(t)
	src := smssend.NewSource(wst, w.ring, senders.Env{Name: "test"}, wlog)
	w.src, w.gwURL = src, srv.URL
	src.Build = func(provider string, creds secret.Bytes) (sms.Sender, error) {
		c, err := smsir.ParseCredentials(creds.Reveal())
		if err != nil {
			return nil, err
		}
		return smsir.New(smsir.Config{Credentials: c, BaseURL: srv.URL + "/v1", RootCAs: testtls.Roots()})
	}
	w.router = sms.NewRouter(src, classify.Routing{})
	w.good, err = smssend.New(smssend.Config{Store: wst, Router: w.router, Keys: w.ring, Log: wlog})
	if err != nil {
		t.Fatal(err)
	}
	// A worker whose delivery key is not the API's: it cannot open any payload,
	// which is the "worker failing" state. The gateways still load, with the key
	// of the source.
	other, err := keyring.NewEphemeral(keyring.DomainOTPDelivery, keyring.DomainSMSCred)
	if err != nil {
		t.Fatal(err)
	}
	w.bad, err = smssend.New(smssend.Config{Store: wst, Router: w.router, Keys: other, Log: wlog})
	if err != nil {
		t.Fatal(err)
	}
	w.sweep, err = sweep.New(sweep.Config{Store: wst, Log: wlog, Page: 1})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *oracleWorld) setReply(mode string) { w.mu.Lock(); w.reply = mode; w.mu.Unlock() }

// templateSQL deletes and re-inserts the mappings of the gateway. It is plain
// text with literals so that a whole reset is one round trip: a run resets the
// world, and a connection per statement made resets the slowest part of the test.
func (w *oracleWorld) templateSQL() string {
	var b strings.Builder
	b.WriteString("DELETE FROM ctrlz.sms_provider_templates WHERE gateway_id = '" + w.gwID.String() + "';")
	for _, key := range sms.Templates() {
		params := "ARRAY['CODE']::text[]"
		if n, _ := sms.PlaceholderCount(key); n == 0 {
			params = "ARRAY[]::text[]"
		}
		for _, loc := range []string{"fa", "en"} {
			b.WriteString("INSERT INTO ctrlz.sms_provider_templates (gateway_id, key, locale, provider_template_id, param_names) VALUES ('" +
				w.gwID.String() + "', '" + key + "', '" + loc + "', '1000', " + params + ");")
		}
	}
	return b.String()
}

// reset returns the world to its starting point between two runs.
func (w *oracleWorld) reset(mode string) {
	w.t.Helper()
	for _, r := range w.held {
		r()
	}
	w.held = nil
	w.setReply("ok")
	m := mode
	if m == "" {
		m = "closed"
	}
	w.f.env.Exec(w.t, w.templateSQL()+`
	  DELETE FROM ctrlz.otp_challenges; TRUNCATE ctrlz.sms_counters; DELETE FROM ctrlz.sms_deliveries;
	  DELETE FROM ctrlz.auth_throttle; DELETE FROM ctrlz.invites;
	  UPDATE ctrlz.sms_gateways SET consecutive_failures = 0, breaker_open_until = NULL, held_ct_sum = NULL, held_code = NULL;
	  UPDATE ctrlz.system_settings SET registration_mode = '`+m+`'`)
	w.router.Invalidate()
	w.f.ck.add(31 * time.Second) // the public configuration is cached for 30 s
}

// drain runs the worker until every row it can claim has ended: three passes, the
// three claims of one row. flap resets the gateway's consecutive count between
// passes, as another user's success does.
func (w *oracleWorld) drain(worker *smssend.Worker, flap bool) {
	w.t.Helper()
	for pass := 0; pass < 3; pass++ {
		n, err := worker.Drain(w.f.env.Ctx)
		if err != nil {
			w.t.Fatalf("drain: %v", err)
		}
		if n == 0 && pass > 0 {
			return // nothing left to claim, and nothing the lapse below would free
		}
		q := `UPDATE ctrlz.otp_challenges SET delivery_claimed_until = now() - interval '1 second' WHERE delivery_claimed_until IS NOT NULL;`
		if flap {
			q += `UPDATE ctrlz.sms_gateways SET consecutive_failures = 0, breaker_open_until = NULL;`
		}
		w.f.env.Exec(w.t, q)
		w.router.Invalidate()
	}
}

// holdGates takes every slot of the Argon2 gate and of both scoring gates.
func (w *oracleWorld) holdGates() {
	w.held = append(w.held, w.hold(w.gate), w.hold(w.strong.Gate()), w.hold(w.anon.Gate()))
}

func (w *oracleWorld) meters() oracle.Meters {
	return oracle.Meters{
		Argon2:   w.hasher.Runs(),
		Scorings: w.strong.Scorings() + w.anon.Scorings(),
		Gates:    w.gate.Attempts() + w.strong.Scorings() + w.anon.Scorings(),
		Pool:     w.f.st.Asked(),
	}
}

// thirdMarker is the device cookie of a browser that signed in to the account of the second tenant, the one account
// that is neither the phone with an account nor the phone without: a marker no request of the walk can hold for.
func (w *oracleWorld) thirdMarker() map[string]string {
	w.t.Helper()
	B := w.f.env.B
	c := w.f.client()
	c.ip = w.f.freshIP()
	c.mustLogin(B.Phone, pwB)
	m := c.jar[session.CookieDevice]
	if m == nil {
		w.t.Fatal("a login gave no device marker")
	}
	return map[string]string{session.CookieDevice: m.Value}
}

// spendClass takes every token of the plain bucket of a network class for the network of ip.
func (w *oracleWorld) spendClass(name, ip string) {
	w.t.Helper()
	class, ok := ratelimit.Lookup(ratelimit.Tenant, name)
	if !ok {
		w.t.Fatalf("no class %s", name)
	}
	addr := netip.MustParseAddr(ip)
	wide, _ := netkey.Wide(addr)
	sub := ratelimit.Subject{Network: netkey.Net(addr), Wide: wide}
	for i := 0; i < 1000; i++ {
		d, err := w.f.deps.Limiter.Allow(w.f.env.Ctx, class, sub)
		if err != nil {
			w.t.Fatal(err)
		}
		if !d.Allowed {
			return
		}
	}
	w.t.Fatalf("class %s never refused", name)
}

// stateAction changes the world for one registered state, after the request is
// prepared and the worker has delivered the preparation, and before the measured
// request. It returns how the worker must drain afterwards.
type stateAction func(w *oracleWorld, req oracle.Request, ip string) (worker *smssend.Worker, flap bool)

func oracleStates() map[string]stateAction {
	return map[string]stateAction{
		oracle.StateNone: func(w *oracleWorld, _ oracle.Request, _ string) (*smssend.Worker, bool) { return w.good, false },
		oracle.StateGateHeld: func(w *oracleWorld, _ oracle.Request, _ string) (*smssend.Worker, bool) {
			w.holdGates()
			return w.good, false
		},
		oracle.StateScopeSpent: func(w *oracleWorld, req oracle.Request, ip string) (*smssend.Worker, bool) {
			// The same request once, so every counter it touches has a row; then
			// every row is pushed past its limit. The measured request meets a spent
			// scope wherever it looks.
			if _, err := oracle.Fire(w.f.h, host, ip, req); err != nil {
				w.t.Fatal(err)
			}
			w.drain(w.good, false)
			w.f.env.Exec(w.t, `UPDATE ctrlz.auth_throttle SET count = 100000, window_start = $1`, w.f.ck.now()) // the app clock decides the window
			w.f.env.Exec(w.t, `UPDATE ctrlz.sms_counters SET count = 100000`)
			return w.good, false
		},
		oracle.StateTemplateUnmapped: func(w *oracleWorld, _ oracle.Request, _ string) (*smssend.Worker, bool) {
			w.f.env.Exec(w.t, `DELETE FROM ctrlz.sms_provider_templates WHERE gateway_id = $1`, w.gwID)
			w.router.Invalidate()
			return w.good, false
		},
		oracle.StateProvider404: func(w *oracleWorld, _ oracle.Request, _ string) (*smssend.Worker, bool) {
			w.setReply("404")
			return w.good, false
		},
		oracle.StateProviderFlapping: func(w *oracleWorld, _ oracle.Request, _ string) (*smssend.Worker, bool) {
			w.setReply("500")
			return w.good, true
		},
		oracle.StateWorkerFailing: func(w *oracleWorld, _ oracle.Request, _ string) (*smssend.Worker, bool) {
			return w.bad, false
		},
		// The next four end the real row by each way it can end unsent or refused. What a
		// row's ending does to the counters must not depend on the ending, because a decoy
		// is never ended at all (sms-r5-1, sms-r5-2, sms-r5-7). The work after the request is
		// in oracleAfterFire.
		oracle.StateRecipientRefused: func(w *oracleWorld, _ oracle.Request, _ string) (*smssend.Worker, bool) {
			w.setReply("recipient")
			return w.good, false
		},
		oracle.StateBlacklisted: func(w *oracleWorld, _ oracle.Request, _ string) (*smssend.Worker, bool) {
			w.setReply("blacklisted")
			return w.good, false
		},
		oracle.StateProviderRefusedLogin: func(w *oracleWorld, _ oracle.Request, _ string) (*smssend.Worker, bool) {
			w.setReply("refused")
			return w.good, false
		},
		oracle.StateBreakerOpensMidRow: func(w *oracleWorld, _ oracle.Request, _ string) (*smssend.Worker, bool) {
			return w.good, false
		},
		// Another session holds the row locks of the global counter (all sixteen shards since 0055, db-r18-2), and keeps them until the request has been
		// answered (oracleAfterFire). A request that takes the row waits for the lock timeout and answers 503, and
		// the phone with an account and the phone without must do the same (tenant-r16-11).
		oracle.StateGlobalCounterHeld: func(w *oracleWorld, _ oracle.Request, _ string) (*smssend.Worker, bool) {
			w.holdGlobalCounter()
			return w.good, false
		},
		oracle.StateWorkerDown: func(w *oracleWorld, _ oracle.Request, _ string) (*smssend.Worker, bool) {
			return w.good, false
		},
		// The database is stopped for every variant at once, in TestOracleDatabaseDown.
		oracle.StateDatabaseDown: nil,
	}
}

// oracleAfterFire holds the states whose fault arrives after the measured request was
// answered and before the row is ended. A state with no entry drains the worker as usual.
func oracleAfterFire() map[string]func(w *oracleWorld) {
	return map[string]func(w *oracleWorld){
		// The request saw an available gateway (the public flag is cached for 30 s), and the
		// breakers open before the worker ends its row, so the row finishes with
		// sms_available false. Every row pending when the last breaker opens does this, and
		// so does every row accepted in the window after a pause lapses and before the first
		// probe fails again (sms-r5-1).
		oracle.StateBreakerOpensMidRow: func(w *oracleWorld) {
			w.f.env.Exec(w.t, `UPDATE ctrlz.sms_gateways SET consecutive_failures = 3, breaker_open_until = now() + interval '1 hour'`)
			w.router.Invalidate()
			w.drain(w.good, false)
		},
		// No worker ran: the row expired unsent, and the sweep ends it (sms-r5-7).
		oracle.StateGlobalCounterHeld: func(w *oracleWorld) {
			w.releaseHeld()
			w.drain(w.good, false)
		},
		oracle.StateWorkerDown: func(w *oracleWorld) {
			w.f.env.Exec(w.t, `UPDATE ctrlz.otp_challenges SET `+testpg.OTPExpiredUnsentSet)
			if _, err := w.sweep.Fast(w.f.env.Ctx); err != nil {
				w.t.Fatalf("sweep: %v", err)
			}
		},
	}
}

// observe runs one subject of one variant under one state and returns what it saw.
func (w *oracleWorld) observe(v oracleVariant, who oracleWho, state string) oracle.Obs {
	w.t.Helper()
	w.reset(v.mode)
	req := v.prepare(w, who)
	// What the preparation asked for is delivered before the fault begins, so the
	// measured movement is the measured request's alone.
	w.drain(w.good, false)
	ip := w.f.freshIP()
	if v.spendClass != "" {
		w.spendClass(v.spendClass, ip)
	}
	worker, flap := oracleStates()[state](w, req, ip)
	// Work left over from the preparation (a failed login of the setup, the pre-request of
	// scope_spent) belongs to no measurement.
	w.work.Release()
	before, m0 := oracle.Take(w.t, w.f.env), w.meters()
	raw, err := oracle.Fire(w.f.h, host, ip, req)
	if err != nil {
		w.t.Fatal(err)
	}
	// What the request asked of the pool until its answer was returned, and then what it left to
	// do after the answer (tenant-r13-2). Nothing else uses this store while the request runs.
	mAnswer := w.meters()
	w.work.Release()
	if after, ok := oracleAfterFire()[state]; ok {
		after(w)
	} else {
		w.drain(worker, flap)
	}
	after, m1 := oracle.Take(w.t, w.f.env), w.meters()
	o := oracle.Observe(raw)
	o.SMS, o.Throttle, o.Gateways = after.Since(before)
	o.Meters = m1.Sub(m0)
	o.Meters.Pool, o.Meters.PoolAfter = mAnswer.Pool-m0.Pool, m1.Pool-mAnswer.Pool
	return o
}

func oracleSubjects(v oracleVariant) (known, unknown oracleWho) {
	return oracleWho{name: "known", known: true, phone: "09120000000"}, oracleWho{name: "unknown", phone: oracleUnknown}
}

// runOracleState runs the whole table under one state on a database of its own.
// One test per state keeps each under the six minute life of a test database, and
// lets a failing state be run alone.
func runOracleState(t *testing.T, state string) {
	w := newOracleWorld(t)
	ex := oracleExceptions()
	if oracleStates()[state] == nil {
		t.Fatalf("state %s has no action", state)
	}
	known, unknown := oracleSubjects(oracleVariant{})
	known.phone = w.f.env.A.Phone
	for _, v := range oracleVariants() {
		t.Run(v.name, func(t *testing.T) {
			w.t = t
			w.f.t = t
			k, u := known, unknown
			if v.noSubject {
				// Two made-up requests: the harness still demands they look alike.
				k, u = oracleWho{name: "first", phone: oracleUnknown}, oracleWho{name: "second", phone: oracleUnknown}
			}
			ko, uo := w.observe(v, k, state), w.observe(v, u, state)
			t.Logf("%s: %d %.60s | %s: %d %.60s", k.name, ko.Status, ko.Body, u.name, uo.Status, uo.Body)
			for _, o := range []oracle.Obs{ko, uo} {
				if v.floor > 0 && o.Dur < v.floor-20*time.Millisecond {
					t.Errorf("an answer took %v, under the %v floor", o.Dur, v.floor)
				}
			}
			for _, d := range ex.Unexplained(v.name, state, k.name, oracle.Compare(ko, uo)) {
				t.Errorf("%s differs between a phone with an account and one without: %s", d.Dim, d.Detail)
			}
			if v.name == "loginPassword" {
				// An account whose password is a console one-time password: its hash is
				// cheap and takes no Argon2 slot (admin-r3-11), which is a difference the
				// rule must see.
				otpw, err := password.NewOneTime()
				if err != nil {
					t.Fatal(err)
				}
				h, err := w.hasher.HashOneTime(otpw)
				if err != nil {
					t.Fatal(err)
				}
				w.f.env.Exec(t, `UPDATE ctrlz.users SET password_hash = $1 WHERE id = $2`, h.Reveal(), w.f.env.A.User)
				ot := oracleWho{name: "known_onetime", known: true, phone: w.f.env.A.Phone}
				oo := w.observe(v, ot, state)
				w.f.setPassword(w.f.env.A.Tenant, w.f.env.A.User, pwA)
				t.Logf("%s: %d %.60s", ot.name, oo.Status, oo.Body)
				for _, d := range ex.Unexplained(v.name, state, ot.name, oracle.Compare(oo, uo)) {
					t.Errorf("%s differs between a one-time password account and one without: %s", d.Dim, d.Detail)
				}
			}
		})
	}
	// An exception no run needed is stale. Only this state's entries can have been
	// used, so only they are judged.
	for _, e := range ex {
		if e.State == state || e.State == "*" {
			if s := ex.StaleFor(state); len(s) > 0 {
				t.Errorf("declared exception used by no run: %v", s)
			}
			break
		}
	}
}

func TestOracleNone(t *testing.T)             { runOracleState(t, oracle.StateNone) }
func TestOracleGateHeld(t *testing.T)         { runOracleState(t, oracle.StateGateHeld) }
func TestOracleScopeSpent(t *testing.T)       { runOracleState(t, oracle.StateScopeSpent) }
func TestOracleTemplateUnmapped(t *testing.T) { runOracleState(t, oracle.StateTemplateUnmapped) }
func TestOracleProvider404(t *testing.T)      { runOracleState(t, oracle.StateProvider404) }
func TestOracleProviderFlapping(t *testing.T) { runOracleState(t, oracle.StateProviderFlapping) }
func TestOracleWorkerFailing(t *testing.T)    { runOracleState(t, oracle.StateWorkerFailing) }
func TestOracleRecipientRefused(t *testing.T) { runOracleState(t, oracle.StateRecipientRefused) }
func TestOracleBlacklisted(t *testing.T)      { runOracleState(t, oracle.StateBlacklisted) }
func TestOracleProviderRefusedLogin(t *testing.T) {
	runOracleState(t, oracle.StateProviderRefusedLogin)
}
func TestOracleBreakerOpensMidRow(t *testing.T) {
	runOracleState(t, oracle.StateBreakerOpensMidRow)
}
func TestOracleWorkerDown(t *testing.T) { runOracleState(t, oracle.StateWorkerDown) }

// TestOracleDatabaseDown is the database_down state: every variant is prepared
// while Postgres is up, then Postgres is stopped and each request is asked for a
// phone with an account and one without. Counters cannot be read while it is
// down, so the observation is the wire and the meters.
func TestOracleDatabaseDown(t *testing.T) {
	w := newOracleWorld(t)
	known, unknown := oracleSubjects(oracleVariant{})
	known.phone = w.f.env.A.Phone
	type pair struct {
		v      oracleVariant
		k, u   oracle.Request
		ko, uo oracle.Obs
	}
	var pairs []pair
	for _, v := range oracleVariants() {
		w.reset(v.mode)
		k, u := known, unknown
		if v.noSubject {
			k, u = oracleWho{name: "first", phone: oracleUnknown}, oracleWho{name: "second", phone: oracleUnknown}
		}
		kr, ur := v.prepare(w, k), v.prepare(w, u)
		w.drain(w.good, false)
		pairs = append(pairs, pair{v: v, k: kr, u: ur})
	}
	// register and loginOtp need the open mode on while they are asked; the
	// configuration is cached, so one mode serves the whole outage.
	w.f.env.Exec(t, `UPDATE ctrlz.system_settings SET registration_mode = 'open'`)
	w.f.ck.add(31 * time.Second)
	w.f.client().get("/auth/config").want(200, "")
	// The free DNS answer is cached too (5 s, T-556): the first request of an outage would try the pool and fail, and the second
	// would find the failure remembered, so the pair would differ by the cache and not by the phone. One good load before the
	// outage, with the clock where it stays, serves both from memory.
	w.f.client().get("/public/free-dns").want(200, "")

	stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := cluster.StopPostgres(stopCtx); err != nil {
		t.Fatalf("stop postgres: %v", err)
	}
	restarted := false
	restart := func() {
		if !restarted {
			restarted = true
			if err := cluster.StartPostgres(context.Background()); err != nil {
				t.Errorf("restart postgres: %v", err)
			}
		}
	}
	t.Cleanup(restart)
	for i := range pairs {
		p := &pairs[i]
		m0 := w.meters()
		kraw, _ := oracle.Fire(w.f.h, host, w.f.freshIP(), p.k)
		m1 := w.meters()
		uraw, _ := oracle.Fire(w.f.h, host, w.f.freshIP(), p.u)
		m2 := w.meters()
		p.ko, p.uo = oracle.Observe(kraw), oracle.Observe(uraw)
		p.ko.Meters, p.uo.Meters = m1.Sub(m0), m2.Sub(m1)
	}
	restart()
	ex := oracleExceptions()
	for _, p := range pairs {
		for _, o := range []oracle.Obs{p.ko, p.uo} {
			if p.v.floor > 0 && o.Dur < p.v.floor-20*time.Millisecond {
				t.Errorf("%s: an answer took %v with the database down, under the %v floor", p.v.name, o.Dur, p.v.floor)
			}
		}
		for _, d := range ex.Unexplained(p.v.name, oracle.StateDatabaseDown, "known", oracle.Compare(p.ko, p.uo)) {
			t.Errorf("%s: %s differs between a phone with an account and one without, database down: %s", p.v.name, d.Dim, d.Detail)
		}
	}
}

// TestOracleCoversEveryNoneOperation fails for a route that needs no session and
// has no variant: a new route cannot go live outside the oracle by omission.
func TestOracleCoversEveryNoneOperation(t *testing.T) {
	have := map[string]bool{}
	for _, v := range oracleVariants() {
		have[v.op] = true
	}
	for _, op := range oracle.NoneOperations(t, ratelimit.Tenant) {
		if !have[op.ID] {
			t.Errorf("operation %s (%s) needs no session and has no variant in oracleVariants", op.ID, op.Key())
		}
	}
	vars := map[string]bool{}
	ops := map[string]bool{}
	for _, op := range oracle.NoneOperations(t, ratelimit.Tenant) {
		ops[op.ID] = true
	}
	for _, v := range oracleVariants() {
		if vars[v.name] {
			t.Errorf("variant %s is declared twice", v.name)
		}
		vars[v.name] = true
		if !ops[v.op] {
			t.Errorf("variant %s names %s, which is not an x-ctrlz-auth none operation", v.name, v.op)
		}
	}
}

// TestOracleHandlesEveryState fails for a registered state this test has no
// action for.
func TestOracleHandlesEveryState(t *testing.T) {
	states := oracleStates()
	for _, s := range oracle.AllStates() {
		if _, ok := states[s]; !ok {
			t.Errorf("state %s is registered in oracle.AllStates and has no entry in oracleStates", s)
		}
	}
	if len(states) != len(oracle.AllStates()) {
		t.Errorf("oracleStates has %d entries, oracle.AllStates %d", len(states), len(oracle.AllStates()))
	}
}

// hold takes the one slot of a gate.
func (w *oracleWorld) hold(g *password.Gate) func() {
	rel, err := g.Acquire(context.Background())
	if err != nil {
		w.t.Fatal(err)
	}
	return rel
}

// heldWork is the afterwork.Runner of the oracle world: it keeps what a handler owes after its floor
// until the test has read the meters of the request itself, then runs it. The production queue runs
// the work at once and off the request, which is what the rule needs, and a test that counts the
// pool asks of the request must be able to tell "inside the answer" from "after it" without a race
// (tenant-r13-2).
type heldWork struct {
	mu  sync.Mutex
	fns []func()
}

func (h *heldWork) Go(ctx context.Context, fn func(context.Context)) bool {
	base := context.WithoutCancel(ctx)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.fns = append(h.fns, func() {
		c, cancel := context.WithTimeout(base, 10*time.Second)
		defer cancel()
		fn(c)
	})
	return true
}

// Release runs everything held, in order, and waits for it.
func (h *heldWork) Release() {
	h.mu.Lock()
	fns := h.fns
	h.fns = nil
	h.mu.Unlock()
	for _, fn := range fns {
		fn()
	}
}

// holdGlobalCounter locks the row of today's global SMS counter in a second session, as a real send that
// has counted and not yet committed does, and keeps the lock until releaseHeld. The row exists first (it
// does from the first send of a day), so the lock is a row lock and not an uncommitted insert. The worker
// does not touch this row (its own gates are the 'outbox' keys), so draining while it is held is safe.
func (w *oracleWorld) holdGlobalCounter() {
	w.t.Helper()
	ctx := w.f.env.Ctx
	// Sixteen shard rows since 0055 (db-r18-2): a request locks one of them at random, so the world holds them all.
	w.f.env.Exec(w.t, `INSERT INTO ctrlz.sms_counters (day, scope, key, count)
SELECT (now() AT TIME ZONE 'Asia/Tehran')::date, 'global', k, 0 FROM unnest(ARRAY['all'] || ARRAY(SELECT 'all:' || n FROM generate_series(1, 15) n)) AS k
ON CONFLICT (day, scope, key) DO NOTHING`)
	conn, err := w.f.env.DB.Super(ctx)
	if err != nil {
		w.t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `BEGIN`); err != nil {
		w.t.Fatal(err)
	}
	tag, err := conn.Exec(ctx, `UPDATE ctrlz.sms_counters SET count = count WHERE scope = 'global' AND (key = 'all' OR key LIKE 'all:%')`)
	if err != nil || tag.RowsAffected() != 16 {
		w.t.Fatalf("the global counter rows were not locked: %v %v", tag, err)
	}
	released := false
	w.held = append(w.held, func() {
		if !released {
			released = true
			_, _ = conn.Exec(ctx, `ROLLBACK`)
			_ = conn.Close(ctx)
		}
	})
}

// releaseHeld gives back whatever the world holds (the gates, the counter row).
func (w *oracleWorld) releaseHeld() {
	for _, r := range w.held {
		r()
	}
	w.held = nil
}

func TestOracleGlobalCounterHeld(t *testing.T) { runOracleState(t, oracle.StateGlobalCounterHeld) }
