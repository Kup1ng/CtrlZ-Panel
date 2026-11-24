package smssend_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/otp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/classify"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/melipayamak"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/noop"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/senders"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/smsir"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testtls"
	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/smssend"
)

var cluster *testpg.Cluster

func TestMain(m *testing.M) {
	os.Exit(testpg.RunMain(m, func(c *testpg.Cluster) { cluster = c }))
}

const (
	canaryIRKey  = "CANARY-IR-KEY-9d41"
	canaryMeliPW = "CANARY-MELI-PW-77c2"
	code         = "246810"
)

var ip = netip.MustParseAddr("198.51.100.7")

// provider is a fake gateway: an httptest server whose reply a test sets.
type provider struct {
	srv   *httptest.Server
	mu    sync.Mutex
	calls []string // request bodies
	reply func(call int, w http.ResponseWriter)
	n     atomic.Int32
}

func newProvider(t *testing.T, ok func(http.ResponseWriter)) *provider {
	p := &provider{}
	p.reply = func(_ int, w http.ResponseWriter) { ok(w) }
	p.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		p.mu.Lock()
		p.calls = append(p.calls, string(b))
		p.mu.Unlock()
		p.reply(int(p.n.Add(1)), w)
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *provider) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.calls)
}

func irOK(w http.ResponseWriter) {
	_, _ = io.WriteString(w, `{"status":1,"message":"ok","data":{"messageId":42,"cost":1}}`)
}
func irStatus(status int) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) { _, _ = io.WriteString(w, `{"status":`+itoa(status)+`,"message":"x"}`) }
}
func meliOK(w http.ResponseWriter) {
	_, _ = io.WriteString(w, `{"Value":"1234567890123456","RetStatus":1,"StrRetStatus":"Ok"}`)
}
func http500(w http.ResponseWriter) { w.WriteHeader(500) }

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

// syncBuf is a log sink that can be read while the worker writes to it.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type rig struct {
	t        *testing.T
	env      *authtest.Env
	ring     *keyring.Ring
	pri, fb  *provider
	priID    uuid.UUID
	fbID     uuid.UUID
	tenant   *store.Store
	worker   *store.Store
	router   *sms.Router
	src      sms.Source
	w        *smssend.Worker
	otp      *otp.Service
	logs     *syncBuf
	noopFile string
	// afterSend, when set, runs after a gateway has accepted a message and before
	// the worker sees the result: a test uses it to stop the worker at the worst
	// moment.
	afterSend func()
}

type opts struct {
	ring     *keyring.Ring // the worker's ring, when a test wants a different one from the sealing ring
	priPrice string
	fbPrice  string
}

// newRig plants a primary sms.ir and a fallback Melipayamak gateway, both
// pointing at fake providers, and a worker over them.
func newRig(t *testing.T, o ...opts) *rig {
	t.Helper()
	var op opts
	if len(o) > 0 {
		op = o[0]
	}
	if op.priPrice == "" {
		op.priPrice = "10"
	}
	if op.fbPrice == "" {
		op.fbPrice = "7"
	}
	env := authtest.New(t, cluster)
	env.ResetSMS(t)
	ring, err := keyring.NewEphemeral(keyring.DomainOTPDelivery, keyring.DomainSMSCred, keyring.DomainAuthMAC)
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, env: env, ring: ring, logs: &syncBuf{}}
	r.pri, r.fb = newProvider(t, irOK), newProvider(t, meliOK)
	r.priID = env.AddGateway(t, ring, authtest.Gateway{Provider: "sms_ir", Role: "primary", Credentials: `{"api_key":"` + canaryIRKey + `"}`, Price: op.priPrice})
	r.fbID = env.AddGateway(t, ring, authtest.Gateway{Provider: "melipayamak", Role: "fallback",
		Credentials: `{"username":"canary-user","password":"` + canaryMeliPW + `"}`, Price: op.fbPrice})
	r.noopFile = t.TempDir() + "/noop.jsonl"
	r.tenant, r.worker = env.Tenant(t), env.Worker(t)

	workerRing := ring
	if op.ring != nil {
		workerRing = op.ring
	}
	log := slog.New(slog.NewJSONHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	src := smssend.NewSource(r.worker, workerRing, senderEnv(r.noopFile), log)
	src.Build = r.build
	r.src = src
	r.router = sms.NewRouter(src, classify.Routing{})
	r.w, err = smssend.New(smssend.Config{Store: r.worker, Router: r.router, Keys: workerRing, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	r.otp, err = otp.New(r.tenant.Auth(), ring, func(ctx context.Context) (store.PublicConfig, error) {
		return r.tenant.Auth().PublicConfig(ctx)
	}, otp.WithCodeSource(func() (secret.String, error) { return secret.New(code), nil }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.assertLogsClean() })
	return r
}

// build points the real drivers at the fake providers. The timeouts are the
// drivers' own defaults, so the hang test measures the real 6 seconds.
func (r *rig) build(provider string, creds secret.Bytes) (sms.Sender, error) {
	snd, err := r.buildInner(provider, creds)
	if err != nil {
		return nil, err
	}
	return hooked{Sender: snd, after: func() {
		if f := r.afterSend; f != nil {
			f()
		}
	}}, nil
}

// hooked runs a callback after each accepted send.
type hooked struct {
	sms.Sender
	after func()
}

func (h hooked) Send(ctx context.Context, m sms.Message, t sms.ProviderTemplate) (sms.Result, error) {
	res, err := h.Sender.Send(ctx, m, t)
	if err == nil {
		h.after()
	}
	return res, err
}

func (r *rig) buildInner(provider string, creds secret.Bytes) (sms.Sender, error) {
	switch provider {
	case "sms_ir":
		c, err := smsir.ParseCredentials(creds.Reveal())
		if err != nil {
			return nil, err
		}
		return smsir.New(smsir.Config{Credentials: c, BaseURL: r.pri.srv.URL + "/v1", RootCAs: testtls.Roots()})
	case "melipayamak":
		c, err := melipayamak.ParseCredentials(creds.Reveal())
		if err != nil {
			return nil, err
		}
		return melipayamak.New(melipayamak.Config{Credentials: c, BaseURL: r.fb.srv.URL + "/api/SendSMS", RootCAs: testtls.Roots()})
	case "noop":
		return noop.New("test", r.noopFile)
	}
	return nil, errors.New("unknown provider")
}

// assertLogsClean is the canary of 18.4 for this worker: no code, no phone, no
// credential reaches a log.
func (r *rig) assertLogsClean() {
	// Scrubbed of random ids and clock values first: "09121" is five hex digits a UUID can spell by
	// chance (authtest.ScrubNoise).
	out := authtest.ScrubNoise(r.logs.String())
	for _, bad := range []string{code, canaryIRKey, canaryMeliPW, "canary-user", "+9891", "09121", r.pri.srv.URL, r.fb.srv.URL, "127.0.0.1"} {
		if strings.Contains(out, bad) {
			r.t.Errorf("a log line holds %q:\n%s", bad, out)
		}
	}
	// Spec 18.4: the same canaries are in no sink table and not in the Postgres
	// server log either (sms_deliveries and alerts are where a gateway failure
	// is recorded).
	r.env.AssertSinksClean(r.t, canaryIRKey, canaryMeliPW, "canary-user")
	r.env.AssertServerLogClean(r.t, canaryIRKey, canaryMeliPW, "canary-user")
}

func (r *rig) drain() int {
	r.t.Helper()
	n, err := r.w.Drain(r.env.Ctx)
	if err != nil {
		r.t.Fatalf("drain: %v", err)
	}
	return n
}

// request makes a login challenge for a phone the way the api does.
func (r *rig) request(phone string) otp.Challenge {
	r.t.Helper()
	ch, err := r.otp.Request(r.env.Ctx, otp.Request{Phone: phone, Purpose: otp.Login, Locale: "fa", IP: ip})
	if err != nil {
		r.t.Fatalf("request %s: %v", phone, err)
	}
	return ch
}

// lapse ends every claim, as twenty seconds of a dead worker would.
func (r *rig) lapse() {
	r.env.Exec(r.t, `UPDATE ctrlz.otp_challenges SET delivery_claimed_until = now() - interval '2 minutes' WHERE delivery_claimed_until IS NOT NULL`)
	r.env.Exec(r.t, `UPDATE ctrlz.sms_outbox SET claimed_until = now() - interval '2 minutes' WHERE claimed_until IS NOT NULL`)
}

// ensureGlobalRow makes the 'all' row of today exist. The global count is sixteen shard rows since 0055
// (db-r18-2) and an issue picks one at random, so the row a test locks, adds a price to or reads is there only
// when the test makes it: the spend lives on it and the worker upserts it, but a test that holds it first has
// to find it.
func (r *rig) ensureGlobalRow() {
	r.t.Helper()
	r.env.Exec(r.t, `INSERT INTO ctrlz.sms_counters (day, scope, key, count) VALUES ((now() AT TIME ZONE 'Asia/Tehran')::date, 'global', 'all', 0)
ON CONFLICT (day, scope, key) DO NOTHING`)
}

func (r *rig) counter(scope, key string) int {
	r.t.Helper()
	var n int
	// The global count is sixteen shard rows since 0055 (db-r18-2): the counter of the world is their sum.
	err := r.env.DB.Scan(r.env.Ctx, `SELECT COALESCE((SELECT sum(count) FROM ctrlz.sms_counters
	  WHERE day = (now() AT TIME ZONE 'Asia/Tehran')::date AND scope = $1 AND (key = $2 OR ($1 = 'global' AND $2 = 'all' AND key LIKE 'all:%'))), 0)`, []any{scope, key}, &n)
	if err != nil {
		r.t.Fatal(err)
	}
	return n
}

func (r *rig) cost() float64 {
	r.t.Helper()
	var c float64
	err := r.env.DB.Scan(r.env.Ctx, `SELECT COALESCE((SELECT cost FROM ctrlz.sms_counters
	  WHERE day = (now() AT TIME ZONE 'Asia/Tehran')::date AND scope = 'global' AND key = 'all'), 0)::float8`, nil, &c)
	if err != nil {
		r.t.Fatal(err)
	}
	return c
}

func (r *rig) deliveryCT(id uuid.UUID) (sealed bool) {
	r.t.Helper()
	var ct []byte
	if err := r.env.DB.Scan(r.env.Ctx, `SELECT delivery_ct FROM ctrlz.otp_challenges WHERE id = $1`, []any{id}, &ct); err != nil {
		r.t.Fatal(err)
	}
	return ct != nil
}

func (r *rig) count(sql string, args ...any) int {
	r.t.Helper()
	var n int
	if err := r.env.DB.Scan(r.env.Ctx, sql, args, &n); err != nil {
		r.t.Fatal(err)
	}
	return n
}

func senderEnv(file string) senders.Env { return senders.Env{Name: "test", NoopFile: file} }

// ---------------------------------------------------------------------------
// OTP delivery

func TestDeliversAnOTPThroughThePrimary(t *testing.T) {
	r := newRig(t)
	phone := r.env.A.Phone
	ch := r.request(phone)
	if !r.deliveryCT(ch.ID) {
		t.Fatal("a known phone's challenge has no payload to send")
	}
	if n := r.drain(); n != 1 {
		t.Fatalf("drained %d rows", n)
	}
	if r.pri.count() != 1 || r.fb.count() != 0 {
		t.Fatalf("calls: primary %d, fallback %d", r.pri.count(), r.fb.count())
	}
	if !strings.Contains(r.pri.calls[0], code) || !strings.Contains(r.pri.calls[0], `"mobile":"0912`) {
		t.Errorf("the provider did not get the code: %s", r.pri.calls[0])
	}
	if r.deliveryCT(ch.ID) {
		t.Error("the sealed code stayed after the gateway accepted it")
	}
	// The code the user received is the code the database checks.
	if err := r.otp.Check(r.env.Ctx, ch.ID, phone, otp.Login, code); err != nil {
		t.Errorf("the delivered code does not verify: %v", err)
	}
	// The delivery log has the attempt, and no phone and no text.
	if n := r.count(`SELECT count(*) FROM ctrlz.sms_deliveries WHERE source = 'otp' AND source_id = $1 AND provider = 'sms_ir'
	  AND outcome = 'accepted' AND provider_msg_id = '42'`, ch.ID); n != 1 {
		t.Errorf("delivery rows: %d", n)
	}
	var dump string
	_ = r.env.DB.Scan(r.env.Ctx, `SELECT string_agg(to_jsonb(d)::text, ' ') FROM ctrlz.sms_deliveries d`, nil, &dump)
	if strings.Contains(dump, phone) || strings.Contains(dump, code) || strings.Contains(dump, "0912") {
		t.Errorf("the delivery log holds a number or a code: %s", dump)
	}
	// The configured price reached the money counter; the gateway shows its success.
	if r.cost() != 10 {
		t.Errorf("cost counter %v", r.cost())
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.sms_gateways WHERE id = $1 AND last_ok_at IS NOT NULL AND consecutive_failures = 0`, r.priID); n != 1 {
		t.Error("gateway success not recorded")
	}
	// Nothing left to send.
	if n := r.drain(); n != 0 {
		t.Errorf("a second pass handled %d rows", n)
	}
}

func TestDecoyIsNeverSentOrCharged(t *testing.T) {
	r := newRig(t)
	ch := r.request("+989129990000") // no such account
	if r.deliveryCT(ch.ID) {
		t.Fatal("a decoy has a payload")
	}
	if n := r.drain(); n != 0 || r.pri.count() != 0 {
		t.Fatalf("a decoy was sent: drained %d, primary %d", n, r.pri.count())
	}
	if r.counter("global", "all") != 0 || r.cost() != 0 {
		t.Error("a decoy cost the world a message")
	}
	if r.counter("phone", "+989129990000") != 1 {
		t.Error("a decoy must count on the phone, like a real request")
	}
}

func TestPrimaryDownFallbackSends(t *testing.T) {
	r := newRig(t)
	r.pri.reply = func(_ int, w http.ResponseWriter) { http500(w) }
	ch := r.request(r.env.A.Phone)
	r.drain()
	if r.pri.count() != 1 || r.fb.count() != 1 {
		t.Fatalf("calls: primary %d, fallback %d", r.pri.count(), r.fb.count())
	}
	if !strings.Contains(r.fb.calls[0], code) {
		t.Errorf("the fallback did not get the code: %s", r.fb.calls[0])
	}
	if r.deliveryCT(ch.ID) {
		t.Error("code not cleared after the fallback accepted")
	}
	// Both attempts are in the log, in order.
	rows := r.count(`SELECT count(*) FROM ctrlz.sms_deliveries WHERE source_id = $1`, ch.ID)
	if rows != 2 {
		t.Fatalf("delivery rows: %d", rows)
	}
	if r.count(`SELECT count(*) FROM ctrlz.sms_deliveries WHERE source_id = $1 AND provider = 'sms_ir' AND outcome = 'unreachable' AND provider_status = 'http_500'`, ch.ID) != 1 ||
		r.count(`SELECT count(*) FROM ctrlz.sms_deliveries WHERE source_id = $1 AND provider = 'melipayamak' AND outcome = 'accepted'`, ch.ID) != 1 {
		t.Error("the two attempts are not logged as expected")
	}
	// The fallback's price is what was charged.
	if r.cost() != 7 {
		t.Errorf("cost %v", r.cost())
	}
	if r.count(`SELECT consecutive_failures FROM ctrlz.sms_gateways WHERE id = $1`, r.priID) != 1 {
		t.Error("the primary's failure was not counted")
	}
}

func TestBothDownRefundsAndOpensTheBreakers(t *testing.T) {
	r := newRig(t)
	r.pri.reply = func(_ int, w http.ResponseWriter) { http500(w) }
	r.fb.reply = func(_ int, w http.ResponseWriter) { http500(w) }
	phone := r.env.A.Phone
	ch := r.request(phone)
	net24 := "198.51.100.0/24"
	if r.counter("phone", phone) != 1 || r.counter("phone_net", phone+"|"+net24) != 1 || r.counter("global", "all") != 1 || r.counter("ip", ip.String()) != 1 {
		t.Fatal("the issue did not count where expected")
	}

	// Three passes, each after the claim lapsed (9.5): the third ends the row.
	for i := 1; i <= 3; i++ {
		r.drain()
		if i < 3 {
			if !r.deliveryCT(ch.ID) {
				t.Fatalf("the row ended after attempt %d", i)
			}
			r.lapse()
		}
	}
	if r.deliveryCT(ch.ID) {
		t.Fatal("the code stayed after the third failed attempt")
	}
	// Only the global key goes back (sms-r5-1, spec 9.5). The phone, the network and
	// the address keys stay spent: a decoy bumps them and is never refunded, so any
	// refund of them would let the 429 of a later request tell a phone with an account
	// from one without.
	for _, k := range [][2]string{{"phone", phone}, {"phone_net", phone + "|" + net24}, {"ip", ip.String()}, {"ip", net24}} {
		if n := r.counter(k[0], k[1]); n != 1 {
			t.Errorf("counter %s %s = %d after the row ended, want 1 (not refunded)", k[0], k[1], n)
		}
	}
	if n := r.counter("global", "all"); n != 0 {
		t.Errorf("global counter = %d after the row ended, want 0 (refunded)", n)
	}
	if r.cost() != 0 {
		t.Errorf("a failed send was charged: %v", r.cost())
	}
	// Delivery rows are bounded: at most two per attempt.
	if n := r.count(`SELECT count(*) FROM ctrlz.sms_deliveries WHERE source_id = $1`, ch.ID); n != 6 {
		t.Errorf("delivery rows: %d, want 6 (3 attempts x 2 gateways)", n)
	}
	// An alert says the SMS is down.
	if r.count(`SELECT count(*) FROM ctrlz.alerts WHERE kind = 'sms_down' AND resolved_at IS NULL`) != 1 {
		t.Error("no open sms_down alert")
	}
	// Three transient failures opened both breakers, and the login page still offers a code: the public
	// flag is configuration alone (sms-r18-2), so a request is accepted for a known and an unknown
	// phone alike and spends its slots like any other (the owner-visible cost of 9.5).
	cfg, err := r.tenant.Auth().PublicConfig(r.env.Ctx)
	if err != nil || !cfg.SMSAvailable {
		t.Fatalf("sms_available = %v (%v) with both breakers open: the flag does not follow the breaker", cfg.SMSAvailable, err)
	}
	unknown := "+989129990001"
	for _, p := range []string{phone, unknown} {
		_, err := r.otp.Request(r.env.Ctx, otp.Request{Phone: p, Purpose: otp.Login, Locale: "fa", IP: ip})
		if errors.Is(err, otp.ErrSMSUnavailable) {
			t.Errorf("request for %s with both gateways down was refused as unavailable: %v", p, err)
		}
	}
	if r.counter("phone", unknown) != 1 {
		t.Error("a request during the outage spent no slot of the phone")
	}

	// Recovery: the gateways come back, the breakers are cleared (here by hand; in
	// production the timer does it), and the same phone gets a challenge again.
	r.pri.reply = func(_ int, w http.ResponseWriter) { irOK(w) }
	r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET breaker_open_until = NULL, consecutive_failures = 0`)
	r.env.Exec(t, `UPDATE ctrlz.otp_challenges SET created_at = created_at - interval '2 minutes'`) // past the cooldown
	r.router.Invalidate()
	ch2 := r.request(phone)
	r.drain()
	if r.deliveryCT(ch2.ID) {
		t.Error("after recovery the code was not sent")
	}
}

// The price of "a refund must not tell a phone with an account from one without"
// (sms-r5-1): a code that never arrived still uses the phone's and the network's slots.
// The cap of three per phone and network holds, the fourth request is limited, and the
// shared global counter is the only one given back. A decoy is never refunded, so the
// 429 is the same for a phone with an account and one without.
func TestAFailedSendKeepsThePerPhoneSlotsAndGivesBackTheGlobalOne(t *testing.T) {
	r := newRig(t)
	r.pri.reply = func(_ int, w http.ResponseWriter) { http500(w) }
	r.fb.reply = func(_ int, w http.ResponseWriter) { http500(w) }
	for i := 0; i < 3; i++ {
		ch := r.request(r.env.A.Phone)
		for a := 0; a < 3; a++ {
			r.drain()
			r.lapse()
		}
		if r.deliveryCT(ch.ID) {
			t.Fatalf("request %d was not given up", i)
		}
		if n := r.counter("global", "all"); n != 0 {
			t.Fatalf("request %d: global counter %d, want 0", i, n)
		}
		r.env.Exec(t, `UPDATE ctrlz.otp_challenges SET created_at = created_at - interval '2 minutes'`)
		r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET breaker_open_until = NULL, consecutive_failures = 0`)
		r.router.Invalidate()
	}
	if n := r.counter("phone", r.env.A.Phone); n != 3 {
		t.Errorf("phone counter %d, want 3 (nothing refunded)", n)
	}
	_, err := r.otp.Request(r.env.Ctx, otp.Request{Phone: r.env.A.Phone, Purpose: otp.Login, Locale: "fa", IP: ip})
	if !errors.Is(err, otp.ErrLimited) {
		t.Errorf("fourth request: %v, want the cap", err)
	}
}

func TestHangTimesOutInSixSecondsAndFallsBack(t *testing.T) {
	r := newRig(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	r.pri.reply = func(_ int, w http.ResponseWriter) { <-release }
	ch := r.request(r.env.A.Phone)
	start := time.Now()
	r.drain()
	took := time.Since(start)
	if took < 5500*time.Millisecond || took > 8*time.Second {
		t.Errorf("a hanging gateway took %v, want about 6 s (9.1)", took)
	}
	if r.fb.count() != 1 || r.deliveryCT(ch.ID) {
		t.Errorf("the fallback did not send after the hang (fallback calls %d)", r.fb.count())
	}
	if r.count(`SELECT count(*) FROM ctrlz.sms_deliveries WHERE source_id = $1 AND provider_status = 'timeout' AND outcome = 'unreachable'`, ch.ID) != 1 {
		t.Error("the hang is not logged as a timeout")
	}
}

func TestAuthAndCreditErrorsFallBackAndAlertOnce(t *testing.T) {
	r := newRig(t)
	// Several sends to one phone in one test: lift the per-phone caps.
	r.env.Exec(t, `UPDATE ctrlz.system_settings SET otp_cap_phone = 100, otp_cap_phone_net = 100`)
	r.pri.reply = func(_ int, w http.ResponseWriter) { irStatus(10)(w) } // key refused
	for i := 0; i < 3; i++ {
		ch := r.request(r.env.A.Phone)
		r.drain()
		if r.deliveryCT(ch.ID) {
			t.Fatalf("send %d did not go through the fallback", i)
		}
		r.env.Exec(t, `UPDATE ctrlz.otp_challenges SET created_at = created_at - interval '2 minutes'`)
	}
	if r.fb.count() != 3 {
		t.Errorf("fallback calls: %d", r.fb.count())
	}
	// Three failures of one class on one gateway are one open alert.
	if n := r.count(`SELECT count(*) FROM ctrlz.alerts WHERE kind = 'sms_gateway' AND params ->> 'key' = $1 AND resolved_at IS NULL`, r.priID.String()+":auth"); n != 1 {
		t.Errorf("open auth alerts: %d, want 1", n)
	}
	if r.count(`SELECT count(*) FROM ctrlz.alerts WHERE kind = 'sms_gateway' AND params ->> 'class' = 'auth' AND params ->> 'provider' = 'sms_ir' AND severity = 'critical'`) != 1 {
		t.Error("the alert does not name provider and class")
	}
	// Three refused keys in a row opened the primary's breaker: an Auth failure
	// says the whole gateway cannot send (9.1). Close it so the credit error
	// reaches the gateway.
	if r.count(`SELECT consecutive_failures FROM ctrlz.sms_gateways WHERE id = $1 AND breaker_open_until IS NOT NULL`, r.priID) != 3 {
		t.Error("three refused keys did not open the breaker")
	}
	r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET breaker_open_until = NULL, consecutive_failures = 0`)
	// The refused key put the primary on hold (sms-r11-9); the operator saves a new key, which is
	// what lifts it.
	r.reseal(r.priID, "sms_ir", `{"api_key":"`+canaryIRKey+`-2"}`)
	r.router.Invalidate()
	// A credit error is a different class, so a different alert.
	r.pri.reply = func(_ int, w http.ResponseWriter) { irStatus(102)(w) }
	r.request(r.env.A.Phone)
	r.drain()
	if n := r.count(`SELECT count(*) FROM ctrlz.alerts WHERE params ->> 'key' = $1`, r.priID.String()+":credit"); n != 1 {
		t.Errorf("credit alerts: %d", n)
	}
	// The provider's message is in no alert.
	var dump string
	_ = r.env.DB.Scan(r.env.Ctx, `SELECT string_agg(a::text, ' ') FROM ctrlz.alerts a`, nil, &dump)
	for _, bad := range []string{canaryIRKey, canaryMeliPW, "+98912"} {
		if strings.Contains(dump, bad) {
			t.Errorf("an alert holds %q", bad)
		}
	}
	// Acking the alert lets the next failure raise a new one.
	r.env.Exec(t, `UPDATE ctrlz.alerts SET resolved_at = now()`)
	r.env.Exec(t, `UPDATE ctrlz.otp_challenges SET created_at = created_at - interval '2 minutes'`)
	r.pri.reply = func(_ int, w http.ResponseWriter) { irStatus(10)(w) }
	r.request(r.env.A.Phone)
	r.drain()
	if n := r.count(`SELECT count(*) FROM ctrlz.alerts WHERE resolved_at IS NULL AND params ->> 'key' = $1`, r.priID.String()+":auth"); n != 1 {
		t.Errorf("after an ack the failure did not raise a new alert: %d", n)
	}
}

func TestHTTP401FromTheProviderIsAuthClass(t *testing.T) {
	r := newRig(t)
	r.pri.reply = func(_ int, w http.ResponseWriter) { w.WriteHeader(401) }
	r.request(r.env.A.Phone)
	r.drain()
	if r.fb.count() != 1 {
		t.Error("no fallback after a 401")
	}
	if r.count(`SELECT count(*) FROM ctrlz.alerts WHERE params ->> 'key' = $1`, r.priID.String()+":auth") != 1 {
		t.Error("no auth alert after a 401")
	}
	// An auth failure counts toward the breaker, like a transient one: it says the
	// whole gateway cannot send. One is not enough to open it.
	if r.count(`SELECT consecutive_failures FROM ctrlz.sms_gateways WHERE id = $1 AND breaker_open_until IS NULL`, r.priID) != 1 {
		t.Error("an auth error did not count toward the breaker")
	}
}

func TestUnreadableCredentialsAreSkippedWithAnAlert(t *testing.T) {
	// The primary's credentials were sealed under another key, as after a lost key
	// file. The worker's ring cannot open them.
	r := newRig(t)
	other, _ := keyring.NewEphemeral(keyring.DomainSMSCred)
	ct, err := sms.SealCredentials(other, r.priID, "sms_ir", secret.NewBytes([]byte(`{"api_key":"`+canaryIRKey+`"}`)))
	if err != nil {
		t.Fatal(err)
	}
	r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET credentials_ct = $2 WHERE id = $1`, r.priID, ct)
	ch := r.request(r.env.A.Phone)
	r.drain()
	if r.pri.count() != 0 {
		t.Error("the unreadable gateway was called")
	}
	if r.fb.count() != 1 || r.deliveryCT(ch.ID) {
		t.Error("the fallback did not send")
	}
	if r.count(`SELECT count(*) FROM ctrlz.alerts WHERE kind = 'sms_gateway' AND params ->> 'key' = $1 AND params ->> 'code' = 'credentials_unreadable'`,
		r.priID.String()+":config") != 1 {
		t.Error("no alert for the unreadable gateway")
	}
	// No delivery row for a gateway that was never called.
	if r.count(`SELECT count(*) FROM ctrlz.sms_deliveries WHERE provider = 'sms_ir'`) != 0 {
		t.Error("a gateway that was skipped has a delivery row")
	}
	// The logs are checked clean for the key by the rig's cleanup.
	if !strings.Contains(r.logs.String(), "credentials unreadable") {
		t.Error("the unreadable credentials were not logged at all")
	}
}

func TestRecipientErrorStopsAndKeepsTheCaps(t *testing.T) {
	r := newRig(t)
	r.pri.reply = func(_ int, w http.ResponseWriter) { irStatus(104)(w) } // the number itself is refused
	phone := r.env.A.Phone
	ch := r.request(phone)
	r.drain()
	if r.fb.count() != 0 {
		t.Error("a refused number went on to the fallback")
	}
	if r.deliveryCT(ch.ID) {
		t.Error("the row was not finished after a recipient error")
	}
	// The per-phone cap stays spent (it is what stops a refused number from being tried
	// without limit), and the global key goes back like every unsent ending (sms-r5-2).
	if r.counter("phone", phone) != 1 || r.counter("global", "all") != 0 {
		t.Error("a recipient failure: the phone slot must stay spent and the global one go back")
	}
	if r.count(`SELECT count(*) FROM ctrlz.sms_deliveries WHERE source_id = $1 AND outcome = 'rejected' AND provider_status = '104'`, ch.ID) != 1 {
		t.Error("the refusal is not logged")
	}
	// A recipient error says nothing about the gateway: no alert, no breaker.
	if r.count(`SELECT count(*) FROM ctrlz.alerts`) != 0 {
		t.Error("a recipient error raised an alert")
	}
}

func TestOnlyUnexpiredRowsSendAfterTheWorkerWasDown(t *testing.T) {
	r := newRig(t)
	fresh := r.request(r.env.A.Phone)
	stale := r.request(r.env.B.Phone)
	// The worker was down past the second code's life. A row cannot be claimed
	// after it expires.
	r.env.Exec(t, `UPDATE ctrlz.otp_challenges SET `+testpg.OTPExpiredUnsentSet+` WHERE id = $1`, stale.ID)
	if n := r.drain(); n != 1 {
		t.Fatalf("drained %d", n)
	}
	if r.deliveryCT(fresh.ID) {
		t.Error("the unexpired code was not sent")
	}
	if !r.deliveryCT(stale.ID) {
		t.Error("the expired code was sent or cleared by the sender (the sweep owns that)")
	}
	if r.pri.count() != 1 {
		t.Errorf("provider calls: %d", r.pri.count())
	}
}

func TestCrashMidSendIsSentAgainAfterTheClaimLapses(t *testing.T) {
	r := newRig(t)
	ch := r.request(r.env.A.Phone)
	// A worker claims the row and dies before it records anything.
	if err := r.worker.WithGlobal(r.env.Ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		got, err := g.OTPClaim(5, 3)
		if err != nil || len(got) != 1 {
			t.Fatalf("claim: %v %v", got, err)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// While the claim holds, another worker leaves the row alone.
	if n := r.drain(); n != 0 || r.pri.count() != 0 {
		t.Fatalf("a held claim was taken: drained %d", n)
	}
	// After it lapses the row is sent: a provider may get two, and that is
	// accepted over a lost code (18.3).
	r.lapse()
	if n := r.drain(); n != 1 {
		t.Fatalf("after the claim lapsed, drained %d", n)
	}
	if r.deliveryCT(ch.ID) || r.pri.count() != 1 {
		t.Error("the row was not sent after the crash")
	}
	if r.count(`SELECT delivery_attempts FROM ctrlz.otp_challenges WHERE id = $1`, ch.ID) != 2 {
		t.Error("attempts should count the dead worker's claim too")
	}
}

func TestUnreadableDeliveryEndsTheRowAndRefunds(t *testing.T) {
	r := newRig(t)
	phone := r.env.A.Phone
	ch := r.request(phone)
	// The row is damaged (or sealed under a key this worker does not hold).
	r.env.Exec(t, `UPDATE ctrlz.otp_challenges SET delivery_ct = '\x00112233' WHERE id = $1`, ch.ID)
	r.drain()
	if r.pri.count() != 0 {
		t.Error("something was sent from a row that cannot be read")
	}
	if r.deliveryCT(ch.ID) {
		t.Error("the unreadable row was left to be claimed again")
	}
	// Only the global key goes back (sms-r3-6): the phone and network keys stay, as
	// for a decoy, so a damaged row does not tell a known phone from an unknown one.
	if r.counter("phone", phone) != 1 || r.counter("global", "all") != 0 {
		t.Errorf("refund after an unreadable row: phone %d (want 1), global %d (want 0)", r.counter("phone", phone), r.counter("global", "all"))
	}
	if r.count(`SELECT count(*) FROM ctrlz.alerts WHERE kind = 'sms_payload'`) != 1 {
		t.Error("no alert for an unreadable row")
	}
}

func TestNoGatewayAtAllEndsAfterThreeAttempts(t *testing.T) {
	r := newRig(t)
	phone := r.env.A.Phone
	ch := r.request(phone)
	// The roles are taken away after the issue: the request saw an available
	// gateway, and the worker finds none.
	r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET role = 'disabled'`)
	r.router.Invalidate()
	for i := 0; i < 3; i++ {
		r.drain()
		r.lapse()
	}
	if r.deliveryCT(ch.ID) {
		t.Fatal("a row with no gateway to send through was left for ever")
	}
	if r.counter("global", "all") != 0 || r.counter("phone", phone) != 1 { // only the global key goes back (sms-r5-1)
		t.Error("the row was not refunded")
	}
	if r.pri.count()+r.fb.count() != 0 {
		t.Error("a disabled gateway was called")
	}
}

// ---------------------------------------------------------------------------
// Outbox

func (r *rig) queue(kind, template, phone string, gateway uuid.UUID, value string) uuid.UUID {
	r.t.Helper()
	id := uuid.Must(uuid.NewV7())
	ct, err := sms.SealOutbox(r.ring, id, phone, secret.New(value))
	if err != nil {
		r.t.Fatal(err)
	}
	r.env.Exec(r.t, `INSERT INTO ctrlz.sms_outbox (id, kind, gateway_id, phone_e164, template_key, locale, params_ct) VALUES ($1, $2, $3, $4, $5, 'fa', $6)`,
		id, kind, nilIf(gateway), phone, template, ct)
	return id
}

func nilIf(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}

func (r *rig) outbox(id uuid.UUID) (state, lastErr string, params bool) {
	r.t.Helper()
	var e *string
	var ct []byte
	if err := r.env.DB.Scan(r.env.Ctx, `SELECT state, last_error, params_ct FROM ctrlz.sms_outbox WHERE id = $1`, []any{id}, &state, &e, &ct); err != nil {
		r.t.Fatal(err)
	}
	if e != nil {
		lastErr = *e
	}
	return state, lastErr, ct != nil
}

func TestInviteIsSentAndItsParamsAreDropped(t *testing.T) {
	r := newRig(t)
	id := r.queue("invite", "invite", "+989121112233", uuid.Nil, "ABCDEFGHJKMNPQRSTVWX")
	r.drain()
	if state, _, params := r.outbox(id); state != "sent" || params {
		t.Fatalf("state %s, params kept %v", state, params)
	}
	if r.pri.count() != 1 || !strings.Contains(r.pri.calls[0], "ABCDEFGHJKMNPQRSTVWX") {
		t.Errorf("the provider did not get the invite code: %v", r.pri.calls)
	}
	// 20 characters fit sms.ir's 25 (finding 6).
	if r.count(`SELECT count(*) FROM ctrlz.sms_deliveries WHERE source = 'outbox' AND source_id = $1 AND outcome = 'accepted'`, id) != 1 {
		t.Error("no delivery row for the outbox message")
	}
	var dump string
	_ = r.env.DB.Scan(r.env.Ctx, `SELECT string_agg(to_jsonb(d)::text, ' ') FROM ctrlz.sms_deliveries d`, nil, &dump)
	if strings.Contains(dump, "989121112233") || strings.Contains(dump, "ABCDEFGH") {
		t.Errorf("the delivery log holds a number or a code: %s", dump)
	}
	if r.cost() != 10 {
		t.Errorf("the money cap does not see outbox messages: %v", r.cost())
	}
}

func TestInviteParamsOpenOnlyWithTheSMSCredKey(t *testing.T) {
	// A worker with another key cannot open an invite: the row ends failed and the
	// provider is not called.
	other, _ := keyring.NewEphemeral(keyring.DomainOTPDelivery, keyring.DomainSMSCred)
	r := newRig(t, opts{ring: other})
	// The gateways were sealed under the rig's ring, so with the other ring they
	// are unreadable too: use a noop gateway for this test instead.
	r.env.Exec(t, `DELETE FROM ctrlz.sms_gateways`)
	r.env.AddGateway(t, other, authtest.Gateway{Provider: "noop", Role: "primary"})
	r.router.Invalidate()
	id := r.queue("invite", "invite", "+989121112233", uuid.Nil, "ABCDEFGHJKMNPQRSTVWX") // sealed under r.ring
	r.drain()
	state, last, params := r.outbox(id)
	if state != "failed" || last != "unreadable" || params {
		t.Errorf("state %s last %s params kept %v", state, last, params)
	}
	if _, err := os.Stat(r.noopFile); err == nil {
		t.Error("something was sent")
	}
}

func TestBothDownRetriesThenTheSweepEndsItAtAnHour(t *testing.T) {
	r := newRig(t)
	r.pri.reply = func(_ int, w http.ResponseWriter) { http500(w) }
	r.fb.reply = func(_ int, w http.ResponseWriter) { http500(w) }
	id := r.queue("invite", "invite", "+989121112233", uuid.Nil, "ABCDEFGHJKMNPQRSTVWX")
	r.drain()
	if state, _, params := r.outbox(id); state != "pending" || !params {
		t.Fatalf("after one failed pass: %s, params kept %v", state, params)
	}
	// The retry is held back, not tried every twenty seconds.
	var until time.Time
	_ = r.env.DB.Scan(r.env.Ctx, `SELECT claimed_until FROM ctrlz.sms_outbox WHERE id = $1`, []any{id}, &until)
	if wait := time.Until(until); wait < 20*time.Second || wait > 60*time.Second {
		t.Errorf("first retry in %v", wait)
	}
	if n := r.drain(); n != 0 {
		t.Errorf("a held-back message was tried again at once: %d", n)
	}
	r.lapse()
	r.drain()
	if r.pri.count() != 2 {
		t.Errorf("provider calls after the second pass: %d", r.pri.count())
	}
	// No phone and no text in the delivery log, whatever happened.
	var dump string
	_ = r.env.DB.Scan(r.env.Ctx, `SELECT string_agg(to_jsonb(d)::text, ' ') FROM ctrlz.sms_deliveries d`, nil, &dump)
	if strings.Contains(dump, "989121112233") || strings.Contains(dump, "ABCDEFGH") {
		t.Errorf("the delivery log holds a number or a code: %s", dump)
	}
	// An hour on, the sweep ends it and drops the sealed value.
	r.env.Exec(t, `UPDATE ctrlz.sms_outbox SET created_at = now() - interval '61 minutes' WHERE id = $1`, id)
	// The retry hold has run out by then; the sweep waits for a claim to lapse (db-r3-2).
	r.lapse()
	if n := r.drain(); n != 0 {
		t.Errorf("a message past the hour was tried again: %d", n)
	}
	if err := r.worker.WithGlobal(r.env.Ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		n, err := g.OutboxFailStaleBatch(1000)
		if n != 1 {
			t.Errorf("OutboxFailStale ended %d", n)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if state, last, params := r.outbox(id); state != "failed" || last != "timeout" || params {
		t.Errorf("after an hour: %s %s params kept %v", state, last, params)
	}
}

func TestOutboxCountCapStopsTheSecondMessage(t *testing.T) {
	r := newRig(t)
	r.env.Exec(t, `UPDATE ctrlz.system_settings SET sms_outbox_cap_daily = 1`)
	a := r.queue("invite", "invite", "+989121112233", uuid.Nil, "AAAAAAAAAAAAAAAAAAAA")
	r.drain()
	b := r.queue("invite", "invite", "+989121112244", uuid.Nil, "BBBBBBBBBBBBBBBBBBBB")
	c := r.queue("invite", "invite", "+989121112255", uuid.Nil, "CCCCCCCCCCCCCCCCCCCC")
	r.drain()
	if state, _, _ := r.outbox(a); state != "sent" {
		t.Errorf("first: %s", state)
	}
	for _, id := range []uuid.UUID{b, c} {
		if state, last, params := r.outbox(id); state != "failed" || last != "cap" || params {
			t.Errorf("over the cap: %s %s params kept %v", state, last, params)
		}
	}
	if r.pri.count() != 1 {
		t.Errorf("a capped message was sent: %d provider calls", r.pri.count())
	}
	// Two capped messages in an hour are one alert.
	if n := r.count(`SELECT count(*) FROM ctrlz.alerts WHERE kind = 'sms_outbox_cap'`); n != 1 {
		t.Errorf("cap alerts: %d, want 1 for the hour", n)
	}
}

func TestOutboxCostCapStopsMessages(t *testing.T) {
	r := newRig(t)
	r.env.Exec(t, `UPDATE ctrlz.system_settings SET sms_cost_cap_daily = 10`) // one message at the primary's price
	a := r.queue("invite", "invite", "+989121112233", uuid.Nil, "AAAAAAAAAAAAAAAAAAAA")
	r.drain()
	b := r.queue("invite", "invite", "+989121112244", uuid.Nil, "BBBBBBBBBBBBBBBBBBBB")
	r.drain()
	if state, _, _ := r.outbox(a); state != "sent" {
		t.Errorf("first: %s", state)
	}
	if state, last, _ := r.outbox(b); state != "failed" || last != "cap" {
		t.Errorf("over the money cap: %s %s", state, last)
	}
	if r.pri.count() != 1 {
		t.Errorf("provider calls: %d", r.pri.count())
	}
}

func TestRetryDoesNotCountTwiceAgainstTheOutboxCap(t *testing.T) {
	r := newRig(t)
	r.env.Exec(t, `UPDATE ctrlz.system_settings SET sms_outbox_cap_daily = 1`)
	r.pri.reply = func(_ int, w http.ResponseWriter) { http500(w) }
	r.fb.reply = func(_ int, w http.ResponseWriter) { http500(w) }
	id := r.queue("invite", "invite", "+989121112233", uuid.Nil, "AAAAAAAAAAAAAAAAAAAA")
	r.drain()
	r.pri.reply = func(_ int, w http.ResponseWriter) { irOK(w) }
	r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET breaker_open_until = NULL`)
	r.router.Invalidate()
	r.lapse()
	r.drain()
	if state, _, _ := r.outbox(id); state != "sent" {
		t.Errorf("the retry of an already counted message was capped: %s", state)
	}
}

func TestTestSendIsPinnedToOneGatewayAndAnswersOnce(t *testing.T) {
	r := newRig(t)
	// A gateway that holds no role yet: the operator tests it before routing.
	extra := r.env.AddGateway(t, r.ring, authtest.Gateway{Provider: "noop", Role: "disabled"})
	r.router.Invalidate()
	id := r.queue("test", "otp", "+989121112233", extra, "123456")
	r.drain()
	if state, _, params := r.outbox(id); state != "sent" || params {
		t.Fatalf("test send: %s params kept %v", state, params)
	}
	b, err := os.ReadFile(r.noopFile)
	if err != nil || !strings.Contains(string(b), "123456") {
		t.Errorf("the pinned gateway did not get the message: %q %v", b, err)
	}
	if r.pri.count()+r.fb.count() != 0 {
		t.Error("a test send went through a routed gateway")
	}

	// A failing pinned gateway answers at once, with its class and code, and does
	// not fall back to the others.
	r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET role = 'disabled' WHERE id = $1`, r.priID) // not routed
	r.pri.reply = func(_ int, w http.ResponseWriter) { irStatus(10)(w) }
	id2 := r.queue("test", "otp", "+989121112233", r.priID, "123456")
	r.router.Invalidate()
	r.drain()
	if state, last, params := r.outbox(id2); state != "failed" || last != "auth:10" || params {
		t.Errorf("failing test send: %s %s params kept %v", state, last, params)
	}
	if r.fb.count() != 0 {
		t.Error("a pinned test send fell back")
	}
}

// ---------------------------------------------------------------------------
// Run, wake-ups and shutdown

func TestRunSendsOnNotificationAndStopsOnCancel(t *testing.T) {
	r := newRig(t)
	ctx, cancel := context.WithCancel(r.env.Ctx)
	// Run has finished its first drain (there is no LISTEN to open, see the poll), so what is issued next can
	// only be sent by a poll.
	done := r.startAndAwaitFirstDrain(ctx, r.w.Run)
	ch := r.request(r.env.A.Phone)
	deadline := time.Now().Add(6 * time.Second)
	for r.deliveryCT(ch.ID) && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if r.deliveryCT(ch.ID) {
		t.Fatal("the running worker did not send within 6 seconds")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestRunDrainsWhatWaitedBeforeItStarted(t *testing.T) {
	// A notification sent while nobody listened is lost; the first drain and the
	// poll find the row anyway.
	r := newRig(t)
	ch := r.request(r.env.A.Phone)
	ctx, cancel := context.WithCancel(r.env.Ctx)
	defer cancel()
	go func() { _ = r.w.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for r.deliveryCT(ch.ID) && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if r.deliveryCT(ch.ID) {
		t.Fatal("a row that waited was not sent")
	}
}

func TestNewRequiresBothKeyDomains(t *testing.T) {
	ring, _ := keyring.NewEphemeral(keyring.DomainOTPDelivery)
	_, err := smssend.New(smssend.Config{Store: &store.Store{}, Router: sms.NewRouter(nil, classify.Routing{}), Keys: ring, Log: slog.New(slog.NewJSONHandler(io.Discard, nil))})
	if err == nil {
		t.Error("a worker without the sms_cred key was built")
	}
}

// ---------------------------------------------------------------------------
// Review round 1 (SMS layer): races between the worker and the sweep, record
// failures, shutdown, several workers, start-up alerts.

// The OTP expired and the claim lapsed while the third attempt was still in a
// slow send, so the sweep ended the row and refunded it. The worker's own
// terminal failure must not refund it a second time (review sms-r1-3, sms-r1-13):
// the network and global counters are shared, so a second refund would open a
// slot that nobody gave back.
func TestSweepAndWorkerNeverRefundTheSameOTPTwice(t *testing.T) {
	r := newRig(t)
	r.fb.reply = func(_ int, w http.ResponseWriter) { http500(w) }
	phone := r.env.A.Phone
	ch := r.request(phone)
	// Another user's message on the shared global counter, so that a second
	// refund shows as 0 where the right answer is 1.
	r.ensureGlobalRow()
	r.env.Exec(t, `UPDATE ctrlz.sms_counters SET count = count + 1 WHERE scope = 'global' AND key = 'all' AND day = (now() AT TIME ZONE 'Asia/Tehran')::date`)
	r.env.Exec(t, `UPDATE ctrlz.otp_challenges SET delivery_attempts = 2 WHERE id = $1`, ch.ID) // the next claim is the third

	var once sync.Once
	interfere := func() {
		once.Do(func() {
			if err := r.env.DB.Exec(r.env.Ctx, `UPDATE ctrlz.otp_challenges SET delivery_claimed_until = now() - interval '2 minutes', expires_at = now() - interval '1 second' WHERE id = $1`, ch.ID); err != nil {
				t.Errorf("interfere: %v", err)
				return
			}
			err := r.worker.WithGlobal(r.env.Ctx, store.TxOpts{}, func(g store.GlobalTx) error {
				n, err := g.OTPExpireUndelivered()
				if n != 1 {
					t.Errorf("the sweep ended %d rows", n)
				}
				return err
			})
			if err != nil {
				t.Errorf("sweep: %v", err)
			}
		})
	}
	r.pri.reply = func(_ int, w http.ResponseWriter) { interfere(); http500(w) }
	r.drain()
	if r.deliveryCT(ch.ID) {
		t.Fatal("the row was not ended")
	}
	if got := r.counter("global", "all"); got != 1 {
		t.Errorf("global counter %d, want 1: the row was refunded twice", got)
	}
	// The phone's own slot stays spent: only the global key goes back (sms-r6-1).
	if got := r.counter("phone", phone); got != 1 {
		t.Errorf("phone counter %d, want 1", got)
	}
}

// A record transaction that fails after the provider accepted (here the gateway
// row was deleted under the snapshot, so the delivery row's foreign key fails)
// must not let the provider send the same code at every claim until the code
// expires (review sms-r1-4). The third claim is the last; after it the row is
// closed and refunded without another provider call.
func TestARecordThatKeepsFailingDoesNotSendTheSameCodeForEver(t *testing.T) {
	r := newRig(t)
	phone := r.env.A.Phone
	ch := r.request(phone)
	var once sync.Once
	r.afterSend = func() {
		once.Do(func() {
			if err := r.env.DB.Exec(r.env.Ctx, `DELETE FROM ctrlz.sms_gateways WHERE id = $1`, r.priID); err != nil {
				t.Errorf("delete gateway: %v", err)
			}
		})
	}
	for i := 0; i < 6; i++ {
		r.drain()
		r.lapse()
	}
	if got := r.pri.count(); got != 3 {
		t.Errorf("the provider got the code %d times, want 3 (the claim ceiling)", got)
	}
	if r.deliveryCT(ch.ID) {
		t.Error("the exhausted row still holds its code")
	}
	if r.counter("global", "all") != 0 || r.counter("phone", phone) != 1 { // only the global key goes back (sms-r5-1)
		t.Error("the exhausted row was not refunded")
	}
	if n := r.count(`SELECT delivery_attempts FROM ctrlz.otp_challenges WHERE id = $1`, ch.ID); n != 3 {
		t.Errorf("attempts %d", n)
	}
}

// The daily count and the claim commit together (review sms-r1-5). When the
// count cannot be written the message is not claimed at all, so no retry can
// find it with Attempts > 1 and skip the count.
func TestOutboxCountAndClaimCommitTogether(t *testing.T) {
	r := newRig(t)
	id := r.queue("invite", "invite", "+989121112233", uuid.Nil, "ABCDEFGHJKMNPQRSTVWX")
	r.env.Exec(t, `REVOKE INSERT, UPDATE ON ctrlz.sms_counters FROM ctrlz_worker`)
	if _, err := r.w.Drain(r.env.Ctx); err == nil {
		t.Fatal("a claim that could not count succeeded")
	}
	if n := r.count(`SELECT attempts FROM ctrlz.sms_outbox WHERE id = $1`, id); n != 0 {
		t.Fatalf("the message was claimed (attempts %d) although its count failed", n)
	}
	if r.pri.count() != 0 {
		t.Error("something was sent")
	}
	r.env.Exec(t, `GRANT INSERT, UPDATE ON ctrlz.sms_counters TO ctrlz_worker`)
	r.drain()
	if state, _, _ := r.outbox(id); state != "sent" {
		t.Errorf("state %s", state)
	}
	if got := r.counter("global", "outbox"); got != 1 {
		t.Errorf("the message was counted %d times, want 1", got)
	}
}

// A gateway that accepted a message just before the worker was told to stop is
// recorded, so a restart does not send the same code or invite again
// (review sms-r1-6).
func TestAcceptedJustBeforeShutdownIsRecordedAndNotSentAgain(t *testing.T) {
	r := newRig(t)
	ctx, cancel := context.WithCancel(r.env.Ctx)
	defer cancel()
	r.afterSend = cancel
	ch := r.request(r.env.A.Phone)
	if _, err := r.w.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	r.afterSend = nil
	if r.deliveryCT(ch.ID) {
		t.Error("the accepted code stayed sealed: the next worker would send it again")
	}
	if r.count(`SELECT count(*) FROM ctrlz.sms_deliveries WHERE source_id = $1 AND outcome = 'accepted'`, ch.ID) != 1 {
		t.Error("the accepted send was not recorded")
	}
	if r.cost() != 10 {
		t.Errorf("the accepted send was not charged: %v", r.cost())
	}
	r.lapse()
	if n := r.drain(); n != 0 || r.pri.count() != 1 {
		t.Errorf("after the restart: drained %d, provider calls %d", n, r.pri.count())
	}

	// The same for an invite.
	ctx2, cancel2 := context.WithCancel(r.env.Ctx)
	defer cancel2()
	r.afterSend = cancel2
	id := r.queue("invite", "invite", "+989121112233", uuid.Nil, "ABCDEFGHJKMNPQRSTVWX")
	if _, err := r.w.Drain(ctx2); err != nil {
		t.Fatal(err)
	}
	r.afterSend = nil
	if state, _, params := r.outbox(id); state != "sent" || params {
		t.Errorf("invite after shutdown: %s, params kept %v", state, params)
	}
	r.lapse()
	r.drain()
	if r.pri.count() != 2 {
		t.Errorf("the invite was sent again: %d provider calls", r.pri.count())
	}
}

// Two workers drain one backlog: SKIP LOCKED and the claim column give every row
// to exactly one of them (9.5, review sms-r1-12).
func TestTwoWorkersShareOneBacklogWithoutDuplicates(t *testing.T) {
	r := newRig(t)
	const n = 12
	values := make([]string, n)
	ids := make([]uuid.UUID, n)
	for i := range values {
		values[i] = fmt.Sprintf("INVITE%014d", i)
		ids[i] = r.queue("invite", "invite", fmt.Sprintf("+98912111%04d", i), uuid.Nil, values[i])
	}
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	src2 := smssend.NewSource(r.worker, r.ring, senderEnv(r.noopFile), log)
	src2.Build = r.build
	w2, err := smssend.New(smssend.Config{Store: r.worker, Router: sms.NewRouter(src2, classify.Routing{}), Keys: r.ring, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for _, w := range []*smssend.Worker{r.w, w2} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := w.Drain(r.env.Ctx); err != nil {
				t.Errorf("drain: %v", err)
			}
		}()
	}
	wg.Wait()
	if got := r.pri.count(); got != n {
		t.Fatalf("the provider got %d messages for %d rows", got, n)
	}
	r.pri.mu.Lock()
	all := strings.Join(r.pri.calls, "\n")
	r.pri.mu.Unlock()
	for i, v := range values {
		if c := strings.Count(all, v); c != 1 {
			t.Errorf("invite %d went out %d times", i, c)
		}
		if state, _, _ := r.outbox(ids[i]); state != "sent" {
			t.Errorf("invite %d is %s", i, state)
		}
	}
	if r.cost() != float64(10*n) {
		t.Errorf("cost %v, want %d", r.cost(), 10*n)
	}
}

// A production start with a noop gateway in a routed role raises its alert at
// start, before any user asks for a code, and sends nothing (spec 9.3, review
// sms-r1-8 and sms-r1-18). This test runs the real driver factory with the
// production environment; the rig's other tests replace the factory.
func TestProductionNoopPrimaryAlertsAtStartAndSendsNothing(t *testing.T) {
	r := newRig(t)
	r.env.Exec(t, `DELETE FROM ctrlz.sms_gateways`)
	noopID := r.env.AddGateway(t, r.ring, authtest.Gateway{Provider: "noop", Role: "primary"})
	logs := &syncBuf{}
	log := slog.New(slog.NewJSONHandler(logs, nil))
	src := smssend.NewSource(r.worker, r.ring, senders.Env{Name: "production"}, log)
	w, err := smssend.New(smssend.Config{Store: r.worker, Router: sms.NewRouter(src, classify.Routing{}), Keys: r.ring, Log: log})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(r.env.Ctx)
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	alerts := func() int {
		return r.count(`SELECT count(*) FROM ctrlz.alerts WHERE kind = 'sms_gateway' AND resolved_at IS NULL
		  AND params ->> 'code' = 'noop_in_production' AND params ->> 'key' = $1`, noopID.String()+":config")
	}
	deadline := time.Now().Add(10 * time.Second)
	for alerts() == 0 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	cancel()
	<-done
	if alerts() != 1 {
		t.Fatalf("no alert at start for a noop primary in production (%d):\n%s", alerts(), logs.String())
	}
	if !strings.Contains(logs.String(), "cannot be used") || !strings.Contains(logs.String(), "noop_in_production") {
		t.Errorf("the problem was not logged: %s", logs.String())
	}

	// A gateway that cannot send at all opens its breaker at start, so the login
	// page already hides OTP and a request is refused before any cap is spent
	// (sms-r2-2). The alert is critical: nothing can be sent through it.
	cfg, err := r.tenant.Auth().PublicConfig(r.env.Ctx)
	if err != nil || cfg.SMSAvailable {
		t.Fatalf("sms_available = %v (%v) with the only routed gateway unusable", cfg.SMSAvailable, err)
	}
	if _, err := r.otp.Request(r.env.Ctx, otp.Request{Phone: r.env.A.Phone, Purpose: otp.Login, Locale: "fa", IP: ip}); !errors.Is(err, otp.ErrSMSUnavailable) {
		t.Fatalf("request while the only gateway is unusable: %v", err)
	}
	if r.count(`SELECT count(*) FROM ctrlz.alerts WHERE kind = 'sms_gateway' AND severity = 'critical' AND params ->> 'key' = $1`, noopID.String()+":config") != 1 {
		t.Error("the alert for an unusable gateway is not critical")
	}

	// The pause ends (here by hand). A user asks for a code. It is not sent, the
	// row ends after its three attempts with its caps back, the alert stays one,
	// and the breaker closes the login page again.
	r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET breaker_open_until = NULL, consecutive_failures = 0`)
	// Round 15 (sms-r15-1, sms-r15-4): the pause ending does not turn the login page back on. The
	// worker wrote its judgement of the gateway into the row at start, and the flag reads it.
	if cfg, err := r.tenant.Auth().PublicConfig(r.env.Ctx); err != nil || cfg.SMSAvailable {
		t.Fatalf("sms_available = %v (%v) after the pause of a gateway that cannot be built", cfg.SMSAvailable, err)
	}
	if _, err := r.otp.Request(r.env.Ctx, otp.Request{Phone: r.env.A.Phone, Purpose: otp.Login, Locale: "fa", IP: ip}); !errors.Is(err, otp.ErrSMSUnavailable) {
		t.Fatalf("a request after the pause was accepted: %v", err)
	}
	// What is left is the window before a worker has written the judgement (a gateway row saved
	// since the last load, or a database restored under a running worker): the row is accepted, the
	// worker passes the gateway over locally, and the row ends with its caps back.
	r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET unusable_ct_sum = NULL`)
	phone := r.env.A.Phone
	ch := r.request(phone)
	for i := 0; i < 3; i++ {
		if _, err := w.Drain(r.env.Ctx); err != nil {
			t.Fatal(err)
		}
		r.lapse()
	}
	if r.deliveryCT(ch.ID) {
		t.Error("the code was left sealed with no gateway to send it")
	}
	if r.counter("global", "all") != 0 || r.counter("phone", phone) != 1 { // only the global key goes back (sms-r5-1)
		t.Error("the unsent code was not refunded")
	}
	if _, err := os.Stat(r.noopFile); err == nil {
		t.Error("the noop gateway wrote a message in production")
	}
	if alerts() != 1 {
		t.Errorf("alerts after use: %d, want still 1", alerts())
	}
	if cfg, err := r.tenant.Auth().PublicConfig(r.env.Ctx); err != nil || cfg.SMSAvailable {
		t.Errorf("sms_available = %v (%v) after three local failures", cfg.SMSAvailable, err)
	}
}

// When both gateways refuse (a wrong key on one, no credit on the other), every
// OTP request would otherwise be answered 202 and never sent. Auth and Credit
// failures count toward the breaker, so after three the login page learns that
// SMS is down (review sms-r1-9).
func TestBothGatewaysRefusingOpenTheBreakersAndSMSIsReportedDown(t *testing.T) {
	r := newRig(t)
	r.pri.reply = func(_ int, w http.ResponseWriter) { irStatus(10)(w) }                          // key refused
	r.fb.reply = func(_ int, w http.ResponseWriter) { _, _ = io.WriteString(w, `{"Value":"2"}`) } // no credit
	phone := r.env.A.Phone
	ch := r.request(phone)
	for i := 0; i < 3; i++ {
		r.drain()
		r.lapse()
	}
	if r.deliveryCT(ch.ID) {
		t.Error("the row was not ended")
	}
	// The breakers are open, and the public flag stays true (configuration alone, sms-r18-2): the outage
	// is shown by the alerts below, and a request is not refused as unavailable.
	cfg, err := r.tenant.Auth().PublicConfig(r.env.Ctx)
	if err != nil || !cfg.SMSAvailable {
		t.Fatalf("sms_available = %v (%v) with both gateways refusing: the flag does not follow the breaker", cfg.SMSAvailable, err)
	}
	if _, err := r.otp.Request(r.env.Ctx, otp.Request{Phone: phone, Purpose: otp.Login, Locale: "fa", IP: ip}); errors.Is(err, otp.ErrSMSUnavailable) {
		t.Errorf("a request with both gateways refusing was refused as unavailable: %v", err)
	}
	if r.count(`SELECT count(*) FROM ctrlz.sms_gateways WHERE breaker_open_until > now()`) != 2 {
		t.Error("the breakers of both gateways are not open")
	}
	for _, key := range []string{r.priID.String() + ":auth", r.fbID.String() + ":credit"} {
		if r.count(`SELECT count(*) FROM ctrlz.alerts WHERE kind = 'sms_gateway' AND severity = 'critical' AND params ->> 'key' = $1`, key) != 1 {
			t.Errorf("no critical alert %s", key)
		}
	}
	// The operator fixes the key and proves it with a test send, which ignores the
	// breaker and closes it on success.
	r.pri.reply = func(_ int, w http.ResponseWriter) { irOK(w) }
	id := r.queue("test", "otp", "+989121112233", r.priID, "123456")
	r.drain()
	if state, _, _ := r.outbox(id); state != "sent" {
		t.Fatalf("test send: %s", state)
	}
	if cfg, _ := r.tenant.Auth().PublicConfig(r.env.Ctx); !cfg.SMSAvailable {
		t.Error("sms_available stayed false after the gateway was proven working")
	}
}
