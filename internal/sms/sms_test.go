package sms_test

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/otp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/classify"
)

func TestErrorFormatHoldsNothingElse(t *testing.T) {
	e := sms.NewError("sms_ir", sms.Auth, sms.StatusCode("401"))
	if e.Error() != "sms: sms_ir unknown" {
		t.Fatalf("a status the table does not name must read unknown, got %q", e.Error())
	}
	e = sms.NewError("sms_ir", sms.Recipient, sms.StatusCode("104"))
	if e.Error() != "sms: sms_ir 104" {
		t.Fatalf("got %q", e.Error())
	}
	// Whatever a caller manages to put in the parts (the lint forbids it, but a test or a
	// future mistake can), an Error holds only members of the closed sets.
	hostile := sms.Code("https://api.sms.ir/v1/send?key=SECRET 09121234567 \n")
	e = sms.NewError("melipayamak https://x", sms.Config, hostile)
	if e.Code != sms.CodeUnknown || e.Provider != sms.ProviderOther {
		t.Fatalf("off-list parts survived: %q %q", e.Provider, e.Code)
	}
	if got := e.Error(); got != "sms: unknown unknown" {
		t.Fatalf("got %q", got)
	}
}

// Every member of the table is spelled in the alphabet of a code and none is long;
// the numeric table is exactly the statuses the two providers document.
func TestCodeTable(t *testing.T) {
	for _, c := range []sms.Code{sms.CodeUnknown, sms.CodeOK, sms.CodeTimeout, sms.CodeNetwork, sms.CodeNoTemplate, sms.CodeCredentialsUnreadable,
		sms.HTTPCode(401), sms.HTTPCode(503), sms.StatusCode("-110"), sms.StatusCode("104"), sms.StatusNumber(115)} {
		if !c.Valid() || c == sms.CodeNone {
			t.Errorf("%q should be a member", c)
		}
	}
	for _, c := range []sms.Code{sms.CodeNone, "value_1234", "status_12", "http_99", "http_600", "http_4o1", "http_0401", "104 ", "1", "99999999999", "09121234567"} {
		if c.Valid() {
			t.Errorf("%q must not be a member", c)
		}
	}
	if sms.HTTPCode(99) != sms.CodeUnknown || sms.HTTPCode(600) != sms.CodeUnknown || sms.StatusCode("123456") != sms.CodeUnknown || sms.StatusCode("09121234567") != sms.CodeUnknown {
		t.Error("a number outside the tables must be the fixed unknown code")
	}
}

func TestClassNames(t *testing.T) {
	want := map[sms.Class]string{
		sms.Transient: "transient", sms.Auth: "auth", sms.Credit: "credit",
		sms.Config: "config", sms.Recipient: "recipient", sms.Blacklisted: "blacklisted",
	}
	for c, n := range want {
		if c.String() != n {
			t.Errorf("%d is %q, want %q", c, c.String(), n)
		}
	}
}

func TestTemplateSet(t *testing.T) {
	for _, k := range []string{"otp", "otp_reset", "otp_phone"} {
		if n, ok := sms.PlaceholderCount(k); !ok || n != 1 {
			t.Errorf("%s: %d %v", k, n, ok)
		}
	}
	for _, k := range []string{"account_exists", "notice_passkey", "notice_recovery"} {
		if n, ok := sms.PlaceholderCount(k); !ok || n != 0 {
			t.Errorf("%s: %d %v", k, n, ok)
		}
	}
	if sms.ValidTemplate("invite") {
		t.Error("the invite template is gone: an invite is never sent by SMS (D67)")
	}
	if sms.ValidTemplate("welcome") {
		t.Error("an unknown key is valid")
	}
	if len(sms.Templates()) != 6 {
		t.Error("six templates")
	}
}

// seededBodies is the table of spec 9.4, key to {fa, en}.
// TestTheSeedsAreTheMigrationsBodies ties it to the migrations that really
// build the rows (0011 and the guarded updates of 0041), so neither can drift alone.
var seededBodies = map[string][2]string{
	"otp":             {"کد تایید Ctrl Z: {code}. اعتبار ۵ دقیقه؛ آن را به کسی ندهید.", "Ctrl Z code: {code}. Valid for 5 minutes. Do not share it."},
	"otp_reset":       {"کد بازیابی رمز Ctrl Z: {code}. اگر شما نخواستید، نادیده بگیرید.", "Ctrl Z password reset code: {code}. Ignore this if you did not ask for it."},
	"otp_phone":       {"کد تغییر شماره Ctrl Z: {code}. اگر شما نبودید، رمز را عوض کنید.", "Ctrl Z phone change code: {code}. If this was not you, change your password."},
	"account_exists":  {"برای این شماره قبلا حساب Ctrl Z ساخته شده است. از صفحه ورود یا فراموشی رمز استفاده کنید.", "This number already has a Ctrl Z account. Use the login or forgot password page."},
	"notice_passkey":  {"Passkey تازه ثبت شد. شما نبودید؟ رمز Ctrl Z را بازیابی کنید.", "Ctrl Z: a passkey was added to your account. If this was not you, use the forgot password page."},
	"notice_recovery": {"کدهای بازیابی Ctrl Z عوض شد. شما نبودید؟ کدها و رمز را عوض کنید.", "Ctrl Z: your recovery codes were replaced. If this was not you, make new codes and change your password."},
}

func TestCheckBody(t *testing.T) {
	good := map[string]string{
		"otp":            "Ctrl Z code: {code}. Valid for 5 minutes.",
		"account_exists": "This number already has an account.",
	}
	for k, b := range good {
		if err := sms.CheckBody(k, b); err != nil {
			t.Errorf("%s: %v", k, err)
		}
	}
	bad := []struct{ key, body string }{
		{"otp", "no marker"},
		{"otp", "{code} and {code}"},
		{"otp", "{code} {name}"},
		{"otp", "{code} see https://ctrlz.example/x"},
		{"otp", "{code} www.example.com"},
		{"otp", "{code} verify at ctrlz-verify.ir"},
		{"otp", "Ctrl Z code: {code} bit.ly"},
		{"otp", "{code}.ir"},
		{"otp", "{code} see ctrlz.ir/x"},
		{"otp", "{code} mail me@example"},
		// Invisible and look-alike characters must not hide a link (sms-r3-4): the
		// ZWNJ and ZWJ of Persian text before the dot, a soft hyphen, a zero width
		// space, a bidi mark, the ideographic and fullwidth full stops, a fullwidth
		// slash and at sign, and a ZWNJ inside "www".
		{"otp", "{code} ctrlz-login‌.ir"},
		{"otp", "{code} ctrlz-login‍.ir"},
		{"otp", "{code} ctrlz­-login.ir"},
		{"otp", "{code} ctrlz-login​.ir"},
		{"otp", "{code} ctrlz-login‏.ir"},
		{"otp", "{code} ctrlz-login‌。ir"},
		{"otp", "{code} ctrlz-login．ir"},
		{"otp", "{code} ctrlz-login｡ir"},
		{"otp", "{code} ctrlz-login.‌ir"},
		{"otp", "{code} ctrlz-login／x"},
		{"otp", "{code} me＠example"},
		{"otp", "{code} www‌.example"},
		{"otp", "{code} ht‌tp://x"},
		{"otp", "{code} ｛code｝"},
		{"otp", "{code}‌.ir"},
		// Default-ignorable and combining characters that render as nothing (or sit
		// on the last letter) between a label and its dot (sms-r4-6): variation
		// selectors, the combining grapheme joiner, Mongolian free variation
		// selectors, Hangul fillers, a tag character, and visible combining marks.
		{"otp", "{code} ctrlz-login\uFE0F.ir"},
		{"otp", "{code} ctrlz-login\uFE00.ir"},
		{"otp", "{code} ctrlz-login\U000E0100.ir"},
		{"otp", "{code} ctrlz-login\u034F.ir"},
		{"otp", "{code} ctrlz-login\u180B.ir"},
		{"otp", "{code} ctrlz-login\u180D.ir"},
		{"otp", "{code} ctrlz-login\u115F.ir"},
		{"otp", "{code} ctrlz-login\u3164.ir"},
		{"otp", "{code} ctrlz-login\uFFA0.ir"},
		{"otp", "{code} ctrlz-login\u17B4.ir"},
		{"otp", "{code} ctrlz-login\U000E0001.ir"},
		{"otp", "{code} ctrlz-login\u0332.ir"},
		{"otp", "{code} \u0627\u0645\u0646\u06cc\u062a\u0650.ir"},
		{"otp", "{code} ctrlz-login.\uFE0Fir"},
		{"otp", "{code} www\uFE0F.example"},
		{"otp", "{code} ht\uFE0Ftp://x"},
		{"account_exists", "has {code}"},
		{"nope", "{code}"},
	}
	for _, c := range bad {
		if err := sms.CheckBody(c.key, c.body); err == nil {
			t.Errorf("%q for %s should be refused", c.body, c.key)
		}
	}
	// The seeded copy of spec 9.4 passes the same rule, in both locales.
	for key, bodies := range seededBodies {
		for _, b := range bodies {
			if err := sms.CheckBody(key, b); err != nil {
				t.Errorf("the seeded %s text is refused: %q", key, b)
			}
		}
	}
	// The seeded Persian text passes the same rule.
	if err := sms.CheckBody("otp", "کد {code}"); err != nil {
		t.Errorf("persian: %v", err)
	}
}

func TestRender(t *testing.T) {
	if got := sms.Render("code {code}.", secret.New("123456")); got != "code 123456." {
		t.Errorf("render: %q", got)
	}
}

func TestBuildChecksTheMapping(t *testing.T) {
	code := secret.New("123456")
	m, err := sms.Build("+989121234567", "otp", "fa", sms.ProviderTemplate{ID: "1", ParamNames: []string{"CODE"}}, code)
	if err != nil || m.Values["CODE"].Reveal() != "123456" || m.To != "+989121234567" {
		t.Fatalf("%+v %v", m, err)
	}
	// A mapping with two parameters for a one-placeholder template is Config, found
	// before any send (9.4).
	if _, err := sms.Build("+98", "otp", "fa", sms.ProviderTemplate{ParamNames: []string{"A", "B"}}, code); !errors.Is(err, sms.ErrParamCount) {
		t.Errorf("two params: %v", err)
	}
	if _, err := sms.Build("+98", "otp", "fa", sms.ProviderTemplate{}, code); !errors.Is(err, sms.ErrParamCount) {
		t.Errorf("no params: %v", err)
	}
	if _, err := sms.Build("+98", "account_exists", "fa", sms.ProviderTemplate{ParamNames: []string{"X"}}, secret.String{}); !errors.Is(err, sms.ErrParamCount) {
		t.Errorf("account_exists with a parameter: %v", err)
	}
	m, err = sms.Build("+98", "account_exists", "fa", sms.ProviderTemplate{ID: "9"}, secret.String{})
	if err != nil || len(m.Values) != 0 {
		t.Errorf("account_exists: %+v %v", m, err)
	}
	if _, err := sms.Build("+98", "otp", "fa", sms.ProviderTemplate{ParamNames: []string{"CODE"}}, secret.String{}); !errors.Is(err, sms.ErrBadValue) {
		t.Errorf("a code template without a code: %v", err)
	}
	if _, err := sms.Build("+98", "account_exists", "fa", sms.ProviderTemplate{}, code); !errors.Is(err, sms.ErrBadValue) {
		t.Errorf("a code for a template without one: %v", err)
	}
}

func TestPayloadsBindToTheirRow(t *testing.T) {
	ring, err := keyring.NewEphemeral(keyring.DomainOTPDelivery, keyring.DomainSMSCred)
	if err != nil {
		t.Fatal(err)
	}
	hash := []byte("0123456789abcdef0123456789abcdef")
	ct, err := sms.SealOTP(ring, "+989121234567", "login", hash, sms.OTPDelivery{Template: "otp", Locale: "fa", Code: secret.New("012345")})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ct), "012345") {
		t.Error("the code is in the ciphertext in clear")
	}
	d, err := sms.OpenOTP(ring, "+989121234567", "login", hash, ct)
	if err != nil || d.Code.Reveal() != "012345" || d.Template != "otp" || d.Locale != "fa" {
		t.Fatalf("%+v %v", d, err)
	}
	// The phone and the purpose are in the AAD: a ciphertext moved to another row
	// does not open.
	if _, err := sms.OpenOTP(ring, "+989121234568", "login", hash, ct); err == nil {
		t.Error("opened under another phone")
	}
	if _, err := sms.OpenOTP(ring, "+989121234567", "reset", hash, ct); err == nil {
		t.Error("opened under another purpose")
	}
	if _, err := sms.SealOTP(ring, "+98", "login", hash, sms.OTPDelivery{Template: "nope", Locale: "fa"}); err == nil {
		t.Error("sealed an unknown template")
	}
	// The hash of the row is in the context too (primitives-r18-2): a ciphertext copied onto a
	// challenge of the same phone and purpose, which holds another code, does not open.
	if _, err := sms.OpenOTP(ring, "+989121234567", "login", []byte("another-hash-0123456789abcdef-x"), ct); err == nil {
		t.Error("opened under another row's code hash")
	}
	// A different key, as after a lost key file, gives the one generic error.
	other, _ := keyring.NewEphemeral(keyring.DomainOTPDelivery, keyring.DomainSMSCred)
	if _, err := sms.OpenOTP(other, "+989121234567", "login", hash, ct); !errors.Is(err, keyring.ErrOpen) {
		t.Errorf("wrong key: %v", err)
	}

	id := uuid.New()
	oct, err := sms.SealOutbox(ring, id, "+989121234567", secret.New("ABCDE-FGHJK"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := sms.OpenOutbox(ring, id, "+989121234567", oct)
	if err != nil || v.Reveal() != "ABCDE-FGHJK" {
		t.Fatalf("%v %v", v, err)
	}
	if _, err := sms.OpenOutbox(ring, uuid.New(), "+989121234567", oct); err == nil {
		t.Error("opened under another id")
	}
	if _, err := sms.OpenOutbox(ring, id, "+989121234568", oct); err == nil {
		t.Error("opened under another phone")
	}

	cred := secret.NewBytes([]byte(`{"api_key":"k"}`))
	cct, err := sms.SealCredentials(ring, id, "sms_ir", cred)
	if err != nil {
		t.Fatal(err)
	}
	got, err := sms.OpenCredentials(ring, id, "sms_ir", cct)
	if err != nil || string(got.Reveal()) != `{"api_key":"k"}` {
		t.Fatalf("credentials: %v", err)
	}
	if _, err := sms.OpenCredentials(ring, id, "melipayamak", cct); err == nil {
		t.Error("credentials opened for another provider")
	}
}

func TestHint(t *testing.T) {
	if sms.Hint("abcdefgh") != "efgh" || sms.Hint("ab") != "ab" || sms.Hint("  ") != "" {
		t.Error("hint")
	}
}

// ---------------------------------------------------------------------------
// Router

type fakeSender struct {
	provider string
	mu       sync.Mutex
	calls    int
	last     sms.Message
	lastTpl  sms.ProviderTemplate
	reply    func(call int) (sms.Result, error)
}

func (f *fakeSender) Provider() string { return f.provider }
func (f *fakeSender) Send(_ context.Context, m sms.Message, t sms.ProviderTemplate) (sms.Result, error) {
	f.mu.Lock()
	f.calls++
	n := f.calls
	f.last, f.lastTpl = m, t
	f.mu.Unlock()
	if f.reply == nil {
		return sms.Result{ProviderID: sms.ParseField(f.provider + "-1")}, nil
	}
	return f.reply(n)
}
func (f *fakeSender) Balance(context.Context) (sms.Field, error) { return sms.ParseField("1"), nil }

type fakeSource struct {
	mu    sync.Mutex
	snap  sms.Snapshot
	err   error
	loads int
}

func (s *fakeSource) Load(context.Context) (sms.Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loads++
	return s.snap, s.err
}

type rig struct {
	pri, fb *fakeSender
	priGW   sms.Gateway
	fbGW    sms.Gateway
	src     *fakeSource
	router  *sms.Router
	now     *time.Time
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{pri: &fakeSender{provider: "sms_ir"}, fb: &fakeSender{provider: "melipayamak"}, src: &fakeSource{}}
	r.priGW = sms.Gateway{ID: uuid.New(), Provider: "sms_ir", Role: "primary", Sender: r.pri}
	r.fbGW = sms.Gateway{ID: uuid.New(), Provider: "melipayamak", Role: "fallback", Sender: r.fb}
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	r.now = &now
	r.set()
	r.router = sms.NewRouter(r.src, classify.Routing{}, sms.WithClock(func() time.Time { return *r.now }))
	return r
}

// set rebuilds the snapshot from the rig's gateways with templates for both.
func (r *rig) set() {
	tpls := map[sms.TemplateRef]sms.ProviderTemplate{}
	for _, g := range []sms.Gateway{r.priGW, r.fbGW} {
		for _, k := range []string{"otp", "otp_reset", "otp_phone"} {
			tpls[sms.TemplateRef{Gateway: g.ID, Key: k, Locale: "fa"}] = sms.ProviderTemplate{ID: "100", ParamNames: []string{"CODE"}}
		}
		tpls[sms.TemplateRef{Gateway: g.ID, Key: "account_exists", Locale: "fa"}] = sms.ProviderTemplate{ID: "101"}
	}
	r.src.mu.Lock()
	r.src.snap = sms.Snapshot{Gateways: []sms.Gateway{r.priGW, r.fbGW}, Templates: tpls}
	r.src.mu.Unlock()
	if r.router != nil {
		r.router.Invalidate()
	}
}

var req = sms.Request{To: "+989121234567", Template: "otp", Locale: "fa", Value: secret.New("123456")}

func TestRouterSendsViaThePrimary(t *testing.T) {
	r := newRig(t)
	out, err := r.router.Send(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	a, ok := out.Accepted()
	if !ok || a.Provider != "sms_ir" || len(out.Attempts) != 1 || r.fb.calls != 0 {
		t.Fatalf("%+v fb=%d", out, r.fb.calls)
	}
	if out.Last() != nil {
		t.Error("an accepted send has a last error")
	}
	if r.pri.last.Values["CODE"].Reveal() != "123456" || r.pri.lastTpl.ID != "100" {
		t.Errorf("message: %+v %+v", r.pri.last, r.pri.lastTpl)
	}
}

func TestRouterFallsBackOnEveryClassButRecipient(t *testing.T) {
	for _, c := range []sms.Class{sms.Transient, sms.Auth, sms.Credit, sms.Config, sms.Blacklisted} {
		r := newRig(t)
		r.pri.reply = func(int) (sms.Result, error) { return sms.Result{}, sms.NewError("sms_ir", c, sms.CodeUnknown) }
		out, err := r.router.Send(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		a, ok := out.Accepted()
		if !ok || a.Provider != "melipayamak" || len(out.Attempts) != 2 || out.Attempts[0].Err.Class() != c {
			t.Errorf("%s: %+v", c, out)
		}
	}
}

func TestRouterStopsOnRecipient(t *testing.T) {
	r := newRig(t)
	r.pri.reply = func(int) (sms.Result, error) {
		return sms.Result{}, sms.NewError("sms_ir", sms.Recipient, sms.StatusCode("104"))
	}
	out, err := r.router.Send(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := out.Accepted(); ok || r.fb.calls != 0 || len(out.Attempts) != 1 || out.Last().Class() != sms.Recipient {
		t.Fatalf("a refused number went on to the fallback: %+v fb=%d", out, r.fb.calls)
	}
}

func TestRouterBothDown(t *testing.T) {
	r := newRig(t)
	down := func(p string) func(int) (sms.Result, error) {
		return func(int) (sms.Result, error) {
			return sms.Result{}, sms.NewError(sms.ParseProvider(p), sms.Transient, sms.CodeNetwork)
		}
	}
	r.pri.reply, r.fb.reply = down("sms_ir"), down("melipayamak")
	out, err := r.router.Send(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := out.Accepted(); ok || len(out.Attempts) != 2 || out.Last().Provider != "melipayamak" {
		t.Fatalf("%+v", out)
	}
}

func TestRouterHonoursBreakerAndSkipsSilently(t *testing.T) {
	r := newRig(t)
	until := r.now.Add(time.Minute)
	r.priGW.BreakerOpenUntil = &until
	r.set()
	out, err := r.router.Send(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if a, ok := out.Accepted(); !ok || a.Provider != "melipayamak" || len(out.Attempts) != 1 || r.pri.calls != 0 {
		t.Fatalf("an open breaker was not skipped: %+v", out)
	}
	// The breaker closes by itself when its time passes.
	*r.now = r.now.Add(2 * time.Minute)
	if out, _ := r.router.Send(context.Background(), req); out.Attempts[0].Provider != "sms_ir" {
		t.Errorf("breaker stayed open after its time")
	}
	// Both open: no attempt at all, and Last says why in a code that is not a
	// provider's.
	u2 := r.now.Add(time.Minute)
	r.priGW.BreakerOpenUntil, r.fbGW.BreakerOpenUntil = &u2, &u2
	r.set()
	out, err = r.router.Send(context.Background(), req)
	if err != nil || len(out.Attempts) != 0 || out.Last().Code != "no_gateway" || out.Last().Class() != sms.Transient {
		t.Fatalf("both open: %+v %v", out, err)
	}
}

func TestRouterPinnedSendIgnoresRoleAndBreaker(t *testing.T) {
	r := newRig(t)
	extra := &fakeSender{provider: "noop"}
	gw := sms.Gateway{ID: uuid.New(), Provider: "noop", Role: "disabled", Sender: extra}
	until := r.now.Add(time.Hour)
	gw.BreakerOpenUntil = &until
	r.src.mu.Lock()
	r.src.snap.Gateways = append(r.src.snap.Gateways, gw)
	r.src.snap.Templates[sms.TemplateRef{Gateway: gw.ID, Key: "otp", Locale: "fa"}] = sms.ProviderTemplate{ID: "1", ParamNames: []string{"C"}}
	r.src.mu.Unlock()
	r.router.Invalidate()
	pinned := req
	pinned.Gateway = gw.ID
	out, err := r.router.Send(context.Background(), pinned)
	if err != nil {
		t.Fatal(err)
	}
	if a, ok := out.Accepted(); !ok || a.Gateway != gw.ID || r.pri.calls != 0 || r.fb.calls != 0 {
		t.Fatalf("pinned: %+v", out)
	}
	// A pinned send does not fall back: that is the point of a test send.
	extra.reply = func(int) (sms.Result, error) {
		return sms.Result{}, sms.NewError("noop", sms.Auth, sms.StatusCode("10"))
	}
	out, _ = r.router.Send(context.Background(), pinned)
	if len(out.Attempts) != 1 || r.fb.calls != 0 {
		t.Errorf("a pinned send fell back: %+v", out)
	}
	// An unknown gateway id has nowhere to go.
	pinned.Gateway = uuid.New()
	out, _ = r.router.Send(context.Background(), pinned)
	if len(out.Attempts) != 0 || out.Last().Code != "no_gateway" {
		t.Errorf("unknown pin: %+v", out)
	}
}

func TestRouterLocalProblems(t *testing.T) {
	r := newRig(t)
	r.priGW.Sender, r.priGW.Problem = nil, "credentials_unreadable"
	r.set()
	out, err := r.router.Send(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Attempts) != 2 || !out.Attempts[0].Local || out.Attempts[0].Err.Class() != sms.Config || out.Attempts[0].Err.Code != "credentials_unreadable" {
		t.Fatalf("an unreadable gateway: %+v", out.Attempts)
	}
	// The whole gateway is unusable, so the worker counts it toward the breaker
	// (sms-r2-2); the fallback's accepted attempt does not count.
	if !classify.CountsTowardBreaker(out.Attempts[0]) || classify.CountsTowardBreaker(out.Attempts[1]) {
		t.Errorf("breaker: %v %v", classify.CountsTowardBreaker(out.Attempts[0]), classify.CountsTowardBreaker(out.Attempts[1]))
	}
	if a, ok := out.Accepted(); !ok || a.Provider != "melipayamak" {
		t.Errorf("the fallback did not send: %+v", out)
	}

	// No template for either locale on a gateway is Config for that gateway.
	r = newRig(t)
	r.src.mu.Lock()
	delete(r.src.snap.Templates, sms.TemplateRef{Gateway: r.priGW.ID, Key: "otp", Locale: "fa"})
	r.src.mu.Unlock()
	r.router.Invalidate()
	out, _ = r.router.Send(context.Background(), req)
	if out.Attempts[0].Err.Code != "no_template" || !out.Attempts[0].Local || r.pri.calls != 0 || classify.CountsTowardBreaker(out.Attempts[0]) {
		t.Errorf("missing template: %+v", out.Attempts[0])
	}

	// A mapping with the wrong number of parameters is Config, before any send.
	r = newRig(t)
	r.src.mu.Lock()
	r.src.snap.Templates[sms.TemplateRef{Gateway: r.priGW.ID, Key: "otp", Locale: "fa"}] = sms.ProviderTemplate{ID: "1", ParamNames: []string{"A", "B"}}
	r.src.mu.Unlock()
	r.router.Invalidate()
	out, _ = r.router.Send(context.Background(), req)
	if out.Attempts[0].Err.Code != "param_count" || r.pri.calls != 0 || classify.CountsTowardBreaker(out.Attempts[0]) {
		t.Errorf("param count: %+v", out.Attempts[0])
	}
}

func TestRouterLocaleFallback(t *testing.T) {
	r := newRig(t)
	en := req
	en.Locale = "en" // only fa is mapped
	out, err := r.router.Send(context.Background(), en)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := out.Accepted(); !ok {
		t.Fatalf("a locale with no mapping did not fall back to the other: %+v", out)
	}
}

func TestRouterRefusesWhatNoGatewayCouldSend(t *testing.T) {
	r := newRig(t)
	for name, bad := range map[string]sms.Request{
		"unknown template": {To: "+98", Template: "nope", Locale: "fa", Value: secret.New("1")},
		"unknown locale":   {To: "+98", Template: "otp", Locale: "de", Value: secret.New("1")},
		"no number":        {Template: "otp", Locale: "fa", Value: secret.New("1")},
		"code missing":     {To: "+98", Template: "otp", Locale: "fa"},
		"stray code":       {To: "+98", Template: "account_exists", Locale: "fa", Value: secret.New("1")},
	} {
		if _, err := r.router.Send(context.Background(), bad); !errors.Is(err, sms.ErrBadRequest) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if r.pri.calls+r.fb.calls != 0 {
		t.Error("a bad request reached a gateway")
	}
}

func TestRouterKeepsLastSnapshotWhenReloadFails(t *testing.T) {
	r := newRig(t)
	if _, err := r.router.Send(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	r.src.mu.Lock()
	r.src.err = errors.New("db down")
	r.src.mu.Unlock()
	*r.now = r.now.Add(5 * time.Minute) // stale: forces a reload, and still inside the bound on an old snapshot
	out, err := r.router.Send(context.Background(), req)
	if err != nil {
		t.Fatalf("a failed reload stopped sending: %v", err)
	}
	if _, ok := out.Accepted(); !ok {
		t.Error("no send with the last good snapshot")
	}

	// With nothing ever loaded, it is ErrNoSnapshot and not a made-up outcome.
	cold := sms.NewRouter(&fakeSource{err: errors.New("db down")}, classify.Routing{})
	if _, err := cold.Send(context.Background(), req); !errors.Is(err, sms.ErrNoSnapshot) {
		t.Errorf("cold: %v", err)
	}
}

func TestRouterReloadsEveryThirtySecondsAndOnInvalidate(t *testing.T) {
	r := newRig(t)
	send := func() { _, _ = r.router.Send(context.Background(), req) }
	send()
	send()
	if r.src.loads != 1 {
		t.Fatalf("loads = %d, want 1", r.src.loads)
	}
	*r.now = r.now.Add(29 * time.Second)
	send()
	if r.src.loads != 1 {
		t.Errorf("reloaded before 30 s: %d", r.src.loads)
	}
	*r.now = r.now.Add(2 * time.Second)
	send()
	if r.src.loads != 2 {
		t.Errorf("did not reload after 30 s: %d", r.src.loads)
	}
	r.router.Invalidate()
	send()
	if r.src.loads != 3 {
		t.Errorf("did not reload after Invalidate: %d", r.src.loads)
	}
}

func TestRouterDropsTextOfAForeignError(t *testing.T) {
	r := newRig(t)
	r.pri.reply = func(int) (sms.Result, error) {
		return sms.Result{}, fmt.Errorf("Post \"https://api.sms.ir/v1/send/verify\": key=SECRET")
	}
	out, _ := r.router.Send(context.Background(), req)
	e := out.Attempts[0].Err
	if e.Class() != sms.Transient || strings.Contains(e.Error(), "SECRET") || strings.Contains(e.Error(), "https") {
		t.Errorf("a driver's own error text got through: %v", e)
	}
}

func TestRouterStopsWhenCallerGivesUp(t *testing.T) {
	r := newRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	r.pri.reply = func(int) (sms.Result, error) {
		cancel()
		return sms.Result{}, context.Canceled
	}
	out, err := r.router.Send(ctx, req)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if len(out.Attempts) != 0 || r.fb.calls != 0 {
		t.Errorf("a shutdown was recorded as a gateway failure: %+v fb=%d", out, r.fb.calls)
	}
}

// slowFailingSource fails every load after a pause and counts the calls.
type slowFailingSource struct {
	mu    sync.Mutex
	snap  sms.Snapshot
	fail  bool
	loads int
	delay time.Duration
}

func (s *slowFailingSource) Load(ctx context.Context) (sms.Snapshot, error) {
	s.mu.Lock()
	s.loads++
	fail, snap := s.fail, s.snap
	s.mu.Unlock()
	if fail {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
		}
		return sms.Snapshot{}, errors.New("db hung")
	}
	return snap, nil
}

// A reload that fails is retried by one goroutine per interval, outside the
// router's mutex. Before the fix every concurrent Send repeated the failing
// query one after another under the lock, so eight sends against a database
// that takes 100 ms to give up took 800 ms, and in production up to the acquire
// timeout each (sms-r2-7).
func TestRouterFailedReloadIsNotRepeatedByEverySend(t *testing.T) {
	base := newRig(t)
	src := &slowFailingSource{snap: base.src.snap, delay: 100 * time.Millisecond}
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	router := sms.NewRouter(src, classify.Routing{}, sms.WithClock(func() time.Time { return now }))
	if _, err := router.Send(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	src.mu.Lock()
	src.fail = true
	src.mu.Unlock()
	now = now.Add(time.Minute) // the snapshot is old: the next Send reloads

	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := router.Send(context.Background(), req)
			if err != nil {
				t.Errorf("a failed reload stopped sending: %v", err)
			} else if _, ok := out.Accepted(); !ok {
				t.Error("no send with the last good snapshot")
			}
		}()
	}
	wg.Wait()
	if took := time.Since(start); took > 450*time.Millisecond {
		t.Errorf("eight sends took %v: they waited for each other's reload", took)
	}
	src.mu.Lock()
	loads := src.loads
	src.mu.Unlock()
	if loads != 2 { // the first load and one failed reload
		t.Errorf("loads = %d, want 2", loads)
	}
	// A Send right after does not retry either, and one after the retry interval does.
	_, _ = router.Send(context.Background(), req)
	src.mu.Lock()
	if src.loads != 2 {
		t.Errorf("retried at once: %d", src.loads)
	}
	src.mu.Unlock()
	now = now.Add(10 * time.Second)
	_, _ = router.Send(context.Background(), req)
	src.mu.Lock()
	if src.loads != 3 {
		t.Errorf("no retry after the interval: %d", src.loads)
	}
	src.mu.Unlock()
}

// A gateway behind an open breaker is counted as skipped, so the worker can tell
// "the other gateway answered Blacklisted" from "the other gateway was never asked"
// (sms-r3-1). A pinned send never skips.
func TestRouterCountsSkippedGateways(t *testing.T) {
	r := newRig(t)
	out, _ := r.router.Send(context.Background(), req)
	if out.Skipped != 0 {
		t.Errorf("skipped = %d with both gateways open", out.Skipped)
	}
	until := r.now.Add(time.Minute)
	r.fbGW.BreakerOpenUntil = &until
	r.pri.reply = func(int) (sms.Result, error) {
		return sms.Result{}, sms.NewError("sms_ir", sms.Blacklisted, sms.StatusCode("115"))
	}
	r.set()
	out, _ = r.router.Send(context.Background(), req)
	if out.Skipped != 1 || len(out.Attempts) != 1 || r.fb.calls != 0 {
		t.Errorf("fallback behind its breaker: skipped %d, attempts %d, fallback calls %d", out.Skipped, len(out.Attempts), r.fb.calls)
	}
	r.priGW.BreakerOpenUntil = &until
	r.set()
	out, _ = r.router.Send(context.Background(), req)
	if out.Skipped != 2 || len(out.Attempts) != 0 {
		t.Errorf("both behind a breaker: skipped %d, attempts %d", out.Skipped, len(out.Attempts))
	}
	pinned := req
	pinned.Gateway = r.priGW.ID
	out, _ = r.router.Send(context.Background(), pinned)
	if out.Skipped != 0 || len(out.Attempts) != 1 {
		t.Errorf("a pinned send skipped: %+v", out)
	}
}

// gatedSource lets a test hold a reload half way and decide what the query "read".
type gatedSource struct {
	mu      sync.Mutex
	snap    sms.Snapshot
	loads   int
	started chan struct{} // receives once per load, as the query begins
	release chan struct{} // the load returns when this yields
	gate    bool          // only the loads while set wait
}

func (s *gatedSource) Load(context.Context) (sms.Snapshot, error) {
	s.mu.Lock()
	s.loads++
	snap, gate := s.snap, s.gate
	s.mu.Unlock()
	if gate {
		s.started <- struct{}{}
		<-s.release
	}
	return snap, nil // what was read before the wait: the old view
}

// A reload that began before a failure was committed returns the old breaker
// view. An Invalidate that arrives meanwhile must survive it, or the router keeps
// calling an open-breaker gateway until the next 30 second reload (sms-r3-2).
func TestRouterInvalidateDuringAReloadIsNotLost(t *testing.T) {
	base := newRig(t)
	src := &gatedSource{snap: base.src.snap, started: make(chan struct{}, 1), release: make(chan struct{})}
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	router := sms.NewRouter(src, classify.Routing{}, sms.WithClock(func() time.Time { return now }))
	if _, err := router.Send(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	src.mu.Lock()
	src.gate = true
	src.mu.Unlock()
	now = now.Add(time.Minute) // old: the next Send reloads

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = router.Send(context.Background(), req)
	}()
	<-src.started // the periodic reload is in flight and has read the old rows
	router.Invalidate()
	src.mu.Lock()
	src.gate = false // later loads see the new rows at once
	src.mu.Unlock()
	close(src.release)
	<-done

	src.mu.Lock()
	before := src.loads
	src.mu.Unlock()
	_, _ = router.Send(context.Background(), req)
	src.mu.Lock()
	after := src.loads
	src.mu.Unlock()
	if after != before+1 {
		t.Errorf("loads %d -> %d: the Invalidate that came during a reload was dropped", before, after)
	}
}

// The admin saves a gateway's credentials in another process, which cannot call
// this router's Invalidate, and then clicks Test send. The snapshot is fresh by
// the clock but outdated by the database, and a pinned send has to see the change
// (sms-r4-1). Nothing here calls Invalidate or set().
func TestRouterPinnedSendSeesWhatWasJustSaved(t *testing.T) {
	r := newRig(t)
	// The first load, as ordinary traffic made it.
	if _, err := r.router.Send(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	loads := r.src.loads

	// A gateway gains its first credentials and its template mapping.
	fresh := &fakeSender{provider: "noop"}
	gw := sms.Gateway{ID: uuid.New(), Provider: "noop", Role: "disabled", Sender: fresh}
	r.src.mu.Lock()
	r.src.snap.Gateways = append(append([]sms.Gateway(nil), r.src.snap.Gateways...), gw)
	r.src.snap.Templates[sms.TemplateRef{Gateway: gw.ID, Key: "otp", Locale: "fa"}] = sms.ProviderTemplate{ID: "1", ParamNames: []string{"C"}}
	r.src.mu.Unlock()
	pinned := req
	pinned.Gateway = gw.ID
	out, err := r.router.Send(context.Background(), pinned)
	if err != nil {
		t.Fatal(err)
	}
	if a, ok := out.Accepted(); !ok || a.Gateway != gw.ID || fresh.calls != 1 {
		t.Fatalf("a gateway saved a moment ago was not found: %+v", out)
	}

	// A key rotated within the 30 seconds: the test must run on the new sender.
	rotated := &fakeSender{provider: "noop"}
	gw.Sender = rotated
	r.src.mu.Lock()
	r.src.snap.Gateways = append([]sms.Gateway(nil), r.src.snap.Gateways[:2]...)
	r.src.snap.Gateways = append(r.src.snap.Gateways, gw)
	r.src.mu.Unlock()
	if _, err := r.router.Send(context.Background(), pinned); err != nil {
		t.Fatal(err)
	}
	if rotated.calls != 1 || fresh.calls != 1 {
		t.Errorf("the test ran on the old credentials: new %d old %d", rotated.calls, fresh.calls)
	}

	// Ordinary traffic keeps its 30 seconds: only pinned sends force a reload.
	before := r.src.loads
	for i := 0; i < 5; i++ {
		if _, err := r.router.Send(context.Background(), req); err != nil {
			t.Fatal(err)
		}
	}
	if r.src.loads != before {
		t.Errorf("routed sends reloaded the gateways %d times", r.src.loads-before)
	}
	if before == loads {
		t.Error("a pinned send did not reload the snapshot")
	}

	// A database that is down is not hammered, and a test is not run on credentials
	// that may have changed: a pinned send whose reload fails gets no snapshot, the
	// next one waits out reloadRetry, and routed traffic keeps the last good one.
	r.src.mu.Lock()
	r.src.err = errors.New("db down")
	r.src.mu.Unlock()
	calls := rotated.calls
	if _, err := r.router.Send(context.Background(), pinned); !errors.Is(err, sms.ErrNoSnapshot) {
		t.Fatalf("a pinned send with a failed reload = %v, want ErrNoSnapshot", err)
	}
	failed := r.src.loads
	for i := 0; i < 3; i++ {
		if _, err := r.router.Send(context.Background(), pinned); !errors.Is(err, sms.ErrNoSnapshot) {
			t.Fatalf("a pinned send inside the retry window = %v", err)
		}
	}
	if r.src.loads != failed {
		t.Errorf("pinned sends retried a failing load %d times within the retry window", r.src.loads-failed)
	}
	if rotated.calls != calls {
		t.Error("a test send ran on a snapshot that could not be refreshed")
	}
	if out, err := r.router.Send(context.Background(), req); err != nil {
		t.Errorf("routed traffic lost the last good snapshot: %v", err)
	} else if _, ok := out.Accepted(); !ok {
		t.Error("routed send not accepted")
	}
}

// A parameter name is used as stored: Build keys the value by the same string the
// drivers look it up by (sms-r4-2).
func TestBuildUsesTheStoredParamName(t *testing.T) {
	code := secret.New("123456")
	m, err := sms.Build("+98", "otp", "fa", sms.ProviderTemplate{ID: "1", ParamNames: []string{"CODE "}}, code)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Values["CODE "]; !ok || len(m.Values) != 1 {
		t.Errorf("the value is not under the stored name: %v", m.Values)
	}
	if _, err := sms.Build("+98", "otp", "fa", sms.ProviderTemplate{ID: "1", ParamNames: []string{" \t"}}, code); !errors.Is(err, sms.ErrParamCount) {
		t.Errorf("a blank name: %v", err)
	}
}

// inBodyAlphabet is the closed alphabet of spec 9.4 written out a second time,
// on purpose and without importing the code's own predicate: the test is the
// statement of the rule, and CheckBody must agree with it for every one of the
// 1,114,112 code points, in both directions. ZWNJ is not listed because it is
// allowed only between two Persian letters (a context rule, tested below).
func inBodyAlphabet(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	case r >= '۰' && r <= '۹': // Persian digits
		return true
	case r == ' ':
		return true
	// Comma, semicolon, exclamation and question mark, hyphen, parentheses,
	// apostrophe, quotation mark, then the Persian comma, semicolon and question
	// mark. '.' and ':' are listed apart: they are allowed before a space or the end.
	case strings.ContainsRune(",;!?-()'\"،؛؟", r):
		return true
	case r == '.' || r == ':':
		return true
	}
	return persianLetterForTest(r)
}

func persianLetterForTest(r rune) bool {
	switch {
	case r >= 'ء' && r <= 'غ', r >= 'ف' && r <= 'ي':
		return true
	}
	return strings.ContainsRune("پچژکگیۀ", r) // پ چ ژ ک گ ی ۀ
}

// TestEveryCodePointOutsideTheAlphabetIsRefused is the enforcement of rule
// link-check. A deny list needs a new entry each time someone finds one more
// invisible or look-alike code point; this test walks all of Unicode, so a code
// point nobody has thought of yet is already covered.
func TestEveryCodePointOutsideTheAlphabetIsRefused(t *testing.T) {
	const prefix = "Ctrl Z code: {code} "
	var refusedWrongly, acceptedWrongly, hidingWrong, dotWrong []string
	for cp := rune(0); cp <= unicode.MaxRune; cp++ {
		// A surrogate cannot be in a Go string; string(cp) turns it into U+FFFD,
		// which is outside the alphabet too. A raw invalid byte is tested apart.
		s := string(cp)

		// 1. The code point alone, after a valid body: accepted exactly when it
		//    is in the alphabet (and ZWNJ is not: it has no Persian neighbours).
		want := inBodyAlphabet(cp)
		got := sms.CheckBody("otp", prefix+s+" end") == nil
		if got != want {
			if got {
				acceptedWrongly = append(acceptedWrongly, fmt.Sprintf("U+%04X", cp))
			} else {
				refusedWrongly = append(refusedWrongly, fmt.Sprintf("U+%04X", cp))
			}
		}

		// 2. The attack itself: the code point between a label and "ir". Whatever it
		//    is, a reader or auto-linker must not be able to see "ctrlz.ir" there. A
		//    member of the alphabet other than '.' and ':' makes a harmless word.
		hidingOK := sms.CheckBody("otp", prefix+"ctrlz"+s+"ir") == nil
		if hidingOK != (want && cp != '.' && cp != ':') {
			hidingWrong = append(hidingWrong, fmt.Sprintf("U+%04X", cp))
		}
		// 3. The same with a real dot next to it, on either side. A space after the dot
		//    is a sentence ("ctrlz. ir"), which no linker reads as a name.
		for _, b := range []string{prefix + "ctrlz" + s + ".ir", prefix + "ctrlz." + s + "ir"} {
			if cp == ' ' && strings.Contains(b, ". ir") {
				continue
			}
			if sms.CheckBody("otp", b) == nil {
				dotWrong = append(dotWrong, fmt.Sprintf("U+%04X", cp))
			}
		}
	}
	if len(acceptedWrongly) > 0 {
		t.Errorf("%d code points outside the alphabet are accepted: %v", len(acceptedWrongly), headOf(acceptedWrongly))
	}
	if len(refusedWrongly) > 0 {
		t.Errorf("%d code points of the alphabet are refused: %v", len(refusedWrongly), headOf(refusedWrongly))
	}
	if len(hidingWrong) > 0 {
		t.Errorf("%d code points between a label and ir are judged wrongly: %v", len(hidingWrong), headOf(hidingWrong))
	}
	if len(dotWrong) > 0 {
		t.Errorf("%d code points next to a real dot are accepted: %v", len(dotWrong), headOf(dotWrong))
	}
}

func headOf(s []string) []string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func TestInvalidUTF8IsRefused(t *testing.T) {
	for b := 0x80; b <= 0xFF; b++ {
		if err := sms.CheckBody("otp", "Ctrl Z code: {code} "+string([]byte{byte(b)})); err == nil {
			t.Errorf("the lone byte 0x%02X is accepted", b)
		}
	}
	if err := sms.CheckBody("otp", "Ctrl Z code: {code} \xed\xa0\x80"); err == nil {
		t.Error("an encoded surrogate is accepted")
	}
}

// The context rules: a full stop and a colon only before a space or the end, a
// ZWNJ only between two Persian letters. Each turns a character that is in the
// alphabet into one that cannot join a label to a suffix or hide anything.
func TestBodyContextRules(t *testing.T) {
	ok := []string{
		"Ctrl Z code: {code}.",
		"Ctrl Z code: {code}. Valid.",
		"{code} .", // a lone stop between spaces joins nothing
		"{code}:",
		"a: b {code}",
		"نداده‌اید {code}", // نداده‌اید
		"می‌خواهم {code}",  // می‌خواهم
	}
	for _, b := range ok {
		if err := sms.CheckBody("otp", b); err != nil {
			t.Errorf("%q is refused: %v", b, err)
		}
	}
	bad := []string{
		"{code}.ir", "{code} x.{code}", "x.{code}",
		"ctrlz.ir {code}", "ctrlz.. {code}", "a.b {code}", "1.5 {code}", ".. {code}",
		"code:{code}", "http:{code}", "a:b {code}", "{code} ::", "ctrlz:80 {code}",
		"‌ {code}", " ‌ {code}", "a‌b {code}", "ا‌ {code}", "‌ا {code}",
		"ا‌‌ا {code}", "ا‌{code}", "{code}‌ا", "ا‌b {code}",
		"‍ {code}", "ا‍ا {code}", // ZWJ is never allowed
	}
	for _, b := range bad {
		if err := sms.CheckBody("otp", b); err == nil {
			t.Errorf("%q should be refused", b)
		}
	}
	// account_exists takes no marker, and a brace is outside the alphabet.
	if err := sms.CheckBody("account_exists", "{code}"); err == nil {
		t.Error("a marker in a template that takes none")
	}
	if err := sms.CheckBody("account_exists", "no marker here."); err != nil {
		t.Errorf("no marker: %v", err)
	}
}

// seedRows reads the rows of an INSERT of templates in a migration, as key/locale to body.
func seedRows(t *testing.T, file string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "migrations", "postgres", "src", file))
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`\('(\w+)', '(fa|en)', '((?:[^']|'')*)'\)`)
	out := map[string]string{}
	for _, r := range re.FindAllStringSubmatch(string(raw), -1) {
		out[r[1]+"/"+r[2]] = strings.ReplaceAll(r[3], "''", "'")
	}
	return out
}

// bodyUpdates reads the guarded UPDATEs of a migration: key/locale to {new, old}. The old text is
// the guard, so a row an operator edited does not match and is left alone.
func bodyUpdates(t *testing.T, file string) map[string][2]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "migrations", "postgres", "src", file))
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`UPDATE ctrlz\.sms_templates SET body = '((?:[^']|'')*)'\s+WHERE key = '(\w+)' AND locale = '(fa|en)' AND body = '((?:[^']|'')*)';`)
	out := map[string][2]string{}
	for _, r := range re.FindAllStringSubmatch(string(raw), -1) {
		out[r[2]+"/"+r[3]] = [2]string{strings.ReplaceAll(r[1], "''", "'"), strings.ReplaceAll(r[4], "''", "'")}
	}
	return out
}

// effectiveBodies is what a migrated database holds: the seed of 0011 with the guarded updates of
// 0041 on top, without the two invite rows 0062 deletes and with the four notice rows it adds (and the advice of
// 0064 on top of them), key/locale to body.
func effectiveBodies(t *testing.T) map[string]string {
	t.Helper()
	seed := seedRows(t, "0011_auth.sql")
	if len(seed) != 10 {
		t.Fatalf("the migration seeds %d templates, spec 9.4 lists 10", len(seed))
	}
	eff := map[string]string{}
	for k, v := range seed {
		eff[k] = v
	}
	ups := bodyUpdates(t, "0041_review_round11_sms.sql")
	if len(ups) != 3 {
		t.Fatalf("0041 updates %d bodies, the owner's decision (D58) names three", len(ups))
	}
	for k, u := range ups {
		if seed[k] != u[1] {
			t.Errorf("0041 guards %s with a text that 0011 does not seed, so the update matches nothing", k)
		}
		eff[k] = u[0]
	}
	// 0062 (D67 and question 19): an invite is never sent by SMS, and a security notice is.
	delete(eff, "invite/fa")
	delete(eff, "invite/en")
	notices := seedRows(t, "0062_notice_sms.sql")
	if len(notices) != 4 {
		t.Fatalf("0062 seeds %d templates, spec 9.4 lists the four of the two notices", len(notices))
	}
	for k, v := range notices {
		eff[k] = v
	}
	// 0064 (review dec-c-r2-3): the advice of the two notices names an action that evicts the thief. Each update
	// guards with the text 0062 seeded, so an operator's edit is never overwritten, and its guard must match
	// what 0062 really seeds or it is dead.
	advice := bodyUpdates(t, "0064_notice_sms_advice.sql")
	if len(advice) != 4 {
		t.Fatalf("0064 updates %d bodies, the two notices have four", len(advice))
	}
	for k, u := range advice {
		if notices[k] != u[1] {
			t.Errorf("0064 guards %s with a text that 0062 does not seed, so the update matches nothing", k)
		}
		eff[k] = u[0]
	}
	if len(eff) != 12 {
		t.Fatalf("a migrated database holds %d templates, spec 9.4 lists 12", len(eff))
	}
	return eff
}

// TestTheSeedsAreTheMigrationsBodies ties spec 9.4's table to the rows a database really holds
// after every migration: the seed of 0011 with the guarded updates of 0041 applied on top. Each
// update must change a row that still holds the 0011 text (an update whose guard matches nothing
// is dead), and every effective body passes CheckBody, so an edit of either migration or of the
// rule that makes a shipped template unusable fails here and not on an operator's first save.
func TestTheSeedsAreTheMigrationsBodies(t *testing.T) {
	eff := effectiveBodies(t)
	for k, body := range eff {
		key, locale, _ := strings.Cut(k, "/")
		i := 0
		if locale == "en" {
			i = 1
		}
		if seededBodies[key][i] != body {
			t.Errorf("%s differs between the migrations and spec 9.4", k)
		}
		if err := sms.CheckBody(key, body); err != nil {
			t.Errorf("the seeded %s body is refused by CheckBody: %v", k, err)
		}
	}
}

// TestOTPBodiesFitOnePart is the length bound of owner decision D58 (sms-r11-2): both providers
// bill each part, and a Persian part holds 70 UCS-2 units, a Latin one 160 GSM-7 characters. The
// three OTP templates are the highest-volume ones, so each is rendered with a full code and held
// to one part, with 6 units of room (64) in Persian so a small copy edit stays inside it. The
// bound is on the effective bodies (the seed with the updates on top), so a later migration that
// lengthens one fails here too.
func TestOTPBodiesFitOnePart(t *testing.T) {
	code := secret.New(strings.Repeat("7", otp.CodeLength))
	eff := effectiveBodies(t)
	for _, key := range []string{"otp", "otp_reset", "otp_phone", "notice_passkey", "notice_recovery"} {
		// Both the table of spec 9.4 and the bodies a migrated database holds.
		for src, bodies := range map[string][2]string{
			"spec 9.4":   {seededBodies[key][0], seededBodies[key][1]},
			"migrations": {eff[key+"/fa"], eff[key+"/en"]},
		} {
			// The same function PutSmsTemplate asks, so what the page accepts and what the seeds
			// are held to cannot drift apart (sms-r13-3).
			if err := sms.CheckBodyLength(key, "fa", bodies[0], otp.CodeLength); err != nil {
				t.Errorf("%s: %s/fa renders to %d UCS-2 units, above %d: it would be billed as two parts", src, key, sms.UCS2Units(sms.Render(bodies[0], code)), sms.MaxOTPUnitsFA)
			}
			if err := sms.CheckBodyLength(key, "en", bodies[1], otp.CodeLength); err != nil {
				n, ok := sms.GSM7Units(sms.Render(bodies[1], code))
				t.Errorf("%s: %s/en is not one GSM-7 part (%d units, in the alphabet %v, limit %d)", src, key, n, ok, sms.MaxOTPUnitsEN)
			}
		}
	}
	// The counters can fail: the seed 0011 shipped is above the bound and a Persian body counted
	// in bytes or in runes is not mistaken for one.
	for k, old := range seedRows(t, "0011_auth.sql") {
		if strings.HasSuffix(k, "/fa") && strings.HasPrefix(k, "otp") && sms.UCS2Units(sms.Render(old, code)) <= 64 {
			t.Errorf("%s: the old seed fits, so the counter does not see the defect it was written for", k)
		}
	}
	if n, ok := sms.GSM7Units("a{b}€ é"); !ok || n != 10 {
		t.Errorf("gsm7Units: %d %v", n, ok)
	}
	if _, ok := sms.GSM7Units("ک"); ok {
		t.Error("gsm7Units accepted a Persian letter")
	}
	if sms.UCS2Units("a😀") != 3 {
		t.Error("ucs2Units does not count a surrogate pair as two")
	}
}

// A provider that echoes the recipient or the code as its message id must not get it
// stored: sms_deliveries holds no number and no code (spec 9.8, sms-r5-8). The router
// scrubs every accepted result, so this holds for every driver, present and future.
func TestRouterDropsFieldsThatEchoTheRecipientOrTheCode(t *testing.T) {
	cases := map[string]struct {
		id, cost string
		wantID   string
		wantCost string
	}{
		"e164 digits":           {id: "989121234567", wantID: ""},
		"national with zero":    {id: "09121234567", wantID: ""},
		"national without zero": {id: "9121234567", wantID: ""},
		"inside a longer id":    {id: "m-989121234567-x", wantID: ""},
		"split by marks":        {id: "0912-123-4567", wantID: ""},
		"persian digits":        {id: "۰۹۱۲۱۲۳۴۵۶۷", wantID: ""},
		"the code":              {id: "123456", wantID: ""},
		"the code in a cost":    {id: "42", cost: "x123456", wantID: "42", wantCost: ""},
		"a real id":             {id: "4200000000001", cost: "10.5", wantID: "4200000000001", wantCost: "10.5"},
		"a short id":            {id: "7", cost: "1", wantID: "7", wantCost: "1"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.pri.reply = func(int) (sms.Result, error) {
				return sms.Result{ProviderID: sms.ParseField(c.id), CostRaw: sms.ParseField(c.cost)}, nil
			}
			out, err := r.router.Send(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			a, ok := out.Accepted()
			if !ok {
				t.Fatalf("not accepted: %+v", out)
			}
			if a.Result.ProviderID.String() != c.wantID || a.Result.CostRaw.String() != c.wantCost {
				t.Errorf("stored id %q cost %q, want %q and %q", a.Result.ProviderID, a.Result.CostRaw, c.wantID, c.wantCost)
			}
		})
	}
}

// An invite code is a registration credential. A provider or a middlebox that answers with it as
// the message id, written without its hyphens, in the other case or with a look-alike letter, must
// not get it stored in sms_deliveries (sms-r11-4): invite.Canonical accepts every one of those
// spellings, so a stored copy would be a usable credential. The first version of Scrubbed compared
// the code as it was sent and dropped only a digit-for-digit echo.
func TestScrubbedDropsAnInviteCodeWrittenAnotherWay(t *testing.T) {
	const code = "ABCDE-FGHJK-MNPQR-STVWX"
	m := sms.Message{To: "+989121234567", Values: map[string]secret.String{"CODE": secret.New(code)}}
	for name, c := range map[string]struct {
		id   string
		drop bool
	}{
		"as sent":                {code, true},
		"without hyphens":        {"ABCDEFGHJKMNPQRSTVWX", true},
		"lower case":             {"abcde-fghjk-mnpqr-stvwx", true},
		"lower case, no hyphens": {"abcdefghjkmnpqrstvwx", true},
		"with an underscore":     {"abcde_fghjk_mnpqr_stvwx", true},
		"inside a longer id":     {"msg.abcdefghjkmnpqrstvwx.1", true},
		"half of it":             {"abcde-fghjk", false},
		"another code":           {"ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ", false},
		"a real id":              {"4200000000001", false},
	} {
		got := sms.Result{ProviderID: sms.ParseField(c.id), CostRaw: sms.ParseField(c.id)}.Scrubbed(m)
		if dropped := got.ProviderID.IsZero() && got.CostRaw.IsZero(); dropped != c.drop {
			t.Errorf("%s: dropped %v, want %v", name, dropped, c.drop)
		}
	}
	// The look-alikes the invite alphabet reads as digits: O as 0, I and L as 1.
	m = sms.Message{To: "+989121234567", Values: map[string]secret.String{"CODE": secret.New("0123A-BCDEF-GHJKM-NPQRS")}}
	if got := (sms.Result{ProviderID: sms.ParseField("O123ABCDEFGHJKMNPQRS")}).Scrubbed(m); !got.ProviderID.IsZero() {
		t.Error("an echo with a letter O for a zero was kept")
	}
	if got := (sms.Result{ProviderID: sms.ParseField("l23ABCDEFGHJKMNPQRS")}).Scrubbed(m); got.ProviderID.IsZero() {
		t.Error("a different code was dropped")
	}
}

// sms-r13-3: the one-part bound holds for what an operator stores, not only for the seeds. The
// SMS page validates a body with CheckBody, which has no length limit, and migration 0041 never
// overwrites an edit, so after one save nothing judged the effective body and the single price the
// owner enters for an OTP message stopped covering it (a 150 character body is three parts, and
// sms_cost_cap_daily would count a third of the spend).
func TestCheckBodyLengthBoundsTheOnePartBodiesAndNothingElse(t *testing.T) {
	long := strings.Repeat("a", 150) + " {code}"
	for _, c := range []struct {
		name, key, locale, body string
		ok                      bool
	}{
		{"fa body of 150 letters", "otp", "fa", long, false},
		{"en body of 150 letters fits one GSM part", "otp", "en", long, true},
		{"en body of 200 letters", "otp_reset", "en", strings.Repeat("a", 200) + " {code}", false},
		{"fa seed-sized body", "otp_phone", "fa", seededBodies["otp_phone"][0], true},
		{"fa body of exactly 64 units", "otp", "fa", strings.Repeat("ا", 57) + " {code}", true},
		{"fa body of 65 units", "otp", "fa", strings.Repeat("ا", 58) + " {code}", false},
		{"en body with a Persian letter is UCS-2", "otp", "en", "کد {code}", false},
		{"en body of exactly 160 units", "otp", "en", strings.Repeat("a", 153) + " {code}", true},
		{"en body of 161 units", "otp", "en", strings.Repeat("a", 154) + " {code}", false},
		{"account_exists is two parts and not bounded here", "account_exists", "fa", strings.Repeat("ا", 200), true},
		{"a notice of 200 letters is two parts", "notice_passkey", "fa", strings.Repeat("ا", 200), false},
		{"the notice_recovery seed fits", "notice_recovery", "fa", seededBodies["notice_recovery"][0], true},
		{"the notice_passkey seed fits in English", "notice_passkey", "en", seededBodies["notice_passkey"][1], true},
	} {
		err := sms.CheckBodyLength(c.key, c.locale, c.body, otp.CodeLength)
		if (err == nil) != c.ok {
			t.Errorf("%s: err %v, want ok %v", c.name, err, c.ok)
		}
		if err != nil && !errors.Is(err, sms.ErrBodyTooLong) {
			t.Errorf("%s: %v is not ErrBodyTooLong", c.name, err)
		}
	}
}

// The snapshot holds which gateways are enabled and their credentials, so a reload that keeps failing
// does not keep it in force for ever: past the bound a send answers ErrNoSnapshot, and the refusal is
// said (round 16, tenant-r16-12). A gateway the operator disabled during the outage is not used.
func TestRouterStopsSendingWithASnapshotTooOldToVouchFor(t *testing.T) {
	r := newRig(t)
	var logs strings.Builder
	r.router = sms.NewRouter(r.src, classify.Routing{}, sms.WithClock(func() time.Time { return *r.now }), sms.WithLog(slog.New(slog.NewTextHandler(&logs, nil))))
	if _, err := r.router.Send(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	r.src.mu.Lock()
	r.src.err = errors.New("db down")
	r.src.mu.Unlock()
	*r.now = r.now.Add(time.Hour)
	if _, err := r.router.Send(context.Background(), req); !errors.Is(err, sms.ErrNoSnapshot) {
		t.Fatalf("a send with a snapshot an hour old and a source that fails = %v, want ErrNoSnapshot", err)
	}
	if !strings.Contains(logs.String(), "cache=sms_router") || strings.Contains(logs.String(), "db down") {
		t.Errorf("the refusal was not said by name, or the error text leaked:\n%s", logs.String())
	}
}

// sms-r16-19: the text of a failure carries no class. The class is read only in classify, and a
// string cannot be followed by a lint, so it is not put in one: for every class and a spread of
// codes, the text holds neither the word of the class nor its number.
func TestAnErrorTextCarriesNoClass(t *testing.T) {
	for c := sms.Transient; c <= sms.Blacklisted; c++ {
		for _, code := range []sms.Code{sms.CodeUnknown, sms.CodeTimeout, sms.CodeNoGateway, sms.HTTPCode(503), sms.StatusCode("104")} {
			text := sms.NewError(sms.ProviderOther, c, code).Error()
			if strings.Contains(text, c.String()) && !strings.Contains(string(code), c.String()) {
				t.Errorf("the text of a %s failure holds its class: %q", c, text)
			}
		}
	}
	// What is stored in a status column is another matter and keeps its bytes: "class:code".
	if got := sms.NewError(sms.ProviderOther, sms.Auth, sms.HTTPCode(401)).Status().String(); got != "auth:http_401" {
		t.Fatalf("the status column text changed: %q", got)
	}
}

// sms-r16-19: no fmt verb prints the fields of an Error (the class is one of them).
func TestNoFormatVerbPrintsTheClassOfAnError(t *testing.T) {
	e := sms.NewError(sms.ProviderOther, sms.Auth, sms.HTTPCode(401))
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%q", "%x"} {
		got := fmt.Sprintf(verb, e)
		if strings.Contains(got, "auth") || strings.Contains(got, "Class") {
			t.Errorf("%s prints the class: %q", verb, got)
		}
	}
	if got := fmt.Sprintf("%v", struct{ Err *sms.Error }{e}); strings.Contains(got, "auth") {
		t.Errorf("a struct holding an Error prints the class: %q", got)
	}
}

// sms-r17-8: the class of an Error is unexported, so no encoder prints it. Round 16 closed the text and
// the fmt verbs and left the exported field to encoding/json and encoding/xml.
func TestAnErrorEncodesNoClass(t *testing.T) {
	type holder struct {
		Err *sms.Error
		N   int
	}
	for c := sms.Transient; c <= sms.Blacklisted; c++ {
		e := sms.NewError(sms.ProviderOther, c, sms.CodeTimeout)
		for name, v := range map[string]any{"error": e, "struct holding it": holder{Err: e}, "an attempt": sms.Attempt{Err: e}} {
			j, err := json.Marshal(v)
			if err != nil {
				t.Fatalf("%s: json: %v", name, err)
			}
			if strings.Contains(strings.ToLower(string(j)), c.String()) || strings.Contains(string(j), "Class") {
				t.Errorf("json of %s (%s) holds the class: %s", name, c, j)
			}
			x, err := xml.Marshal(v)
			if err == nil && (strings.Contains(strings.ToLower(string(x)), c.String()) || strings.Contains(string(x), "Class")) {
				t.Errorf("xml of %s (%s) holds the class: %s", name, c, x)
			}
		}
	}
}
