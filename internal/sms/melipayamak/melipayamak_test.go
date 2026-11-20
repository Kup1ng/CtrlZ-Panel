package melipayamak_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/classify"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/melipayamak"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testtls"
)

const (
	user = "canary-user-77"
	pass = "CANARY-MELI-PASSWORD-0002"
)

var tpl = sms.ProviderTemplate{ID: "55501", ParamNames: []string{"CODE"}}

func message() sms.Message {
	return sms.Message{To: "+989121234567", Template: "otp", Locale: "fa", Values: map[string]secret.String{"CODE": secret.New("012345")}}
}

func newDriver(t *testing.T, base string, timeout time.Duration) sms.Sender {
	t.Helper()
	d, err := melipayamak.New(melipayamak.Config{
		Credentials: melipayamak.Credentials{Username: user, Password: secret.New(pass)}, BaseURL: base, Timeout: timeout, RootCAs: testtls.Roots(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func asError(t *testing.T, err error) *sms.Error {
	t.Helper()
	var e *sms.Error
	if !errors.As(err, &e) {
		t.Fatalf("not an *sms.Error: %v", err)
	}
	return e
}

func reply(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

func TestSendShape(t *testing.T) {
	var got struct {
		method, path, ctype string
		form                url.Values
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got.method, got.path, got.ctype, got.form = r.Method, r.URL.Path, r.Header.Get("Content-Type"), r.PostForm
		_, _ = io.WriteString(w, `{"Value":"1234567890123456","RetStatus":1,"StrRetStatus":"Ok"}`)
	}))
	defer srv.Close()
	res, err := newDriver(t, srv.URL+"/api/SendSMS", 0).Send(context.Background(), message(), tpl)
	if err != nil {
		t.Fatal(err)
	}
	if res.ProviderID.String() != "1234567890123456" || !res.CostRaw.IsZero() {
		t.Errorf("result: %+v", res)
	}
	if got.method != "POST" || got.path != "/api/SendSMS/BaseServiceNumber" || got.ctype != "application/x-www-form-urlencoded" {
		t.Errorf("request: %+v", got)
	}
	want := map[string]string{"username": user, "password": pass, "text": "012345", "to": "09121234567", "bodyId": "55501"}
	for k, v := range want {
		if got.form.Get(k) != v {
			t.Errorf("field %s = %q, want %q", k, got.form.Get(k), v)
		}
	}
}

func TestVariablesAreSeparatedBySemicolons(t *testing.T) {
	var text string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		text = r.PostForm.Get("text")
		_, _ = io.WriteString(w, "9999999999999999")
	}))
	defer srv.Close()
	m := sms.Message{To: "+989121234567", Values: map[string]secret.String{"A": secret.New("one"), "B": secret.New("two")}}
	_, err := newDriver(t, srv.URL, 0).Send(context.Background(), m, sms.ProviderTemplate{ID: "1", ParamNames: []string{"A", "B"}})
	if err != nil || text != "one;two" {
		t.Fatalf("text %q err %v", text, err)
	}
	// A value with the separator would shift the variables, so it is refused.
	m.Values["A"] = secret.New("o;ne")
	_, err = newDriver(t, srv.URL, 0).Send(context.Background(), m, sms.ProviderTemplate{ID: "1", ParamNames: []string{"A", "B"}})
	if e := asError(t, err); e.Code != "value_separator" {
		t.Errorf("separator: %v", e)
	}
}

// TestBothDocumentedReplyShapes covers the envelope and the bare value (9.2).
func TestBothDocumentedReplyShapes(t *testing.T) {
	for name, body := range map[string]string{
		"envelope string": `{"Value":"1234567890123456","RetStatus":1,"StrRetStatus":"Ok"}`,
		"envelope number": `{"Value":1234567890123456,"RetStatus":1,"StrRetStatus":"Ok"}`,
		"bare":            `1234567890123456`,
		"bare quoted":     `"1234567890123456"`,
		"bare spaced":     "  1234567890123456\r\n",
	} {
		srv := httptest.NewTLSServer(reply(200, body))
		res, err := newDriver(t, srv.URL, 0).Send(context.Background(), message(), tpl)
		srv.Close()
		if err != nil || res.ProviderID.String() != "1234567890123456" {
			t.Errorf("%s: %+v %v", name, res, err)
		}
	}
}

func TestRecordIDMustBeLongAndAllDigits(t *testing.T) {
	// Fifteen digits is an error number that looks like an id: not accepted.
	for _, body := range []string{`123456789012345`, `12345678901234a6`, `-1234567890123456`} {
		srv := httptest.NewTLSServer(reply(200, body))
		_, err := newDriver(t, srv.URL, 0).Send(context.Background(), message(), tpl)
		srv.Close()
		if err == nil {
			t.Errorf("%q accepted as success", body)
		}
	}
}

func TestCodeTableOfSection92(t *testing.T) {
	table := map[sms.Class][]string{
		sms.Auth:        {"0", "-1", "-108", "-109", "-110", "-111", "10", "12"},
		sms.Credit:      {"2"},
		sms.Transient:   {"6", "11", "19", "-6"},
		sms.Config:      {"-2", "-3", "-4", "-5", "-7", "-10", "7", "17"},
		sms.Recipient:   {"16", "18"},
		sms.Blacklisted: {"35"},
	}
	for class, codes := range table {
		for _, code := range codes {
			for _, shape := range []string{`{"Value":"` + code + `","RetStatus":2,"StrRetStatus":"prose with ` + pass + `"}`, code} {
				srv := httptest.NewTLSServer(reply(200, shape))
				_, err := newDriver(t, srv.URL, 0).Send(context.Background(), message(), tpl)
				srv.Close()
				e := asError(t, err)
				if e.Class != class || e.Code != sms.StatusCode(code) || e.Code == sms.CodeUnknown {
					t.Errorf("%s: %v %s, want %v", shape, e.Class, e.Code, class)
				}
				if strings.Contains(e.Error(), pass) || strings.Contains(e.Error(), "prose") {
					t.Errorf("error text holds the reply: %q", e.Error())
				}
			}
		}
	}
	// A value that is neither an id nor in the table is Config, not a success.
	srv := httptest.NewTLSServer(reply(200, `{"Value":"999"}`))
	defer srv.Close()
	if e := asError(t, func() error {
		_, err := newDriver(t, srv.URL, 0).Send(context.Background(), message(), tpl)
		return err
	}()); e.Class != sms.Config || e.Code != sms.CodeUnknown {
		t.Errorf("unknown value: %v", e)
	}
}

func TestHTTPStatuses(t *testing.T) {
	for _, c := range []struct {
		status int
		body   string
		class  sms.Class
		code   sms.Code
	}{
		{401, ``, sms.Auth, "http_401"},
		{403, ``, sms.Auth, "http_403"},
		{429, ``, sms.Transient, "http_429"},
		{500, `oops`, sms.Transient, "http_500"},
		{502, ``, sms.Transient, "http_502"},
		{301, ``, sms.Config, "redirect"},
		{404, ``, sms.Config, "http_404"},
		{200, ``, sms.Transient, "bad_reply"},
		{200, `{"RetStatus":1}`, sms.Transient, "bad_reply"},
		{200, `{not json`, sms.Transient, "bad_reply"},
	} {
		srv := httptest.NewTLSServer(reply(c.status, c.body))
		_, err := newDriver(t, srv.URL, 0).Send(context.Background(), message(), tpl)
		srv.Close()
		e := asError(t, err)
		if e.Class != c.class || e.Code != c.code {
			t.Errorf("HTTP %d %q: %v %s, want %v %s", c.status, c.body, e.Class, e.Code, c.class, c.code)
		}
	}
}

func TestRefusesBeforeTheNetwork(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	d := newDriver(t, srv.URL, 0)
	foreign := message()
	foreign.To = "+14155550100"
	for name, c := range map[string]struct {
		msg   sms.Message
		tpl   sms.ProviderTemplate
		class sms.Class
	}{
		"foreign number":   {foreign, tpl, sms.Recipient},
		"template not int": {message(), sms.ProviderTemplate{ID: "x", ParamNames: []string{"CODE"}}, sms.Config},
		"param missing":    {message(), sms.ProviderTemplate{ID: "1", ParamNames: []string{"NOPE"}}, sms.Config},
	} {
		_, err := d.Send(context.Background(), c.msg, c.tpl)
		if e := asError(t, err); e.Class != c.class {
			t.Errorf("%s: %v", name, e)
		}
	}
	if hits.Load() != 0 {
		t.Error("a request left for a message the driver could not send")
	}
}

func TestDeadHostErrorHoldsNoSecret(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	d := newDriver(t, "https://"+addr+"/api/SendSMS", 2*time.Second)
	_, err = d.Send(context.Background(), message(), tpl)
	e := asError(t, err)
	if e.Class != sms.Transient || e.Code != "network" {
		t.Errorf("dead host: %v", e)
	}
	for _, leak := range []string{pass, user, addr, "127.0.0.1", "http", "BaseServiceNumber", "09121234567", "012345"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error text %q holds %q", err.Error(), leak)
		}
	}
}

func TestHangTimesOut(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	start := time.Now()
	_, err := newDriver(t, srv.URL, 300*time.Millisecond).Send(context.Background(), message(), tpl)
	if e := asError(t, err); e.Class != sms.Transient || e.Code != "timeout" {
		t.Errorf("hang: %v", e)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("took %v", time.Since(start))
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	var elsewhere atomic.Int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere.Add(1) }))
	defer other.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect) // 307 would replay the body
	}))
	defer srv.Close()
	_, err := newDriver(t, srv.URL, 0).Send(context.Background(), message(), tpl)
	if e := asError(t, err); e.Code != "redirect" {
		t.Errorf("%v", e)
	}
	if elsewhere.Load() != 0 {
		t.Error("the password was replayed to another host")
	}
}

func TestBalance(t *testing.T) {
	var form url.Values
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form = r.PostForm
		if !strings.HasSuffix(r.URL.Path, "/GetCredit") {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, `{"Value":"50000.25","RetStatus":1,"StrRetStatus":"Ok"}`)
	}))
	defer srv.Close()
	got, err := newDriver(t, srv.URL+"/api/SendSMS", 0).Balance(context.Background())
	if err != nil || got.String() != "50000.25" || form.Get("username") != user || form.Get("password") != pass {
		t.Fatalf("%q %v", got, err)
	}
	// A balance of zero is a balance, although 0 is also a refused login in a send.
	zero := httptest.NewTLSServer(reply(200, `{"Value":"0","RetStatus":1}`))
	defer zero.Close()
	if got, err := newDriver(t, zero.URL, 0).Balance(context.Background()); err != nil || got.String() != "0" {
		t.Errorf("zero balance: %q %v", got, err)
	}
	bad := httptest.NewTLSServer(reply(200, `{"Value":"-110"}`))
	defer bad.Close()
	if _, err := newDriver(t, bad.URL, 0).Balance(context.Background()); asError(t, err).Class != sms.Auth {
		t.Errorf("balance -110: %v", err)
	}
	// The REST answer to wrong credentials is the text NULL, which is a refused login and not
	// a balance (sms-r9-3). Any other word, a negative number nobody listed and a malformed
	// number are no balance either: the Field alphabet takes letters, so the shape is judged here.
	for _, v := range []string{"NULL", "null", " Null "} {
		srv := httptest.NewTLSServer(reply(200, `{"Value":"`+v+`","RetStatus":1}`))
		_, err := newDriver(t, srv.URL, 0).Balance(context.Background())
		srv.Close()
		if e := asError(t, err); e.Class != sms.Auth || e.Code != sms.StatusCode("0") {
			t.Errorf("balance %q: %v %s, want Auth 0", v, e.Class, e.Code)
		}
	}
	for _, v := range []string{"OK", "-999", "1e5", "12.", ".5", "1.2.3", "12 34", "1,000"} {
		srv := httptest.NewTLSServer(reply(200, `{"Value":"`+v+`"}`))
		got, err := newDriver(t, srv.URL, 0).Balance(context.Background())
		srv.Close()
		if err == nil {
			t.Errorf("balance %q accepted as %q", v, got)
		} else if e := asError(t, err); e.Class != sms.Transient || e.Code != sms.CodeBadReply {
			t.Errorf("balance %q: %v %s", v, e.Class, e.Code)
		}
	}
	for _, v := range []string{"7", "0.5", "123456"} {
		srv := httptest.NewTLSServer(reply(200, `{"Value":"`+v+`"}`))
		got, err := newDriver(t, srv.URL, 0).Balance(context.Background())
		srv.Close()
		if err != nil || got.String() != v {
			t.Errorf("balance %q: %q %v", v, got, err)
		}
	}
}

func TestParseCredentials(t *testing.T) {
	c, err := melipayamak.ParseCredentials([]byte(`{"username":"u","password":"p"}`))
	if err != nil || c.Username != "u" || c.Password.Reveal() != "p" {
		t.Fatalf("%v", err)
	}
	for _, bad := range []string{``, `{}`, `{"username":"u"}`, `{"password":"p"}`, `{"username":" ","password":"p"}`,
		`{"api_key":"k"}`, `{"username":"u","password":"p","x":1}`, `{"username":"u","password":"p"}{}`} {
		_, err := melipayamak.ParseCredentials([]byte(bad))
		if err == nil {
			t.Errorf("%q accepted", bad)
		} else if strings.Contains(err.Error(), `"p"`) {
			t.Errorf("error repeats input: %v", err)
		}
	}
	if _, err := melipayamak.New(melipayamak.Config{}); err == nil {
		t.Error("a driver without credentials")
	}
}

// A reply the table does not know must never put the provider's text into the
// error code, which reaches the worker log, sms_deliveries, sms_gateways and the
// alerts (review sms-r1-7, sms-r1-14). A provider that echoes the number or the
// code in its answer would otherwise leak both.
func TestUnknownReplyTextNeverBecomesTheErrorCode(t *testing.T) {
	hostile := []string{
		"09121234567", "+989121234567", "012345", "246810", "-246810",
		"Invalid number 09121234567", "bad code 246810", "badnumber09121234567",
		"12345", "ABCDEFGHJKMNPQRSTVWX",
	}
	for _, v := range hostile {
		for _, shape := range []string{`{"Value":"` + v + `","RetStatus":2}`, v} {
			srv := httptest.NewTLSServer(reply(200, shape))
			_, err := newDriver(t, srv.URL, 0).Send(context.Background(), message(), tpl)
			srv.Close()
			e := asError(t, err)
			if e.Class != sms.Config || e.Code != sms.CodeUnknown {
				t.Errorf("%q: %v %q, want config unknown", shape, e.Class, e.Code)
			}
			for _, bad := range []string{"0912", "9121234567", "246810", "012345", "ABCDEFGH", "badnumber", "Invalid"} {
				if strings.Contains(e.Error(), bad) || strings.Contains(e.Code.String(), bad) {
					t.Errorf("%q leaked %q into %q", shape, bad, e.Error())
				}
			}
		}
	}
	// A short number the table does not name is the unknown code too: the rule keeps no
	// part of a reply in a code (rule closed-values-in-logs).
	for _, v := range []string{"999", "-12", "1234"} {
		srv := httptest.NewTLSServer(reply(200, `{"Value":"`+v+`"}`))
		_, err := newDriver(t, srv.URL, 0).Send(context.Background(), message(), tpl)
		srv.Close()
		if e := asError(t, err); e.Code != sms.CodeUnknown {
			t.Errorf("short code %s became %q", v, e.Code)
		}
	}
}

func TestTLSIsVerified(t *testing.T) {
	var served atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served.Add(1)
		_, _ = io.WriteString(w, `{"Value":"1234567890123456"}`)
	}))
	defer srv.Close()
	build := func(roots *x509.CertPool) sms.Sender {
		d, err := melipayamak.New(melipayamak.Config{
			Credentials: melipayamak.Credentials{Username: user, Password: secret.New(pass)},
			BaseURL:     srv.URL + "/api/SendSMS", Timeout: 2 * time.Second, RootCAs: roots,
		})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	// Without the server's certificate in the roots the call fails and nothing is
	// served: there is no switch that turns verification off (spec 9.2).
	_, err := build(nil).Send(context.Background(), message(), tpl)
	if e := asError(t, err); e.Class != sms.Transient {
		t.Errorf("untrusted certificate: %v", e)
	}
	if served.Load() != 0 {
		t.Error("the request reached a server whose certificate was not trusted")
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	if _, err := build(pool).Send(context.Background(), message(), tpl); err != nil {
		t.Errorf("trusted certificate: %v", err)
	}
}

func TestOnlyTheFixedHostIsDialled(t *testing.T) {
	srvA := httptest.NewTLSServer(reply(200, `{"Value":"1234567890123456"}`))
	defer srvA.Close()
	var b atomic.Int32
	srvB := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { b.Add(1) }))
	defer srvB.Close()
	if _, err := newDriver(t, srvA.URL+"/api/SendSMS", 0).Send(context.Background(), message(), tpl); err != nil {
		t.Fatal(err)
	}
	if b.Load() != 0 {
		t.Error("another host was dialled")
	}
}

func TestResponseBodyIsBounded(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"Value":"1234567890123456","pad":"`+strings.Repeat("x", 200<<10)+`"}`)
	}))
	defer srv.Close()
	// 64 KiB of a larger body is read, which cuts the JSON: a reply we cannot parse
	// is bad_reply and not a crash or a memory problem.
	_, err := newDriver(t, srv.URL+"/api/SendSMS", 0).Send(context.Background(), message(), tpl)
	if e := asError(t, err); e.Code != "bad_reply" {
		t.Errorf("oversized reply: %v", e)
	}
}

// The record id is any all-digit value of more than 15 digits, in the envelope as
// bare. The message was accepted whatever its length, so the send still succeeds,
// but a value no real id reaches is not kept: it would be stored for 90 days and
// shown on the SMS page (sms-r4-3).
func TestOversizedRecordIDIsAcceptedButNotKept(t *testing.T) {
	for _, c := range []struct{ digits, kept int }{{16, 16}, {64, 64}, {65, 0}, {60000, 0}} {
		id := strings.Repeat("1", c.digits)
		for _, shape := range []string{`{"Value":` + id + `}`, `{"Value":"` + id + `"}`} {
			srv := httptest.NewTLSServer(reply(200, shape))
			res, err := newDriver(t, srv.URL, 0).Send(context.Background(), message(), tpl)
			srv.Close()
			if err != nil {
				t.Fatalf("%d digits: an accepted message failed: %v", c.digits, err)
			}
			if len(res.ProviderID.String()) != c.kept {
				t.Errorf("%d digits: kept %d characters, want %d", c.digits, len(res.ProviderID.String()), c.kept)
			}
		}
	}
}

// sms-r8-2: the same paste artefacts are refused for both fields (see smsir).
func TestParseCredentialsRefusesControlCharactersAndSurroundingSpace(t *testing.T) {
	for _, field := range []string{"username", "password"} {
		for _, v := range []string{"a\x00b", "a\x01b", "a\x7fb", "a\tb", " ab", "ab ", "ab\u00a0", "ab\n"} {
			m := map[string]string{"username": "u", "password": "p"}
			m[field] = v
			raw, _ := json.Marshal(m)
			if _, err := melipayamak.ParseCredentials(raw); err == nil {
				t.Errorf("%s %q accepted", field, v)
			}
		}
	}
	if _, err := melipayamak.ParseCredentials([]byte(`{"username":"u s","password":"p w"}`)); err != nil {
		t.Errorf("a space inside a value is not a paste artefact: %v", err)
	}
}

// TestEveryConfigCodeHasAStatedScope is the driver half of the rule
// sms-failure-classification for sms-r9-1: the Config codes are discovered from the driver,
// each must have a scope stated here, and the classifier must give it. -3 (line not defined)
// and -7 (sender number error) are about the account's line, so every template on the
// gateway fails the same way and the scope is Gateway; the others are about one template or
// the request.
func TestEveryConfigCodeHasAStatedScope(t *testing.T) {
	want := map[string]classify.Scope{
		"-3": classify.Gateway, "-7": classify.Gateway,
		"-2": classify.Template, "-4": classify.Template, "-5": classify.Template, "-10": classify.Template,
		"7": classify.Template, "17": classify.Template,
	}
	seen := map[string]bool{}
	for n := -300; n <= 300; n++ {
		code := strconv.Itoa(n)
		srv := httptest.NewTLSServer(reply(200, `{"Value":"`+code+`"}`))
		_, err := newDriver(t, srv.URL, 0).Send(context.Background(), message(), tpl)
		srv.Close()
		e := asError(t, err)
		if e.Class != sms.Config || e.Code == sms.CodeUnknown {
			continue
		}
		seen[code] = true
		scope, stated := want[code]
		if !stated {
			t.Errorf("code %s is Config in the driver and has no stated scope: decide it in classify.Of and here", code)
			continue
		}
		if got := classify.ScopeOf(e); got != scope {
			t.Errorf("code %s: scope %v, want %v", code, got, scope)
		}
	}
	for code := range want {
		if !seen[code] {
			t.Errorf("code %s is stated here and is no longer a Config code of the driver", code)
		}
	}
}

// The provider's page shows an XML sample for BaseServiceNumber and no JSON one, so a REST
// endpoint may answer `<string xmlns=...>5521234567890123456</string>`. Read as "not a value" it
// recorded an accepted send as failed: the router sent it again through the other gateway, the
// user got two codes, and the breaker of the gateway that delivers opened (sms-r11-6).
func TestAnXMLReplyIsReadLikeAnyOtherShape(t *testing.T) {
	const decl = `<?xml version="1.0" encoding="utf-8"?>` + "\n"
	const open = `<string xmlns="http://tempuri.org/">`
	for name, c := range map[string]struct {
		body string
		id   string // the record id, or ""
		code string // the error code, or ""
	}{
		"with the declaration":     {decl + open + "5521234567890123456</string>", "5521234567890123456", ""},
		"without the declaration":  {open + "5521234567890123456</string>", "5521234567890123456", ""},
		"short, as in the finding": {open + "5521234567890123456</string>", "5521234567890123456", ""},
		"padded and spaced":        {decl + "  " + open + "\n 5521234567890123456 \n</string>\n", "5521234567890123456", ""},
		"persian digits":           {open + "۵۵۲۱۲۳۴۵۶۷۸۹۰۱۲۳۴۵۶</string>", "5521234567890123456", ""},
		"a long record id":         {decl + open + strings.Repeat("5", 40) + "</string>", strings.Repeat("5", 40), ""},
		"a comment is skipped":     {open + "<!-- ok -->5521234567890123456</string>", "5521234567890123456", ""},
		"an error code":            {decl + open + "-110</string>", "", "-110"},
		"another error code":       {open + "2</string>", "", "2"},
	} {
		srv := httptest.NewTLSServer(reply(200, c.body))
		res, err := newDriver(t, srv.URL, 0).Send(context.Background(), message(), tpl)
		srv.Close()
		switch {
		case c.id != "":
			if err != nil || res.ProviderID.String() != c.id {
				t.Errorf("%s: want the record id kept, got %+v %v", name, res, err)
			}
		default:
			e := asError(t, err)
			if e.Code.String() != c.code {
				t.Errorf("%s: code %q, want %q", name, e.Code, c.code)
			}
		}
	}
	// What is not one value stays a failed read, Transient bad_reply, never a record id and
	// never an unknown Config code: an error page, a document with children, a doctype, an
	// element after the first, and a value that is not text.
	for name, body := range map[string]string{
		"an html error page":       `<html><body><h1>502 Bad Gateway</h1></body></html>`,
		"a child element":          open + `<v>5521234567890123456</v></string>`,
		"a doctype":                `<!DOCTYPE string [<!ENTITY x "5521234567890123456">]>` + open + "&x;</string>",
		"two elements":             open + "5521234567890123456</string><string>1</string>",
		"text outside":             "5521234567890123456 " + open + "1</string>",
		"not closed":               open + "5521234567890123456",
		"empty":                    open + "</string>",
		"a processing instruction": decl + `<?php echo 1 ?>` + open + "1</string>",
	} {
		srv := httptest.NewTLSServer(reply(200, body))
		_, err := newDriver(t, srv.URL, 0).Send(context.Background(), message(), tpl)
		srv.Close()
		if err == nil {
			t.Errorf("%s: read as success", name)
			continue
		}
		if e := asError(t, err); e.Class != sms.Transient || e.Code.String() != "bad_reply" {
			t.Errorf("%s: %v %v, want transient bad_reply", name, e.Class, e.Code)
		}
	}
}

func TestAnXMLBalanceIsRead(t *testing.T) {
	srv := httptest.NewTLSServer(reply(200, `<?xml version="1.0"?><double xmlns="http://tempuri.org/">1500.5</double>`))
	defer srv.Close()
	got, err := newDriver(t, srv.URL+"/api/SendSMS", 0).Balance(context.Background())
	if err != nil || got.String() != "1500.5" {
		t.Fatalf("%q %v", got, err)
	}
}
