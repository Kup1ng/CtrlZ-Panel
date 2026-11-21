package smsir_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/invite"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/otp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/classify"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/smsir"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testtls"
)

const apiKey = "CANARY-SMSIR-KEY-0001"

var tpl = sms.ProviderTemplate{ID: "123456", ParamNames: []string{"CODE"}}

func message(to string) sms.Message {
	return sms.Message{To: to, Template: "otp", Locale: "fa", Values: map[string]secret.String{"CODE": secret.New("012345")}}
}

func newDriver(t *testing.T, base string, timeout time.Duration, roots *x509.CertPool) sms.Sender {
	t.Helper()
	// A nil pool means the throw-away certificate of httptest TLS servers; a test that wants an untrusted
	// server passes an empty pool.
	if roots == nil {
		roots = testtls.Roots()
	}
	d, err := smsir.New(smsir.Config{Credentials: smsir.Credentials{APIKey: secret.New(apiKey)}, BaseURL: base, Timeout: timeout, RootCAs: roots})
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

// reply serves a fixed status and body.
func reply(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

func TestSendShape(t *testing.T) {
	var got struct {
		method, path, key, ctype string
		body                     map[string]any
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method, got.path, got.key, got.ctype = r.Method, r.URL.Path, r.Header.Get("X-API-KEY"), r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&got.body)
		_, _ = io.WriteString(w, `{"status":1,"message":"ok","data":{"messageId":98765,"cost":0.5}}`)
	}))
	defer srv.Close()
	d := newDriver(t, srv.URL+"/v1", 0, nil)
	res, err := d.Send(context.Background(), message("+989121234567"), tpl)
	if err != nil {
		t.Fatal(err)
	}
	if res.ProviderID.String() != "98765" || res.CostRaw.String() != "0.5" {
		t.Errorf("result: %+v", res)
	}
	if got.method != "POST" || got.path != "/v1/send/verify" || got.key != apiKey || got.ctype != "application/json" {
		t.Errorf("request: %+v", got)
	}
	// templateId is a number, the mobile is the 09 form, and the value keeps its
	// leading zero because it travels as text.
	if got.body["mobile"] != "09121234567" || got.body["templateId"] != float64(123456) {
		t.Errorf("body: %+v", got.body)
	}
	params := got.body["parameters"].([]any)[0].(map[string]any)
	if params["name"] != "CODE" || params["value"] != "012345" {
		t.Errorf("parameters: %+v", params)
	}
	if d.Provider() != "sms_ir" {
		t.Error("provider name")
	}
}

func TestSendWithoutDataStillCounts(t *testing.T) {
	srv := httptest.NewTLSServer(reply(200, `{"status":1,"message":"ok"}`))
	defer srv.Close()
	res, err := newDriver(t, srv.URL, 0, nil).Send(context.Background(), message("+989121234567"), tpl)
	if err != nil || !res.ProviderID.IsZero() {
		t.Fatalf("%+v %v", res, err)
	}
}

// TestStatusTableOfSection92 runs every code of the table.
func TestStatusTableOfSection92(t *testing.T) {
	table := map[sms.Class][]int{
		sms.Auth:        {10, 11, 12, 13, 14},
		sms.Credit:      {102},
		sms.Transient:   {0, 20},
		sms.Config:      {101, 113, 114, 116, 117, 118, 119, 123},
		sms.Recipient:   {104},
		sms.Blacklisted: {115},
	}
	for class, codes := range table {
		for _, code := range codes {
			body, _ := json.Marshal(map[string]any{"status": code, "message": "provider prose with SECRET " + apiKey})
			srv := httptest.NewTLSServer(reply(200, string(body)))
			_, err := newDriver(t, srv.URL, 0, nil).Send(context.Background(), message("+989121234567"), tpl)
			srv.Close()
			e := asError(t, err)
			if e.Class() != class {
				t.Errorf("status %d: class %v, want %v", code, e.Class(), class)
			}
			// Every status of the table is a member of the code table, not the unknown
			// word: the table of 9.2 and codes.go cannot drift apart unseen.
			if e.Code != sms.StatusNumber(code) || e.Code == sms.CodeUnknown {
				t.Errorf("status %d: code %q", code, e.Code)
			}
			// The provider's message is never used: not in the text, not in the code.
			if strings.Contains(e.Error(), "SECRET") || strings.Contains(e.Error(), apiKey) || strings.Contains(e.Error(), "prose") {
				t.Errorf("status %d: error text %q holds the reply", code, e.Error())
			}
		}
	}
}

func TestHTTPStatuses(t *testing.T) {
	for _, c := range []struct {
		status int
		body   string
		class  sms.Class
		code   sms.Code
	}{
		{401, `{"status":10}`, sms.Auth, "http_401"},
		{401, ``, sms.Auth, "http_401"},
		{429, ``, sms.Transient, "http_429"},
		{500, `<html>oops</html>`, sms.Transient, "http_500"},
		{503, ``, sms.Transient, "http_503"},
		{302, ``, sms.Config, "redirect"},
		{404, `not json`, sms.Config, "http_404"},
		{200, `not json`, sms.Transient, "bad_reply"},
		{200, ``, sms.Transient, "bad_reply"},
		{200, `{"status":777}`, sms.Config, sms.CodeUnknown},
		{200, `{"status":9121234567}`, sms.Config, sms.CodeUnknown},
		{400, `{"status":114}`, sms.Config, "114"},
	} {
		srv := httptest.NewTLSServer(reply(c.status, c.body))
		_, err := newDriver(t, srv.URL, 0, nil).Send(context.Background(), message("+989121234567"), tpl)
		srv.Close()
		e := asError(t, err)
		if e.Class() != c.class || e.Code != c.code {
			t.Errorf("HTTP %d %q: %v %s, want %v %s", c.status, c.body, e.Class(), e.Code, c.class, c.code)
		}
	}
}

func TestRefusesBeforeTheNetwork(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	d := newDriver(t, srv.URL, 0, nil)
	for name, c := range map[string]struct {
		msg   sms.Message
		tpl   sms.ProviderTemplate
		class sms.Class
		code  sms.Code
	}{
		"foreign number":   {message("+14155550100"), tpl, sms.Recipient, "number_format"},
		"short number":     {message("+98912"), tpl, sms.Recipient, "number_format"},
		"template not int": {message("+989121234567"), sms.ProviderTemplate{ID: "abc", ParamNames: []string{"CODE"}}, sms.Config, "template_id"},
		"template zero":    {message("+989121234567"), sms.ProviderTemplate{ID: "0", ParamNames: []string{"CODE"}}, sms.Config, "template_id"},
		"param missing":    {message("+989121234567"), sms.ProviderTemplate{ID: "1", ParamNames: []string{"OTHER"}}, sms.Config, "param_missing"},
		// sms.ir types templateId as an int32 (sms-r9-2): above it the binding answers 400, which
		// counts toward the breaker, so the id is refused here with no call.
		"template above int32":  {message("+989121234567"), sms.ProviderTemplate{ID: "3000000000", ParamNames: []string{"CODE"}}, sms.Config, "template_id"},
		"template int32 plus 1": {message("+989121234567"), sms.ProviderTemplate{ID: "2147483648", ParamNames: []string{"CODE"}}, sms.Config, "template_id"},
		"value too long": {sms.Message{To: "+989121234567", Values: map[string]secret.String{"CODE": secret.New(strings.Repeat("9", 26))}},
			tpl, sms.Config, "value_too_long"},
	} {
		_, err := d.Send(context.Background(), c.msg, c.tpl)
		e := asError(t, err)
		if e.Class() != c.class || e.Code != c.code {
			t.Errorf("%s: %v %s", name, e.Class(), e.Code)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("%d requests left the driver for a message it could not send", hits.Load())
	}
	// 25 characters is the limit and passes.
	srv2 := httptest.NewTLSServer(reply(200, `{"status":1}`))
	defer srv2.Close()
	ok := sms.Message{To: "+989121234567", Values: map[string]secret.String{"CODE": secret.New(strings.Repeat("9", 25))}}
	if _, err := newDriver(t, srv2.URL, 0, nil).Send(context.Background(), ok, tpl); err != nil {
		t.Errorf("25 characters: %v", err)
	}
}

// TestDeadHostErrorHoldsNoSecret is R21 for this driver: Go's own error carries
// the whole URL, and ours must not.
func TestDeadHostErrorHoldsNoSecret(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close() // nothing listens here now
	d := newDriver(t, "https://"+addr+"/v1", 2*time.Second, nil)
	_, err = d.Send(context.Background(), message("+989121234567"), tpl)
	e := asError(t, err)
	if e.Class() != sms.Transient || e.Code != "network" {
		t.Errorf("dead host: %v", e)
	}
	for _, leak := range []string{apiKey, addr, "127.0.0.1", "http", "/v1", "09121234567", "012345", "send/verify"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error text %q holds %q", err.Error(), leak)
		}
	}
	if _, err := d.Balance(context.Background()); err == nil || strings.Contains(err.Error(), apiKey) || strings.Contains(err.Error(), addr) {
		t.Errorf("balance on a dead host: %v", err)
	}
}

func TestHangTimesOut(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	d := newDriver(t, srv.URL, 300*time.Millisecond, nil)
	start := time.Now()
	_, err := d.Send(context.Background(), message("+989121234567"), tpl)
	took := time.Since(start)
	e := asError(t, err)
	if e.Class() != sms.Transient || e.Code != "timeout" {
		t.Errorf("hang: %v", e)
	}
	if took > 2*time.Second {
		t.Errorf("took %v", took)
	}
}

func TestCancelledContextIsNotAGatewayFailure(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	_, err := newDriver(t, srv.URL, 5*time.Second, nil).Send(ctx, message("+989121234567"), tpl)
	var e *sms.Error
	if errors.As(err, &e) {
		t.Errorf("a cancelled context became a provider error: %v", e)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
}

func TestDefaultTimeoutsAreTheSpecs(t *testing.T) {
	// 9.1: connect 3 s, total 6 s. A driver built with no override carries them.
	d, err := smsir.New(smsir.Config{Credentials: smsir.Credentials{APIKey: secret.New(apiKey)}})
	if err != nil {
		t.Fatal(err)
	}
	if d.Provider() != "sms_ir" {
		t.Fatal("provider")
	}
	// The package constant is the only host.
	if smsir.DefaultBase != "https://api.sms.ir/v1" {
		t.Error("base URL changed")
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	var elsewhere atomic.Int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere.Add(1) }))
	defer other.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	_, err := newDriver(t, srv.URL, 0, nil).Send(context.Background(), message("+989121234567"), tpl)
	if e := asError(t, err); e.Code != "redirect" {
		t.Errorf("redirect: %v", e)
	}
	if elsewhere.Load() != 0 {
		t.Error("the redirect was followed and the key went with it")
	}
}

func TestTLSIsVerified(t *testing.T) {
	var served atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served.Add(1)
		_, _ = io.WriteString(w, `{"status":1}`)
	}))
	defer srv.Close()
	// Without the server's certificate in the roots, the call fails and nothing is
	// served: there is no switch that turns verification off.
	_, err := newDriver(t, srv.URL, 2*time.Second, x509.NewCertPool()).Send(context.Background(), message("+989121234567"), tpl)
	if e := asError(t, err); e.Class() != sms.Transient {
		t.Errorf("untrusted certificate: %v", e)
	}
	if served.Load() != 0 {
		t.Error("the request reached a server whose certificate was not trusted")
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	if _, err := newDriver(t, srv.URL, 2*time.Second, pool).Send(context.Background(), message("+989121234567"), tpl); err != nil {
		t.Errorf("trusted certificate: %v", err)
	}
}

func TestOnlyTheFixedHostIsDialled(t *testing.T) {
	// The client dials the host:port of its base and nothing else, whatever URL a
	// request carries.
	srvA := httptest.NewTLSServer(reply(200, `{"status":1}`))
	defer srvA.Close()
	var b atomic.Int32
	srvB := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { b.Add(1) }))
	defer srvB.Close()
	// A base URL whose host differs from the one dialled is not constructible:
	// the dial guard compares the address of every connection with the base.
	d := newDriver(t, srvA.URL, 0, nil)
	if _, err := d.Send(context.Background(), message("+989121234567"), tpl); err != nil {
		t.Fatal(err)
	}
	if b.Load() != 0 {
		t.Error("another host was dialled")
	}
}

func TestResponseBodyIsBounded(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"status":1,"pad":"`+strings.Repeat("x", 200<<10)+`"}`)
	}))
	defer srv.Close()
	// 64 KiB of a larger body is read, which cuts the JSON: a reply we cannot parse
	// is bad_reply and not a crash or a memory problem.
	_, err := newDriver(t, srv.URL, 0, nil).Send(context.Background(), message("+989121234567"), tpl)
	if e := asError(t, err); e.Code != "bad_reply" {
		t.Errorf("oversized reply: %v", e)
	}
}

func TestBalance(t *testing.T) {
	var key string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key = r.Header.Get("X-API-KEY")
		if r.URL.Path != "/v1/credit" || r.Method != "GET" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, `{"status":1,"message":"ok","data":12345.5}`)
	}))
	defer srv.Close()
	got, err := newDriver(t, srv.URL+"/v1", 0, nil).Balance(context.Background())
	if err != nil || got.String() != "12345.5" || key != apiKey {
		t.Fatalf("%q %v key=%q", got, err, key)
	}
	bad := httptest.NewTLSServer(reply(200, `{"status":10}`))
	defer bad.Close()
	if _, err := newDriver(t, bad.URL, 0, nil).Balance(context.Background()); asError(t, err).Class() != sms.Auth {
		t.Errorf("balance with a refused key: %v", err)
	}
	unauth := httptest.NewTLSServer(reply(401, ``))
	defer unauth.Close()
	if _, err := newDriver(t, unauth.URL, 0, nil).Balance(context.Background()); asError(t, err).Class() != sms.Auth {
		t.Errorf("balance 401: %v", err)
	}
}

func TestParseCredentials(t *testing.T) {
	c, err := smsir.ParseCredentials([]byte(`{"api_key":"abc"}`))
	if err != nil || c.APIKey.Reveal() != "abc" {
		t.Fatalf("%v", err)
	}
	for _, bad := range []string{``, `{}`, `{"api_key":""}`, `{"api_key":"  "}`, `{"username":"u","password":"p"}`,
		`{"api_key":"a","extra":1}`, `{"api_key":"a"} {}`, `[]`, `{"api_key":"a\nb"}`, `{"api_key":"` + strings.Repeat("a", 300) + `"}`} {
		_, err := smsir.ParseCredentials([]byte(bad))
		if err == nil {
			t.Errorf("%q accepted", bad)
			continue
		}
		if strings.Contains(err.Error(), "abc") || strings.Contains(err.Error(), "username") && strings.Contains(bad, "p\"") {
			t.Errorf("error repeats input: %v", err)
		}
	}
	if _, err := smsir.New(smsir.Config{}); err == nil {
		t.Error("a driver without a key")
	}
}

func TestMobile(t *testing.T) {
	for in, want := range map[string]string{"+989121234567": "09121234567", "+989351234567": "09351234567"} {
		if got, ok := smsir.Mobile(in); !ok || got != want {
			t.Errorf("%s: %s %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "09121234567", "+982112345678", "+98912123456a", "+9891212345678"} {
		if _, ok := smsir.Mobile(in); ok {
			t.Errorf("%q accepted", in)
		}
	}
}

// An unknown status must not carry the provider's number into the error code,
// which reaches the log, sms_deliveries, the gateway row and the alerts. A
// provider (or a proxy in the path) that echoes the recipient or the code in
// "status" would otherwise leak both (sms-r2-11).
func TestUnknownStatusNeverBecomesTheErrorCode(t *testing.T) {
	for _, v := range []string{"9121234567", "989121234567", "246810", "-246810", "12345", "-5"} {
		srv := httptest.NewTLSServer(reply(200, `{"status":`+v+`}`))
		_, err := newDriver(t, srv.URL, 0, nil).Send(context.Background(), message("+989121234567"), tpl)
		srv.Close()
		e := asError(t, err)
		if e.Class() != sms.Config || e.Code != sms.CodeUnknown {
			t.Errorf("status %s: %v %q, want config unknown", v, e.Class(), e.Code)
		}
		if strings.Contains(e.Error(), strings.TrimPrefix(v, "-")) {
			t.Errorf("status %s leaked into %q", v, e.Error())
		}
	}
	// A short number the table does not name is the unknown code too (rule
	// closed-values-in-logs: no part of a reply is kept in a code).
	for _, v := range []string{"777", "9999", "2"} {
		srv := httptest.NewTLSServer(reply(200, `{"status":`+v+`}`))
		_, err := newDriver(t, srv.URL, 0, nil).Send(context.Background(), message("+989121234567"), tpl)
		srv.Close()
		if e := asError(t, err); e.Code != sms.CodeUnknown {
			t.Errorf("short status %s became %q", v, e.Code)
		}
	}
}

// The live shape of a successful reply was never confirmed (T-411). A "data" of
// another type must not turn a message the provider queued into a failed
// attempt: the router would send it again through the fallback, and the user
// would get two codes (sms-r2-5).
func TestAcceptedReplyWithUnexpectedDataStillCounts(t *testing.T) {
	for _, c := range []struct {
		body, id, cost string
	}{
		{`{"status":1,"data":{"messageId":"abc-123"}}`, "abc-123", ""},
		{`{"status":1,"data":{"messageId":42,"cost":"free"}}`, "42", ""},
		{`{"status":1,"data":{"messageId":42,"cost":1.5}}`, "42", "1.5"},
		{`{"status":1,"data":"queued"}`, "", ""},
		{`{"status":1,"data":[1,2]}`, "", ""},
		{`{"status":1,"data":null}`, "", ""},
		{`{"status":1,"data":{"messageId":{"x":1},"cost":[1]}}`, "", ""},
		{`{"status":1,"data":{"messageId":"has spaces and 09121234567"}}`, "", ""},
		{`{"status":1,"data":{"messageId":"` + strings.Repeat("a", 65) + `"}}`, "", ""},
		// A number is kept as the provider wrote it, so its length is the provider's
		// to choose: past 64 characters it is dropped, accepted all the same (sms-r4-3).
		{`{"status":1,"data":{"messageId":` + strings.Repeat("7", 65) + `,"cost":` + strings.Repeat("9", 65) + `}}`, "", ""},
		{`{"status":1,"data":{"messageId":` + strings.Repeat("7", 64) + `,"cost":` + strings.Repeat("9", 64) + `}}`, strings.Repeat("7", 64), strings.Repeat("9", 64)},
	} {
		srv := httptest.NewTLSServer(reply(200, c.body))
		res, err := newDriver(t, srv.URL, 0, nil).Send(context.Background(), message("+989121234567"), tpl)
		srv.Close()
		if err != nil {
			t.Errorf("%s: %v", c.body, err)
			continue
		}
		if res.ProviderID.String() != c.id || res.CostRaw.String() != c.cost {
			t.Errorf("%s: id %q cost %q, want %q %q", c.body, res.ProviderID, res.CostRaw, c.id, c.cost)
		}
	}
	// A refusal with a data of another type is still a refusal by its status.
	srv := httptest.NewTLSServer(reply(200, `{"status":102,"data":"no credit"}`))
	defer srv.Close()
	_, err := newDriver(t, srv.URL, 0, nil).Send(context.Background(), message("+989121234567"), tpl)
	if e := asError(t, err); e.Class() != sms.Credit {
		t.Errorf("status 102 with string data: %v", e.Class())
	}
}

// sms-r8-2: a key the admin's PUT accepts must be one the HTTP client can send. A key with a
// control character used to pass ParseCredentials and then fail locally, before any dial, as a
// network error: the breaker opened and sms_down was raised while the provider's own Auth answer
// never came. Every byte value is tried at the start, the middle and the end of a key, and what
// ParseCredentials accepts is sent through the real driver to a server that answers 200: it must
// not come back as a transport failure.
func TestEveryAcceptedKeyCanBeSent(t *testing.T) {
	srv := httptest.NewTLSServer(reply(200, `{"status":1,"data":5}`))
	defer srv.Close()
	accepted := 0
	for b := 0; b < 256; b++ {
		ch := string(rune(b))
		for _, key := range []string{ch + "abc", "a" + ch + "c", "abc" + ch} {
			raw, _ := json.Marshal(map[string]string{"api_key": key})
			c, err := smsir.ParseCredentials(raw)
			if err != nil {
				continue
			}
			accepted++
			d, err := smsir.New(smsir.Config{Credentials: c, BaseURL: srv.URL, RootCAs: testtls.Roots()})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := d.Balance(context.Background()); err != nil {
				t.Errorf("a key with byte %#x was accepted and cannot be sent: %v", b, err)
			}
		}
	}
	if accepted < 100 {
		t.Fatalf("only %d keys accepted: the test is not trying the ordinary ones", accepted)
	}
	// The ones the finding named, by name: they must be refused at the PUT.
	for _, key := range []string{"ab\x00c", "ab\x01c", "ab\x7fc", "ab\tc", " abc", "abc ", "abc\u00a0", "\u2003abc"} {
		raw, _ := json.Marshal(map[string]string{"api_key": key})
		if _, err := smsir.ParseCredentials(raw); err == nil {
			t.Errorf("key %q accepted", key)
		}
	}
}

// TestEveryConfigStatusHasAStatedScope is the driver half of the rule
// sms-failure-classification for sms-r9-1. The driver tags a status Config; whether that is
// the whole gateway (the line or the plan) or one template is decided in classify.Of. The
// statuses are discovered from the driver by asking it about every number, so a status
// added to its table without a stated scope here fails this test, and the scope written here
// is the one the classifier must give (an account-wide status left as Template would leave
// OTP offered while no code arrives).
func TestEveryConfigStatusHasAStatedScope(t *testing.T) {
	want := map[int]classify.Scope{
		101: classify.Gateway, 118: classify.Gateway, 119: classify.Gateway, 123: classify.Gateway,
		113: classify.Template, 114: classify.Template, 116: classify.Template, 117: classify.Template,
	}
	seen := map[int]bool{}
	for status := -5; status <= 300; status++ {
		if status == 1 { // 1 is the accepted status, not a failure
			continue
		}
		body, _ := json.Marshal(map[string]any{"status": status})
		srv := httptest.NewTLSServer(reply(200, string(body)))
		_, err := newDriver(t, srv.URL, 0, nil).Send(context.Background(), message("+989121234567"), tpl)
		srv.Close()
		e := asError(t, err)
		if e.Class() != sms.Config || e.Code == sms.CodeUnknown {
			continue
		}
		seen[status] = true
		scope, stated := want[status]
		if !stated {
			t.Errorf("status %d is Config in the driver and has no stated scope: decide it in classify.Of and here", status)
			continue
		}
		if got := classify.ScopeOf(e); got != scope {
			t.Errorf("status %d: scope %v, want %v", status, got, scope)
		}
	}
	for status := range want {
		if !seen[status] {
			t.Errorf("status %d is stated here and is no longer a Config status of the driver", status)
		}
	}
}

func TestParseTemplateIDIsTheInt32OfTheProvider(t *testing.T) {
	for in, want := range map[string]bool{
		"1": true, "123456": true, "2147483647": true, " 123456 ": false, "+7": false,
		"0": false, "-1": false, "2147483648": false, "3000000000": false, "999999999999999999": false, "": false, "12a": false,
	} {
		if _, ok := smsir.ParseTemplateID(in); ok != want {
			t.Errorf("ParseTemplateID(%q) = %v, want %v", in, ok, want)
		}
	}
	// The largest id still goes out on the wire as it is.
	var got string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		_, _ = io.WriteString(w, `{"status":1}`)
	}))
	defer srv.Close()
	if _, err := newDriver(t, srv.URL, 0, nil).Send(context.Background(), message("+989121234567"), sms.ProviderTemplate{ID: "2147483647", ParamNames: []string{"CODE"}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `"templateId":2147483647`) {
		t.Errorf("request body %q", got)
	}
}

// TestEveryValueTheServiceSendsFitsTheProviderLimit ties the values the service really
// makes to sms.ir's 25 character parameter limit (sms-r9-4). The formatted invite code is
// 23 characters, two under the limit, and a longer code (more characters, bigger groups)
// would make every invite fail locally as value_too_long, a message-scope failure with a
// warning and no breaker, so nothing but this test would say so.
func TestEveryValueTheServiceSendsFitsTheProviderLimit(t *testing.T) {
	var values []secret.String
	for range 200 {
		code, _, err := invite.New()
		if err != nil {
			t.Fatal(err)
		}
		values = append(values, code)
		otpCode, err := otp.NewCode()
		if err != nil {
			t.Fatal(err)
		}
		values = append(values, otpCode)
	}
	srv := httptest.NewTLSServer(reply(200, `{"status":1}`))
	defer srv.Close()
	d := newDriver(t, srv.URL, 0, nil)
	for _, v := range values {
		if n := len([]rune(v.Reveal())); n > smsir.ValueLimit {
			t.Fatalf("a value of %d characters is over the sms.ir limit of %d", n, smsir.ValueLimit)
		}
		m := sms.Message{To: "+989121234567", Values: map[string]secret.String{"CODE": v}}
		if _, err := d.Send(context.Background(), m, tpl); err != nil {
			t.Fatalf("a value the service makes is refused by the driver: %v", err)
		}
	}
}

// A reply with no status key is not the documented status 0 ("system error"). It decoded to 0, so
// the recorded code was transient:0 for a 400 binding error of the HTTP stack, and the operator
// looked for an outage at sms.ir instead of a bad request (sms-r11-7).
func TestAReplyWithNoStatusKeyIsReadByItsHTTPStatus(t *testing.T) {
	for _, c := range []struct {
		name   string
		status int
		body   string
		class  sms.Class
		code   sms.Code
	}{
		{"an empty object, 400", 400, `{}`, sms.Config, "http_400"},
		{"null, 400", 400, `null`, sms.Config, "http_400"},
		{"a binding error with no status key, 400", 400, `{"title":"One or more validation errors occurred.","errors":{"mobile":["bad"]}}`, sms.Config, "http_400"},
		{"a null status, 422", 422, `{"status":null,"message":"x"}`, sms.Config, "http_422"},
		{"an empty object, 200", 200, `{}`, sms.Transient, "bad_reply"},
		{"null, 200", 200, `null`, sms.Transient, "bad_reply"},
		{"a status of the wrong type, 200", 200, `{"status":"1"}`, sms.Transient, "bad_reply"},
		// The documented status 0 is still the documented status 0.
		{"the documented status 0, 200", 200, `{"status":0,"message":"system error"}`, sms.Transient, "0"},
	} {
		srv := httptest.NewTLSServer(reply(c.status, c.body))
		_, err := newDriver(t, srv.URL, 0, nil).Send(context.Background(), message("+989121234567"), tpl)
		srv.Close()
		e := asError(t, err)
		if e.Class() != c.class || e.Code != c.code {
			t.Errorf("Send, %s: %v %s, want %v %s", c.name, e.Class(), e.Code, c.class, c.code)
		}
	}
	// Balance has the same reading: only a 200 with a status key says anything about the account.
	for _, c := range []struct {
		name string
		body string
		code sms.Code
	}{
		{"an empty object", `{}`, "bad_reply"},
		{"null", `null`, "bad_reply"},
		{"data with no status", `{"data":12.5}`, "bad_reply"},
		{"the documented status 0", `{"status":0}`, "0"},
	} {
		srv := httptest.NewTLSServer(reply(200, c.body))
		_, err := newDriver(t, srv.URL, 0, nil).Balance(context.Background())
		srv.Close()
		e := asError(t, err)
		if e.Class() != sms.Transient || e.Code != c.code {
			t.Errorf("Balance, %s: %v %s, want transient %s", c.name, e.Class(), e.Code, c.code)
		}
	}
}

// The status table is the subset Verify can produce (sms-r11-8). 118 is read as the account's
// quota (Gateway, in TestEveryConfigStatusHasAStatedScope); the statuses of bulk and scheduled sends
// and the empty text are not ours, and read as the one unknown word, which fails closed.
func TestStatusesVerifyCannotProduceReadAsUnknown(t *testing.T) {
	for _, status := range []int{103, 105, 106, 107, 108, 109, 110, 111, 112} {
		body, _ := json.Marshal(map[string]any{"status": status})
		srv := httptest.NewTLSServer(reply(200, string(body)))
		_, err := newDriver(t, srv.URL, 0, nil).Send(context.Background(), message("+989121234567"), tpl)
		srv.Close()
		e := asError(t, err)
		if e.Class() != sms.Config || e.Code != sms.CodeUnknown {
			t.Errorf("status %d: %v %s, want config unknown", status, e.Class(), e.Code)
		}
		if classify.ScopeOf(e) != classify.Ambiguous {
			t.Errorf("status %d: scope %v, want ambiguous", status, classify.ScopeOf(e))
		}
	}
}
