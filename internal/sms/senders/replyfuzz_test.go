package senders_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/melipayamak"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/smsir"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testtls"
)

// The reply fuzz of rule boundary-input (P1 auth review round 5, rules.md topic 9,
// spec 9.2). Whatever a gateway answers, the values a driver stores or shows
// (the message id, the cost, the balance, and the code of an error) are bounded
// and in one alphabet, the provider's prose never reaches them, and a send the
// provider accepted is never turned into a failure by a value that is odd. Each
// driver gets thousands of generated replies, in the shapes of its published
// documentation and in shapes nobody documented.
//
// The replies are generated and not listed, so a new field a driver starts to read
// is covered by the next run. Their values come from a pool built to break the
// bounds that were added one at a time (sms-r2-5, sms-r4-3): numbers of any size,
// strings of 64 KiB, NUL and format characters, Persian digits, white space around
// a value, nested structures.

const canary = "CANARY-PROVIDER-PROSE-91"

// fieldRE is the closed alphabet of a stored field.
var fieldRE = regexp.MustCompile(`^[0-9A-Za-z_.+-]{0,64}$`)

// codeRE is the alphabet of an sms.Error code.
var codeRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,32}$`)

// values builds the pool a field of a reply is drawn from, as JSON text.
func values(r *rand.Rand) []string {
	digitsOf := func(n int) string { return strings.Repeat(string(rune('1'+r.IntN(9))), n) }
	persian := strings.Map(func(c rune) rune { return '۰' + (c - '0') }, digitsOf(18))
	arabic := strings.Map(func(c rune) rune { return '٠' + (c - '0') }, digitsOf(18))
	str := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	return []string{
		"98765", "0.5", "-1", "1E+3", "1e400", "-0", "0.00000000000000000000000000000000000000000000000000000000000000000001",
		digitsOf(15), digitsOf(16), digitsOf(17), digitsOf(63), digitsOf(64), digitsOf(65), digitsOf(500), digitsOf(60000),
		str("abc-123_X"), str("  42  "), str(""), str(" "), str("a b"), str("a\u0000b"), str("12\u200b34"), str("\u202e123"),
		str("\ufeff123"), str("<script>"), str(canary), str(strings.Repeat("x", 64)), str(strings.Repeat("x", 65)),
		str(strings.Repeat("x", 64<<10)), str(persian), str(arabic), str("١٢٣٤٥٦٧٨٩٠١٢٣٤٥٦٧٨"), str("ａｂｃ１２３"), str("é"),
		str("1,5"), str("0x10"), str("+989121234567"), str("09121234567"), str("\r\n"),
		"null", "true", "false", "[]", "[1,2]", `{}`, `{"a":{"b":[1,2,{"c":null}]}}`, `[` + strings.Repeat("[", 200) + strings.Repeat("]", 200) + `]`,
		"\"\xff\xfe\"", "1.5.5", "--1", "1e", ".", "-",
	}
}

type reply struct {
	status int
	body   string
}

// smsirReplies: the envelope {"status", "message", "data": {...}} in every shape.
func smsirReplies(r *rand.Rand) []reply {
	var out []reply
	vs := values(r)
	statuses := []string{"1", "0", "10", "20", "102", "104", "115", "114", "99999999999999999999", "-5", "\"1\"", "null", "1.5", "123456789"}
	for _, st := range statuses {
		for _, v := range vs {
			w := vs[r.IntN(len(vs))]
			out = append(out,
				reply{200, fmt.Sprintf(`{"status":%s,"message":%q,"data":{"messageId":%s,"cost":%s}}`, st, canary, v, w)},
				reply{200, fmt.Sprintf(`{"status":%s,"message":%q,"data":%s}`, st, canary, v)},
				reply{200, fmt.Sprintf(`{"status":%s,"data":{"messageId":%s}}`, st, v)},
			)
		}
		out = append(out, reply{200, fmt.Sprintf(`{"status":%s}`, st)}, reply{500, fmt.Sprintf(`{"status":%s}`, st)})
	}
	return out
}

// meliReplies: the envelope {"Value": ...} or a bare value, in every shape.
func meliReplies(r *rand.Rand) []reply {
	var out []reply
	vs := values(r)
	for _, v := range vs {
		out = append(out,
			reply{200, fmt.Sprintf(`{"Value":%s,"RetStatus":1,"StrRetStatus":%q}`, v, canary)},
			reply{200, v},
			reply{200, "  " + strings.Trim(v, `"`) + "\n"},
		)
	}
	for _, code := range []string{"0", "-110", "2", "35", "16", "12345", "99999", "-99999"} {
		out = append(out, reply{200, `{"Value":"` + code + `"}`}, reply{200, code})
	}
	return out
}

func check(t *testing.T, name string, res sms.Result, err error) {
	t.Helper()
	if err == nil {
		for field, f := range map[string]string{"ProviderID": res.ProviderID.String(), "CostRaw": res.CostRaw.String()} {
			if !fieldRE.MatchString(f) {
				t.Errorf("%s: %s %q is not a bounded field of the closed alphabet", name, field, truncate(f))
			}
		}
		return
	}
	var e *sms.Error
	if !errors.As(err, &e) {
		// The only error that is not an *sms.Error is the caller's own context.
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("%s: not an *sms.Error: %v", name, truncate(err.Error()))
		}
		return
	}
	if !e.Code.Valid() || !e.Provider.Valid() {
		t.Errorf("%s: error code %q provider %q is not from the closed tables", name, truncate(e.Code.String()), truncate(e.Provider.String()))
	}
	if strings.Contains(err.Error(), canary) {
		t.Errorf("%s: the provider's prose reached the error text", name)
	}
}

func truncate(s string) string {
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}

func serve(t *testing.T, rs []reply) (url string, next func() reply) {
	t.Helper()
	i := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		cur := rs[i%len(rs)]
		w.WriteHeader(cur.status)
		_, _ = io.WriteString(w, cur.body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, func() reply { cur := rs[i%len(rs)]; i++; return cur }
}

func TestSmsirRepliesAreBounded(t *testing.T) {
	rs := smsirReplies(rand.New(rand.NewPCG(1, 2)))
	url, next := serve(t, rs)
	d, err := smsir.New(smsir.Config{Credentials: smsir.Credentials{APIKey: secret.New("CANARY-KEY")}, BaseURL: url, RootCAs: testtls.Roots()})
	if err != nil {
		t.Fatal(err)
	}
	msg := sms.Message{To: "+989121234567", Template: "otp", Locale: "fa", Values: map[string]secret.String{"CODE": secret.New("012345")}}
	tpl := sms.ProviderTemplate{ID: "123456", ParamNames: []string{"CODE"}}
	accepted := 0
	for range rs {
		cur := next()
		res, err := d.Send(context.Background(), msg, tpl)
		check(t, truncate(cur.body), res, err)
		if err == nil {
			accepted++
		}
	}
	if accepted == 0 {
		t.Fatal("no generated reply was accepted: the generator no longer exercises the accepted path")
	}
	// Balance reads the same envelope.
	for range rs {
		cur := next()
		got, err := d.Balance(context.Background())
		if err == nil && !fieldRE.MatchString(got.String()) {
			t.Errorf("balance %q out of bounds (reply %s)", truncate(got.String()), truncate(cur.body))
		}
		if err != nil {
			check(t, "balance", sms.Result{}, err)
		}
	}
}

func TestMelipayamakRepliesAreBounded(t *testing.T) {
	rs := meliReplies(rand.New(rand.NewPCG(3, 4)))
	url, next := serve(t, rs)
	d, err := melipayamak.New(melipayamak.Config{Credentials: melipayamak.Credentials{Username: "canary-user", Password: secret.New("CANARY-PASS")}, BaseURL: url, RootCAs: testtls.Roots()})
	if err != nil {
		t.Fatal(err)
	}
	msg := sms.Message{To: "+989121234567", Template: "otp", Locale: "fa", Values: map[string]secret.String{"CODE": secret.New("012345")}}
	tpl := sms.ProviderTemplate{ID: "55501", ParamNames: []string{"CODE"}}
	accepted := 0
	for range rs {
		cur := next()
		res, err := d.Send(context.Background(), msg, tpl)
		check(t, truncate(cur.body), res, err)
		if err == nil {
			accepted++
		}
	}
	if accepted == 0 {
		t.Fatal("no generated reply was accepted: the generator no longer exercises the accepted path")
	}
	for range rs {
		cur := next()
		got, err := d.Balance(context.Background())
		if err == nil && !fieldRE.MatchString(got.String()) {
			t.Errorf("balance %q out of bounds (reply %s)", truncate(got.String()), truncate(cur.body))
		}
		if err != nil {
			check(t, "balance", sms.Result{}, err)
		}
	}
}

// TestDigitsFoldInTheDecoder: a gateway that answers in Persian or Arabic-Indic
// digits gives the same record id as one that answers in ASCII, and a send is still
// an accepted one.
func TestDigitsFoldInTheDecoder(t *testing.T) {
	for _, body := range []string{`"۱۲۳۴۵۶۷۸۹۰۱۲۳۴۵۶۷۸"`, `{"Value":"١٢٣٤٥٦٧٨٩٠١٢٣٤٥٦٧٨"}`, `{"Value":"1234567890123456780"}`} {
		url, _ := serve(t, []reply{{200, body}})
		d, err := melipayamak.New(melipayamak.Config{Credentials: melipayamak.Credentials{Username: "u", Password: secret.New("p")}, BaseURL: url, RootCAs: testtls.Roots()})
		if err != nil {
			t.Fatal(err)
		}
		res, err := d.Send(context.Background(), sms.Message{To: "+989121234567", Template: "otp", Locale: "fa", Values: map[string]secret.String{"CODE": secret.New("1")}}, sms.ProviderTemplate{ID: "1", ParamNames: []string{"CODE"}})
		if err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		if got := res.ProviderID.String(); !strings.HasPrefix(got, "12345678901234567") || strings.Trim(got, "0123456789") != "" {
			t.Errorf("%s: id %q is not the ASCII digits", body, got)
		}
	}
	for in, want := range map[string]string{"۱۲۳": "123", "٠٩٨": "098", "１２３": "123", " 42 ": "42", "a b": "", "a\u0000": "", "": "", "x+1.5e-3_": "x+1.5e-3_"} {
		if got := sms.ParseField(in).String(); got != want {
			t.Errorf("ParseField(%q) = %q, want %q", in, got, want)
		}
	}
}
