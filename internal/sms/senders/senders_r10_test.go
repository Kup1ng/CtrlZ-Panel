package senders_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/melipayamak"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/senders"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/smsir"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testtls"
)

// Review round 10 of the SMS layer (sms-r10-4, sms-r10-7).

// TestOneJudgeOfAProviderTemplateIdForEveryProvider is the property of sms-r9-2 and sms-r10-4
// across providers: the PUT (ValidTemplateID) and each driver's own check agree, and what any of
// them accepts is 1 to 18 ASCII digits with a value above zero. sms.ir adds its int32 bound.
// Round 9 tested only the sms.ir driver, and the Melipayamak one took "-5", "+7", "0" and 19 digits.
func TestOneJudgeOfAProviderTemplateIdForEveryProvider(t *testing.T) {
	common := []struct {
		id   string
		want bool
	}{
		{"1", true}, {"7", true}, {"123456", true}, {"999999999999999999", true}, {"007", true},
		{"", false}, {"0", false}, {"00", false}, {"-5", false}, {"+7", false}, {" 7", false}, {"7 ", false}, {"1 2", false},
		{"1e3", false}, {"0x10", false}, {"12a", false}, {"7.5", false}, {"٧", false}, {"١٢٣", false},
		{"1000000000000000000", false}, {"9223372036854775807", false}, {"9223372036854775808", false},
	}
	for _, c := range common {
		for _, prov := range []string{melipayamak.Provider, "noop"} {
			if got := senders.ValidTemplateID(prov, c.id); got != c.want {
				t.Errorf("ValidTemplateID(%s, %q) = %v, want %v", prov, c.id, got, c.want)
			}
		}
		// sms.ir is the common rule and the int32 bound.
		want := c.want
		if n, ok := sms.ParseTemplateNumber(c.id); ok && n > 2147483647 {
			want = false
		}
		if got := senders.ValidTemplateID(smsir.Provider, c.id); got != want {
			t.Errorf("ValidTemplateID(sms_ir, %q) = %v, want %v", c.id, got, want)
		}
	}
	// Each driver's own function agrees with the PUT: a stored row is judged as the PUT would.
	for _, c := range common {
		if _, ok := melipayamak.ParseTemplateID(c.id); ok != c.want {
			t.Errorf("melipayamak.ParseTemplateID(%q) = %v, want %v", c.id, ok, c.want)
		}
	}
	if got, ok := melipayamak.ParseTemplateID("123"); !ok || got != "123" {
		t.Errorf("melipayamak.ParseTemplateID(123) = %q, %v", got, ok)
	}
}

// balanceCorpus is text that a balance reply can hold and that is not a balance. None of it is a
// number a provider documents as a status, so every driver must answer Transient bad_reply.
var balanceCorpus = []string{
	"Error", "error", "OK", "free", "NaN", "Infinity", "1e9", "1E9", "1e", "2.5e3", "+5", "--5", "1.2.3", ".5", "5.", ".", "-.5",
	"12abc", "0x10", "1,000", "1 000", "_", "a-b", "9_9", "5+", "٫", "1_000",
}

// TestNoDriverReadsANonNumberAsABalance runs every driver's Balance over the same corpus (the
// shared sms.ParseCredit judges it), so a third driver cannot skip the rule that sms-r9-3 applied to
// Melipayamak alone and sms-r10-7 found open in sms.ir.
func TestNoDriverReadsANonNumberAsABalance(t *testing.T) {
	type driver struct {
		name  string
		build func(url string) (sms.Sender, error)
		// replies are the bodies the provider's credit call can carry the text in.
		replies func(text string) []string
	}
	jsonString := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	isJSONNumber := func(s string) bool {
		var n json.Number
		return json.Unmarshal([]byte(s), &n) == nil && strings.TrimSpace(s) == s && s != "" && (s[0] == '-' || s[0] >= '0' && s[0] <= '9')
	}
	drivers := []driver{
		{"sms_ir", func(u string) (sms.Sender, error) {
			return smsir.New(smsir.Config{Credentials: smsir.Credentials{APIKey: secret.New("0123456789abcdef0123456789abcdef")}, BaseURL: u, RootCAs: testtls.Roots()})
		}, func(text string) []string {
			out := []string{`{"status":1,"data":` + jsonString(text) + `}`}
			if isJSONNumber(text) {
				out = append(out, `{"status":1,"data":`+text+`}`)
			}
			return out
		}},
		{"melipayamak", func(u string) (sms.Sender, error) {
			return melipayamak.New(melipayamak.Config{Credentials: melipayamak.Credentials{Username: "user", Password: secret.New("pass-word-1")}, BaseURL: u, RootCAs: testtls.Roots()})
		}, func(text string) []string {
			return []string{`{"Value":` + jsonString(text) + `}`}
		}},
	}
	for _, d := range drivers {
		for _, text := range balanceCorpus {
			for _, body := range d.replies(text) {
				body := body
				srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = io.Copy(io.Discard, r.Body)
					_, _ = io.WriteString(w, body)
				}))
				s, err := d.build(srv.URL)
				if err != nil {
					srv.Close()
					t.Fatalf("%s: %v", d.name, err)
				}
				f, err := s.Balance(context.Background())
				srv.Close()
				e, ok := err.(*sms.Error)
				if err == nil || !ok || e.Class() != sms.Transient || e.Code != sms.CodeBadReply || !f.IsZero() {
					t.Errorf("%s: reply %s: balance %q, err %v; want Transient bad_reply and no balance", d.name, body, f.String(), err)
				}
			}
		}
		// The control: plain numbers are balances, in every driver.
		for _, text := range []string{"0", "7", "1500", "12.5", "100000000"} {
			for _, body := range d.replies(text) {
				body := body
				srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = io.WriteString(w, body)
				}))
				s, _ := d.build(srv.URL)
				f, err := s.Balance(context.Background())
				srv.Close()
				if err != nil || f.String() != text {
					t.Errorf("%s: reply %s: balance %q, err %v; want %q", d.name, body, f.String(), err, text)
				}
			}
		}
	}
}

// TestSMSIrNegativeBalanceIsNotABalance is the example of the finding: sms.ir answering a number
// below zero, as a JSON number, is not a credit.
func TestSMSIrNegativeBalanceIsNotABalance(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"status":1,"data":-5}`)
	}))
	defer srv.Close()
	s, err := smsir.New(smsir.Config{Credentials: smsir.Credentials{APIKey: secret.New("0123456789abcdef0123456789abcdef")}, BaseURL: srv.URL, RootCAs: testtls.Roots()})
	if err != nil {
		t.Fatal(err)
	}
	if f, err := s.Balance(context.Background()); err == nil || !f.IsZero() {
		t.Fatalf("balance %q, err %v", f.String(), err)
	}
}
