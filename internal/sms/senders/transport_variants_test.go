package senders_test

import (
	"context"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/melipayamak"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/smsir"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testtls"
)

// Rule sms-failure-classification, round 12 (sms-r12-1): an accepted reply that arrives in an odd
// transport dress is still an accepted reply. Round 11 (sms-r11-6) added one reading to one
// driver, and each driver was tested on its own hand-written shapes, so a byte order mark, which
// ASP.NET gateways emit, turned an accepted and billed message into a Transient bad_reply: the
// router sent the code again through the fallback and the primary's breaker opened.
//
// The corpus below is shared. Every success body of every driver is run through every variant of
// the transport (byte order marks, line breaks, white space, UTF-16), and each must be accepted.
// A driver added to the table of this test is covered the day it is added; a variant added to the
// list covers every driver.

// variant dresses a body as a gateway might send it.
type variant struct {
	name string
	wrap func(string) []byte
}

func utf16Bytes(s string, bigEndian bool, bom bool) []byte {
	var out []byte
	put := func(u uint16) {
		if bigEndian {
			out = append(out, byte(u>>8), byte(u))
		} else {
			out = append(out, byte(u), byte(u>>8))
		}
	}
	if bom {
		put(0xFEFF)
	}
	for _, u := range utf16.Encode([]rune(s)) {
		put(u)
	}
	return out
}

func variants() []variant {
	const bom = "\xEF\xBB\xBF"
	return []variant{
		{"plain", func(s string) []byte { return []byte(s) }},
		{"utf8 BOM", func(s string) []byte { return []byte(bom + s) }},
		{"utf8 BOM and CRLF", func(s string) []byte { return []byte(bom + s + "\r\n") }},
		{"CRLF before", func(s string) []byte { return []byte("\r\n" + s + "\r\n") }},
		{"leading spaces and tab", func(s string) []byte { return []byte("  \t" + s + " ") }},
		{"white space before the BOM", func(s string) []byte { return []byte("\r\n" + bom + s) }},
		{"two BOMs", func(s string) []byte { return []byte(bom + bom + s) }},
		{"utf16 LE BOM", func(s string) []byte { return utf16Bytes(s, false, true) }},
		{"utf16 BE BOM", func(s string) []byte { return utf16Bytes(s, true, true) }},
	}
}

type successBody struct {
	name string
	body string
}

func smsirSuccess() []successBody {
	return []successBody{
		{"envelope", `{"status":1,"message":"ok","data":{"messageId":98765432,"cost":1.2}}`},
		{"pretty", "{\n  \"status\": 1,\n  \"data\": {\"messageId\": 98765432}\n}\n"},
	}
}

func meliSuccess() []successBody {
	id := "5521234567890123456"
	xml := func(decl string) string { return decl + `<string xmlns="http://tempuri.org/">` + id + `</string>` }
	return []successBody{
		{"envelope", `{"Value":"` + id + `","RetStatus":1,"StrRetStatus":"Ok"}`},
		{"bare", id},
		{"bare json string", `"` + id + `"`},
		{"xml no declaration", xml("")},
		{"xml utf-8", xml(`<?xml version="1.0" encoding="utf-8"?>` + "\n")},
		{"xml utf-16", xml(`<?xml version="1.0" encoding="utf-16"?>` + "\n")},
		{"xml iso-8859-1", xml(`<?xml version="1.0" encoding="iso-8859-1"?>` + "\n")},
		{"xml windows-1256", xml(`<?xml version="1.0" encoding="windows-1256"?>` + "\n")},
	}
}

func TestEveryDriverAcceptsASuccessReplyInEveryTransportVariant(t *testing.T) {
	msg := sms.Message{To: "+989121234567", Template: "otp", Locale: "fa", Values: map[string]secret.String{"CODE": secret.New("012345")}}
	drivers := []struct {
		name    string
		bodies  []successBody
		newSend func(url string) (sms.Sender, error)
		tpl     sms.ProviderTemplate
	}{
		{"sms_ir", smsirSuccess(), func(url string) (sms.Sender, error) {
			return smsir.New(smsir.Config{Credentials: smsir.Credentials{APIKey: secret.New("CANARY-KEY")}, BaseURL: url, RootCAs: testtls.Roots()})
		}, sms.ProviderTemplate{ID: "123456", ParamNames: []string{"CODE"}}},
		{"melipayamak", meliSuccess(), func(url string) (sms.Sender, error) {
			return melipayamak.New(melipayamak.Config{Credentials: melipayamak.Credentials{Username: "u", Password: secret.New("CANARY-PASS")}, BaseURL: url, RootCAs: testtls.Roots()})
		}, sms.ProviderTemplate{ID: "55501", ParamNames: []string{"CODE"}}},
	}
	for _, d := range drivers {
		for _, b := range d.bodies {
			for _, v := range variants() {
				name := d.name + "/" + b.name + "/" + v.name
				url, _ := serve(t, []reply{{200, string(v.wrap(b.body))}})
				snd, err := d.newSend(url)
				if err != nil {
					t.Fatal(err)
				}
				res, err := snd.Send(context.Background(), msg, d.tpl)
				if err != nil {
					t.Errorf("%s: an accepted reply was read as a failure: %v", name, err)
					continue
				}
				if res.ProviderID.String() == "" {
					t.Errorf("%s: accepted, but the record id was lost", name)
				}
			}
		}
	}
	// The same dress on the balance reply of each driver.
	for _, v := range variants() {
		url, _ := serve(t, []reply{{200, string(v.wrap(`{"status":1,"data":1500}`))}})
		snd, _ := smsir.New(smsir.Config{Credentials: smsir.Credentials{APIKey: secret.New("CANARY-KEY")}, BaseURL: url, RootCAs: testtls.Roots()})
		if got, err := snd.(interface {
			Balance(context.Context) (sms.Field, error)
		}).Balance(context.Background()); err != nil || got.String() != "1500" {
			t.Errorf("sms_ir balance/%s: %q %v", v.name, got, err)
		}
		url, _ = serve(t, []reply{{200, string(v.wrap(`{"Value":"1500"}`))}})
		snd, _ = melipayamak.New(melipayamak.Config{Credentials: melipayamak.Credentials{Username: "u", Password: secret.New("p")}, BaseURL: url, RootCAs: testtls.Roots()})
		if got, err := snd.(interface {
			Balance(context.Context) (sms.Field, error)
		}).Balance(context.Background()); err != nil || got.String() != "1500" {
			t.Errorf("melipayamak balance/%s: %q %v", v.name, got, err)
		}
	}
}

// The dress must not turn a refusal into an acceptance: a BOM-prefixed error code is still the
// error, and prose in a BOM-prefixed body is still not a record id.
func TestATransportVariantDoesNotMakeAFailureLookLikeSuccess(t *testing.T) {
	msg := sms.Message{To: "+989121234567", Template: "otp", Locale: "fa", Values: map[string]secret.String{"CODE": secret.New("012345")}}
	tpl := sms.ProviderTemplate{ID: "55501", ParamNames: []string{"CODE"}}
	for _, v := range variants() {
		for _, body := range []string{"-110", `{"Value":"-110"}`, "<html><body>oops</body></html>", "accepted"} {
			url, _ := serve(t, []reply{{200, string(v.wrap(body))}})
			snd, _ := melipayamak.New(melipayamak.Config{Credentials: melipayamak.Credentials{Username: "u", Password: secret.New("p")}, BaseURL: url, RootCAs: testtls.Roots()})
			if _, err := snd.Send(context.Background(), msg, tpl); err == nil {
				t.Errorf("melipayamak/%s/%q was accepted", v.name, strings.TrimSpace(body))
			}
		}
	}
}
