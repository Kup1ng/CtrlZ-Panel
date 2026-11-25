// Package melipayamak is the Melipayamak driver (spec 9.2, 9.3). It sends by
// template: POST /api/SendSMS/BaseServiceNumber, form-encoded, with username,
// password, text (the variables, in order, separated by ";"), to (one number) and
// bodyId (the approved template).
//
// SendOtp is not used. It takes the code as an integer, which drops a leading
// zero, and has fixed text with no brand.
//
// What is confirmed and what is not. The reply is a single value: the record id
// (more than 15 digits) on success, or a small error number. The official
// getcredit page shows that the REST service wraps a value as
// {"Value": ..., "RetStatus": 1, "StrRetStatus": "Ok"}, and the BaseServiceNumber
// page shows no envelope at all. So the parser takes both shapes, the envelope
// and a bare value, and the first live send settles which one is real. If it is
// neither, only parseValue changes (spec 9.2, "Could not be read"). Nothing here
// has run against a live account.
//
// An account can require its API key in place of the password (codes -110 and
// the console article say so), so the "password" credential holds either.
package melipayamak

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/digits"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/smshttp"
)

// Provider is the name stored in sms_gateways.provider.
const Provider = "melipayamak"

// DefaultBase is the REST root. It is a constant (9.3).
const DefaultBase = "https://rest.payamak-panel.com/api/SendSMS"

// Credentials is the JSON sealed in sms_gateways.credentials_ct.
type Credentials struct {
	Username string // not secret by itself, and the source of the hint
	Password secret.String
}

type credentialsJSON struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// ParseCredentials reads {"username": ..., "password": ...} and nothing else.
func ParseCredentials(raw []byte) (Credentials, error) {
	bad := errors.New("melipayamak: credentials must be {\"username\": ..., \"password\": ...}")
	var j credentialsJSON
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&j); err != nil || dec.More() {
		return Credentials{}, bad
	}
	// Both go in a form body, which carries any byte, but a control character or a space at an
	// end is a paste artefact either way and the hint would show a value that was not sent
	// (sms-r8-2): the same test as the sms.ir key.
	if !smshttp.SendableCredential(j.Username) || !smshttp.SendableCredential(j.Password) || len(j.Username) > 128 || len(j.Password) > 256 {
		return Credentials{}, bad
	}
	return Credentials{Username: j.Username, Password: secret.New(j.Password)}, nil
}

// Config builds a Sender. BaseURL, RootCAs and Timeout exist for tests.
type Config struct {
	Credentials Credentials
	BaseURL     string
	RootCAs     *x509.CertPool
	Timeout     time.Duration
}

type driver struct {
	user   string
	pass   secret.String
	base   string
	client *smshttp.Client
}

// New returns the Sender.
func New(cfg Config) (sms.Sender, error) {
	if cfg.Credentials.Username == "" || cfg.Credentials.Password.IsZero() {
		return nil, errors.New("melipayamak: no credentials")
	}
	base := cfg.BaseURL
	if base == "" {
		base = DefaultBase
	}
	hp, err := smshttp.HostPort(base)
	if err != nil {
		return nil, err
	}
	return &driver{
		user: cfg.Credentials.Username, pass: cfg.Credentials.Password, base: strings.TrimRight(base, "/"),
		client: smshttp.NewClient(hp, smshttp.Options{Total: cfg.Timeout, RootCAs: cfg.RootCAs}),
	}, nil
}

func (d *driver) Provider() string { return Provider }

// The code table of spec 9.2, keyed by the value as the provider returns it.
func classify(code string) (sms.Class, bool) {
	switch code {
	case "0", "-1", "-108", "-109", "-110", "-111", "10", "12":
		return sms.Auth, true
	case "2":
		return sms.Credit, true
	case "6", "11", "19", "-6":
		return sms.Transient, true
	case "-2", "-3", "-4", "-5", "-7", "-10", "7", "17":
		return sms.Config, true
	case "16", "18":
		return sms.Recipient, true
	case "35":
		return sms.Blacklisted, true
	}
	return 0, false
}

// parseValue reads the one value of a reply, from the envelope or bare.
func parseValue(body []byte) (string, bool) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return "", false
	}
	if body[0] == '{' {
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber() // a record id is over 15 digits and must not pass through a float
		var env map[string]any
		if err := dec.Decode(&env); err != nil {
			return "", false
		}
		return scalar(env["Value"])
	}
	if body[0] == '<' {
		return xmlValue(body)
	}
	// A bare value, possibly a JSON string or number.
	s := strings.Trim(string(body), "\"")
	if s == "" || len(s) > 64 {
		return "", false
	}
	return digits.ToASCII(strings.TrimSpace(s)), true
}

// xmlValue reads the one value of an XML reply of the shape the provider's SOAP page shows,
// `<string xmlns="http://tempuri.org/">VALUE</string>`, with or without the XML declaration
// (sms-r11-6). The research found only that sample for BaseServiceNumber, so a REST endpoint that
// answers in XML is as likely as the JSON envelope, and a reply read as "not a value" would
// record an accepted send as failed: the router would send it again through the other gateway
// and the user would get two codes. The reader is strict on purpose: one element, only text in
// it, no doctype or processing instruction other than the declaration, so an HTML error page or
// a document with children is not a value and stays a Transient bad_reply.
func xmlValue(body []byte) (string, bool) {
	dec := xml.NewDecoder(bytes.NewReader(body))
	dec.Strict = true
	dec.CharsetReader = charsetReader
	var text strings.Builder
	depth, seenRoot := 0, false
	for {
		tok, err := dec.RawToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", false
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if seenRoot && depth == 0 {
				return "", false
			}
			seenRoot = true
			depth++
			if depth > 1 {
				return "", false // a child element: this is not the single-value shape
			}
		case xml.EndElement:
			depth--
		case xml.CharData:
			if depth == 1 {
				text.Write(t)
			} else if len(bytes.TrimSpace(t)) > 0 {
				return "", false
			}
		case xml.ProcInst:
			if t.Target != "xml" || seenRoot {
				return "", false
			}
		case xml.Directive:
			return "", false
		case xml.Comment:
		}
	}
	if !seenRoot || depth != 0 {
		return "", false
	}
	s := digits.ToASCII(strings.TrimSpace(text.String()))
	if s == "" || len(s) > 64 {
		return "", false
	}
	return s, true
}

// charsetReader serves an XML declaration that names an encoding other than UTF-8 (sms-r12-1). The
// value of a reply is digits, which every one of these encodings spells with the same bytes, so a
// declaration is no reason to call an accepted send a failure. UTF-16 is already converted by
// smshttp.Normalize when the body carries its byte order mark, and a body that only declares it
// is read as it is. A byte above 0x7F is the start of text, never of a digit: ISO-8859-1 maps it to
// its code point and the Arabic code page (windows-1256) to U+FFFD, and the single-value test
// then refuses the reply as it would any other non-numeric text. Any other name is refused.
func charsetReader(label string, in io.Reader) (io.Reader, error) {
	switch strings.ToLower(label) {
	case "utf-16", "utf-16le", "utf-16be", "us-ascii", "ascii":
		return in, nil
	case "iso-8859-1", "latin1", "windows-1252":
		return recode(in, false), nil
	case "windows-1256", "cp1256", "iso-8859-6":
		return recode(in, true), nil
	}
	return nil, errors.New("melipayamak: unsupported charset")
}

// recode reads the whole of in (it is at most 64 KiB, smshttp.MaxBody) and writes it as UTF-8.
func recode(in io.Reader, lossy bool) io.Reader {
	var src bytes.Buffer
	if _, err := src.ReadFrom(io.LimitReader(in, smshttp.MaxBody)); err != nil {
		return bytes.NewReader(nil)
	}
	var out bytes.Buffer
	for _, c := range src.Bytes() {
		switch {
		case c < 0x80:
			out.WriteByte(c)
		case lossy:
			out.WriteRune(0xFFFD)
		default:
			out.WriteRune(rune(c))
		}
	}
	return &out
}

func scalar(v any) (string, bool) {
	switch x := v.(type) {
	case json.Number:
		return x.String(), true
	case string:
		// Digits are folded here, in the decoder: a gateway that answers in Persian
		// digits must read as a record id or a known code like any other.
		x = digits.ToASCII(strings.TrimSpace(x))
		return x, x != ""
	}
	return "", false
}

// isRecordID is the success test: all digits, more than 15 of them.
func isRecordID(s string) bool {
	if len(s) <= 15 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// ParseTemplateID reads the approved template (bodyId) as Melipayamak takes it: 1 to 18 ASCII
// digits with a value above zero, which is what the admin PUT allows, judged by the one
// function every provider uses (sms.ParseTemplateNumber, sms-r9-2, sms-r10-4). It is here,
// next to Send, so the PUT and the driver judge an id the same way. ParseInt alone took a
// sign, a zero and nineteen digits.
func ParseTemplateID(s string) (string, bool) {
	if _, ok := sms.ParseTemplateNumber(s); !ok {
		return "", false
	}
	return s, true
}

// Mobile turns +989XXXXXXXXX into 09XXXXXXXXX. The provider's page does not state
// the number format; the first live send confirms it (9.2).
func Mobile(e164 string) (string, bool) {
	if len(e164) != 13 || !strings.HasPrefix(e164, "+989") {
		return "", false
	}
	for _, r := range e164[1:] {
		if r < '0' || r > '9' {
			return "", false
		}
	}
	return "0" + e164[3:], true
}

func (d *driver) Send(ctx context.Context, m sms.Message, t sms.ProviderTemplate) (sms.Result, error) {
	fail := func(c sms.Class, code sms.Code) (sms.Result, error) {
		return sms.Result{}, sms.NewError(Provider, c, code)
	}
	mobile, ok := Mobile(m.To)
	if !ok {
		return fail(sms.Recipient, sms.CodeNumberFormat)
	}
	bodyID, ok := ParseTemplateID(t.ID)
	if !ok {
		return fail(sms.Config, sms.CodeTemplateID)
	}
	vars := make([]string, 0, len(t.ParamNames))
	for _, name := range t.ParamNames {
		v, ok := m.Values[name]
		if !ok {
			return fail(sms.Config, sms.CodeParamMissing)
		}
		if strings.Contains(v.Reveal(), ";") {
			return fail(sms.Config, sms.CodeValueSeparator)
		}
		vars = append(vars, v.Reveal())
	}
	form := url.Values{}
	form.Set("username", d.user)
	form.Set("password", d.pass.Reveal())
	form.Set("text", strings.Join(vars, ";"))
	form.Set("to", mobile)
	form.Set("bodyId", bodyID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.base+"/BaseServiceNumber", strings.NewReader(form.Encode()))
	if err != nil {
		return fail(sms.Config, sms.CodeRequest)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := smshttp.Do(d.client, req)
	if err != nil {
		return sms.Result{}, d.transportError(ctx, err)
	}
	switch {
	case resp.Status == http.StatusUnauthorized || resp.Status == http.StatusForbidden:
		return fail(sms.Auth, sms.HTTPCode(resp.Status))
	case resp.Status == http.StatusTooManyRequests || resp.Status >= 500:
		return fail(sms.Transient, sms.HTTPCode(resp.Status))
	case resp.Status >= 300 && resp.Status < 400:
		return fail(sms.Config, sms.CodeRedirect)
	}
	val, ok := parseValue(resp.Body)
	if !ok {
		if resp.Status == http.StatusOK {
			return fail(sms.Transient, sms.CodeBadReply)
		}
		return fail(sms.Config, sms.HTTPCode(resp.Status))
	}
	if isRecordID(val) {
		// The reply is accepted whatever its length: the provider took the message,
		// and failing it would send it again through the fallback. But the id lands
		// in sms_deliveries for 90 days, so a value no real id reaches is dropped
		// (sms-r4-3).
		// ParseField returns the empty Field for one that is too long.
		return sms.Result{ProviderID: sms.ParseField(val)}, nil // no cost in the reply (9.2)
	}
	if c, known := classify(val); known {
		return fail(c, sms.StatusCode(val))
	}
	// An unknown value: not a record id and not in the table. The provider's own text
	// must not become our error code, which is logged and stored: a reply may echo the
	// number or the code that was sent. The code is the one fixed unknown word, never
	// a piece of the reply (rule closed-values-in-logs; this used to keep a value of up
	// to four digits, and each filter of the reply was found short by a review round).
	return fail(sms.Config, sms.CodeUnknown)
}

func (d *driver) transportError(ctx context.Context, err error) error {
	if ctx.Err() != nil && !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, smshttp.ErrTimeout) {
		return sms.NewError(Provider, sms.Transient, sms.CodeTimeout)
	}
	return sms.NewError(Provider, sms.Transient, sms.CodeNetwork)
}

// Balance posts GetCredit. The value is the credit, counted in SMS messages and not in Rial
// (research sms-iran.md 5.4), so it cannot be set against a price in Rial.
func (d *driver) Balance(ctx context.Context) (sms.Field, error) {
	form := url.Values{}
	form.Set("username", d.user)
	form.Set("password", d.pass.Reveal())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.base+"/GetCredit", strings.NewReader(form.Encode()))
	if err != nil {
		return sms.Field{}, sms.NewError(Provider, sms.Config, sms.CodeRequest)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := smshttp.Do(d.client, req)
	if err != nil {
		return sms.Field{}, d.transportError(ctx, err)
	}
	if resp.Status != http.StatusOK {
		return sms.Field{}, sms.NewError(Provider, sms.Transient, sms.HTTPCode(resp.Status))
	}
	val, ok := parseValue(resp.Body)
	if !ok {
		return sms.Field{}, sms.NewError(Provider, sms.Transient, sms.CodeBadReply)
	}
	// The REST service answers the bad-credentials case of GetCredit with the text NULL (SOAP
	// answers 0), which is a refused login and never a balance (sms-r9-3).
	if strings.EqualFold(val, "NULL") {
		return sms.Field{}, sms.NewError(Provider, sms.Auth, sms.StatusCode("0"))
	}
	// A credit of "0" is a real balance, and "0" is also the code for a refused login; the
	// balance call cannot tell them apart, so it reads "0" as the balance. The same goes for
	// every positive number: a balance of 7 messages is not the status 7, so only a negative
	// value is read as a status code.
	if c, known := classify(val); known && strings.HasPrefix(val, "-") {
		return sms.Field{}, sms.NewError(Provider, c, sms.StatusCode(val))
	}
	// Only a plain non-negative number is a balance, and sms.ParseCredit is the one judge of
	// that for every driver (sms-r9-3, sms-r10-7). The Field alphabet takes letters, so without
	// it any word the service answers with would be shown as the credit.
	f, ok := sms.ParseCredit(val)
	if !ok {
		return sms.Field{}, sms.NewError(Provider, sms.Transient, sms.CodeBadReply)
	}
	return f, nil
}
