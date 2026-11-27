// Package smsir is the sms.ir driver (spec 9.2, 9.3). It sends a Verify template:
// POST /v1/send/verify with the API key in the X-API-KEY header, and reads the
// reply envelope {"status", "message", "data": {"messageId", "cost"}}.
//
// Nothing here has run against a live account (T-411 waits for the owner's key).
// The request and reply shapes, the status table and the 25 character limit come
// from sms.ir's published documentation, read on 2026-11-06; the sandbox key of
// type Sandbox (template 123456, parameter CODE) is how the owner confirms them.
//
// The reply's "message" text is never used. It is provider prose, it can echo the
// request, and the class and code come from the numeric status alone.
package smsir

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/smshttp"
)

// Provider is the name stored in sms_gateways.provider.
const Provider = "sms_ir"

// DefaultBase is the API root. It is a constant: no host comes from the database
// (9.3).
const DefaultBase = "https://api.sms.ir/v1"

// ValueLimit is the longest parameter value sms.ir accepts (status 114), in characters. It is
// exported so a test can hold every value the service sends (an invite code, an OTP) to it
// (sms-r9-4).
const (
	maxValue   = 25
	ValueLimit = maxValue
)

// ParseTemplateID reads a template id as sms.ir types it: templateId is an int32 in its
// OpenAPI document, so 1 to 2147483647. The admin PUT accepts up to 18 digits for every
// provider, and an id above the bound would reach the wire unchanged and come back as a
// binding 400, an undocumented answer that counts toward the breaker (sms-r9-2).
func ParseTemplateID(s string) (int64, bool) {
	id, ok := sms.ParseTemplateNumber(s)
	if !ok || id > math.MaxInt32 {
		return 0, false
	}
	return id, true
}

// Credentials is the JSON sealed in sms_gateways.credentials_ct.
type Credentials struct {
	APIKey secret.String
}

type credentialsJSON struct {
	APIKey string `json:"api_key"`
}

// ParseCredentials reads {"api_key": "..."} and nothing else. The error is a
// fixed string: it never repeats the input.
func ParseCredentials(raw []byte) (Credentials, error) {
	var j credentialsJSON
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&j); err != nil || dec.More() {
		return Credentials{}, errors.New("smsir: credentials must be {\"api_key\": ...}")
	}
	// The key travels in a header, so what the HTTP layer would refuse is refused here, at the
	// PUT, and not discovered as a network outage at the first send (sms-r8-2).
	if !smshttp.SendableCredential(j.APIKey) || len(j.APIKey) > 256 {
		return Credentials{}, errors.New("smsir: credentials must be {\"api_key\": ...}")
	}
	return Credentials{APIKey: secret.New(j.APIKey)}, nil
}

// Config builds a Sender. BaseURL, RootCAs and Timeout exist for tests; the
// worker leaves them at their zero values.
type Config struct {
	Credentials Credentials
	BaseURL     string
	RootCAs     *x509.CertPool
	Timeout     time.Duration
}

type driver struct {
	key    secret.String
	base   string
	client *smshttp.Client
}

// New returns the Sender.
func New(cfg Config) (sms.Sender, error) {
	if cfg.Credentials.APIKey.IsZero() {
		return nil, errors.New("smsir: no API key")
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
		key:    cfg.Credentials.APIKey,
		base:   strings.TrimRight(base, "/"),
		client: smshttp.NewClient(hp, smshttp.Options{Total: cfg.Timeout, RootCAs: cfg.RootCAs}),
	}, nil
}

func (d *driver) Provider() string { return Provider }

// The status table of spec 9.2.
func classify(status int) (sms.Class, bool) {
	switch status {
	case 10, 11, 12, 13, 14:
		return sms.Auth, true
	case 102:
		return sms.Credit, true
	case 0, 20:
		return sms.Transient, true
	case 101, 113, 114, 116, 117, 118, 119, 123:
		return sms.Config, true
	case 104:
		return sms.Recipient, true
	case 115:
		return sms.Blacklisted, true
	}
	return 0, false
}

type verifyBody struct {
	Mobile     string      `json:"mobile"`
	TemplateID int64       `json:"templateId"`
	Parameters []parameter `json:"parameters"`
}

type parameter struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// reply keeps "data" raw. The live shape of a successful reply has never been
// confirmed (T-411), and a type that does not fit it must not turn a message the
// provider has queued into a failed attempt: the router would then send it
// again through the fallback, and the user would hold two codes. Only "status"
// decides whether the send was accepted; "data" is read leniently afterwards.
type reply struct {
	// A pointer, so that a body with no status key (an empty object, null, a binding error of the
	// HTTP stack) is told from the documented status 0, "system error": a missing key decoded to 0
	// and was recorded as that status instead of the HTTP code (sms-r11-7).
	Status *int            `json:"status"`
	Data   json.RawMessage `json:"data"`
}

// dataFields reads what it can from "data". A field of an unexpected type is
// left empty, never an error: both are bookkeeping, not part of the verdict. The
// bounds and the alphabet are the Field type's, so there is nothing to check here.
func dataFields(raw json.RawMessage) (messageID, cost sms.Field) {
	var d struct {
		MessageID sms.Field  `json:"messageId"`
		Cost      sms.Number `json:"cost"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &d) != nil {
		return sms.Field{}, sms.Field{}
	}
	return d.MessageID, d.Cost.Field
}

// Mobile turns +989XXXXXXXXX into 09XXXXXXXXX, the form the driver sends. The
// provider page's example reads "919xxxx904"; the sandbox settles which one it
// wants (9.2), and this is the one place to change.
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
	// An id sms.ir cannot hold is refused here, before any call: its binding answers 400 for
	// it, and a 400 counts toward the breaker, so one mistyped mapping would take the gateway
	// down (sms-r9-2). The same function guards the admin PUT.
	id, ok := ParseTemplateID(t.ID)
	if !ok {
		return fail(sms.Config, sms.CodeTemplateID)
	}
	body := verifyBody{Mobile: mobile, TemplateID: id, Parameters: make([]parameter, 0, len(t.ParamNames))}
	for _, name := range t.ParamNames {
		v, ok := m.Values[name]
		if !ok {
			return fail(sms.Config, sms.CodeParamMissing)
		}
		if len([]rune(v.Reveal())) > maxValue {
			return fail(sms.Config, sms.CodeValueTooLong)
		}
		body.Parameters = append(body.Parameters, parameter{Name: name, Value: v.Reveal()})
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return fail(sms.Config, sms.CodeEncode)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.base+"/send/verify", bytes.NewReader(raw))
	if err != nil {
		return fail(sms.Config, sms.CodeRequest)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-API-KEY", d.key.Reveal())

	resp, err := smshttp.Do(d.client, req)
	if err != nil {
		return sms.Result{}, d.transportError(ctx, err)
	}
	rep, parsed := parse(resp.Body)

	switch {
	case resp.Status == http.StatusUnauthorized:
		return fail(sms.Auth, sms.HTTPCode(resp.Status))
	case resp.Status == http.StatusTooManyRequests || resp.Status >= 500:
		return fail(sms.Transient, sms.HTTPCode(resp.Status))
	case resp.Status >= 300 && resp.Status < 400:
		return fail(sms.Config, sms.CodeRedirect)
	}
	if !parsed {
		if resp.Status == http.StatusOK {
			return fail(sms.Transient, sms.CodeBadReply)
		}
		return fail(sms.Config, sms.HTTPCode(resp.Status))
	}
	if resp.Status == http.StatusOK && *rep.Status == 1 {
		res := sms.Result{}
		res.ProviderID, res.CostRaw = dataFields(rep.Data)
		return res, nil
	}
	if c, known := classify(*rep.Status); known {
		return fail(c, sms.StatusNumber(*rep.Status))
	}
	// A status the table does not name is one fixed word. The number a provider (or a
	// proxy in the path) sends could be the recipient's number or the code, and the
	// result reaches the log, sms_deliveries, the gateway row and the alerts, so it is
	// never part of the code (rule closed-values-in-logs).
	return fail(sms.Config, sms.CodeUnknown)
}

func parse(body []byte) (reply, bool) {
	var r reply
	if err := json.Unmarshal(body, &r); err != nil || r.Status == nil {
		return reply{}, false
	}
	return r, true
}

// transportError maps the fixed errors of smshttp to classes. A cancelled
// context is returned as it is, so the router knows the caller gave up.
func (d *driver) transportError(ctx context.Context, err error) error {
	if ctx.Err() != nil && !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, smshttp.ErrTimeout) {
		return sms.NewError(Provider, sms.Transient, sms.CodeTimeout)
	}
	return sms.NewError(Provider, sms.Transient, sms.CodeNetwork)
}

// Balance reads GET /credit. The "data" field is a number (the credit).
func (d *driver) Balance(ctx context.Context) (sms.Field, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.base+"/credit", nil)
	if err != nil {
		return sms.Field{}, sms.NewError(Provider, sms.Config, sms.CodeRequest)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-API-KEY", d.key.Reveal())
	resp, err := smshttp.Do(d.client, req)
	if err != nil {
		return sms.Field{}, d.transportError(ctx, err)
	}
	if resp.Status == http.StatusUnauthorized {
		return sms.Field{}, sms.NewError(Provider, sms.Auth, sms.HTTPCode(resp.Status))
	}
	if resp.Status != http.StatusOK {
		return sms.Field{}, sms.NewError(Provider, sms.Transient, sms.HTTPCode(resp.Status))
	}
	var r struct {
		Status *int      `json:"status"`
		Data   sms.Field `json:"data"`
	}
	if err := json.Unmarshal(resp.Body, &r); err != nil || r.Status == nil || *r.Status != 1 {
		if err == nil && r.Status != nil {
			if c, known := classify(*r.Status); known {
				return sms.Field{}, sms.NewError(Provider, c, sms.StatusNumber(*r.Status))
			}
		}
		return sms.Field{}, sms.NewError(Provider, sms.Transient, sms.CodeBadReply)
	}
	// Only a plain non-negative number is a balance, and sms.ParseCredit is the one judge of
	// that for every driver (sms-r10-7): the Field alphabet takes letters, a sign and an
	// exponent, so "Error", "-5" or "1e9" in "data" were shown as the credit.
	credit, ok := sms.ParseCredit(r.Data.String())
	if !ok {
		return sms.Field{}, sms.NewError(Provider, sms.Transient, sms.CodeBadReply)
	}
	return credit, nil
}
