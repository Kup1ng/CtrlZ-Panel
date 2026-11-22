package adminapi

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"math/big"
	"regexp"
	"slices"
	"strings"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/Kup1ng/CtrlZ-Panel/internal/adminapi/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/adminnotice"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/otp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/phone"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/noop"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/senders"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The providers a route may name. The list is closed: it is the check constraint
// of sms_gateways.provider.
func validProvider(p string) bool {
	return p == "sms_ir" || p == "melipayamak" || p == noop.Provider
}

// providerAllowed refuses what a route must not touch: an unknown provider, and
// the noop gateway outside dev and test, so a production deployment cannot route
// OTPs into a file (9.8, 15.2).
func (s *Server) providerAllowed(p string) *httpx.Error {
	if !validProvider(p) {
		return errValidation("provider", "unknown")
	}
	if p == noop.Provider && !noop.Allowed(s.d.Env) {
		return errValidation("provider", "not_allowed")
	}
	return nil
}

// moneyRE is a Rial amount as text: up to ten digits and four decimals, which is
// what numeric(14, 4) holds. It is text all the way to the column, so no float
// rounds a price.
var moneyRE = regexp.MustCompile(`^[0-9]{1,10}(\.[0-9]{1,4})?$`)

func gatewayRow(r store.SMSGatewayRow) gen.SmsGatewayRow {
	// noop has no credentials to be configured with: its row existing is enough.
	out := gen.SmsGatewayRow{
		Provider: gen.SmsProvider(r.Provider), Role: gen.SmsGatewayRowRole(r.Role), Configured: r.Configured || r.Provider == noop.Provider,
		PendingConfirmation: ptr(r.Pending),
		CostPerMessage:      r.CostPerMessage, LastOkAt: timePtr(r.LastOKAt), LastErrorAt: timePtr(r.LastErrorAt),
		BreakerOpenUntil: timePtr(r.BreakerOpenUntil),
	}
	if r.Hint != "" {
		out.Hint = ptr(r.Hint)
	}
	if r.LastErrorCode != "" {
		out.LastErrorCode = ptr(r.LastErrorCode)
	}
	return out
}

// gatewayList is the answer of the gateway routes: one row per real provider,
// with an unconfigured placeholder for a provider that has no row yet, so the
// page always shows both, and any noop row there is.
func gatewayList(rows []store.SMSGatewayRow) gen.SmsGatewayList {
	out := gen.SmsGatewayList{Items: []gen.SmsGatewayRow{}}
	have := map[string]bool{}
	for _, r := range rows {
		have[r.Provider] = true
		out.Items = append(out.Items, gatewayRow(r))
	}
	for _, p := range []string{"sms_ir", "melipayamak"} {
		if !have[p] {
			out.Items = append(out.Items, gen.SmsGatewayRow{Provider: gen.SmsProvider(p), Role: "disabled"})
		}
	}
	slices.SortFunc(out.Items, func(a, b gen.SmsGatewayRow) int { return strings.Compare(string(a.Provider), string(b.Provider)) })
	return out
}

func (s *Server) gateways(g store.GlobalTx) (gen.SmsGatewayList, error) {
	rows, err := g.SMSGateways()
	if err != nil {
		return gen.SmsGatewayList{}, err
	}
	return gatewayList(rows), nil
}

// ListSmsGateways is GET /sms/gateways. A row never holds credentials.
func (s *Server) ListSmsGateways(ctx context.Context, _ gen.ListSmsGatewaysRequestObject) (gen.ListSmsGatewaysResponseObject, error) {
	var out gen.SmsGatewayList
	err := s.readGlobal(ctx, func(g store.GlobalTx) (err error) {
		out, err = s.gateways(g)
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.ListSmsGateways200JSONResponse(out), nil
}

// PutSmsGateway is PUT /sms/gateways/{provider} (spec 15.2). Credentials are
// checked for shape, sealed under sms_cred at once, and never returned; the id
// of the row is in the AAD, so it is made before the insert. They are saved as
// PENDING and carry nothing until the owner runs `ctrlz-admin sms confirm` on
// the server (admin-r18-1, D64 sms-gateway-takeover, spec 10.8): a session that
// was taken, with one fresh code, can no longer point every tenant's codes at a
// provider account of its own.
func (s *Server) PutSmsGateway(ctx context.Context, req gen.PutSmsGatewayRequestObject) (gen.PutSmsGatewayResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	prov := string(req.Provider)
	if e := s.providerAllowed(prov); e != nil {
		return nil, e
	}
	b := *req.Body
	var fields []audit.Field
	var raw []byte
	var hint string
	if b.Credentials != nil {
		if raw, err = json.Marshal(*b.Credentials); err != nil {
			return nil, errValidation("credentials", "invalid")
		}
		defer clear(raw)
		if hint, err = senders.CheckCredentials(prov, raw); err != nil {
			// The error text is fixed and holds no part of the input.
			return nil, errValidation("credentials", "invalid")
		}
		fields = append(fields, audit.FieldCredentials)
	}
	var cost *string
	if b.CostPerMessage != nil {
		c := strings.TrimSpace(*b.CostPerMessage)
		if c != "" && !moneyRE.MatchString(c) {
			return nil, errValidation("cost_per_message", "invalid")
		}
		if c != "" {
			cost = &c
		}
		fields = append(fields, audit.FieldCostPerMessage)
	}
	if len(fields) == 0 {
		return nil, errValidation("body", "empty")
	}
	var row gen.SmsGatewayRow
	err = s.global(ctx, func(g store.GlobalTx) error {
		// The admin rows come first, then the gateway, and the audit lock last: the one
		// lock order of internal/lockrank (users and admin_users, then the settings
		// rows, then the audit chain). The other ways round are ABBA cycles with a login
		// in flight (review round 3, admin-r3-3) or with another writer of the gateway.
		if b.Credentials != nil {
			if err := s.noticeGatewayChange(g); err != nil {
				return err
			}
		}
		candidate, err := uuid.NewV7()
		if err != nil {
			return err
		}
		id, err := g.SMSGatewayEnsure(candidate, prov)
		if err != nil {
			return err
		}
		if b.Credentials != nil {
			ct, err := sms.SealCredentials(s.d.Keys, id, prov, secret.NewBytes(raw))
			if err != nil {
				return err
			}
			staged, err := g.SMSGatewayStageCredentials(id, ct, hint)
			if err != nil {
				return err
			}
			if !staged {
				// A pair already waits for the console (db-r19-2). Replacing it would let a later PUT
				// (a thief's) take the place of the one the owner is about to confirm by a hint the
				// stager chooses. Returning rolls the whole PUT back, the banner included: nothing changed.
				return errValidation("credentials", "pending_exists")
			}
		}
		if b.CostPerMessage != nil {
			if _, err := g.SMSGatewaySetCost(id, cost); err != nil {
				return err
			}
			// A price removed under a money cap would leave the cap inert (sms-r5-6).
			// Only a removal is checked: giving a price never widens the gap.
			if cost == nil || isZeroMoney(*cost) {
				if err := requirePriceUnderCap(g, "cost_per_message"); err != nil {
					return err
				}
			}
		}
		if _, err := audit.Admin(g, s.now(), p.AdminID, httpx.ClientIPFrom(g.Context()), audit.SMSGatewayChange{Gateway: id, Fields: fields}); err != nil {
			return err
		}
		list, err := s.gateways(g)
		if err != nil {
			return err
		}
		for _, r := range list.Items {
			if string(r.Provider) == prov {
				row = r
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return gen.PutSmsGateway200JSONResponse(row), nil
}

// notConfiguredCode names why a role could not be given: unconfirmed credentials, or none at all.
func (s *Server) notConfiguredCode(g store.GlobalTx, role, primary, fallback string) string {
	provider := primary
	if role == "fallback" {
		provider = fallback
	}
	if pending, err := g.SMSPendingGateways(); err == nil {
		for _, p := range pending {
			if p.Provider == provider {
				return "pending_confirmation"
			}
		}
	}
	return "not_configured"
}

// PutSmsRouting is PUT /sms/routing. sms_gateways_role_uq cannot be deferred, so
// the store clears the named roles first and assigns after (15.2).
func (s *Server) PutSmsRouting(ctx context.Context, req gen.PutSmsRoutingRequestObject) (gen.PutSmsRoutingResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	primary, fallback := string(deref(req.Body.Primary)), string(deref(req.Body.Fallback))
	if primary == "" && fallback == "" {
		return nil, errValidation("body", "empty")
	}
	if primary != "" && primary == fallback {
		return nil, errValidation("fallback", "same_as_primary")
	}
	for field, v := range map[string]string{"primary": primary, "fallback": fallback} {
		if v == "" {
			continue
		}
		if e := s.providerAllowed(v); e != nil {
			return nil, errValidation(field, e.Fields[0].Code)
		}
	}
	var out gen.SmsGatewayList
	err = s.global(ctx, func(g store.GlobalTx) error {
		// Admin rows first (see PutSmsGateway). If the change below is refused, the
		// transaction rolls back and the banner with it.
		if err := s.noticeGatewayChange(g); err != nil {
			return err
		}
		// The noop gateway (dev and test only, checked above) has no credentials, so
		// it has no other way to get a row: routing to it creates the row.
		for _, v := range []string{primary, fallback} {
			if v == noop.Provider {
				candidate, err := uuid.NewV7()
				if err != nil {
					return err
				}
				if _, err := g.SMSGatewayEnsure(candidate, v); err != nil {
					return err
				}
			}
		}
		failed, err := g.SMSRoutingSetNamed(primary, fallback)
		if err != nil {
			return err
		}
		if failed != "" {
			// A named gateway that does not exist or holds no credentials. The
			// transaction rolls back, so the clear step is undone. The field is the
			// role of the gateway that failed, not always the primary.
			// Credentials that wait for the console are not credentials: the same refusal,
			// with a code that says what to do (the routing never reaches an unconfirmed
			// gateway, admin-r18-1).
			return errValidation(failed, s.notConfiguredCode(g, failed, primary, fallback))
		}
		// A newly routed gateway without a price would make a set money cap inert.
		if err := requirePriceUnderCap(g, "primary"); err != nil {
			return err
		}
		var fields []audit.Field
		anchor := uuid.Nil
		if primary != "" {
			fields = append(fields, audit.FieldPrimary)
		}
		if fallback != "" {
			fields = append(fields, audit.FieldFallback)
		}
		for _, v := range []string{primary, fallback} {
			if v == "" {
				continue
			}
			if id, _, found, err := g.SMSGatewayByProvider(v); err != nil {
				return err
			} else if found && anchor == uuid.Nil {
				anchor = id
			}
		}
		if _, err := audit.Admin(g, s.now(), p.AdminID, httpx.ClientIPFrom(g.Context()), audit.SMSRoutingChange{Gateway: anchor, Fields: fields}); err != nil {
			return err
		}
		out, err = s.gateways(g)
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.PutSmsRouting200JSONResponse(out), nil
}

// testCode is the value a test message carries: a random six digits. A test send
// proves the gateway works; the number means nothing.
func testCode() (secret.String, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return secret.String{}, errors.New("adminapi: no randomness")
	}
	s := n.String()
	return secret.New(strings.Repeat("0", 6-len(s)) + s), nil
}

// TestSmsGateway is POST /sms/gateways/{provider}/test (spec 15.2). It goes
// through sms_outbox, since admin has no route out, and pins the message to this
// gateway so it neither falls back nor follows the roles.
func (s *Server) TestSmsGateway(ctx context.Context, req gen.TestSmsGatewayRequestObject) (gen.TestSmsGatewayResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	prov := string(req.Provider)
	if e := s.providerAllowed(prov); e != nil {
		return nil, e
	}
	e164, err := phone.Normalize(req.Body.Phone)
	if err != nil {
		return nil, errInvalidPhone()
	}
	if !sms.ValidTemplate(req.Body.Template) {
		return nil, errValidation("template", "unknown")
	}
	locale := string(deref(req.Body.Locale))
	if locale == "" {
		locale = "fa"
	}
	if !sms.ValidLocale(locale) {
		return nil, errValidation("locale", "invalid")
	}
	// A template with no placeholder (account_exists) takes no value: the router
	// refuses one as a bad request, and the row would end as bad_payload with an
	// alert whatever the gateway's state. The empty value is what the worker opens.
	var value secret.String
	if want, _ := sms.PlaceholderCount(req.Body.Template); want > 0 {
		if value, err = testCode(); err != nil {
			return nil, err
		}
	}
	var outbox uuid.UUID
	err = s.global(ctx, func(g store.GlobalTx) error {
		gw, configured, found, err := g.SMSGatewayByProvider(prov)
		if err != nil {
			return err
		}
		if !found {
			return httpx.NotFound()
		}
		if !configured && prov != noop.Provider {
			return errValidation("provider", "not_configured")
		}
		if outbox, err = uuid.NewV7(); err != nil {
			return err
		}
		ct, err := sms.SealOutbox(s.d.Keys, outbox, e164, value)
		if err != nil {
			return err
		}
		if err := g.SMSOutboxInsert(store.NewOutbox{
			ID: outbox, Kind: "test", GatewayID: gw, Phone: e164, TemplateKey: req.Body.Template, Locale: locale, ParamsCT: ct, CreatedBy: p.AdminID,
		}); err != nil {
			return err
		}
		_, err = audit.Admin(g, s.now(), p.AdminID, httpx.ClientIPFrom(g.Context()), audit.SMSTestSend{Gateway: gw, Fields: []audit.Field{audit.FieldTemplate}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.TestSmsGateway202JSONResponse{OutboxId: openapi_types.UUID(outbox)}, nil
}

// GetSmsOutbox is GET /sms/outbox/{id}: the state, never the phone or the text.
func (s *Server) GetSmsOutbox(ctx context.Context, req gen.GetSmsOutboxRequestObject) (gen.GetSmsOutboxResponseObject, error) {
	var st store.SMSOutboxStatus
	err := s.readGlobal(ctx, func(g store.GlobalTx) error {
		v, ok, err := g.SMSOutboxStatus(req.Id)
		if err != nil {
			return err
		}
		if !ok {
			return httpx.NotFound()
		}
		st = v
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := gen.SmsOutboxStatus{State: gen.SmsOutboxStatusState(st.State)}
	if st.LastError != "" {
		out.LastError = ptr(st.LastError)
	}
	return gen.GetSmsOutbox200JSONResponse(out), nil
}

// templateRows joins the texts with the provider mappings.
func templateRows(g store.GlobalTx) ([]gen.SmsTemplateRow, error) {
	ts, err := g.SMSTemplates()
	if err != nil {
		return nil, err
	}
	ms, err := g.SMSProviderTemplates()
	if err != nil {
		return nil, err
	}
	out := make([]gen.SmsTemplateRow, 0, len(ts))
	for _, t := range ts {
		row := gen.SmsTemplateRow{Key: t.Key, Locale: t.Locale, Body: t.Body, Mappings: []gen.SmsTemplateMapping{}}
		for _, m := range ms {
			if m.Key == t.Key && m.Locale == t.Locale {
				names := m.ParamNames
				if names == nil {
					names = []string{}
				}
				row.Mappings = append(row.Mappings, gen.SmsTemplateMapping{Provider: m.Provider, ProviderTemplateId: m.ProviderTemplateID, ParamNames: names})
			}
		}
		out = append(out, row)
	}
	return out, nil
}

func findTemplate(rows []gen.SmsTemplateRow, key, locale string) (gen.SmsTemplateRow, bool) {
	for _, r := range rows {
		if r.Key == key && r.Locale == locale {
			return r, true
		}
	}
	return gen.SmsTemplateRow{}, false
}

// ListSmsTemplates is GET /sms/templates.
func (s *Server) ListSmsTemplates(ctx context.Context, _ gen.ListSmsTemplatesRequestObject) (gen.ListSmsTemplatesResponseObject, error) {
	var rows []gen.SmsTemplateRow
	err := s.readGlobal(ctx, func(g store.GlobalTx) (err error) {
		rows, err = templateRows(g)
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.ListSmsTemplates200JSONResponse(gen.SmsTemplateList{Items: rows}), nil
}

// PutSmsTemplate is PUT /sms/templates/{key}/{locale}. It changes the text we
// ask the provider to approve, and so the text of every code sent on the official
// sender line: with a copied cookie and no authenticator a thief could write
// "read this code to the caller" there, so it needs a fresh code like the rest of
// the SMS page (admin-r18-3).
func (s *Server) PutSmsTemplate(ctx context.Context, req gen.PutSmsTemplateRequestObject) (gen.PutSmsTemplateResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	key, locale := req.Key, string(req.Locale)
	if !sms.ValidTemplate(key) || !sms.ValidLocale(locale) {
		return nil, httpx.NotFound()
	}
	if err := sms.CheckBody(key, req.Body.Body); err != nil {
		return nil, errValidation("body", "invalid")
	}
	// The one-part bound of owner decision D58 holds for what is stored, not only for the seeds: the
	// price entered for an OTP message covers one billed part (sms-r13-3).
	if err := sms.CheckBodyLength(key, locale, req.Body.Body, otp.CodeLength); err != nil {
		return nil, errValidation("body", "too_long")
	}
	var row gen.SmsTemplateRow
	err = s.global(ctx, func(g store.GlobalTx) error {
		ok, err := g.SMSTemplateSet(key, locale, req.Body.Body)
		if err != nil {
			return err
		}
		if !ok {
			return httpx.NotFound()
		}
		if _, err := audit.Admin(g, s.now(), p.AdminID, httpx.ClientIPFrom(g.Context()), audit.SMSTemplateChange{Fields: []audit.Field{audit.FieldBody}, Key: sms.ParseTemplate(key), Locale: localeOf(locale)}); err != nil {
			return err
		}
		rows, err := templateRows(g)
		if err != nil {
			return err
		}
		row, _ = findTemplate(rows, key, locale)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return gen.PutSmsTemplate200JSONResponse(row), nil
}

// PutSmsProviderTemplate is PUT /sms/gateways/{provider}/templates/{key}/
// {locale}. The number of parameter names must equal the template's
// placeholders, or the gateway would answer Config param_count at send time.
func (s *Server) PutSmsProviderTemplate(ctx context.Context, req gen.PutSmsProviderTemplateRequestObject) (gen.PutSmsProviderTemplateResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	prov := string(req.Provider)
	if e := s.providerAllowed(prov); e != nil {
		return nil, e
	}
	key, locale := req.Key, string(req.Locale)
	if !sms.ValidTemplate(key) || !sms.ValidLocale(locale) {
		return nil, httpx.NotFound()
	}
	b := *req.Body
	// The document bounds both: the id is 1 to 18 digits and a parameter name is 1 to
	// 64 characters of letters, digits and "_.-" (rule boundary-input), so nothing
	// here can be blank or padded, and the drivers look the value up by the stored
	// name as it is (sms-r4-2).
	id := b.ProviderTemplateId
	// The document allows 18 digits for every provider; what one provider's driver can send is
	// narrower (sms.ir types the id as an int32), and an id it would refuse at send time is
	// refused here, so a typo cannot reach the wire and count against the breaker (sms-r9-2).
	if !senders.ValidTemplateID(prov, id) {
		return nil, errValidation("provider_template_id", "invalid")
	}
	want, _ := sms.PlaceholderCount(key)
	if len(b.ParamNames) != want {
		return nil, errValidation("param_names", "count")
	}
	paramNames := b.ParamNames
	var row gen.SmsTemplateRow
	err = s.global(ctx, func(g store.GlobalTx) error {
		candidate, err := uuid.NewV7()
		if err != nil {
			return err
		}
		gw, err := g.SMSGatewayEnsure(candidate, prov)
		if err != nil {
			return err
		}
		if err := g.SMSProviderTemplateSet(gw, key, locale, id, paramNames); err != nil {
			return err
		}
		if _, err := audit.Admin(g, s.now(), p.AdminID, httpx.ClientIPFrom(g.Context()), audit.SMSTemplateChange{
			Gateway: gw, Fields: []audit.Field{audit.FieldProviderTemplate}, Key: sms.ParseTemplate(key), Locale: localeOf(locale),
		}); err != nil {
			return err
		}
		rows, err := templateRows(g)
		if err != nil {
			return err
		}
		row, _ = findTemplate(rows, key, locale)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return gen.PutSmsProviderTemplate200JSONResponse(row), nil
}

func limitsOf(l store.SMSLimits) gen.SmsLimits {
	return gen.SmsLimits{
		OtpCapPhone: l.CapPhone, OtpCapPhoneNet: l.CapPhoneNet, OtpCapIp: l.CapIP, OtpCapNet24: l.CapNet24,
		OtpCapPhoneTrusted: l.CapPhoneTrusted, OtpCapNet48: l.CapNet48, OtpCapGlobal: l.CapGlobal,
		OtpCooldownS: l.CooldownSeconds, OtpSoftPct: l.SoftPercent, SmsCostCapDaily: l.CostCapDaily, SmsOutboxCapDaily: l.OutboxCapDaily,
	}
}

// GetSmsLimits is GET /sms/limits.
func (s *Server) GetSmsLimits(ctx context.Context, _ gen.GetSmsLimitsRequestObject) (gen.GetSmsLimitsResponseObject, error) {
	var l store.SMSLimits
	err := s.readGlobal(ctx, func(g store.GlobalTx) (err error) {
		l, err = g.SMSLimitsGet()
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.GetSmsLimits200JSONResponse(limitsOf(l)), nil
}

// PutSmsLimits is PUT /sms/limits. The table's CHECKs refuse values out of
// range; the audit row names the fields that changed, never their values.
func (s *Server) PutSmsLimits(ctx context.Context, req gen.PutSmsLimitsRequestObject) (gen.PutSmsLimitsResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	b := *req.Body
	var cost *string
	if b.SmsCostCapDaily != nil && strings.TrimSpace(*b.SmsCostCapDaily) != "" {
		c := strings.TrimSpace(*b.SmsCostCapDaily)
		if !moneyRE.MatchString(c) {
			return nil, errValidation("sms_cost_cap_daily", "invalid")
		}
		cost = &c
	}
	next := store.SMSLimits{
		CapPhone: b.OtpCapPhone, CapPhoneNet: b.OtpCapPhoneNet, CapIP: b.OtpCapIp, CapNet24: b.OtpCapNet24,
		CapPhoneTrusted: b.OtpCapPhoneTrusted, CapNet48: b.OtpCapNet48, CapGlobal: b.OtpCapGlobal,
		CooldownSeconds: b.OtpCooldownS, SoftPercent: b.OtpSoftPct, CostCapDaily: cost, OutboxCapDaily: b.SmsOutboxCapDaily,
	}
	var out store.SMSLimits
	err = s.d.Store.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		// The old values come under the settings row lock: the audit row names the fields that
		// changed, and a read with no lock is the state before another admin's commit (admin-r11-1).
		cur, err := g.SMSLimitsLock()
		if err != nil {
			return err
		}
		s.d.afterLimitsRead()
		if err := g.SMSLimitsSet(next); err != nil {
			return err
		}
		// A cap on money needs a price on every route, or it never refuses anything
		// (sms-r5-6).
		if next.CostCapDaily != nil {
			if err := requirePriceUnderCap(g, "sms_cost_cap_daily"); err != nil {
				return err
			}
		}
		out = next
		_, err = audit.Admin(g, s.now(), p.AdminID, httpx.ClientIPFrom(g.Context()), audit.SMSLimitsChange{Fields: changedLimits(cur, next)})
		return err
	})
	if errors.Is(err, store.ErrConstraint) {
		return nil, errValidation("limits", "out_of_range")
	}
	if err != nil {
		return nil, adminError(err)
	}
	return gen.PutSmsLimits200JSONResponse(limitsOf(out)), nil
}

// changedLimits names the fields whose value differs.
func changedLimits(a, b store.SMSLimits) []audit.Field {
	out := []audit.Field{}
	add := func(name audit.Field, differs bool) {
		if differs {
			out = append(out, name)
		}
	}
	add(audit.FieldOTPCapPhone, a.CapPhone != b.CapPhone)
	add(audit.FieldOTPCapPhoneNet, a.CapPhoneNet != b.CapPhoneNet)
	add(audit.FieldOTPCapIP, a.CapIP != b.CapIP)
	add(audit.FieldOTPCapNet24, a.CapNet24 != b.CapNet24)
	add(audit.FieldOTPCapPhoneTrusted, a.CapPhoneTrusted != b.CapPhoneTrusted)
	add(audit.FieldOTPCapNet48, a.CapNet48 != b.CapNet48)
	add(audit.FieldOTPCapGlobal, a.CapGlobal != b.CapGlobal)
	add(audit.FieldOTPCooldown, a.CooldownSeconds != b.CooldownSeconds)
	add(audit.FieldOTPSoftPct, a.SoftPercent != b.SoftPercent)
	add(audit.FieldSMSCostCapDaily, (a.CostCapDaily == nil) != (b.CostCapDaily == nil) || a.CostCapDaily != nil && b.CostCapDaily != nil && !sameMoney(*a.CostCapDaily, *b.CostCapDaily))
	add(audit.FieldSMSOutboxCapDaily, a.OutboxCapDaily != b.OutboxCapDaily)
	return out
}

// sameMoney compares two numeric texts: numeric(…) pads decimals, so "5000" and
// "5000.00" are the same amount.
func sameMoney(a, b string) bool {
	trim := func(s string) string {
		if strings.Contains(s, ".") {
			s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
		}
		return s
	}
	return trim(a) == trim(b)
}

// GetSmsStats is GET /sms/stats.
func (s *Server) GetSmsStats(ctx context.Context, req gen.GetSmsStatsRequestObject) (gen.GetSmsStatsResponseObject, error) {
	days := 7
	if req.Params.Days != nil {
		days = *req.Params.Days
	}
	if days < 1 || days > 90 {
		return nil, errValidation("days", "out_of_range")
	}
	out := gen.SmsStats{Days: []gen.SmsDay{}, Gateways: []gen.SmsGatewayStat{}}
	err := s.readGlobal(ctx, func(g store.GlobalTx) error {
		ds, gs, err := g.SMSStats(days)
		if err != nil {
			return err
		}
		for _, d := range ds {
			out.Days = append(out.Days, gen.SmsDay{Day: openapi_types.Date{Time: d.Day}, OtpCount: d.OTPCount, OutboxCount: d.OutboxCount, Cost: d.Cost})
		}
		for _, x := range gs {
			out.Gateways = append(out.Gateways, gen.SmsGatewayStat{Provider: x.Provider, Accepted: x.Accepted, Failed: x.Failed})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return gen.GetSmsStats200JSONResponse(out), nil
}

// noticeGatewayChange puts the banner of 10.7 on every admin. Credentials and
// routing decide whose account receives every login, reset and phone-change code,
// and a provider's dashboard lists them with their text. A session with one fresh
// code can make the change, so the owner must be told in the product and not only
// find it in the audit log. It runs in the transaction of the change: if the
// banner cannot be written the change is not made.
func (s *Server) noticeGatewayChange(g store.GlobalTx) error {
	_, err := g.AdminNoticeAppendAll(adminnotice.Notice{Kind: adminnotice.SMSGatewayChanged, At: s.now()})
	return err
}

// localeOf is a locale the route has already checked, as the closed type the audit
// row carries.
func localeOf(s string) sms.Locale {
	l, _ := sms.ParseLocale(s)
	return l
}

// requirePriceUnderCap refuses a state in which the daily money cap is set and a gateway
// the router can choose has no price. The worker adds a gateway's configured price to the
// day's cost when it accepts a message, and adds nothing when there is none, so with an
// unpriced route the cost stays 0 and no message is ever refused for money: the cap
// would look armed and be inert (sms-r5-6). It runs in the transaction of every write
// that can open that gap (the cap, a gateway's price, the routing), after the write, so
// a refusal rolls it back; field names the input to blame. A price of zero is no price.
//
// The three writers do not see each other's uncommitted change under Read Committed, so the
// check is the store's one statement behind the settings row lock (GlobalTx.SMSPriceMissingUnderCap),
// and a writer that arrives second waits for the first and reads its result (round 6, admin-r6-3;
// TestMoneyCapAndPriceWritersDoNotRace and the race driver cost.needs_price).
func requirePriceUnderCap(g store.GlobalTx, field string) error {
	missing, err := g.SMSPriceMissingUnderCap()
	if err != nil {
		return err
	}
	if missing {
		return errValidation(field, "price_required")
	}
	return nil
}

// isZeroMoney reports a numeric text that is zero ("0", "0.0000").
func isZeroMoney(s string) bool {
	return strings.Trim(s, "0.") == ""
}
