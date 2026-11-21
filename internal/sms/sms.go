// Package sms is the SMS layer of P1 (spec 9): the Sender interface a provider
// driver implements, the error classes the router acts on, the templates, the
// sealed payloads the api and admin leave for the worker, and the Router that
// tries the primary gateway and then the fallback.
//
// The package holds no database code and no HTTP code. The router is handed a
// snapshot of the gateways by whoever owns the store (internal/worker/smssend),
// and reports what happened as an Outcome that the worker writes to the
// database. That split keeps every send testable with fake senders, and keeps
// the one package that touches the network (the drivers) away from the one that
// touches Postgres.
//
// counterkeys.go mirrors the counters auth_otp_issue bumps, for the catalog test.
package sms

import (
	"context"
	"fmt"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// Message is what a provider sends. It has no rendered text: providers send an
// approved template with values (9.1). Values is keyed by the gateway's own
// parameter names (sms_provider_templates.param_names), so the router builds a
// Message per gateway.
type Message struct {
	To       string // E.164
	Template string // otp, otp_reset, otp_phone, invite, account_exists
	Locale   string // fa or en
	Values   map[string]secret.String
}

// ProviderTemplate is the mapping of one of our templates to the provider's
// approved copy on one gateway.
type ProviderTemplate struct {
	ID         string   // sms.ir templateId, Melipayamak bodyId
	ParamNames []string // names (sms.ir) or the order of variables (Melipayamak)
}

// Result is what a provider returned for an accepted message. Both members are
// Fields: bounded, in a closed alphabet, and empty when the reply held nothing
// usable (field.go).
type Result struct {
	ProviderID Field
	CostRaw    Field // as the provider reported it
}

// Sender is one provider driver.
type Sender interface {
	Provider() string // sms_ir, melipayamak, noop
	Send(ctx context.Context, m Message, t ProviderTemplate) (Result, error)
	Balance(ctx context.Context) (Field, error)
}

// Class says what the router does about a failure (9.1).
type Class int

// The classes of spec 9.1.
const (
	Transient   Class = iota + 1 // network, timeout, 5xx, 429: try the fallback, count toward the breaker
	Auth                         // the key or login was refused: fallback, alert
	Credit                       // the account is out of credit: fallback, alert
	Config                       // template, parameter or sender problem: fallback, alert
	Recipient                    // the number itself was refused: stop, no fallback
	Blacklisted                  // the number is on the telecom blacklist: fallback
)

func (c Class) String() string {
	switch c {
	case Transient:
		return "transient"
	case Auth:
		return "auth"
	case Credit:
		return "credit"
	case Config:
		return "config"
	case Recipient:
		return "recipient"
	case Blacklisted:
		return "blacklisted"
	}
	return "unknown"
}

// Error is a failed send. It formats as "sms: <provider> <code>" and nothing else: no URL, no
// number, no provider text, and NOT the class. Every part is a member of a closed set
// (ProviderName, Code), so there is nothing to scan: a driver can say only what the table of
// codes.go says, and a reply it did not expect is CodeUnknown (review round 5, rule
// closed-values-in-logs).
//
// The class is left out on purpose (sms-r16-19). The class of a failure is read only in
// internal/sms/classify, and a lint cannot follow a string: text taken from err.Error() can be put
// in a variable, switched on, or formatted through an interface and compared with a literal. With
// no class in the text there is nothing in it to read, so the whole class of such decisions is
// closed by construction and the lint no longer matches the call shapes. TestAnErrorTextCarriesNoClass
// keeps it so.
type Error struct {
	Provider ProviderName
	Code     Code
	class    Class
}

// NewError builds an Error. A provider or a code off its list becomes the fixed
// unknown member, so a value that bypassed the lint still cannot reach a log.
func NewError(provider ProviderName, class Class, code Code) *Error {
	if !provider.Valid() {
		provider = ProviderOther
	}
	if !code.Valid() {
		code = CodeUnknown
	}
	return &Error{Provider: provider, class: class, Code: code}
}

// Class is the class of the failure. It is a METHOD over an unexported field on purpose (sms-r17-8):
// with an exported field, encoding/json and encoding/xml printed it and a template read it by reflection,
// and the lint of rule sms-failure-classification judges the selectors and the flows of Go code, which
// none of those are. Outside internal/sms/classify the lint refuses a call of this method (it is not in
// smsClassMethods), and no encoder sees an unexported field.
func (e *Error) Class() Class { return e.class }

func (e *Error) Error() string {
	return "sms: " + string(e.Provider) + " " + string(e.Code)
}

// Format prints the Error as its text for every verb, so no verb (%+v, %#v, %d) prints the struct
// and with it the class (sms-r16-19). Without it, fmt would print the fields of an *Error for the
// verbs that are not valid for a string.
func (e *Error) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte(e.Error())) }

// Status is the text kept in the status columns that name a failure
// (sms_gateways.last_error_code, sms_outbox.last_error): the class and the code,
// both from closed sets.
func (e *Error) Status() Status { return Status{class: e.class, code: e.Code} }

// Status is a closed value for a status column: "class:code", or a bare Code (a
// reason an outbox row ended without a send). It implements closed.Text.
type Status struct {
	class Class
	code  Code
}

// StatusOf is a bare code as a Status.
func StatusOf(c Code) Status { return Status{code: c} }

// String is "class:code" or the bare code.
func (s Status) String() string {
	if s.class == 0 {
		return string(s.code)
	}
	return s.class.String() + ":" + string(s.code)
}

// Valid reports that the code is on its list and the class, when present, is one of
// the six.
func (s Status) Valid() bool {
	if s.class != 0 && (s.class < Transient || s.class > Blacklisted) {
		return false
	}
	return s.code.Valid()
}

// MarshalText makes a Class travel as its name wherever it is encoded.
func (c Class) MarshalText() ([]byte, error) { return []byte(c.String()), nil }
