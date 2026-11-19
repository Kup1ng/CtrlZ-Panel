// Package classify is the one place that says what an SMS failure means (spec 9.1,
// 9.5, 9.7; P1 auth review round 5, rule sms-failure-classification).
//
// Before this package the breaker count, sms_available, numberRefused, the refund
// keys, the delivery outcome and the alert severity and key each looked at the error
// class in their own way, and every new failure mode (Auth, Credit, an unreadable
// key, a missing mapping, a blacklist, a skipped gateway) was classified case by case
// at each of them. Some left OTP offered while nothing could be sent. Now:
//
//   - One closed table (this file) maps every sms.Code to a Scope: what the failure
//     is about.
//   - Every decision that used to read a class is a pure function (decide.go) of the
//     scopes of the attempts and of the routing state (Skipped, Pinned, Local), and is
//     defined once.
//   - Nothing else reads a class. internal/lint TestSMSFailureClassIsReadOnlyInClassify
//     fails for any code outside this package that reads the Class of an sms.Error,
//     calls a method on an sms.Class, compares one or switches on one.
//
// A new failure mode is therefore one row in the table below, and the exhaustive test
// fails until that row exists.
package classify

import (
	"strings"

	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
)

// Scope is what a failure is about, and so what it may change.
type Scope int

// The scopes. The comment on each says what the decisions of decide.go do with it.
const (
	// Gateway: the whole gateway cannot send (a refused key, no credit, credentials that
	// do not open, none stored, a noop row in production, an unknown provider). It counts
	// toward the breaker, so that with every routed gateway so, sms_available turns off
	// (9.7). A critical alert names the gateway.
	Gateway Scope = iota + 1
	// Template: a mapping is missing or wrong, or the provider rejected the template (no
	// mapping, a parameter count that differs, a documented provider status about the template; an answer the driver tags Config but no status documents is Ambiguous, and a documented status about the account's line or plan is Gateway, see Of). It is about
	// one template, so it does not count toward the breaker and sms_available stays true:
	// counting it would switch off every other purpose (9.7). A warning names the
	// template, a critical one when no routed gateway can send it.
	Template
	// Message: this value or request could not be sent (a code too long for the
	// provider, a separator in it, a request the driver could not build). Handled as
	// Template is: no breaker, an alert keyed by template. It is its own scope because
	// the cause is the message, not the mapping, and an operator reads the two apart.
	Message
	// Number: the number itself was refused (Recipient, Blacklisted). No breaker, no
	// alert. When every gateway that was asked refuses it, the row ends and keeps its
	// caps (9.5).
	Number
	// Ambiguous: the provider may or may not have the message (a timeout, a network
	// error, a 5xx, a reply that could not be read). It counts toward the breaker, since
	// it says nothing is arriving, and the message is tried again. No alert of its own:
	// sms_down speaks for it.
	Ambiguous
)

// String is the word of a scope.
func (s Scope) String() string {
	switch s {
	case Gateway:
		return "gateway"
	case Template:
		return "template"
	case Message:
		return "message"
	case Number:
		return "number"
	case Ambiguous:
		return "ambiguous"
	}
	return "unknown"
}

// Name is the scope as a closed string, for a log attribute.
func (s Scope) Name() ScopeName { return ScopeName(s.String()) }

// ScopeName is a Scope as a closed string.
type ScopeName string

// Valid reports membership.
func (n ScopeName) Valid() bool {
	switch n {
	case "gateway", "template", "message", "number", "ambiguous", "unknown":
		return true
	}
	return false
}

// Of is the table: the scope of a code. class matters only for the codes that mean what
// the provider's status said (a provider status, an HTTP status, a redirect, a reply
// that could not be read, an answer the table of codes.go does not name): the same word
// is a refused key from one status and a refused template from another, and the class
// is how the driver told them apart. ok is false when the code is in no row, which
// ScopeOf answers closed and the exhaustive test refuses.
func Of(c sms.Code, class sms.Class) (s Scope, ok bool) {
	switch c {
	// The whole gateway is unusable. These are the reasons a gateway has no Sender
	// (internal/sms/senders, smssend.Source): nothing can go through it.
	case sms.CodeNoCredentials, sms.CodeBadCredentials, sms.CodeNoopInProduction,
		sms.CodeUnknownProvider, sms.CodeCredentialsUnreadable, sms.CodeUnusable:
		return Gateway, true

	// A mapping, or the provider's template, is the problem.
	case sms.CodeNoTemplate, sms.CodeParamCount, sms.CodeTemplateID, sms.CodeParamMissing:
		return Template, true

	// This message or request is the problem. cap, unreadable and bad_payload are the
	// reasons a queued message ended unsent; they are never an attempt's answer, but
	// they are about one message, and the table names every code.
	case sms.CodeBadMessage, sms.CodeValueTooLong, sms.CodeValueSeparator, sms.CodeRequest, sms.CodeEncode,
		sms.CodeCap, sms.CodeUnreadable, sms.CodeBadPayload:
		return Message, true

	// The number is refused.
	case sms.CodeNumberFormat:
		return Number, true

	// The network, or the router's own "nothing answered". ok is here because an Error
	// never carries it; if one ever does, the closed answer is the one that keeps the
	// breaker honest.
	case sms.CodeTimeout, sms.CodeNetwork, sms.CodeFile, sms.CodeNoGateway, sms.CodeDriverErr, sms.CodeOK:
		return Ambiguous, true

	// What the provider said decides, but only a status number the provider documents
	// can say "this template". An answer that is not a documented status (a redirect, an
	// HTTP status the driver has no row for such as a 404 after a path change or a 403 from
	// a firewall, a status number nobody listed, a reply that could not be read) is about
	// the gateway as a whole until proven otherwise: it counts toward the breaker, so
	// that a gateway answering such a thing to every send turns sms_available off instead
	// of leaving OTP offered while nothing arrives (sms-r5-4, rule
	// sms-failure-classification). The drivers still tag these Config; the decision is
	// here, once, for every driver.
	case sms.CodeUnknown, sms.CodeRedirect, sms.CodeBadReply:
		return byClass(class, false), true
	}
	if providerStatus(c) {
		if class == sms.Config && accountWide(c) {
			return Gateway, true
		}
		return byClass(class, documentedStatus(c)), true
	}
	return Ambiguous, false
}

// accountWide reports a documented status that describes the account's line or plan and
// not one template or message: sms.ir 101 (line invalid), 118 (the message count is over the
// allowed limit, read as the account's quota: Verify sends one message, so no count of the message
// itself can exceed it; sms-r11-8, to be confirmed by the first live reply, T-411), 119 (the plan
// must be upgraded) and 123 (the sending line is not active), Melipayamak -3 (line not defined) and -7
// (sender number error). Every template on that gateway fails the same way, so the scope
// is Gateway: it counts toward the breaker and sms_available turns false, where a Template
// scope would leave OTP offered while no code arrives (sms-r9-1, the class rule
// sms-failure-classification exists to close). The decision is here, once, for every
// driver, which keep tagging these Config; the drivers' tests fail for a Config status
// that has no stated scope, so a new status is decided the day it is added.
//
// The statuses are matched by number alone because the table does not know the provider;
// the two providers' status spaces do not overlap on these six (the other numbers a
// driver tags Config are template or message problems and stay Template).
func accountWide(c sms.Code) bool {
	switch c {
	case sms.StatusCode("101"), sms.StatusCode("118"), sms.StatusCode("119"), sms.StatusCode("123"),
		sms.StatusCode("-3"), sms.StatusCode("-7"):
		return true
	}
	return false
}

// providerStatus reports a code of the two families the drivers read from a provider: a
// documented numeric status and an HTTP status.
func providerStatus(c sms.Code) bool {
	if !c.Valid() {
		return false
	}
	s := string(c)
	return strings.HasPrefix(s, "http_") || s[0] == '-' || (s[0] >= '0' && s[0] <= '9')
}

// documentedStatus reports a code that is one of the provider's own status numbers, as
// against an HTTP status the driver passes on.
func documentedStatus(c sms.Code) bool {
	return !strings.HasPrefix(string(c), "http_")
}

// byClass is the scope of an answer whose meaning is the provider's: the driver's class
// says what it was about. documented says the answer is a status number the provider's
// page names; only then does Config mean a template, since anything else the driver
// could not place is not known to be about a template. An unknown class is Ambiguous,
// which counts toward the breaker and so can only make OTP be reported down, never
// offered for nothing.
func byClass(c sms.Class, documented bool) Scope {
	switch c {
	case sms.Auth, sms.Credit:
		return Gateway
	case sms.Config:
		if documented {
			return Template
		}
		return Ambiguous
	case sms.Recipient, sms.Blacklisted:
		return Number
	}
	return Ambiguous
}

// ScopeOf is the scope of a failure. A code in no row of the table is Ambiguous: it
// counts toward the breaker and never says "this is only one message", so a failure
// nobody classified cannot leave OTP offered while nothing is sent.
func ScopeOf(e *sms.Error) Scope {
	if e == nil {
		return Ambiguous
	}
	s, _ := Of(e.Code, e.Class)
	return s
}

// Routing is the sms.Policy of the router. It is the only implementation.
type Routing struct{}

// Final reports that no other gateway would change the answer: the provider says the
// number itself was refused as a recipient (spec 9.1). Blacklisted is a refusal by one
// route, and the next may carry it, so it is not final.
func (Routing) Final(e *sms.Error) bool { return e != nil && e.Class == sms.Recipient }

// Refused reports a refused login: an Auth answer that the provider's own page documents as one,
// which a retry with the same credentials only repeats. The router holds the gateway on it instead
// of probing it with user traffic, because a run of failed logins is what gets the panel address
// blocked (Melipayamak -108) and the block outlasts the wrong key (sms-r11-9). The decision is
// here, with the other readings of an answer.
//
// The hold has no timer, so it must rest on proof that the login was refused (sms-r12-5). A status
// number of the table is that proof. An HTTP status is not, with one exception: sms.ir documents
// 401 as its refused key (research sms-iran.md, 5.1), while Melipayamak documents no HTTP login
// status at all, and a 403 or 401 that comes from a provider's edge (a WAF, a rate limit, a CDN
// rule) says nothing about the credentials. Those stay Auth for the alert, which asks the
// operator to look, and count toward the breaker, which probes again after its pause and so
// recovers by itself; they do not hold the gateway out of service until a restart.
func (Routing) Refused(e *sms.Error) bool {
	if e == nil || e.Class != sms.Auth {
		return false
	}
	if documentedStatus(e.Code) {
		return providerStatus(e.Code)
	}
	return e.Provider == sms.ProviderSMSIR && e.Code == sms.HTTPCode(401)
}

var _ sms.Policy = Routing{}
