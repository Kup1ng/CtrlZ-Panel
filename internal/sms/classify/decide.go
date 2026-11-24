package classify

import (
	"github.com/Kup1ng/CtrlZ-Panel/internal/closed"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
)

// Everything below is a pure function of the scopes of the attempts of one send
// (sms.Outcome) and of the routing state the Outcome records: Local (no network call
// was made), Skipped (a routed gateway passed over behind an open breaker) and Pinned (a
// test send for one gateway). Nothing here reads a database or a clock, and nothing
// outside this package decides any of it (rule sms-failure-classification).
//
// The truth table these functions implement is spec 9.7. TestTruthTable states it once
// per scope, and TestMatrix runs it over every scope, one or two routed gateways, and a
// breaker that is closed or already open.

// CountsTowardBreaker says whether one attempt counts as a failure of its gateway for
// the breaker (9.1): the failure says the gateway as a whole cannot deliver, whether
// because it said so (Gateway) or because nothing it was given arrived (Ambiguous).
// A failure about one template, one message or one number does not count, because a
// breaker is per gateway and counting it would switch off every other purpose.
//
// This is what makes the router's own availability false when it should be (the public
// sms_available no longer reads a breaker, round 18, sms-r18-2): with every routed gateway
// counted, three failures each open both breakers. An attempt that returns false here
// can never turn it off.
func CountsTowardBreaker(a sms.Attempt) bool {
	if a.Err == nil {
		return false
	}
	switch ScopeOf(a.Err) {
	case Gateway, Ambiguous:
		return true
	}
	return false
}

// NumberRefused says the number itself was refused and no retry would change that, so
// the row ends at once and its caps stay spent (9.5, sms-r2-9). That is the case when a
// gateway answered a final refusal (Routing.Final), or when every attempt that reached
// a provider answered Number scope and every routed gateway was really asked.
//
// "Asked" is the point (sms-r3-1): a routed gateway that was skipped behind an open
// breaker, or that could not be used at all (Gateway scope, local), was not asked, and
// the number may be one that only that route reaches. A missing template or a value that
// does not fit it on the other gateway (Template or Message scope, local) does not undo
// the first answer, since no retry changes it. A provider answer of any other scope
// (a timeout, a refused key, a rejected template) means that gateway did not give a
// verdict on the number.
func NumberRefused(out sms.Outcome) bool {
	if l := out.Last(); l != nil && (Routing{}).Final(l) {
		return true
	}
	if out.Skipped > 0 {
		return false
	}
	asked := 0
	for _, a := range out.Attempts {
		s := ScopeOf(a.Err)
		if a.Local {
			if s == Template || s == Message {
				continue
			}
			return false
		}
		if a.Err == nil || s != Number {
			return false
		}
		asked++
	}
	return asked > 0
}

// DeliveryOutcome is the outcome word of a failed attempt that reached a provider, for
// sms_deliveries: "unreachable" when nothing is known to have arrived (Ambiguous), and
// "rejected" when the provider answered.
func DeliveryOutcome(a sms.Attempt) string {
	if ScopeOf(a.Err) == Ambiguous {
		return "unreachable"
	}
	return "rejected"
}

// What an unsent OTP row gives back is not decided here, on purpose. An ending that
// refunds names a key, and a key list is a thing every ending can get wrong (rounds 3 to
// 6). The store's refund (GlobalTx.CountersRefund) takes the instant of the message and
// nothing else and writes the global counter, as literals in its statement, so no ending
// can choose a different set. The reason is spec 9.5: auth_otp_issue bumps ip, phone_net
// and phone for every request, a decoy included, and adds to global for a real code only (a decoy probes and
// locks that row and adds zero, 0052), so only
// the global key may go back or the 429 of a later request tells a phone with an account
// from one without. internal/lint TestRefundIsTheGlobalKeyOnly keeps it that way.

// Alert is one row for alerts, to be raised with GlobalTx.AlertOnce.
type Alert struct {
	Severity string
	Kind     string
	Key      closed.Key
	Params   closed.Params
}

// Alert kinds the SMS worker raises about gateways and about the service.
const (
	KindGateway = "sms_gateway"
	KindDown    = "sms_down"
)

// GatewayParams are the params of an alert about the whole gateway.
func GatewayParams(e *sms.Error) closed.Params {
	return sms.AlertParams(sms.GatewayAlert{Provider: e.Provider, Class: e.Class(), Code: e.Code})
}

// TemplateParams are the params of an alert about one template.
func TemplateParams(e *sms.Error, t sms.TemplateKey) closed.Params {
	return sms.AlertParams(sms.TemplateAlert{Provider: e.Provider, Class: e.Class(), Code: e.Code, Template: t})
}

// Alerts are the gateway alerts the attempts of one send raise, one per failed attempt
// that has one. Alerts rely on alerts_open_key_uq for their frequency: one open alert
// per key, an operator's ack closes it and the next failure opens a new one.
//
//   - Gateway scope: critical, key "<gateway>:<class>". Nothing can be sent through the
//     gateway.
//   - Template and Message scope: a warning with its own key per template,
//     "<gateway>:<class>:<template>", so an unacknowledged warning cannot hide a later
//     critical one on the same gateway (ON CONFLICT DO NOTHING). When no routed gateway
//     can send the message (every routed gateway was tried, none skipped, each answered
//     in these scopes, and it is not a test send), nothing a user asks for it will
//     arrive although the gateway is configured (the public flag does not follow the breaker, sms-r18-2), so that is critical with the key
//     "<gateway>:<class>:<template>:none" (9.7, sms-r3-5).
//   - Number and Ambiguous: none. A refused number is the user's; the transient state is
//     what sms_down and the breaker are for.
func Alerts(out sms.Outcome, tpl sms.TemplateKey) []Alert {
	unroutable := templateUnroutable(out)
	var alerts []Alert
	for _, a := range out.Attempts {
		if a.Err == nil {
			continue
		}
		e := a.Err
		switch ScopeOf(e) {
		case Gateway:
			alerts = append(alerts, Alert{"critical", KindGateway, closed.NewKey(closed.ID(a.Gateway), e.Class()), GatewayParams(e)})
		case Template, Message:
			if unroutable {
				alerts = append(alerts, Alert{"critical", KindGateway, closed.NewKey(closed.ID(a.Gateway), e.Class(), tpl, sms.KeyNone), TemplateParams(e, tpl)})
				continue
			}
			alerts = append(alerts, Alert{"warning", KindGateway, closed.NewKey(closed.ID(a.Gateway), e.Class(), tpl), TemplateParams(e, tpl)})
		}
	}
	return alerts
}

// Down is the sms_down alert for a send whose last answer was Ambiguous: an OTP that ends
// unsent after only transient failures is an outage to tell the operator about. One open
// alert for the whole service.
func Down(out sms.Outcome) (Alert, bool) {
	last := out.Last()
	if last == nil || ScopeOf(last) != Ambiguous {
		return Alert{}, false
	}
	return Alert{"critical", KindDown, closed.NewKey(sms.KeyAll), GatewayParams(last)}, true
}

// templateUnroutable says that no routed gateway can send this message: every routed
// gateway was tried (none skipped behind a breaker) and each answered about the message
// and not about itself. It is false for a pinned test send, where a missing mapping on
// the one gateway is the operator's answer.
func templateUnroutable(out sms.Outcome) bool {
	if out.Pinned || out.Skipped > 0 || len(out.Attempts) == 0 {
		return false
	}
	for _, a := range out.Attempts {
		if a.Err == nil {
			return false
		}
		if s := ScopeOf(a.Err); s != Template && s != Message {
			return false
		}
	}
	return true
}
