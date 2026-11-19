package sms

import (
	"github.com/Kup1ng/CtrlZ-Panel/internal/closed"
)

// The params of the alerts the SMS worker raises, and the words their dedupe keys
// are made of. An alert's params reach the admin page and its key is stored inside
// them, so both are held to the closed-values rule: each field is a number or a
// member of a closed set, and closed.Marshal refuses a struct that is not (a
// reflection test, TestAlertParamsAreClosed, walks this file's types; review round
// 5, rule closed-values-in-logs). Before it, the worker built them from
// map[string]string.

// GatewayAlert is the params of a gateway alert that is about the whole gateway.
type GatewayAlert struct {
	Provider ProviderName `json:"provider"`
	Class    Class        `json:"class"`
	Code     Code         `json:"code"`
}

// TemplateAlert is GatewayAlert for a Config answer about one template.
type TemplateAlert struct {
	Provider ProviderName `json:"provider"`
	Class    Class        `json:"class"`
	Code     Code         `json:"code"`
	Template TemplateKey  `json:"template"`
}

// ReasonAlert is the params of an alert that says only why a message ended unsent.
type ReasonAlert struct {
	Reason Code `json:"reason"`
}

// AlertParams marshals v, and on the failure that cannot happen for a struct built
// by this file (a field off its list) falls back to the fixed unknown reason, so an
// alert is still raised. internal/sms/classify builds the gateway and template alerts
// from it, since what an alert says about a failure is that package's decision.
func AlertParams(v any) closed.Params {
	p, err := closed.NewParams(v)
	if err != nil {
		p, _ = closed.NewParams(ReasonAlert{Reason: CodeUnknown})
	}
	return p
}

// ReasonParams is the params of an alert that carries only a reason.
func ReasonParams(c Code) closed.Params { return AlertParams(ReasonAlert{Reason: c}) }

// KeyWord is a fixed word of an alert key: the parts that are neither an id nor a
// class nor a code.
type KeyWord string

// The words.
const (
	KeyAll    KeyWord = "all"    // sms_down: one open alert for the whole service
	KeyCap    KeyWord = "cap"    // sms_outbox_cap: the hour follows
	KeyOTP    KeyWord = "otp"    // sms_payload for an OTP row
	KeyOutbox KeyWord = "outbox" // sms_payload for an outbox row
	KeyNone   KeyWord = "none"   // no routed gateway can send the template
)

// Valid reports membership.
func (k KeyWord) Valid() bool {
	switch k {
	case KeyAll, KeyCap, KeyOTP, KeyOutbox, KeyNone:
		return true
	}
	return false
}

// String is the word.
func (k KeyWord) String() string { return string(k) }

// Valid reports that c is one of the six classes.
func (c Class) Valid() bool { return c >= Transient && c <= Blacklisted }
