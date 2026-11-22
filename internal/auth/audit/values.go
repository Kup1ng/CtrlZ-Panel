package audit

import (
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
)

// The closed sets an audit event may carry (spec 13.2, 13.3). A string field of an
// event is a named type that lists its members and says whether a value belongs;
// closed.Check, called by marshalParams, refuses an event whose field is off its
// list, and a reflection test (TestEveryEventFieldIsClosed) refuses an event with a
// plain string field. This replaced a scan for runs of digits, which each review
// round found a field kind, script or separator to get round (review round 5, rule
// closed-values-in-logs; findings primitives-r1-8, primitives-r2-4, primitives-r3-1).
//
// Every type has a Parse function that maps a string from outside (a column, a flag,
// a request) to a member or to one fixed unknown member. The callers use it; an
// event that is given a value built some other way is caught by Valid.

// Method says how a proof was given.
type Method string

// The methods, and the two combinations a reauth can record.
const (
	MethodPassword         Method = "password"
	MethodOTP              Method = "otp"
	MethodPasskey          Method = "passkey"
	MethodTOTP             Method = "totp"
	MethodRecovery         Method = "recovery"
	MethodPasswordTOTP     Method = "password+totp"
	MethodPasswordRecovery Method = "password+recovery"
	MethodUnknown          Method = "unknown"
)

// MethodOf maps a method name to its member.
func MethodOf(s string) Method {
	switch m := Method(s); m {
	case MethodPassword, MethodOTP, MethodPasskey, MethodTOTP, MethodRecovery:
		return m
	}
	return MethodUnknown
}

// Valid reports membership.
func (m Method) Valid() bool {
	switch m {
	case MethodPassword, MethodOTP, MethodPasskey, MethodTOTP, MethodRecovery,
		MethodPasswordTOTP, MethodPasswordRecovery, MethodUnknown:
		return true
	}
	return false
}

// WithSecondFactor is the method of a password proof followed by a second factor.
// With no first proof the second factor is the method; a second factor other than
// TOTP or a recovery code leaves a password alone.
func (m Method) WithSecondFactor(second Method) Method {
	if m == "" {
		return second
	}
	if m != MethodPassword {
		return m
	}
	switch second {
	case MethodTOTP:
		return MethodPasswordTOTP
	case MethodRecovery:
		return MethodPasswordRecovery
	}
	return m
}

// Via says how an account or an admin action came about.
type Via string

// The ways.
const (
	ViaOpen    Via = "open"
	ViaInvite  Via = "invite"
	ViaAdmin   Via = "admin"
	ViaCLI     Via = "cli"
	ViaUnknown Via = "unknown"
)

// ViaOf maps a name to its member.
func ViaOf(s string) Via {
	switch v := Via(s); v {
	case ViaOpen, ViaInvite, ViaAdmin, ViaCLI:
		return v
	}
	return ViaUnknown
}

// Valid reports membership.
func (v Via) Valid() bool {
	switch v {
	case ViaOpen, ViaInvite, ViaAdmin, ViaCLI, ViaUnknown:
		return true
	}
	return false
}

// RegMode is a registration mode (11.1).
type RegMode string

// The modes.
const (
	RegClosed  RegMode = "closed"
	RegInvite  RegMode = "invite"
	RegOpen    RegMode = "open"
	RegUnknown RegMode = "unknown"
)

// RegModeOf maps a name to its member.
func RegModeOf(s string) RegMode {
	switch m := RegMode(s); m {
	case RegClosed, RegInvite, RegOpen:
		return m
	}
	return RegUnknown
}

// Valid reports membership.
func (m RegMode) Valid() bool {
	switch m {
	case RegClosed, RegInvite, RegOpen, RegUnknown:
		return true
	}
	return false
}

// KeyDomain is a key domain of the key ring (8.1), the same list as keyring.Domains.
type KeyDomain string

// DomainUnknown is the member for a name the key ring does not define.
const DomainUnknown KeyDomain = "unknown"

// KeyDomainOf maps a name to its member.
func KeyDomainOf(s string) KeyDomain {
	if keyring.ValidDomain(s) {
		return KeyDomain(s)
	}
	return DomainUnknown
}

// Valid reports membership.
func (d KeyDomain) Valid() bool { return d == DomainUnknown || keyring.ValidDomain(string(d)) }

// AlertKind is the kind of an alert. The SMS kinds are listed; the kinds of later
// phases arrive as AlertOther until they are added here.
type AlertKind string

// The kinds.
const (
	AlertSMSGateway   AlertKind = "sms_gateway"
	AlertSMSDown      AlertKind = "sms_down"
	AlertSMSOutboxCap AlertKind = "sms_outbox_cap"
	AlertSMSPayload   AlertKind = "sms_payload"
	AlertOther        AlertKind = "other"
)

// AlertKindOf maps a name to its member.
func AlertKindOf(s string) AlertKind {
	switch k := AlertKind(s); k {
	case AlertSMSGateway, AlertSMSDown, AlertSMSOutboxCap, AlertSMSPayload:
		return k
	}
	return AlertOther
}

// Valid reports membership.
func (k AlertKind) Valid() bool {
	switch k {
	case AlertSMSGateway, AlertSMSDown, AlertSMSOutboxCap, AlertSMSPayload, AlertOther:
		return true
	}
	return false
}

// Field names a setting that a change touched. The SMS events record these and
// never a value (13.2).
type Field string

// The fields, for the gateway, the routing, the template and the limits events.
const (
	FieldCredentials Field = "credentials"
	// FieldCredentialsConfirmed is the console making pending credentials the active ones; FieldCredentials
	// from the panel only stages them (admin-r18-1).
	FieldCredentialsConfirmed Field = "credentials_confirmed"
	FieldCostPerMessage       Field = "cost_per_message"
	FieldPrimary              Field = "primary"
	FieldFallback             Field = "fallback"
	FieldTemplate             Field = "template"
	FieldBody                 Field = "body"
	FieldProviderTemplate     Field = "provider_template"

	FieldOTPCapPhone        Field = "otp_cap_phone"
	FieldOTPCapPhoneNet     Field = "otp_cap_phone_net"
	FieldOTPCapIP           Field = "otp_cap_ip"
	FieldOTPCapNet24        Field = "otp_cap_net24"
	FieldOTPCapPhoneTrusted Field = "otp_cap_phone_trusted"
	FieldOTPCapNet48        Field = "otp_cap_net48"
	FieldOTPCapGlobal       Field = "otp_cap_global"
	FieldOTPCooldown        Field = "otp_cooldown_s"
	FieldOTPSoftPct         Field = "otp_soft_pct"
	FieldSMSCostCapDaily    Field = "sms_cost_cap_daily"
	FieldSMSOutboxCapDaily  Field = "sms_outbox_cap_daily"
)

// Valid reports membership.
func (f Field) Valid() bool {
	switch f {
	case FieldCredentials, FieldCredentialsConfirmed, FieldCostPerMessage, FieldPrimary, FieldFallback, FieldTemplate, FieldBody, FieldProviderTemplate,
		FieldOTPCapPhone, FieldOTPCapPhoneNet, FieldOTPCapIP, FieldOTPCapNet24, FieldOTPCapPhoneTrusted, FieldOTPCapNet48,
		FieldOTPCapGlobal, FieldOTPCooldown, FieldOTPSoftPct, FieldSMSCostCapDaily, FieldSMSOutboxCapDaily:
		return true
	}
	return false
}

// Host is a relying-party id: a registered domain name the admin configured for the
// WebAuthn origin (7.2). It is the one member set that is a grammar and not a list,
// because a deployment chooses its own domain. The grammar cannot spell a phone
// number or a secret: lower-case ASCII letters, digits and hyphens in labels of at
// most 63 characters, separated by dots, at most 253 characters, a top-level label
// of letters only, and at most nine digits in the whole name (a number needs ten, however it is
// split by hyphens, dots or letters). A value outside it is HostInvalid, never a cleaned copy.
type Host string

// HostInvalid stands for a relying-party id that is not a plausible domain name.
const HostInvalid Host = "invalid"

// HostOf maps a relying-party id to its member.
func HostOf(s string) Host {
	if hostGrammar(s) {
		return Host(s)
	}
	return HostInvalid
}

// Valid reports membership.
func (h Host) Valid() bool { return h == HostInvalid || hostGrammar(string(h)) }

func hostGrammar(s string) bool {
	// The digits are counted over the whole name by the one rule of the log grammars, not per run and
	// not by a counter of our own (round 16, primitives-r16-13; round 17, primitives-r17-15): a run
	// reset at '-' and '.', so "0912-123-4567.example" (a mobile number split the way it is written)
	// was a valid name, and a letter between the digits hid one as well. A number needs ten digits
	// and no domain a panel is served from has that many.
	if len(s) == 0 || len(s) > 253 || !logattr.FewDigits(s) {
		return false
	}
	label, labels := 0, 0
	last := byte('.')
	allLetters := true // of the label being read
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			label++
		case c >= '0' && c <= '9':
			label++
			allLetters = false
		case c == '-':
			if last == '.' || i == len(s)-1 {
				return false
			}
			label++
			allLetters = false
		case c == '.':
			if label == 0 || last == '-' || label > 63 {
				return false
			}
			label, labels, allLetters = 0, labels+1, true
		default:
			return false
		}
		last = c
	}
	// The last label is the top-level one: letters only, at least two. A single label
	// ("localhost") is allowed for a development panel.
	return label > 0 && label <= 63 && allLetters && (labels == 0 || label >= 2)
}
