package sms

// The closed vocabularies the SMS layer puts in alert params, audit rows and log
// lines besides Code (review round 5, rule closed-values-in-logs). Each is a string
// type that lists its members and says whether a value is one; a value that comes
// from outside (a database column, a request) goes through the Parse function, which
// maps anything unlisted to one fixed unknown member.

// ProviderName is a gateway's provider. The column has a CHECK on it; the type
// repeats the list so that a value read from anywhere else cannot reach a log.
type ProviderName string

// The providers, and the two stand-ins.
const (
	ProviderSMSIR       ProviderName = "sms_ir"
	ProviderMelipayamak ProviderName = "melipayamak"
	ProviderNoop        ProviderName = "noop"
	ProviderNone        ProviderName = "none"    // no gateway was asked
	ProviderOther       ProviderName = "unknown" // anything else
)

// ParseProvider maps a provider name to its member, or to ProviderOther.
func ParseProvider(s string) ProviderName {
	switch p := ProviderName(s); p {
	case ProviderSMSIR, ProviderMelipayamak, ProviderNoop, ProviderNone:
		return p
	}
	return ProviderOther
}

// Valid reports membership.
func (p ProviderName) Valid() bool {
	switch p {
	case ProviderSMSIR, ProviderMelipayamak, ProviderNoop, ProviderNone, ProviderOther:
		return true
	}
	return false
}

// String is the name.
func (p ProviderName) String() string { return string(p) }

// TemplateKey is one of the five template keys, or TemplateUnknown for a row that
// never got that far (an OTP whose payload could not be read).
type TemplateKey string

// TemplateUnknown stands for a message whose template is not known.
const TemplateUnknown TemplateKey = "unknown"

// ParseTemplate maps a key to its member, or to TemplateUnknown.
func ParseTemplate(s string) TemplateKey {
	if ValidTemplate(s) {
		return TemplateKey(s)
	}
	return TemplateUnknown
}

// Valid reports membership.
func (k TemplateKey) Valid() bool { return k == TemplateUnknown || ValidTemplate(string(k)) }

// String is the key.
func (k TemplateKey) String() string { return string(k) }

// Locale is fa or en.
type Locale string

// ParseLocale returns the locale and whether s was one.
func ParseLocale(s string) (Locale, bool) { return Locale(s), ValidLocale(s) }

// Valid reports membership.
func (l Locale) Valid() bool { return ValidLocale(string(l)) }

// String is the locale.
func (l Locale) String() string { return string(l) }

// ClassName is a Class as a closed string, for a log attribute (logattr.Enum takes
// a closed string type; a Class is an int).
type ClassName string

// Name is the class as a ClassName.
func (c Class) Name() ClassName { return ClassName(c.String()) }

// Valid reports membership: the six class names and "unknown".
func (n ClassName) Valid() bool {
	switch n {
	case "transient", "auth", "credit", "config", "recipient", "blacklisted", "unknown":
		return true
	}
	return false
}
