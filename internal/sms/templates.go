package sms

import (
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// The five templates of spec 9.4. A key is the contract between the code that
// asks for a message and the approved copy a gateway holds, so the set is closed.
const (
	TemplateOTP           = "otp"
	TemplateOTPReset      = "otp_reset"
	TemplateOTPPhone      = "otp_phone"
	TemplateInvite        = "invite"
	TemplateAccountExists = "account_exists"
)

// Templates lists the keys, in the order the SMS page shows them.
func Templates() []string {
	return []string{TemplateOTP, TemplateOTPReset, TemplateOTPPhone, TemplateInvite, TemplateAccountExists}
}

// ValidTemplate reports whether key is one of the five.
func ValidTemplate(key string) bool {
	_, ok := PlaceholderCount(key)
	return ok
}

// ValidLocale reports whether l is fa or en.
func ValidLocale(l string) bool { return l == "fa" || l == "en" }

// OtherLocale is the locale a message falls back to when a gateway has no
// mapping for the asked one (9.4).
func OtherLocale(l string) string {
	if l == "fa" {
		return "en"
	}
	return "fa"
}

// placeholder is the one marker a template body may hold (9.4). It is neutral on
// purpose: the provider's own syntax differs, and the gateway mapping says which
// of its parameters receives the value.
const placeholder = "{code}"

// PlaceholderCount is how many values a template takes: one code, or none for
// account_exists. ok is false for an unknown key.
func PlaceholderCount(key string) (n int, ok bool) {
	switch key {
	case TemplateOTP, TemplateOTPReset, TemplateOTPPhone, TemplateInvite:
		return 1, true
	case TemplateAccountExists:
		return 0, true
	}
	return 0, false
}

// Errors of template handling. They hold fixed text.
var (
	ErrUnknownTemplate = errors.New("sms: unknown template")
	ErrParamCount      = errors.New("sms: provider parameter count differs from the template")
	ErrBadBody         = errors.New("sms: template body does not fit its key")
	ErrBadValue        = errors.New("sms: value does not fit the template")
)

// CheckBody validates the text an operator edits on the SMS page: exactly the
// key's number of {code} markers, and nothing else that is not on a closed
// alphabet. A provider refuses a link in a variable and the invite code replaced
// it (finding 6), and an operator must not be able to submit an address for
// approval inside the copy.
//
// The check is an allow list on purpose. Unicode has an open set of characters
// that render as nothing or look like a dot or a slash (ZWNJ, other format
// characters, variation selectors, the combining grapheme joiner, ideographic
// full stops), and a deny list needed a new entry in each of three review rounds.
// With a closed alphabet a character nobody has thought of is refused by
// default. The alphabet is: ASCII letters and digits, Persian letters and
// digits, a space, and the punctuation in punctuation below. Three characters are
// allowed only in a context (see the switch), and no other character is.
//
// No domain can be spelled with this alphabet: a label joins a suffix only
// through a full stop, and a full stop is allowed only before a space or the end.
// The slash, the backslash and '@' are not in the alphabet, which is what
// excludes a scheme's "//", a path and an address.
func CheckBody(key, body string) error {
	want, ok := PlaceholderCount(key)
	if !ok {
		return ErrUnknownTemplate
	}
	syms, n, ok := bodySymbols(body)
	if !ok || n != want {
		return ErrBadBody
	}
	for i, r := range syms {
		next := endOfText
		if i+1 < len(syms) {
			next = syms[i+1]
		}
		switch {
		case r == marker, inAlphabet(r):
			// Fine in any place.
		case r == '.' || r == ':':
			// Only before a space or the end: "ctrlz.ir" and "bit.ly" cannot be
			// written, and "{code}.ir" cannot either (the marker is not a space).
			if next != endOfText && next != ' ' {
				return ErrBadBody
			}
		case r == zwnj:
			// Persian orthography needs it between two joining letters, and nowhere
			// else. Between a Latin label and anything it would hide a dot from a
			// reader or a check, so a neighbour that is not a Persian letter
			// (the marker, a space, a Latin letter, the edge) refuses it.
			if i == 0 || !isPersianLetter(syms[i-1]) || !isPersianLetter(next) {
				return ErrBadBody
			}
		default:
			return ErrBadBody
		}
	}
	return nil
}

// The one-part bound of owner decision D58 (sms-r11-2, sms-r13-3). Both providers bill each part
// of a message, and a Persian part holds 70 UCS-2 units, a Latin one 160 GSM-7 characters. The
// three OTP templates are the highest-volume ones and the price an operator enters for them is
// one price per message, so the cap on spend (sms_cost_cap_daily) counts one part for each. A body
// that needs two parts makes that count too low, and the bound has to hold for the body that is
// really sent: the seeds (TestOTPBodiesFitOnePart) and every edit made on the SMS page, which is
// why PutSmsTemplate asks this same function. Persian keeps 6 units of room (64) so a small copy
// edit stays inside the part.
const (
	MaxOTPUnitsFA = 64
	MaxOTPUnitsEN = 160
)

// ErrBodyTooLong says an OTP body would be billed as more than one part once a code is in it.
var ErrBodyTooLong = errors.New("sms: template body does not fit one billed part")

// oneBilledPart says whether key is a template the D58 bound holds for.
func oneBilledPart(key string) bool {
	return key == TemplateOTP || key == TemplateOTPReset || key == TemplateOTPPhone
}

// CheckBodyLength holds the three OTP templates to one billed part, rendered with a code of
// codeLength digits: at most MaxOTPUnitsFA UCS-2 units in Persian, and in English at most
// MaxOTPUnitsEN GSM-7 units with every character in the GSM alphabet (one outside it sends the
// whole message as UCS-2, 70 units). Other keys are not bounded here. CheckBody judges the
// alphabet and the markers and this judges the length; a caller that stores a body runs both.
func CheckBodyLength(key, locale, body string, codeLength int) error {
	if !oneBilledPart(key) {
		return nil
	}
	rendered := Render(body, secret.New(strings.Repeat("7", codeLength)))
	if locale == "en" {
		n, ok := GSM7Units(rendered)
		if !ok || n > MaxOTPUnitsEN {
			return ErrBodyTooLong
		}
		return nil
	}
	if UCS2Units(rendered) > MaxOTPUnitsFA {
		return ErrBodyTooLong
	}
	return nil
}

// GSM7Units counts a text in GSM 7-bit units, and says whether every character is in the GSM
// alphabet. The extension characters take two units.
func GSM7Units(s string) (n int, ok bool) {
	const basic = "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà"
	const ext = "^{}\\[~]|€"
	for _, r := range s {
		switch {
		case strings.ContainsRune(basic, r):
			n++
		case strings.ContainsRune(ext, r):
			n += 2
		default:
			return n, false
		}
	}
	return n, true
}

// UCS2Units counts a text in UTF-16 code units, the unit a Persian SMS part is counted in.
func UCS2Units(s string) int {
	n := 0
	for _, r := range s {
		n++
		if r > 0xFFFF {
			n++
		}
	}
	return n
}

// Sentinels in the symbol slice. They are negative, so no real code point equals
// one of them.
const (
	marker    rune = -1 // one {code}
	endOfText rune = -2 // past the last symbol
)

const zwnj = '‌'

// bodySymbols turns a body into runes with each {code} collapsed to marker, so
// the marker's neighbours are judged as symbols and not as the six characters of
// its spelling. ok is false for invalid UTF-8 (a lone byte, an encoded surrogate)
// and for U+FFFD, which is what a decoder shows for either; neither is a letter.
func bodySymbols(body string) (syms []rune, markers int, ok bool) {
	syms = make([]rune, 0, len(body))
	for rest := body; rest != ""; {
		if strings.HasPrefix(rest, placeholder) {
			syms = append(syms, marker)
			markers++
			rest = rest[len(placeholder):]
			continue
		}
		r, size := utf8.DecodeRuneInString(rest)
		if r == utf8.RuneError {
			return nil, 0, false
		}
		syms = append(syms, r)
		rest = rest[size:]
	}
	return syms, markers, true
}

// inAlphabet is the closed set of characters allowed in any place. It is a switch
// over listed members, never a Unicode category or a script test: a category such
// as Mn or Lo admits the variation selectors, the tatweel, Arabic harakat and
// thousands of look-alikes, which is the hole this replaced. '.', ':' and ZWNJ
// are not here because each has a context rule in CheckBody.
func inAlphabet(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	case r >= '۰' && r <= '۹': // Persian digits
		return true
	case r == ' ':
		return true
	}
	return isPersianLetter(r) || strings.ContainsRune(punctuation, r)
}

// punctuation is what a sentence needs: comma, semicolon, exclamation and
// question mark, hyphen, parentheses, apostrophe ("panel's"), quotation mark, and
// the Persian comma, semicolon and question mark. No slash, backslash, '@', '%',
// '+', '#', '=' or '_': each is part of how an address, a mail address or a phone
// shortcut is written.
const punctuation = ",;!?-()'\"،؛؟"

// isPersianLetter lists the letters of the Persian alphabet, the Arabic letters
// Persian text also uses (kaf and yeh in their Arabic forms, which a pasted
// text brings), and nothing else: not the tatweel U+0640, not a harakat, not a
// letter of another Arabic-script language.
func isPersianLetter(r rune) bool {
	switch {
	case r >= 'ء' && r <= 'غ', r >= 'ف' && r <= 'ي':
		return true
	}
	switch r {
	case 'پ', 'چ', 'ژ', 'ک', 'گ', 'ی', 'ۀ': // پ چ ژ ک گ ی ۀ
		return true
	}
	return false
}

// Render fills a body with the value. The noop gateway and the SMS page's
// preview use it; a real provider renders its own approved copy.
func Render(body string, value secret.String) string {
	return strings.ReplaceAll(body, placeholder, value.Reveal())
}

// Build makes the Message one gateway sends: the single value goes under the
// gateway's first parameter name (sms.ir) or in its first position
// (Melipayamak), and a mapping whose parameter count differs from the
// template's is refused before any send (9.4). value must be empty for a
// template that takes none, and set for one that takes a code.
func Build(to, key, locale string, t ProviderTemplate, value secret.String) (Message, error) {
	want, ok := PlaceholderCount(key)
	if !ok {
		return Message{}, ErrUnknownTemplate
	}
	if len(t.ParamNames) != want {
		return Message{}, ErrParamCount
	}
	if (want == 1) == value.IsZero() {
		return Message{}, ErrBadValue
	}
	m := Message{To: to, Template: key, Locale: locale}
	if want == 1 {
		// The name is used exactly as stored: the drivers look the value up by the
		// raw name in t.ParamNames, so a key trimmed here would not be found there
		// (sms-r4-2). The admin PUT stores names trimmed; this only refuses a blank.
		name := t.ParamNames[0]
		if strings.TrimSpace(name) == "" {
			return Message{}, ErrParamCount
		}
		m.Values = map[string]secret.String{name: value}
	}
	return m, nil
}

// templateIDWidth is the length the admin API document allows a provider template id.
const templateIDWidth = 18

// ParseTemplateNumber is the one judge of a provider template id for every provider (sms-r9-2,
// sms-r10-4): 1 to templateIDWidth ASCII digits with a value above zero, nothing else. No
// sign, no white space, no other script's digits, no zero. The admin PUT (through
// senders.ValidTemplateID) and each driver's own last line of defence call it, so a stored
// row that came by SQL or a restore is judged as the PUT would have judged it. A driver adds
// the bound its provider's own type has (sms.ir: int32). strconv.ParseInt alone took a sign, a
// zero and nineteen digits, and what it let through reached the wire as a provider status the
// table does not list, which counts toward the breaker.
func ParseTemplateNumber(s string) (int64, bool) {
	if s == "" || len(s) > templateIDWidth {
		return 0, false
	}
	var n int64
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int64(s[i]-'0')
	}
	return n, n > 0
}
