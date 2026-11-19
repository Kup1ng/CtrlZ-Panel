package sms

import "strconv"

// Code is the "what happened" part of a failed send: the word in "sms: sms_ir auth
// 104", the provider_status column of sms_deliveries, the last_error_code of the
// gateway row, the code in an alert's params and in a log line.
//
// It is a member of one closed table, this file's, and nothing else. Before this
// rule a driver built a code from the provider's reply ("value_" + the digits it
// had received, "status_" + a number, "http_" + a status), and every review round
// found a reply shape that slipped through the filter that was supposed to make the
// string safe (review round 5, rule closed-values-in-logs; findings primitives-r1-8,
// sms-r1-7, sms-r1-14, primitives-r2-4, sms-r2-11, primitives-r3-1). Now a reply the
// table does not name is CodeUnknown, one fixed word, and the table is the only
// place a Code is made: internal/lint refuses a conversion sms.Code(x) or a string
// literal that becomes a Code anywhere else, and Valid is checked again where a
// Code is stored (NewError, the store's closed.Text parameters, closed.Check).
//
// The table is a switch, not a map, because the workspace forbids package-level
// mutable state; it lists every member in the open, which is what a reviewer wants
// to read.
type Code string

// CodeNone is the zero Code: "no problem" in a Gateway. It is not a member of the
// table (Valid is false) and is never stored or logged.
const CodeNone Code = ""

// String is the code text.
func (c Code) String() string { return string(c) }

// The words the layer itself says. None of them is derived from a reply.
const (
	CodeUnknown Code = "unknown" // the one fixed answer to anything the table does not name
	CodeOK      Code = "ok"      // an accepted attempt in sms_deliveries

	// The network and the request.
	CodeTimeout  Code = "timeout"
	CodeNetwork  Code = "network"
	CodeRequest  Code = "request"
	CodeRedirect Code = "redirect"
	CodeBadReply Code = "bad_reply"
	CodeFile     Code = "file"
	CodeEncode   Code = "encode"

	// A message or mapping the driver refused before sending.
	CodeNumberFormat   Code = "number_format"
	CodeTemplateID     Code = "template_id"
	CodeParamMissing   Code = "param_missing"
	CodeValueTooLong   Code = "value_too_long"
	CodeValueSeparator Code = "value_separator"

	// The router's own.
	CodeNoGateway  Code = "no_gateway"
	CodeDriverErr  Code = "driver_error"
	CodeUnusable   Code = "unusable"
	CodeNoTemplate Code = "no_template"
	CodeParamCount Code = "param_count"
	CodeBadMessage Code = "bad_message"

	// Why a gateway could not be built (internal/sms/senders).
	CodeNoCredentials         Code = "no_credentials"
	CodeBadCredentials        Code = "bad_credentials"
	CodeNoopInProduction      Code = "noop_in_production"
	CodeUnknownProvider       Code = "unknown_provider"
	CodeCredentialsUnreadable Code = "credentials_unreadable"

	// Why a queued message ended unsent.
	CodeCap        Code = "cap"
	CodeUnreadable Code = "unreadable"
	CodeBadPayload Code = "bad_payload"
)

// numericCode lists the status values the two providers' pages document that the send and the
// balance calls can return (9.2), in the form a driver reads them: the subset that Verify and
// GetCredit produce, not every number a page names. sms.ir also documents 103 (empty text), 105 to
// 112 (bulk and scheduled sends) and Verify builds none of those from a bad message of ours, so a
// reply that carries one is not a status of this service and is CodeUnknown, like any other
// number nobody listed (sms-r11-8). A provider reply outside this list is CodeUnknown.
// Two providers share one list: the Error also carries the provider's name, and a
// "0" means one thing for sms.ir and another for Melipayamak.
func numericCode(s string) (Code, bool) {
	switch s {
	case "0", "2", "6", "7", "10", "11", "12", "13", "14", "16", "17", "18", "19", "20", "35",
		"101", "102", "104", "113", "114", "115", "116", "117", "118", "119", "123",
		"-1", "-2", "-3", "-4", "-5", "-6", "-7", "-10", "-108", "-109", "-110", "-111":
		return Code(s), true
	}
	return CodeUnknown, false
}

// StatusCode is a provider status, as the text the driver read, or CodeUnknown when
// the documented table does not hold it.
func StatusCode(s string) Code {
	c, _ := numericCode(s)
	return c
}

// StatusNumber is StatusCode for a status the driver decoded as a number.
func StatusNumber(n int) Code { return StatusCode(strconv.Itoa(n)) }

// HTTPCode is "http_" and the status, for the statuses 100 to 599, and CodeUnknown
// for any other number. There are 500 members, all spelled by three digits.
func HTTPCode(status int) Code {
	if status < 100 || status > 599 {
		return CodeUnknown
	}
	return Code("http_" + strconv.Itoa(status))
}

// Valid reports whether c is a member of the table.
func (c Code) Valid() bool {
	switch c {
	case CodeUnknown, CodeOK,
		CodeTimeout, CodeNetwork, CodeRequest, CodeRedirect, CodeBadReply, CodeFile, CodeEncode,
		CodeNumberFormat, CodeTemplateID, CodeParamMissing, CodeValueTooLong, CodeValueSeparator,
		CodeNoGateway, CodeDriverErr, CodeUnusable, CodeNoTemplate, CodeParamCount, CodeBadMessage,
		CodeNoCredentials, CodeBadCredentials, CodeNoopInProduction, CodeUnknownProvider, CodeCredentialsUnreadable,
		CodeCap, CodeUnreadable, CodeBadPayload:
		return true
	}
	if n, ok := httpStatusOf(c); ok {
		return n >= 100 && n <= 599
	}
	_, ok := numericCode(string(c))
	return ok
}

// httpStatusOf reads the three digits of an "http_NNN" code.
func httpStatusOf(c Code) (int, bool) {
	s := string(c)
	if len(s) != 8 || s[:5] != "http_" {
		return 0, false
	}
	n := 0
	for i := 5; i < 8; i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, true
}

// ParseCode reads a code back from where it was stored (the hold columns of sms_gateways): a
// member of the table is returned as it is, anything else is CodeUnknown. It is here, with the
// table, because this file is the only place a Code is made from a string (rule
// closed-values-in-logs), and a row can hold a value this build does not know after a rollback.
func ParseCode(s string) Code {
	if c := Code(s); c.Valid() {
		return c
	}
	return CodeUnknown
}
