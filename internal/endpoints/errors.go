// Package endpoints is the one write path of Endpoints, groups, schedule windows and clients
// (docs/specs/p3-endpoints.md 3): every change of those tables, from a route or a later phase, goes through it. A route
// handler decodes a request and calls it; this package owns the lock order of 3.7, the lock passwords of 3.3, the
// destinations check of 3.4, the caps of 3.5, the validation of 3.8 and the outbox marks of 3.2, so no route can forget one.
package endpoints

import "strings"

// Kind is what a refusal is, in the vocabulary of the API: the handler maps it to a status and a code and reads nothing
// else of the error.
type Kind uint8

// The refusals of the write path.
const (
	// KindNotFound is 404 not_found: an Endpoint, group, client, window or profile id of the request is not the caller's.
	KindNotFound Kind = iota + 1
	// KindValidation is 422 validation_failed with Fields.
	KindValidation
	// KindLocked is 423 profile_locked: the request needs the lock password of a profile and carries none (Fields names
	// /lock_passwords with code required).
	KindLocked
	// KindInvalidCredentials is 401 invalid_credentials: a lock password is wrong (Fields names /lock_passwords/<i>).
	KindInvalidCredentials
	// KindHeld is 409 endpoint_held: an admin holds an Endpoint of the request, or a claim of it is suspended.
	KindHeld
	// KindDestinationsLost is 409 destinations_lost: the write would take a location away from a profile that targets it.
	KindDestinationsLost
	// KindConflict is 409 conflict: a lost race the request cannot be retried from (the rows a verified password stood
	// for changed between the check and the write).
	KindConflict
	// KindTokenNotAllowed is 403 token_not_allowed: an API token can never present a lock password (spec 3.3).
	KindTokenNotAllowed
	// KindKeyReused is 409 idempotency_key_reused.
	KindKeyReused
)

func (k Kind) String() string {
	switch k {
	case KindNotFound:
		return "not_found"
	case KindValidation:
		return "validation_failed"
	case KindLocked:
		return "profile_locked"
	case KindInvalidCredentials:
		return "invalid_credentials"
	case KindHeld:
		return "endpoint_held"
	case KindDestinationsLost:
		return "destinations_lost"
	case KindConflict:
		return "conflict"
	case KindTokenNotAllowed:
		return "token_not_allowed"
	case KindKeyReused:
		return "idempotency_key_reused"
	}
	return "unknown"
}

// Field names one invalid value: Name is a JSON pointer built from member names and indexes of the request (never a value
// from it), Code is from the closed set of spec 3.8.
type Field struct {
	Name string
	Code string
}

// Error is a refusal. It carries no request data besides the field names and codes, which are closed.
type Error struct {
	Kind   Kind
	Fields []Field
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString(e.Kind.String())
	for i, f := range e.Fields {
		if i == 3 {
			b.WriteString(" ...")
			break
		}
		b.WriteString(" " + f.Name + ":" + f.Code)
	}
	return b.String()
}

// fieldLimit is how many field entries one answer carries: it bounds the size of an answer, not the work of a request.
const fieldLimit = 100

func notFound() *Error { return &Error{Kind: KindNotFound} }

func invalid(fs ...Field) *Error {
	if len(fs) > fieldLimit {
		fs = fs[:fieldLimit]
	}
	return &Error{Kind: KindValidation, Fields: fs}
}

// The closed set of field codes (spec 3.8): P2 3.7's set plus the codes of this phase.
const (
	CodeRequired          = "required"
	CodeTooLong           = "too_long"
	CodeTooShort          = "too_short"
	CodeInvalid           = "invalid"
	CodeDuplicate         = "duplicate"
	CodeExists            = "exists"
	CodeExceeded          = "exceeded"
	CodeOutOfRange        = "out_of_range"
	CodeUnknown           = "unknown"
	CodeSameProfile       = "same_profile"
	CodeNeedsAuthorizedIP = "needs_authorized_ip"
	CodeGrid              = "grid"
	CodeOverlap           = "overlap"
	CodeReserved          = "reserved"
)
