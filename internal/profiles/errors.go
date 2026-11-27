// Package profiles is the one write path of a profile (docs/specs/p2-profiles.md 3): every change of
// a profile's content or name, from a route, a job or a later phase, goes through it. A route handler
// decodes a request and calls it inside the transaction the handler opened; this package owns the
// guard, the outbox marks, the quotas, the D42 refusal and the location sets, so no route can forget
// one.
package profiles

import "strings"

// Kind is what a refusal is, in the vocabulary of the API: the handler maps it to a status and a code
// and never reads anything else of the error.
type Kind uint8

// The refusals of the write path.
const (
	// KindNotFound is 404 not_found: the profile, or a folder, rule or selector id of the request, is not the
	// caller's (another tenant's id and another profile's id look the same).
	KindNotFound Kind = iota + 1
	// KindLocked is 423 profile_locked.
	KindLocked
	// KindValidation is 422 validation_failed with Fields.
	KindValidation
	// KindInUse is 409 profile_in_use: an Endpoint or a schedule window still uses the profile.
	KindInUse
	// KindConflict is 409 conflict: a lost race the request cannot be retried from.
	KindConflict
	// KindKeyReused is 409 idempotency_key_reused.
	KindKeyReused
	// KindJobRunning is 409 job_running: the tenant already has a queued or running job.
	KindJobRunning
)

func (k Kind) String() string {
	switch k {
	case KindNotFound:
		return "not_found"
	case KindLocked:
		return "profile_locked"
	case KindValidation:
		return "validation_failed"
	case KindInUse:
		return "profile_in_use"
	case KindConflict:
		return "conflict"
	case KindKeyReused:
		return "idempotency_key_reused"
	case KindJobRunning:
		return "job_running"
	}
	return "unknown"
}

// Field names one invalid value: Name is a JSON pointer built from member names and indexes of the
// request (never a value from it), Code is from the closed set of the spec (3.7).
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
	if e.Kind == KindValidation && len(e.Fields) > 0 {
		var b strings.Builder
		b.WriteString("validation_failed")
		for i, f := range e.Fields {
			if i == 3 {
				b.WriteString(" ...")
				break
			}
			b.WriteString(" ")
			b.WriteString(f.Name + ":" + f.Code)
		}
		return b.String()
	}
	return e.Kind.String()
}

// fieldLimit is how many field entries one answer carries (spec 6.2): it bounds the size of an answer, not
// the work a request can make the server do.
const fieldLimit = 100

func notFound() *Error { return &Error{Kind: KindNotFound} }

// invalid builds a validation refusal, cut at fieldLimit.
func invalid(fs ...Field) *Error {
	if len(fs) > fieldLimit {
		fs = fs[:fieldLimit]
	}
	return &Error{Kind: KindValidation, Fields: fs}
}

// The closed set of field codes (spec 3.7). A document adds its own in the package that reads it.
const (
	CodeRequired              = "required"
	CodeTooLong               = "too_long"
	CodeTooShort              = "too_short"
	CodeInvalid               = "invalid"
	CodeDuplicate             = "duplicate"
	CodeExists                = "exists"
	CodeExceeded              = "exceeded"
	CodeOutOfRange            = "out_of_range"
	CodeInPast                = "in_past"
	CodeUnknown               = "unknown"
	CodeNotAvailable          = "not_available"
	CodeNeedsFolderAction     = "needs_folder_action"
	CodeHasInheritingRules    = "has_inheriting_rules"
	CodeLocationNotAllowed    = "location_not_allowed"
	CodeNoSharedDestination   = "no_shared_destination"
	CodeIranianName           = "iranian_name"
	CodeLocationUnavailableFA = "location_unavailable" // an outcome flag, never a refusal
)
