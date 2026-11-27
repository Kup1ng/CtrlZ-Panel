package nodeadmin

import (
	"errors"
	"fmt"

	"github.com/google/uuid"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/zone"

	"github.com/Kup1ng/CtrlZ-Panel/internal/compiler"
)

// Membership is what a PairTable is built from (SC 8a.4, Membership). It is the compiler's type: the routes judge a
// change with the rows read and the table built by the one rule the compiler writes the log with (P4 6.1), so a table
// the route accepts is a table the compiler would write and the nodes would take. This package keeps only the part that
// is the routes' own, the reason a refusal is shown to the admin in.
type Membership = compiler.Membership

// BuildTable is the table the log would carry after the change: the compiler's table with activate, a node that is still
// pending, counted as active, so a confirmation is judged as the approval that follows it will be (a node that would
// repeat an address in use fails here and not at the approval).
func BuildTable(m *Membership, activate uuid.UUID) *policyv1.PairTable {
	return compiler.BuildPairTableAs(m, activate)
}

// TableError is a table the shared validators refuse. Reason is a stable phrase of the validator (field and
// rule, no value), which the route returns as the code of the field pair_table.
type TableError struct{ Reason string }

func (e *TableError) Error() string { return "nodeadmin: pair table invalid: " + e.Reason }

// ValidateTable runs the compiler's judge of a table (SC 8a.4, Valid table) and puts its refusal into the words the admin
// sees. A panic of the builder counts as a refusal, as it does for the compiler.
func ValidateTable(pt *policyv1.PairTable) error {
	err := compiler.ValidateTable(pt)
	if err == nil {
		return nil
	}
	// zone.Build names the field and the rule in a stable phrase. The wire validator's text is used when only it
	// refused (proxy_ip, the SPKI length); both are fixed phrases built from field names and sizes, never from a value.
	var be *zone.BuildError
	switch {
	case errors.Is(err, compiler.ErrBuilderPanic):
		return &TableError{Reason: "builder"}
	case errors.As(err, &be):
		return &TableError{Reason: fmt.Sprintf("%s: %s", be.Field, be.Msg)}
	}
	r := err.Error()
	if len(r) > 120 {
		r = r[:120]
	}
	return &TableError{Reason: r}
}

// CheckMembership builds the table that the rows would give, with activate counted as active, and judges it.
func CheckMembership(m *Membership, activate uuid.UUID) error {
	// The shared validators read an empty SPKI as a revoked entry, so they cannot tell it from an active row whose key
	// is missing. The compiler refuses such a table and keeps the last one, which would leave every later change
	// unpublished while the route answered success; the route refuses it first, by the compiler's own rule.
	if compiler.ActiveWithoutSPKI(m, activate) {
		return &TableError{Reason: "spki_sha256: an active node has no 32-byte key"}
	}
	return ValidateTable(BuildTable(m, activate))
}
