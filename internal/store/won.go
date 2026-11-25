package store

import (
	"github.com/jackc/pgx/v5/pgconn"
)

// Won is the answer of a conditional statement that decides a cap, a single use or
// the end of a row (P1 auth review, round 5, rule caps-and-endings; spec 9.5). It is
// the only permission to act on the thing the statement guards: send the code,
// refund the counters, charge the day, create the credential, run the job. Yes says
// whether this statement was the one that got the row.
//
// Why a type and not a bool. Caps, single uses and endings were checked in one
// statement and acted on in another, or the answer of the conditional statement was
// thrown away (a finish that did not ask whether it had finished the row), and the
// same few actors (the worker's finish, the fast sweep, the exhausted pass, the stale
// sweep, a second worker, two finishes) each acted on one row: double refunds, a
// refund of a code the user consumed, a breaker that escalated once per racer, a
// passkey past its cap. The statement is the decision; Go must not decide again.
//
// The zero value is a loss, so a path that forgets to set it fails closed. Only this
// package builds one, from a row a statement returned (won, wonRows, wonRow), so no
// caller can conjure a win from a count it took itself. TestCapsAndEndingsRule
// (internal/lint) fails for a call that returns a Won whose result is dropped, kept
// in a blank, or never reaches a condition, and for a Yes outside a condition.
type Won struct{ yes bool }

// Yes reports whether the statement returned the row. Use it in a condition (an if, a
// for, a switch case) or return its value; the lint refuses anything else.
func (w Won) Yes() bool { return w.yes }

// won makes a Won from the fact that a statement's row came back.
func won(yes bool) Won { return Won{yes: yes} }

// wonRows is the Won of an UPDATE or DELETE without RETURNING: it won when it changed
// exactly one row. The statement's WHERE is the condition; more than one row cannot
// happen for the key predicates used, and is not a win.
func wonRows(tag pgconn.CommandTag) Won { return Won{yes: tag.RowsAffected() == 1} }

// wonRow is the Won of a statement with RETURNING that was read with QueryRow: a row
// is a win, pgx.ErrNoRows is a loss and anything else is the error.
func wonRow(err error) (Won, error) {
	ok, err := notFound(err)
	return Won{yes: ok}, err
}
