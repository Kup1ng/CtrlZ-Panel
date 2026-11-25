package lint_test

import "github.com/Kup1ng/CtrlZ-Panel/internal/lockrank"

// A locking subselect of a write is picked once, as an ARRAY (P1 auth review round 17, sms-r17-4; round 18,
// sms-r18-9; rule lock-order).
//
// Round 16 (db-r16-19) moved the sweeps to `id = ANY (ARRAY(SELECT ... FOR UPDATE ...))` because an
// `IN (SELECT ... LIMIT n FOR UPDATE SKIP LOCKED)` is a semi-join the planner may rescan, and a rescan after
// the outer statement changed rows picks the NEXT rows: a statement meant to take n rows took more. The fix
// was applied to the sweeps that had been seen; the four claim and ending statements of the worker kept the old
// shape, and the lint accepted them as "skipping" (NoWait) whatever the subselect was wrapped in.
//
// The rule is by construction and fails closed: in a statement that writes, EVERY row-locking clause that sits
// inside parentheses (a subselect or a CTE body) must be the body of an `ARRAY(`. A locking clause at the top
// level of a statement is the statement's own lock and is not a subselect. No spelling of the subselect's
// predicate, alias or ordering is read, so a new statement is judged by the shape of its lock, not by its name.
//
// Round 18: the check was a second reader of the SQL text, a parenthesis counter over raw bytes that skipped
// only '...' strings and matched FOR\s+UPDATE with a regular expression, while internal/lockrank's own lexer
// (the one Analyze and Writes read) already knew comments, quoted names and the keyword spelled across
// white space. It is now lockrank.LockingSubselects, over the tokens of that one lexer: a ')' in a comment, in
// a quoted identifier or in a string cannot pop the stack, FOR/**/UPDATE is a lock, and a text the lexer
// cannot read (a dollar-quoted string) is an error and a finding here, never a clean pass.
//
// Contract: it judges the text of one SQL statement. It does not judge the plpgsql bodies of definer
// functions (TestDefinerWritesLockInKeyOrder reads those from the live catalog).

// lockingSubselectsOutsideArray returns how many locking clauses of sql sit inside parentheses not opened by
// ARRAY, or the error of the lexer.
func lockingSubselectsOutsideArray(sql string) (int, error) {
	n, _, err := lockrank.LockingSubselects(sql)
	return n, err
}
