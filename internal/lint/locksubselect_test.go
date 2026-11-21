package lint_test

import (
	"regexp"
	"strings"
)

// A locking subselect of a write is picked once, as an ARRAY (P1 auth review round 17, sms-r17-4; rule lock-order).
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
// Contract: it judges the text of one SQL statement. It does not judge the plpgsql bodies of definer functions
// (TestDefinerWritesLockInKeyOrder reads those from the live catalog), and a string literal is skipped.

var lockClause = regexp.MustCompile(`(?i)\bFOR\s+(?:NO\s+KEY\s+UPDATE|UPDATE|KEY\s+SHARE|SHARE)\b`)

// lockingSubselectsOutsideArray returns the offsets of the locking clauses of sql that sit inside parentheses
// not opened by ARRAY.
func lockingSubselectsOutsideArray(sql string) []int {
	// open[i] is the offset of the '(' still open at position i, or -1. Built in one pass that skips quoted text.
	open := make([]int, len(sql)+1)
	var stack []int
	inStr := false
	for i := 0; i < len(sql); i++ {
		c := sql[i]
		if inStr {
			if c == '\'' {
				inStr = false
			}
			open[i] = -2
			continue
		}
		switch c {
		case '\'':
			inStr = true
			open[i] = -2
			continue
		case '(':
			stack = append(stack, i)
		case ')':
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
		if len(stack) == 0 {
			open[i] = -1
		} else {
			open[i] = stack[len(stack)-1]
		}
	}
	var bad []int
	for _, m := range lockClause.FindAllStringIndex(sql, -1) {
		p := open[m[0]]
		if p == -2 || p == -1 {
			continue
		}
		before := strings.TrimRight(sql[:p], " \t\r\n")
		if len(before) >= 5 && strings.EqualFold(before[len(before)-5:], "ARRAY") {
			continue
		}
		bad = append(bad, m[0])
	}
	return bad
}
