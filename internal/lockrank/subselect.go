package lockrank

import "fmt"

// LockingSubselects counts the row-locking clauses of one SQL statement that sit inside parentheses
// not opened by ARRAY, and the clauses at the statement's own top level (P1 auth review round 18,
// sms-r18-9; rule lock-order).
//
// Why it is here. A locking subselect of a write is picked once, as an ARRAY: `id = ANY (ARRAY(SELECT
// id FROM t ... FOR UPDATE SKIP LOCKED))`. An `IN (SELECT ... LIMIT n FOR UPDATE SKIP LOCKED)` is a
// semi-join the planner may rescan, and a rescan after the outer statement changed rows picks the NEXT
// rows (db-r16-19, sms-r17-4). The check used to be a second reader of the SQL text, a counter of
// parentheses over the raw bytes that skipped only '...' strings, and it disagreed with this package's
// own reader, which Analyze and Writes use and which lints the same text: a ')' inside a comment, a
// quoted identifier or a dollar-quoted string popped its stack, and FOR/**/UPDATE is a lock to the
// server and not to a regular expression. It now reads the TOKENS of lex, so a statement has one
// reading: comments are gone, a string is one token, a quoted name is one word, and a text the lexer
// cannot read (dollar quoting, an unterminated string or comment) is an ERROR that the caller must
// report, never a clean answer (fail closed).
//
// Contract: it judges the text of one SQL statement. It does not judge the plpgsql bodies of definer
// functions (the catalog test reads those from the live database), and it does not say which table a
// clause locks, only the shape around it.
func LockingSubselects(sql string) (insideNotArray, topLevel int, err error) {
	toks, err := lex(sql)
	if err != nil {
		return 0, 0, err
	}
	// open holds, for each parenthesis still open, whether it was opened by the word ARRAY.
	var open []bool
	for i, t := range toks {
		switch t.k {
		case '(':
			open = append(open, i > 0 && isWord(toks[i-1], "array"))
		case ')':
			if len(open) == 0 {
				return 0, 0, fmt.Errorf("lockrank: a closing parenthesis with no opening one")
			}
			open = open[:len(open)-1]
		case 'w':
			// lockClause is the one recogniser of a lock: Analyze ranks what it finds, so a spelling it
			// learns is counted here at once (sms-r18-20).
			if c, _ := lockClause(toks, i); c == "" {
				continue
			}
			switch {
			case len(open) == 0:
				topLevel++
			case !open[len(open)-1]:
				insideNotArray++
			}
		}
	}
	if len(open) != 0 {
		return 0, 0, fmt.Errorf("lockrank: an opening parenthesis that is never closed")
	}
	return insideNotArray, topLevel, nil
}
