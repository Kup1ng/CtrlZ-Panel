package lockrank_test

import (
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/lockrank"
)

// TestLockingSubselectsCanFail plants every spelling of a locking subselect that is not the body of an ARRAY,
// and the ordinary SQL that used to hide it from a counter of parentheses over raw bytes (sms-r18-9): a
// parenthesis inside a line comment, a block comment, a quoted identifier and a string; the keyword spelled
// across a comment or a newline. Each is one clause inside parentheses. The accepted shapes follow.
func TestLockingSubselectsCanFail(t *testing.T) {
	const head = "UPDATE ctrlz.sms_outbox o SET attempts = o.attempts + 1 WHERE "
	bad := map[string]string{
		"in":                        "o.id IN (SELECT c.id FROM ctrlz.sms_outbox c ORDER BY c.created_at LIMIT $1 FOR UPDATE SKIP LOCKED)",
		"any without array":         "o.id = ANY (SELECT c.id FROM ctrlz.sms_outbox c FOR UPDATE)",
		"a cte body":                "o.id IN (WITH p AS (SELECT c.id FROM ctrlz.sms_outbox c FOR UPDATE) SELECT id FROM p)",
		"no key update":             "o.id IN (SELECT c.id FROM ctrlz.sms_outbox c FOR NO KEY UPDATE)",
		"for share":                 "o.id IN (SELECT c.id FROM ctrlz.sms_outbox c FOR SHARE)",
		"for key share":             "o.id IN (SELECT c.id FROM ctrlz.sms_outbox c FOR KEY SHARE)",
		"a line comment with a )":   "o.id IN ( -- the picked rows )\n SELECT c.id FROM ctrlz.sms_outbox c ORDER BY c.created_at LIMIT $1 FOR UPDATE SKIP LOCKED)",
		"a block comment with a )":  "o.id IN ( /* the picked rows ) */ SELECT c.id FROM ctrlz.sms_outbox c LIMIT $1 FOR UPDATE SKIP LOCKED)",
		"a quoted identifier is )":  "o.id IN (SELECT c.id AS \")\" FROM ctrlz.sms_outbox c LIMIT $1 FOR UPDATE SKIP LOCKED)",
		"a string with a )":         "o.kind = ')' AND o.id IN (SELECT c.id FROM ctrlz.sms_outbox c LIMIT $1 FOR UPDATE SKIP LOCKED)",
		"a comment inside the lock": "o.id IN (SELECT c.id FROM ctrlz.sms_outbox c LIMIT $1 FOR/**/UPDATE SKIP LOCKED)",
		"a newline inside the lock": "o.id IN (SELECT c.id FROM ctrlz.sms_outbox c LIMIT $1 FOR\n\tUPDATE SKIP LOCKED)",
		"a derived table":           "o.id IN (SELECT id FROM (SELECT c.id FROM ctrlz.sms_outbox c FOR UPDATE) s)",
	}
	for name, where := range bad {
		in, top, err := lockrank.LockingSubselects(head + where)
		if err != nil || in != 1 || top != 0 {
			t.Errorf("%s: inside=%d top=%d err=%v, want one clause inside parentheses", name, in, top, err)
		}
	}
	for name, sql := range map[string]string{
		"an array":                               head + "o.id = ANY (ARRAY(SELECT c.id FROM ctrlz.sms_outbox c ORDER BY c.id FOR UPDATE SKIP LOCKED))",
		"an array, comment with a )":             head + "o.id = ANY (ARRAY( -- ) \n SELECT c.id FROM ctrlz.sms_outbox c FOR UPDATE))",
		"an array, spaced":                       head + "o.id = ANY ( ARRAY (SELECT c.id FROM ctrlz.sms_outbox c FOR UPDATE))",
		"no lock at all":                         head + "o.id IN (SELECT c.id FROM ctrlz.sms_outbox c)",
		"the word in a string":                   head + "o.kind = 'FOR UPDATE' AND o.id IN (SELECT c.id FROM ctrlz.sms_outbox c)",
		"the word in a comment":                  head + "o.id IN (SELECT c.id FROM ctrlz.sms_outbox c /* FOR UPDATE */)",
		"the word in a line comment":             head + "o.id IN (SELECT c.id FROM ctrlz.sms_outbox c) -- FOR UPDATE",
		"a FOR that is no lock (one recogniser)": head + "o.id IN (SELECT c.id FROM ctrlz.sms_outbox c FOR x)",
		"no lock, a plain subselect":             head + "o.id IN (SELECT c.id FROM ctrlz.sms_outbox c WHERE c.kind = 'a') AND true",
	} {
		if in, _, err := lockrank.LockingSubselects(sql); err != nil || in != 0 {
			t.Errorf("%s: inside=%d err=%v, want none", name, in, err)
		}
	}
	// The statement's own lock is not a subselect: counted at the top level.
	if in, top, err := lockrank.LockingSubselects("SELECT id FROM ctrlz.sms_outbox WHERE id = $1 FOR UPDATE"); err != nil || in != 0 || top != 1 {
		t.Errorf("a top-level lock: inside=%d top=%d err=%v", in, top, err)
	}
	// A text the lexer cannot read is an error and never a clean answer, so a caller must report it.
	for name, sql := range map[string]string{
		"dollar quoting":      head + "o.kind = $$)$$ AND o.id IN (SELECT c.id FROM ctrlz.sms_outbox c LIMIT $1 FOR UPDATE SKIP LOCKED)",
		"a tagged dollar":     head + "o.kind = $q$)$q$",
		"an open string":      head + "o.kind = 'x",
		"an open comment":     head + "o.id IN (SELECT 1) /* x",
		"an unclosed paren":   head + "o.id IN (SELECT c.id FROM ctrlz.sms_outbox c FOR UPDATE",
		"a closing paren too": head + "o.id IN (SELECT 1))",
	} {
		if _, _, err := lockrank.LockingSubselects(sql); err == nil {
			t.Errorf("%s: no error for a text that cannot be read", name)
		}
	}
}
