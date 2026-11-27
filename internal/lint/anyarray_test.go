package lint_test

import "regexp"

// anyArray reads `x = ANY (ARRAY(SELECT ...))` (x a column or a row of columns, for a composite key) as `x IN (SELECT ...)`. The two pick the same rows; the ARRAY
// form is an InitPlan, evaluated once, which a locking, limited subselect needs: an IN over such a subselect is a
// semi-join the planner may rescan for each row the outer statement visits, and a rescan after the outer
// statement changed rows picks the next ones (internal/store/locks.go, db-r16-19).
var anyArray = regexp.MustCompile(`(?is)^(\s*(?:[\w.]+|\([\w.\s,]+\)))\s*=\s*ANY\s*\(\s*ARRAY\s*\((.*)\)\s*\)\s*$`)

func anyArrayAsIn(c string) string {
	if m := anyArray.FindStringSubmatch(c); m != nil {
		return m[1] + " IN (" + m[2] + ")"
	}
	return c
}
