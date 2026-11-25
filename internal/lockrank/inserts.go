package lockrank

import "strings"

// RowInsert is one INSERT of a text, as far as its shape says whether it can add several rows and in what
// order (P1 auth review round 17, fix gate, db-r17-17).
//
// Why. Writes reads UPDATE and DELETE, and the class it guards ("every statement that can lock several rows of
// one table takes them in one order, or never waits") is wider: an INSERT of several rows into a table with a
// unique index waits for another transaction's UNCOMMITTED row of the same key (ON CONFLICT DO NOTHING waits
// too: it has to know whether that row commits), and it meets such rows in the order its plan produces them, so
// two statements that insert the same keys in different orders wait for each other. A sort is the one shape
// that makes the order a property of the statement and not of the plan.
//
// Contract. Multi is true for a source that can produce several rows: a SELECT with a FROM item, a set
// operation or a call of a function that can return a set, a WITH, a parenthesised query, TABLE, or VALUES with
// more than one tuple; false for DEFAULT VALUES, a single VALUES tuple and a plain SELECT with no FROM item
// (which adds the one row its WHERE lets through). Sorted is true
// when the source carries an ORDER BY at the statement's own level (before ON CONFLICT or RETURNING) and the
// whole list is ascending bare columns: DESC, USING, NULLS, an expression, a function call, a position and a
// collation all read as NOT sorted, because they are another order than every other inserter's (db-r18-6; the
// first form accepted any ORDER BY, so two inserters of one table could sort in opposite orders and both
// pass). OrderedBy is that list, names only, alias dropped. OrderedTo is, for each term, the column of the
// TARGET table that the statement's select list feeds from it (the term is the select item or its alias, and
// the item stands at the position of the column in the insert's column list), or "" when it feeds none or the
// insert has no column list, so the caller compares the order the ROWS are inserted in with the table's one
// order and not the spelling of a source alias. A source it cannot read is Multi and not Sorted, so it fails
// closed. Only ctrlz tables are read, as in Writes.
type RowInsert struct {
	Table     string
	Multi     bool
	Sorted    bool
	OrderedBy []string
	OrderedTo []string
}

// Inserts lists the INSERT statements of sql in order of appearance. A SELECT with no FROM item adds one row,
// unless its list holds a set-returning function (`SELECT unnest($1)`), and a text has no way to know which
// functions return sets: here every function call counts as one, so such a source is Multi (fail closed).
func Inserts(sql string) ([]RowInsert, error) {
	return InsertsWith(sql, func(string) bool { return true })
}

// InsertsWith is Inserts for a caller that knows which functions return sets (the live catalog:
// pg_proc.proretset): a call of a function for which setReturning is false does not make a SELECT with no
// FROM item several rows. The name is the one after the last dot, lower case.
func InsertsWith(sql string, setReturning func(name string) bool) ([]RowInsert, error) {
	toks, err := lex(sql)
	if err != nil {
		return nil, err
	}
	var out []RowInsert
	for i := 0; i+2 < len(toks); i++ {
		if !isWord(toks[i], "insert") || !isWord(toks[i+1], "into") || toks[i+2].k != 'w' {
			continue
		}
		table, ok := tableOf(toks[i+2].s)
		if !ok {
			continue
		}
		out = append(out, readInsert(toks, i+3, table, setReturning))
	}
	return out, nil
}

// readInsert reads what follows the table of an INSERT: an alias, a column list, OVERRIDING, then the source.
func readInsert(toks []token, i int, table string, setReturning func(string) bool) RowInsert {
	ri := RowInsert{Table: table, Multi: true}
	if i < len(toks) && isWord(toks[i], "as") {
		i += 2
	} else if i < len(toks) && toks[i].k == 'w' && !notAlias(toks[i].s) && toks[i].s != "overriding" && toks[i].s != "default" && toks[i].s != "select" && toks[i].s != "with" && toks[i].s != "table" {
		i++
	}
	// A column list is a parenthesis that does not open a query.
	var cols []string
	if i < len(toks) && toks[i].k == '(' && !(i+1 < len(toks) && (isWord(toks[i+1], "select") || isWord(toks[i+1], "with") || isWord(toks[i+1], "values"))) {
		if c := closeOf(toks, i); c >= 0 {
			for _, tk := range toks[i+1 : c] {
				if tk.k == 'w' {
					cols = append(cols, lastPart(tk.s))
				}
			}
			i = c + 1
		}
	}
	for i < len(toks) && toks[i].k == 'w' && (toks[i].s == "overriding" || toks[i].s == "system" || toks[i].s == "user" || toks[i].s == "value") {
		i++
	}
	if i >= len(toks) {
		return ri
	}
	switch {
	case isWord(toks[i], "default"):
		ri.Multi = false
		return ri
	case isWord(toks[i], "values"):
		ri.Multi = valuesTuples(toks[i+1:]) > 1
		return ri
	}
	// A query: sorted when an ORDER BY stands at this level before the conflict clause or RETURNING; one row
	// when it is a plain SELECT with no FROM item at its own level, no set operation and no call of a function
	// that can return a set.
	depth := 0
	plain := isWord(toks[i], "select")
	calls := false
	orderAt := -1
	// finish reads the sort list once the end of the statement's own level is known.
	finish := func(end int) RowInsert {
		ri.Multi = !plain || calls
		if orderAt >= 0 {
			ri.OrderedBy, ri.OrderedTo, ri.Sorted = readSort(toks, i, orderAt, end, cols)
		}
		return ri
	}
	for j := i; j < len(toks); j++ {
		if toks[j].k == 'w' && j+1 < len(toks) && toks[j+1].k == '(' && setReturning(lastPart(toks[j].s)) {
			calls = true
		}
		switch {
		case toks[j].k == '(':
			depth++
		case toks[j].k == ')':
			depth--
			if depth < 0 {
				return finish(j)
			}
		case toks[j].k == ';' && depth == 0:
			return finish(j)
		case depth == 0 && (isWord(toks[j], "returning") || isWord(toks[j], "on") && j+1 < len(toks) && isWord(toks[j+1], "conflict")):
			return finish(j)
		case depth == 0 && (isWord(toks[j], "from") || isWord(toks[j], "union") || isWord(toks[j], "intersect") || isWord(toks[j], "except")):
			plain = false
		case depth == 0 && isWord(toks[j], "order") && j+1 < len(toks) && isWord(toks[j+1], "by") && orderAt < 0:
			orderAt = j
		}
	}
	return finish(len(toks))
}

// readSort reads the ORDER BY of an insert's source that starts at toks[orderAt] and ends before toks[end]:
// the terms, whether every one is a bare ascending column, and the target column each feeds. A clause that
// holds anything else (a function, an operator, DESC, USING, NULLS, COLLATE, a number) is not sorted.
func readSort(toks []token, from, orderAt, end int, cols []string) (by, to []string, ok bool) {
	r := toks[orderAt+2 : end]
	// LIMIT, OFFSET, FETCH and a lock clause end the list; a row-locking clause has no meaning in an insert's
	// source but is not part of the sort either.
	for k, tk := range r {
		if tk.k == 'w' && orderTailEnd(tk.s) {
			r = r[:k]
			break
		}
	}
	if len(r) == 0 {
		return nil, nil, false
	}
	var terms []string // the words as written, qualifier kept
	for _, it := range splitTop(r) {
		if len(it) == 2 && isWord(it[1], "asc") {
			it = it[:1]
		}
		if len(it) != 1 || it[0].k != 'w' || notAlias(it[0].s) || it[0].s[0] == '$' || it[0].s[0] >= '0' && it[0].s[0] <= '9' {
			return nil, nil, false
		}
		terms = append(terms, it[0].s)
		by = append(by, lastPart(it[0].s))
	}
	// Which select item a term sorts by is the server's rule, not a matter of spelling (db-r18-16): a BARE name
	// is the name of an output column first (its alias, or a lone column's name), but a QUALIFIED name (x.c)
	// is always an input column and never an output alias, so it feeds the item that is that very column
	// (`x.c` or `x.c AS a`), and an item that merely shares its last part (`md5(x.c) AS c`) is a different
	// value.
	items := selectItems(toks, from, orderAt)
	for _, term := range terms {
		col := ""
		for pos, it := range items {
			if pos >= len(cols) {
				break
			}
			if strings.Contains(term, ".") && it.word == term || !strings.Contains(term, ".") && it.name == term {
				col = cols[pos]
				break
			}
		}
		to = append(to, col)
	}
	return by, to, true
}

// splitTop splits tokens at the commas that stand outside every parenthesis.
func splitTop(r []token) [][]token {
	var out [][]token
	depth, start := 0, 0
	for k, tk := range r {
		switch {
		case tk.k == '(':
			depth++
		case tk.k == ')':
			depth--
		case tk.k == ',' && depth == 0:
			out = append(out, r[start:k])
			start = k + 1
		}
	}
	return append(out, r[start:])
}

// selectItem is one item of a SELECT list: the name it goes by (its alias, or a lone column's name; "" for
// any other expression) and, when what it computes is one bare or qualified column, that word as written.
type selectItem struct{ name, word string }

// outputNames returns, per position of the SELECT list that starts at toks[from], the name the item goes by.
// A source that is not a plain SELECT has no names (the caller then finds no target column and the sort does
// not count).
func outputNames(toks []token, from, orderAt int) []string {
	var out []string
	for _, it := range selectItems(toks, from, orderAt) {
		out = append(out, it.name)
	}
	return out
}

// selectItems reads the select list that starts at toks[from] and ends at its FROM or at orderAt.
func selectItems(toks []token, from, orderAt int) []selectItem {
	if from >= len(toks) || !isWord(toks[from], "select") {
		return nil
	}
	j := from + 1
	if j < len(toks) && (isWord(toks[j], "distinct") || isWord(toks[j], "all")) {
		j++
	}
	depth, end := 0, orderAt
	for k := j; k < orderAt; k++ {
		switch {
		case toks[k].k == '(':
			depth++
		case toks[k].k == ')':
			depth--
		case depth == 0 && isWord(toks[k], "from"):
			end = k
			k = orderAt
		}
	}
	var out []selectItem
	for _, it := range splitTop(toks[j:end]) {
		var si selectItem
		expr := it
		switch {
		case len(it) >= 3 && isWord(it[len(it)-2], "as") && it[len(it)-1].k == 'w':
			si.name = it[len(it)-1].s
			expr = it[:len(it)-2]
		case len(it) == 1 && it[0].k == 'w':
			si.name = lastPart(it[0].s)
		case len(it) >= 2 && it[len(it)-1].k == 'w' && it[len(it)-2].k != 'o' && !notAlias(it[len(it)-1].s):
			si.name = it[len(it)-1].s
			expr = it[:len(it)-1]
		}
		if len(expr) == 1 && expr[0].k == 'w' {
			si.word = expr[0].s
		}
		out = append(out, si)
	}
	return out
}

// lastPart returns the part of a possibly qualified name after its last dot.
func lastPart(w string) string {
	for i := len(w) - 1; i >= 0; i-- {
		if w[i] == '.' {
			return w[i+1:]
		}
	}
	return w
}

// valuesTuples counts the top-level parenthesised tuples that follow VALUES.
func valuesTuples(r []token) int {
	n, depth := 0, 0
	for _, t := range r {
		switch {
		case t.k == '(':
			if depth == 0 {
				n++
			}
			depth++
		case t.k == ')':
			depth--
			if depth < 0 {
				return n
			}
		case t.k == ';' && depth == 0:
			return n
		case depth == 0 && t.k == 'w' && (t.s == "on" || t.s == "returning"):
			return n
		}
	}
	return n
}

// InsertKey is the one order in which every multi-row INSERT into a table sorts its rows, and why that key.
type InsertKey struct {
	Cols []string
	Why  string
}

// InsertOrder is the closed table of the tables that are inserted into several rows at a time (db-r18-6). Two
// inserters of one table that sort by different keys can wait for each other's uncommitted rows (the order is
// a property of the statement and not of the plan only when it is the SAME order), so the order is declared
// here once, for the table, and a statement is judged against it: its sort list, read to the target columns
// it feeds (RowInsert.OrderedTo), must be exactly this list. A table that is not listed fails closed, and so
// does any other sort (DESC, USING, an expression, a function, a position). The key is the one that a second
// transaction can collide on: a generated id never collides, so a table whose rows carry a caller-chosen
// unique value sorts by that value.
func InsertOrder() map[string]InsertKey {
	return map[string]InsertKey{
		"recovery_codes": {Cols: []string{"code_hash"}, Why: "the unique value the caller chooses; the id is generated and never collides"},
		"policy_outbox":  {Cols: []string{"tenant_id"}, Why: "one row per tenant of the batch; the dedupe key leads with the tenant and the batch id is the same for the whole statement"},
	}
}

// InsertOrderProblem says why a multi-row insert is not in the table's one order, or "" when it is (or adds
// one row and has no order to keep).
func InsertOrderProblem(in RowInsert) string {
	if !in.Multi {
		return ""
	}
	if !in.Sorted {
		return "an INSERT into ctrlz." + in.Table + " that can add several rows does not sort them by an ascending list of bare columns (ORDER BY a, b: not DESC, USING, NULLS, an expression, a function or a position), so two transactions that insert the same keys can wait for each other"
	}
	key, ok := InsertOrder()[in.Table]
	if !ok {
		return "ctrlz." + in.Table + " is inserted into several rows at a time but has no entry in lockrank.InsertOrder: declare the one order every such insert sorts by, with the reason"
	}
	if len(in.OrderedTo) != len(key.Cols) {
		return "an INSERT into ctrlz." + in.Table + " sorts by " + strings.Join(in.OrderedTo, ", ") + " (the columns the sort feeds), not by the table's one insert order " + strings.Join(key.Cols, ", ")
	}
	for i, c := range key.Cols {
		if in.OrderedTo[i] != c {
			return "an INSERT into ctrlz." + in.Table + " sorts by " + strings.Join(in.OrderedTo, ", ") + " (the columns the sort feeds), not by the table's one insert order " + strings.Join(key.Cols, ", ")
		}
	}
	return ""
}
