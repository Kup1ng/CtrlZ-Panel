package lockrank

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
// when the source carries an ORDER BY at the statement's own level (before ON CONFLICT or RETURNING). It does
// not say by WHICH columns: that two multi-row inserters of one table sort alike is the caller's to check,
// and no table has two today. A source it cannot read is Multi and not Sorted, so it fails closed. Only
// ctrlz tables are read, as in Writes.
type RowInsert struct {
	Table  string
	Multi  bool
	Sorted bool
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
	if i < len(toks) && toks[i].k == '(' && !(i+1 < len(toks) && (isWord(toks[i+1], "select") || isWord(toks[i+1], "with") || isWord(toks[i+1], "values"))) {
		if c := closeOf(toks, i); c >= 0 {
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
				ri.Multi = !plain || calls
				return ri
			}
		case toks[j].k == ';' && depth == 0:
			ri.Multi = !plain || calls
			return ri
		case depth == 0 && (isWord(toks[j], "returning") || isWord(toks[j], "on") && j+1 < len(toks) && isWord(toks[j+1], "conflict")):
			ri.Multi = !plain || calls
			return ri
		case depth == 0 && (isWord(toks[j], "from") || isWord(toks[j], "union") || isWord(toks[j], "intersect") || isWord(toks[j], "except")):
			plain = false
		case depth == 0 && isWord(toks[j], "order") && j+1 < len(toks) && isWord(toks[j+1], "by"):
			ri.Sorted = true
		}
	}
	ri.Multi = !plain || calls
	return ri
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
