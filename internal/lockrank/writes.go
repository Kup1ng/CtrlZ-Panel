package lockrank

import "strings"

// Writes reads the UPDATE and DELETE statements of a text and says, for each, whether it can lock more
// than one row of its table and, if it can, whether it locks them in one order (P1 auth review round 16,
// db-r16-19, rule lock-order; rebuilt as one grammar in round 17, db-r17-2, -3 and -10).
//
// Why. The rank of this package orders the TABLES a transaction locks. Inside one table (rank) the rows
// of a multi-row UPDATE or DELETE are locked in the order the statement happens to scan them, and two
// statements that scan the same rows by different paths (the worker's sweep of expired sessions by an
// IN-subselect, a user's "log out all" by its own predicate) lock them in opposite orders and deadlock
// (40P01, a 503 for one of them). The old rule left "the intra-rank order of a multi-row UPDATE" to the
// statement's author, and the author is not in the room when the next statement is written. The rule is
// now one shape: a statement that can touch several rows takes them through a locking subselect that
// orders by the primary key, `id IN (SELECT id FROM t WHERE ... ORDER BY id FOR UPDATE)`, which every
// such statement shares, so two of them can only meet in the same order.
//
// Contract. It reads statements as the lexer of Analyze does (comments dropped, strings opaque, a name is
// one token). Every verdict below is read from ONE grammar of the WHERE clause (rounds 16 and 17 each found
// a verdict that looked for a token and ignored the rest of the clause), and a column is believed to be a
// column of the written table only when its spelling says so (a scope, below):
//
//   - The WHERE has no top-level OR. With one, no conjunct binds the statement (the other branch writes its
//     rows in whatever order it likes), so Keyed, Ordered, NoWait and Pinned are all empty.
//   - A column of the written table is the bare name when the statement has no FROM or USING list, or a name
//     qualified by the alias declared for the target (by the table name when none is declared). A bare name
//     in a statement that joins another table, and a column qualified by the alias of a joined table, are not
//     the written table's: `... FROM ctrlz.sessions s WHERE s.id = $2 AND r.session_id = s.id` writes many
//     refresh rows although `s.id` is pinned.
//   - A write is Keyed when one top-level conjunct is exactly `id = $n` (a parameter or a PL/pgSQL name p_*
//     or v_*) over a column of the written table.
//   - It is Ordered or NoWait only through ONE shape: one top-level conjunct that is exactly
//     `<key> = ANY (ARRAY (SELECT <key> FROM <the written table> ...))`, `<key> = ANY (SELECT ...)` or
//     `<key> IN (SELECT ...)`, where the key is `id`, `ctid` (the physical address of a row the subselect
//     locks, which an index can find where a row comparison of a composite key cannot) or a row of two or
//     more columns for a composite key, over columns of the written table, and the subselect selects the
//     same key. The subselect reads ONE table (no join, no second FROM item). It is Ordered when it has
//     ORDER BY id, ascending, directly followed by LIMIT, OFFSET, FETCH, FOR or its end (a descending key, a
//     cast, USING, a second key or any other token after the key is another order than every other writer's)
//     and then FOR UPDATE or FOR NO KEY UPDATE, and NoWait when that lock clause says SKIP LOCKED: the
//     statement then writes only rows it locked without waiting, so it cannot be the waiting side of a cycle.
//     Only the id key is ever Ordered. A table with no id (a composite primary key) cannot be Ordered, and
//     RowWrite.OrderedBy then says by which columns the one locking subselect sorts, ascending, so a caller
//     that knows the table's unique keys (the live catalog) can accept the sort that IS the key.
//
// Anything else (a second key, a lock clause of another level or table, the subselect in an OR branch, a
// column other than the key, a set operation, a join in the subselect) is neither. It does not judge the
// rows of the tables a DELETE cascades to: the sessions rank is held first and the cascade follows the
// parent's order. Statements it cannot read are the caller's (Analyze refuses them first).

// RowWrite is one UPDATE or DELETE of a statement text.
type RowWrite struct {
	Table   string
	Kind    string // "update" or "delete"
	Keyed   bool
	Ordered bool
	NoWait  bool
	// OrderedBy are the columns of the sort of the locking subselect (every key kind), in order, when the
	// sort is a plain ascending list of columns of the written table directly followed by the end of the
	// clause and then FOR UPDATE or FOR NO KEY UPDATE; nil otherwise. Ordered is the case ["id"] on an id key.
	OrderedBy []string
	// Pinned are the columns the top-level conjuncts equate to one parameter (see pinnedBy).
	Pinned []string
	// Batches are the top-level conjuncts that take the statement's rows from a LIMITed subselect of the written
	// table, whatever lock the subselect takes (the bounded-sweeps lint asks it; db-r17-14).
	Batches []Batch
}

// Batch is one conjunct `<key> = ANY (ARRAY (SELECT <key> FROM <the written table> ... LIMIT <expr>))`, `... = ANY
// (SELECT ...)` or `<key> IN (SELECT ...)`, read by the same grammar as the lock shape: the key columns are
// columns of the written table (an alias of a joined table is not), the subselect reads that one table and
// selects the same key, and the LIMIT is the subselect's own. Limit is the tokens of the LIMIT expression.
type Batch struct {
	Key   []string
	Limit []string
}

// scope says which spellings of a column belong to the one table a clause speaks about.
type scope struct {
	table  string // the bare table name
	alias  string // the alias declared for it, "" when none
	single bool   // no other table is in the statement's FROM or USING list, so a bare column is this table's
}

// col returns the column a word names and whether the word is a column of the scope's table.
func (s scope) col(w string) (string, bool) {
	i := strings.LastIndexByte(w, '.')
	if i < 0 {
		return w, s.single
	}
	q := w[:i]
	own := s.alias != "" && q == s.alias || s.alias == "" && (q == s.table || q == "ctrlz."+s.table)
	return w[i+1:], own
}

// Writes lists the writes of sql in order of appearance.
func Writes(sql string) ([]RowWrite, error) {
	toks, err := lex(sql)
	if err != nil {
		return nil, err
	}
	var out []RowWrite
	for i := 0; i+1 < len(toks); i++ {
		if toks[i].k != 'w' {
			continue
		}
		kind, ti := "", 0
		switch {
		case toks[i].s == "update" && !lockClauseBefore(toks, i):
			kind, ti = "update", i+1
		case toks[i].s == "delete" && toks[i+1].k == 'w' && toks[i+1].s == "from":
			kind, ti = "delete", i+2
		default:
			continue
		}
		if ti >= len(toks) || toks[ti].k != 'w' {
			continue
		}
		table, ok := tableOf(toks[ti].s)
		if !ok {
			continue
		}
		w := RowWrite{Table: table, Kind: kind}
		sc := headOf(toks, ti+1, table, kind)
		where := whereOf(toks, ti+1)
		w.Keyed = keyedBy(sc, where)
		w.Ordered, w.NoWait, w.OrderedBy = lockShape(sc, where)
		w.Batches = batchesOf(sc, where)
		w.Pinned = pinnedBy(sc, where)
		out = append(out, w)
	}
	return out, nil
}

// lockClauseBefore says whether the UPDATE at i is the word of FOR UPDATE or FOR NO KEY UPDATE.
func lockClauseBefore(toks []token, i int) bool {
	if i == 0 || toks[i-1].k != 'w' {
		return false
	}
	p := toks[i-1].s
	return p == "for" || p == "key" || p == "do"
}

// headOf reads what follows the target of a write: its alias, and whether the statement joins another
// table (a FROM list of an UPDATE, a USING list of a DELETE, at the statement's own depth).
func headOf(toks []token, from int, table, kind string) scope {
	sc := scope{table: table, single: true}
	i := from
	if i < len(toks) && isWord(toks[i], "as") {
		i++
		if i < len(toks) && toks[i].k == 'w' {
			sc.alias = toks[i].s
		}
	} else if i < len(toks) && toks[i].k == 'w' && !notAlias(toks[i].s) {
		sc.alias = toks[i].s
	}
	join := "from"
	if kind == "delete" {
		join = "using"
	}
	depth := 0
	for j := from; j < len(toks); j++ {
		tk := toks[j]
		switch {
		case tk.k == '(':
			depth++
		case tk.k == ')':
			if depth == 0 {
				return sc
			}
			depth--
		case depth > 0:
		case tk.k == ';' || isWord(tk, "where") || isWord(tk, "returning"):
			return sc
		case isWord(tk, join):
			sc.single = false
		}
	}
	return sc
}

// whereOf returns the tokens of the WHERE clause of the write whose target ends before index from, at the
// statement's own depth: it stops at RETURNING, at a semicolon, or at the paren that closes the statement
// when it sits inside a CTE or a subquery. Nested parentheses stay in the slice.
func whereOf(toks []token, from int) []token {
	depth := 0
	start := -1
	for j := from; j < len(toks); j++ {
		tk := toks[j]
		switch {
		case tk.k == '(':
			depth++
		case tk.k == ')':
			if depth == 0 {
				if start < 0 {
					return nil
				}
				return toks[start:j]
			}
			depth--
		case tk.k == ';' && depth == 0:
			if start < 0 {
				return nil
			}
			return toks[start:j]
		case tk.k == 'w' && depth == 0 && tk.s == "returning":
			if start < 0 {
				return nil
			}
			return toks[start:j]
		case tk.k == 'w' && depth == 0 && tk.s == "where" && start < 0:
			start = j + 1
		}
	}
	if start < 0 {
		return nil
	}
	return toks[start:]
}

// conjuncts splits a clause at its top-level ANDs and calls f with each conjunct. A clause with a top-level
// OR has no conjuncts that bind the statement, so f is not called at all: this is the one place every verdict
// takes that rule from (db-r17-2 and -10: keyedBy had read `id = $n AND ... OR ...` as one row).
func conjuncts(where []token, f func(c []token)) {
	if hasTopLevelOr(where) {
		return
	}
	var conj []token
	depth := 0
	for _, tk := range where {
		switch {
		case tk.k == '(':
			depth++
			conj = append(conj, tk)
		case tk.k == ')':
			depth--
			conj = append(conj, tk)
		case depth == 0 && isWord(tk, "and"):
			f(conj)
			conj = nil
		default:
			conj = append(conj, tk)
		}
	}
	f(conj)
}

// keyedBy says whether one top-level conjunct of the clause is `id = $n` over a column of the written table.
func keyedBy(sc scope, where []token) bool {
	keyed := false
	conjuncts(where, func(c []token) {
		// A cast of the parameter (`id = $2::uuid`) is the same one row: the two ':' of the cast are tokens of
		// their own, followed by the type name.
		if len(c) == 6 && c[3].k == 'o' && c[3].s == ":" && c[4].k == 'o' && c[4].s == ":" && c[5].k == 'w' {
			c = c[:3]
		}
		if len(c) == 3 && c[0].k == 'w' && c[1].k == 'o' && c[1].s == "=" && c[2].k == 'w' && isParam(c[2].s) {
			if col, own := sc.col(c[0].s); own && col == "id" {
				keyed = true
			}
		}
	})
	return keyed
}

// lockShape reads the one shape that locks the rows of a statement in an order or without waiting (see the
// Contract of Writes).
func lockShape(sc scope, where []token) (ordered, nowait bool, orderedBy []string) {
	conjuncts(where, func(c []token) {
		if sub, key, ok := idSubselect(sc, c); ok {
			o, n, by := subLocks(sc.table, sub, key)
			ordered = ordered || o
			nowait = nowait || n
			if orderedBy == nil {
				orderedBy = by
			}
		}
	})
	return ordered, nowait, orderedBy
}

// batchesOf reads the Batches of a clause (see Batch).
func batchesOf(sc scope, where []token) []Batch {
	var out []Batch
	conjuncts(where, func(c []token) {
		sub, key, ok := idSubselect(sc, c)
		if !ok {
			return
		}
		_, after, ok := selectedKey(sc.table, sub, key)
		if !ok {
			return
		}
		if lim := limitOf(sub[after:]); len(lim) > 0 {
			out = append(out, Batch{Key: key, Limit: lim})
		}
	})
	return out
}

// limitOf returns the tokens of the LIMIT expression at the level of the tokens it is given: from the word
// after LIMIT to OFFSET, FETCH, FOR or the end (a LIMIT of a nested level is not this level's).
func limitOf(r []token) []string {
	depth := 0
	for i := 0; i < len(r); i++ {
		switch {
		case r[i].k == '(':
			depth++
		case r[i].k == ')':
			depth--
		case depth == 0 && isWord(r[i], "limit"):
			var out []string
			d := 0
			for _, t := range r[i+1:] {
				if d == 0 && t.k == 'w' && (t.s == "offset" || t.s == "fetch" || t.s == "for") {
					break
				}
				switch t.k {
				case '(':
					d++
				case ')':
					d--
				}
				out = append(out, t.s)
			}
			return out
		}
	}
	return nil
}

func isWord(t token, s string) bool { return t.k == 'w' && t.s == s }

// closeOf returns the index of the paren that closes the one opened at c[open], or -1.
func closeOf(c []token, open int) int {
	depth := 0
	for i := open; i < len(c); i++ {
		switch c[i].k {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// keyOf reads the key at the start of a conjunct: the word id or ctid over a column of the written table
// (one column), or a row of two or more such words in parentheses, `(scope, key)`, for a table whose primary
// key is composite. It returns the key's column names and the index after the key.
func keyOf(sc scope, c []token) (cols []string, next int) {
	if len(c) > 0 && c[0].k == 'w' {
		if col, own := sc.col(c[0].s); own && (col == "id" || col == "ctid") {
			return []string{col}, 1
		}
		return nil, 0
	}
	if len(c) == 0 || c[0].k != '(' {
		return nil, 0
	}
	i := 1
	for {
		if i >= len(c) || c[i].k != 'w' {
			return nil, 0
		}
		col, own := sc.col(c[i].s)
		if !own {
			return nil, 0
		}
		cols = append(cols, col)
		i++
		if i < len(c) && c[i].k == ',' {
			i++
			continue
		}
		break
	}
	if i >= len(c) || c[i].k != ')' || len(cols) < 2 {
		return nil, 0
	}
	return cols, i + 1
}

// idSubselect returns the tokens inside the subselect of a conjunct that is exactly
// `<key> = ANY (ARRAY (<sub>))`, `<key> = ANY (<sub>)` or `<key> IN (<sub>)`, with the key's columns: nothing
// before the key and nothing after the closing paren, so the subselect is the whole of the condition.
func idSubselect(sc scope, c []token) ([]token, []string, bool) {
	cols, k := keyOf(sc, c)
	if cols == nil {
		return nil, nil, false
	}
	r := c[k:]
	n := len(r)
	switch {
	case n >= 4 && r[0].k == 'o' && r[0].s == "=" && isWord(r[1], "any") && r[2].k == '(':
		if n > 5 && isWord(r[3], "array") && r[4].k == '(' && closeOf(r, 4) == n-2 && closeOf(r, 2) == n-1 {
			return r[5 : n-2], cols, true
		}
		if closeOf(r, 2) == n-1 {
			return r[3 : n-1], cols, true
		}
	case n >= 3 && isWord(r[0], "in") && r[1].k == '(' && closeOf(r, 1) == n-1:
		return r[2 : n-1], cols, true
	}
	return nil, nil, false
}

// subEnds are the words that may follow the one table of a subselect's FROM list: nothing else (a join, a
// comma item, a second table, a set operation) keeps the subselect to one table.
func subEnd(w string) bool {
	switch w {
	case "where", "order", "limit", "offset", "for", "fetch":
		return true
	}
	return false
}

// selectedKey reads `SELECT <key> FROM <table> [[AS] alias]` at the start of a subselect, requiring that the
// table is the written one, that it is the ONLY item of the FROM list, and that the selected columns are the
// key of the outer conjunct (the same names, each a column of that table). It returns the subselect's scope
// and the index after the FROM item.
func selectedKey(table string, sub []token, cols []string) (scope, int, bool) {
	if len(sub) < 4 || !isWord(sub[0], "select") {
		return scope{}, 0, false
	}
	i := 1
	paren := len(cols) > 1 && sub[i].k == '('
	if paren {
		i++
	}
	var sel []string
	for j := range cols {
		if i >= len(sub) || sub[i].k != 'w' {
			return scope{}, 0, false
		}
		sel = append(sel, sub[i].s)
		i++
		if j < len(cols)-1 {
			if i >= len(sub) || sub[i].k != ',' {
				return scope{}, 0, false
			}
			i++
		}
	}
	if paren {
		if i >= len(sub) || sub[i].k != ')' {
			return scope{}, 0, false
		}
		i++
	}
	if i+1 >= len(sub) || !isWord(sub[i], "from") || sub[i+1].k != 'w' {
		return scope{}, 0, false
	}
	if t, ok := tableOf(sub[i+1].s); !ok || t != table {
		return scope{}, 0, false
	}
	sc := scope{table: table, single: true}
	i += 2
	switch {
	case i < len(sub) && isWord(sub[i], "as") && i+1 < len(sub) && sub[i+1].k == 'w':
		sc.alias = sub[i+1].s
		i += 2
	case i < len(sub) && sub[i].k == 'w' && !notAlias(sub[i].s):
		sc.alias = sub[i].s
		i++
	}
	if i < len(sub) && !(sub[i].k == 'w' && subEnd(sub[i].s)) {
		return scope{}, 0, false
	}
	for j, w := range sel {
		if col, own := sc.col(w); !own || col != cols[j] {
			return scope{}, 0, false
		}
	}
	return sc, i, true
}

// orderTailEnds are the words that may follow `ORDER BY id [ASC]` in a subselect that takes the one order.
func orderTailEnd(w string) bool {
	switch w {
	case "limit", "offset", "fetch", "for":
		return true
	}
	return false
}

// subLocks reads a subselect at its own level: it must select the key FROM the written table, and its own
// level must carry the clauses (a lock clause of a nested or other level does not count). A key other than id
// is never Ordered (the one order is by id), but a statement that takes its rows with SKIP LOCKED never waits.
func subLocks(table string, sub []token, cols []string) (ordered, nowait bool, orderedBy []string) {
	sc, after, ok := selectedKey(table, sub, cols)
	if !ok {
		return false, false, nil
	}
	var sortCols []string
	depth := 0
	orderAt, lockAt := -1, -1
	badOrder := false
	for i := after; i < len(sub); i++ {
		switch {
		case sub[i].k == '(':
			depth++
		case sub[i].k == ')':
			depth--
		case depth != 0:
		case isWord(sub[i], "union") || isWord(sub[i], "intersect") || isWord(sub[i], "except"):
			return false, false, nil
		case isWord(sub[i], "order") && i+1 < len(sub) && isWord(sub[i+1], "by"):
			// The whole sort clause is read: a list of columns of this table, each ascending, and the next token
			// is the end of the clause. DESC, a cast, USING or a NULLS clause lock the rows in another order
			// than the writers that share the shape.
			list, good := sortList(sc, sub[i+2:])
			if good && orderAt < 0 {
				orderAt = i
				sortCols = list
			} else {
				badOrder = true
			}
		case isWord(sub[i], "for") && lockedForWrite(sub[i+1:]):
			if lockAt < 0 {
				lockAt = i
			}
		}
	}
	if lockAt < 0 {
		return false, false, nil
	}
	sorted := orderAt >= 0 && !badOrder && orderAt < lockAt
	if sorted {
		orderedBy = sortCols
	}
	ordered = sorted && len(cols) == 1 && cols[0] == "id" && len(sortCols) == 1 && sortCols[0] == "id"
	// SKIP LOCKED belongs to the lock clause of this subselect: it follows FOR UPDATE or FOR NO KEY UPDATE.
	rest := sub[lockAt+1:]
	k := 1
	if isWord(rest[0], "no") {
		k = 3
	}
	nowait = k+1 < len(rest) && isWord(rest[k], "skip") && isWord(rest[k+1], "locked")
	return ordered, nowait, orderedBy
}

// sortList reads the list that follows ORDER BY: columns of the scope's table, each optionally ASC, separated
// by commas, and then the end of the subselect or one of the words that end a sort clause. It reports the
// column names and whether the whole clause was of that shape.
func sortList(sc scope, r []token) ([]string, bool) {
	var cols []string
	i := 0
	for {
		if i >= len(r) || r[i].k != 'w' {
			return nil, false
		}
		col, own := sc.col(r[i].s)
		if !own || orderTailEnd(r[i].s) {
			return nil, false
		}
		cols = append(cols, col)
		i++
		if i < len(r) && isWord(r[i], "asc") {
			i++
		}
		if i < len(r) && r[i].k == ',' {
			i++
			continue
		}
		break
	}
	return cols, i >= len(r) || r[i].k == 'w' && orderTailEnd(r[i].s)
}

func hasSuffix(s, suf string) bool {
	return len(s) >= len(suf) && s[len(s)-len(suf):] == suf
}

// lockedForWrite says whether the tokens after FOR spell UPDATE or NO KEY UPDATE (the two write locks).
func lockedForWrite(rest []token) bool {
	w := func(i int, s string) bool { return i < len(rest) && rest[i].k == 'w' && rest[i].s == s }
	return w(0, "update") || w(0, "no") && w(1, "key") && w(2, "update")
}

// isParam says whether a word is a bind parameter ($n) or a PL/pgSQL parameter or variable. The definer functions
// of the migrations name their parameters p_* and their variables v_* (the convention is the one place a
// variable is told from a column in a body), so `id = p_request_id` names one row as `id = $2` does.
func isParam(w string) bool {
	if len(w) > 1 && w[0] == '$' {
		return true
	}
	return len(w) > 2 && (w[:2] == "p_" || w[:2] == "v_") && !strings.Contains(w, ".")
}

// pinnedBy returns the columns of the written table that the top-level conjuncts of the clause equate to one
// parameter or variable (`col = $n`, `a.col = p_x`, `$n = col`), alias dropped. A caller that knows the unique
// keys of a table (the live catalog) can then tell a write that names one row by a key other than id (a token
// hash, a composite primary key) from one that can touch several (db-r16-21). The clause with a top-level OR
// pins nothing, and neither does a column of a joined table (db-r17-10).
func pinnedBy(sc scope, where []token) []string {
	var out []string
	conjuncts(where, func(c []token) {
		if len(c) == 3 && c[1].k == 'o' && c[1].s == "=" && c[0].k == 'w' && c[2].k == 'w' {
			col, par := c[0].s, c[2].s
			if isParam(col) && !isParam(par) {
				col, par = par, col
			}
			if isParam(par) && !isParam(col) {
				if name, own := sc.col(col); own {
					out = append(out, name)
				}
			}
		}
	})
	return out
}

// hasTopLevelOr says whether the clause has an OR outside every parenthesis: a conjunct of such a clause
// does not bind the statement, because the other branch writes its rows in whatever order it likes.
func hasTopLevelOr(where []token) bool {
	depth := 0
	for _, tk := range where {
		switch {
		case tk.k == '(':
			depth++
		case tk.k == ')':
			depth--
		case depth == 0 && isWord(tk, "or"):
			return true
		}
	}
	return false
}
