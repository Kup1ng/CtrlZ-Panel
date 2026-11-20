package lockrank

import "strings"

// Writes reads the UPDATE and DELETE statements of a text and says, for each, whether it can lock more
// than one row of its table and, if it can, whether it locks them in one order (P1 auth review round 16,
// db-r16-19, rule lock-order).
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
// one token). A write is Keyed when the top-level WHERE of the statement holds the conjunct `id = $n`
// (one row of a table whose primary key ends in id, with the tenant column as the other conjunct).
//
// It is Ordered or NoWait only through ONE shape, read from the grammar of the WHERE and not from the
// presence of tokens (db-r16-22: the first reading took ORDER BY, FOR UPDATE and SKIP LOCKED anywhere in the
// clause, so a locking subselect of ANOTHER table, or one in an OR branch, made a statement of plan order
// look ordered). The WHERE has no top-level OR, and one of its top-level AND conjuncts is exactly
// `id = ANY (ARRAY (SELECT id FROM <the written table> ...))`, `id = ANY (SELECT id FROM <the written table>
// ...)` or `id IN (SELECT id FROM <the written table> ...)`, whose subselect, at its own level, is Ordered
// when it has ORDER BY id with no further key and then FOR UPDATE or FOR NO KEY UPDATE, and NoWait when that
// lock clause says SKIP LOCKED: the statement then writes only rows it locked without waiting, so it cannot be
// the waiting side of a cycle. Anything else (a second key, a lock clause of another level or table, the
// subselect in an OR branch, a column other than id, a set operation) is neither. It does not judge the rows
// of the tables a DELETE cascades to: the sessions rank is held first and the cascade follows the parent's
// order. Statements it cannot read are the caller's (Analyze refuses them first).

// RowWrite is one UPDATE or DELETE of a statement text.
type RowWrite struct {
	Table   string
	Kind    string // "update" or "delete"
	Keyed   bool
	Ordered bool
	NoWait  bool
	// Pinned are the columns the top-level conjuncts equate to one parameter (see pinnedBy).
	Pinned []string
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
		where := whereOf(toks, ti+1)
		w.Keyed = keyedBy(where)
		w.Ordered, w.NoWait = lockShape(table, where)
		w.Pinned = pinnedBy(where)
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

// keyedBy says whether one top-level conjunct of the clause is `id = $n` (or `alias.id = $n`).
func keyedBy(where []token) bool {
	depth := 0
	conj := []token{}
	flush := func() bool {
		ok := len(conj) == 3 && conj[0].k == 'w' && (conj[0].s == "id" || hasSuffix(conj[0].s, ".id")) &&
			conj[1].k == 'o' && conj[1].s == "=" && conj[2].k == 'w' && isParam(conj[2].s)
		conj = conj[:0]
		return ok
	}
	for _, tk := range where {
		switch {
		case tk.k == '(':
			depth++
			conj = append(conj, tk)
		case tk.k == ')':
			depth--
			conj = append(conj, tk)
		case depth == 0 && tk.k == 'w' && tk.s == "and":
			if flush() {
				return true
			}
		default:
			conj = append(conj, tk)
		}
	}
	return flush()
}

// lockShape reads the one shape that locks the rows of a statement in an order or without waiting (see the
// Contract of Writes). The conjuncts are taken at the top level of the clause, and a top-level OR anywhere
// makes the whole clause no shape, because `a AND id = ANY (...) OR b` writes the rows of b in plan order.
func lockShape(table string, where []token) (ordered, nowait bool) {
	if hasTopLevelOr(where) {
		return false, false
	}
	var conj []token
	judge := func() {
		if sub, arity, ok := idSubselect(conj); ok {
			o, n := subLocks(table, sub, arity)
			ordered = ordered || o && arity == 1
			nowait = nowait || n
		}
		conj = conj[:0]
	}
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
			judge()
		default:
			conj = append(conj, tk)
		}
	}
	judge()
	return ordered, nowait
}

func isIDWord(t token) bool {
	return t.k == 'w' && (t.s == "id" || hasSuffix(t.s, ".id"))
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

// keyOf reads the key at the start of a conjunct: the word id (arity 1) or a row of two or more words in
// parentheses, `(scope, key)`, for a table whose primary key is composite. It returns the arity and the index
// after the key.
func keyOf(c []token) (arity, next int) {
	if len(c) > 0 && isIDWord(c[0]) {
		return 1, 1
	}
	if len(c) == 0 || c[0].k != '(' {
		return 0, 0
	}
	i := 1
	for {
		if i >= len(c) || c[i].k != 'w' {
			return 0, 0
		}
		arity++
		i++
		if i < len(c) && c[i].k == ',' {
			i++
			continue
		}
		break
	}
	if i >= len(c) || c[i].k != ')' || arity < 2 {
		return 0, 0
	}
	return arity, i + 1
}

// idSubselect returns the tokens inside the subselect of a conjunct that is exactly
// `<key> = ANY (ARRAY (<sub>))`, `<key> = ANY (<sub>)` or `<key> IN (<sub>)`, with the arity of the key: nothing
// before the key and nothing after the closing paren, so the subselect is the whole of the condition.
func idSubselect(c []token) ([]token, int, bool) {
	arity, k := keyOf(c)
	if arity == 0 {
		return nil, 0, false
	}
	r := c[k:]
	n := len(r)
	switch {
	case n >= 4 && r[0].k == 'o' && r[0].s == "=" && isWord(r[1], "any") && r[2].k == '(':
		if n > 5 && isWord(r[3], "array") && r[4].k == '(' && closeOf(r, 4) == n-2 && closeOf(r, 2) == n-1 {
			return r[5 : n-2], arity, true
		}
		if closeOf(r, 2) == n-1 {
			return r[3 : n-1], arity, true
		}
	case n >= 3 && isWord(r[0], "in") && r[1].k == '(' && closeOf(r, 1) == n-1:
		return r[2 : n-1], arity, true
	}
	return nil, 0, false
}

// selectedKey reads `SELECT <key> FROM <table>` at the start of a subselect: the single column id (arity 1), or
// arity words, with or without parentheses around them. It returns the index after the table name.
func selectedKey(table string, sub []token, arity int) (int, bool) {
	if len(sub) < 4 || !isWord(sub[0], "select") {
		return 0, false
	}
	i := 1
	if arity == 1 {
		if !isIDWord(sub[1]) {
			return 0, false
		}
		i = 2
	} else {
		paren := sub[i].k == '('
		if paren {
			i++
		}
		for j := 0; j < arity; j++ {
			if i >= len(sub) || sub[i].k != 'w' {
				return 0, false
			}
			i++
			if j < arity-1 {
				if i >= len(sub) || sub[i].k != ',' {
					return 0, false
				}
				i++
			}
		}
		if paren {
			if i >= len(sub) || sub[i].k != ')' {
				return 0, false
			}
			i++
		}
	}
	if i+1 >= len(sub) || !isWord(sub[i], "from") || sub[i+1].k != 'w' {
		return 0, false
	}
	if t, ok := tableOf(sub[i+1].s); !ok || t != table {
		return 0, false
	}
	return i + 2, true
}

// subLocks reads a subselect at its own level: it must select the key FROM the written table, and its own
// level must carry the clauses (a lock clause of a nested or other level does not count). A composite key is
// never Ordered (the one order is by id), but a statement that takes its rows with SKIP LOCKED never waits.
func subLocks(table string, sub []token, arity int) (ordered, nowait bool) {
	after, ok := selectedKey(table, sub, arity)
	if !ok {
		return false, false
	}
	depth := 0
	orderAt, lockAt := -1, -1
	for i := after; i < len(sub); i++ {
		switch {
		case sub[i].k == '(':
			depth++
		case sub[i].k == ')':
			depth--
		case depth != 0:
		case isWord(sub[i], "union") || isWord(sub[i], "intersect") || isWord(sub[i], "except"):
			return false, false
		case isWord(sub[i], "order") && i+2 < len(sub) && isWord(sub[i+1], "by") && isIDWord(sub[i+2]):
			if i+3 < len(sub) && sub[i+3].k == ',' {
				continue // ORDER BY id, other: not one order for every statement
			}
			if orderAt < 0 {
				orderAt = i
			}
		case isWord(sub[i], "for") && lockedForWrite(sub[i+1:]):
			if lockAt < 0 {
				lockAt = i
			}
		}
	}
	if lockAt < 0 {
		return false, false
	}
	ordered = orderAt >= 0 && orderAt < lockAt
	// SKIP LOCKED belongs to the lock clause of this subselect: it follows FOR UPDATE or FOR NO KEY UPDATE.
	rest := sub[lockAt+1:]
	k := 1
	if isWord(rest[0], "no") {
		k = 3
	}
	nowait = k+1 < len(rest) && isWord(rest[k], "skip") && isWord(rest[k+1], "locked")
	return ordered, nowait
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

// pinnedBy returns the columns that the top-level conjuncts of the clause equate to one parameter or
// variable (`col = $n`, `a.col = p_x`, `$n = col`), alias dropped. A caller that knows the unique keys of a
// table (the live catalog) can then tell a write that names one row by a key other than id (a token hash, a
// composite primary key) from one that can touch several (db-r16-21). The clause with a top-level OR pins
// nothing.
func pinnedBy(where []token) []string {
	if hasTopLevelOr(where) {
		return nil
	}
	var out []string
	var conj []token
	flush := func() {
		if len(conj) == 3 && conj[1].k == 'o' && conj[1].s == "=" && conj[0].k == 'w' && conj[2].k == 'w' {
			col, par := conj[0].s, conj[2].s
			if isParam(col) && !isParam(par) {
				col, par = par, col
			}
			if isParam(par) {
				if i := strings.LastIndexByte(col, '.'); i >= 0 {
					col = col[i+1:]
				}
				out = append(out, col)
			}
		}
		conj = conj[:0]
	}
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
			flush()
		default:
			conj = append(conj, tk)
		}
	}
	flush()
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
