package lockrank

// QueryLoop context of a write (P1 auth review round 18, db-r18-8).
//
// Why. A definer function that sweeps by looking rows up and then writing them one at a time
// (`FOR v_id IN SELECT s.id ... ORDER BY s.id LIMIT n LOOP DELETE ... WHERE d.id = v_id`) takes its row locks
// in the order of the LOOP'S QUERY. The write itself is Keyed (one row), so the statement-level reading
// calls it safe whether or not the query sorts, and a later CREATE OR REPLACE that drops the ORDER BY passed
// every guard: two overlapping runs (a worker restarted beside the old one) then take the same rows in plan
// order and one dies of 40P01. The class is "a lock is taken in the order of whatever drives the statement":
// the loop that drives a write is read like the subselect that drives a multi-row one.
//
// Contract. For every UPDATE and DELETE that stands inside a loop of a PL/pgSQL body, RowWrite.InQueryLoop is
// true, whatever the loop is: a FOR over a query, a cursor, a set-returning call or EXECUTE, a numeric range
// (its body may take the rows of an array in the caller's order: `FOR i IN 1 .. n LOOP DELETE ... WHERE id =
// p[i]`), a WHILE, a FOREACH or a bare LOOP that FETCHes. Round 18's first reading excused the numeric range
// and found a FOR by the token before it, so a label (`<<l>> FOR`), a cursor driven by a plain LOOP and an
// array loop were not judged (db-r18-15); the reading is now the other way round and fails closed: a FOR is a
// lock clause only when what follows it is one of the four lock strengths (the closed list lockStrength), and
// every other FOR, every WHILE and every LOOP opens a loop. RowWrite.LoopOrderedBy is the sort of the
// innermost loop, and is set only when that loop is a FOR over a SELECT that selects ONE bare column and sorts
// by that same column, ascending (so the rows reach the loop variable in the order of the sort, whatever table
// the query reads: a loop over sessions sorted by sessions.id does not sort the rows of users it hands their
// keys to, because its select list is not what it sorts by); it is nil for every other loop. It does not read
// the loops of a LANGUAGE sql body (it has none).

// lockStrength says whether the words after a FOR are a row-lock clause (FOR UPDATE, FOR NO KEY UPDATE, FOR
// SHARE, FOR KEY SHARE): the only four, closed by the server's grammar.
func lockStrength(toks []token, j int) bool {
	at := func(k int) string {
		if j+k < len(toks) && toks[j+k].k == 'w' {
			return toks[j+k].s
		}
		return ""
	}
	switch at(1) {
	case "update", "share":
		return true
	case "no":
		return at(2) == "key" && at(3) == "update"
	case "key":
		return at(2) == "share"
	}
	return false
}

// queryLoopAt returns, for the token at index at, whether it stands inside a loop and the sort of the
// innermost loop.
func queryLoopAt(toks []token, at int) (in bool, orderedBy []string) {
	var stack [][]string // one frame per open loop: its sort, nil when it has none
	for j := 0; j < at && j < len(toks); j++ {
		switch {
		case isWord(toks[j], "for") && !lockStrength(toks, j):
			loopAt := -1
			depth := 0
			for k := j + 1; k < len(toks) && loopAt < 0; k++ {
				switch {
				case toks[k].k == '(':
					depth++
				case toks[k].k == ')':
					depth--
				case depth == 0 && isWord(toks[k], "loop"):
					loopAt = k
				}
			}
			if loopAt < 0 {
				// A FOR with no LOOP is not a statement of a body we can read: everything after it is in a loop.
				stack = append(stack, nil)
				continue
			}
			var by []string
			if loopAt >= j+4 && toks[j+1].k == 'w' && isWord(toks[j+2], "in") {
				by = loopSort(toks[j+3 : loopAt])
			}
			stack = append(stack, by)
			j = loopAt
		case isWord(toks[j], "end") && j+1 < len(toks) && isWord(toks[j+1], "loop"):
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			j++
		case isWord(toks[j], "loop"):
			// A LOOP no FOR header consumed: WHILE, FOREACH, a bare LOOP.
			stack = append(stack, nil)
		}
	}
	if len(stack) == 0 {
		return false, nil
	}
	return true, stack[len(stack)-1]
}

// loopSort is the sort of a FOR ... IN <src> loop that the caller can rely on: src is a SELECT with one
// select item that is a single column, and its ORDER BY is one ascending term that is that same column.
func loopSort(src []token) []string {
	ob := orderByAt(src)
	if ob < 0 || !isWord(src[0], "select") {
		return nil
	}
	if len(selectItems(src, 0, ob)) != 1 {
		return nil
	}
	by, to, ok := readSort(src, 0, ob, len(src), []string{"loop variable"})
	if !ok || len(by) != 1 || to[0] == "" {
		return nil
	}
	return by
}

// orderByAt returns the index of the ORDER BY at the query's own level, or -1.
func orderByAt(src []token) int {
	depth := 0
	for k, tk := range src {
		switch {
		case tk.k == '(':
			depth++
		case tk.k == ')':
			depth--
		case depth == 0 && isWord(tk, "order") && k+1 < len(src) && isWord(src[k+1], "by"):
			return k
		}
	}
	return -1
}
