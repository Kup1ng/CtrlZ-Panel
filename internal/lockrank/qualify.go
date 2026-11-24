package lockrank

import (
	"fmt"
	"sync"
)

// The lock order is judged from the tables a statement names, and Analyze
// recognises a table only as ctrlz.<name>. The roles' search_path is
// "pg_catalog, ctrlz", so a statement that writes `UPDATE sessions` runs fine in
// the database and would be classified as touching nothing: no rank check, no
// key shares, no cascade reach. Reading the text for the tables it does name
// cannot find the ones it names the other way, so the rule is an allow list that
// fails closed (P1 auth review round 5, finding db-r5-2): every place where SQL
// puts a table name must hold a ctrlz-qualified name, a function call, a
// subquery, a catalog table, or the name of a CTE of the same text. Anything
// else is an error, and so the statement is refused by the guard, the lint and
// the catalog check alike.

type want uint8

const (
	wantNone   want = iota
	wantFrom        // a from-list item: table, function, subquery, CTE
	wantTarget      // the target of INSERT, UPDATE or DELETE: a table of ctrlz
)

// exprFuncs are the functions whose argument list uses FROM as syntax, not as a
// from-list.
var exprFuncs = sync.OnceValue(func() map[string]bool {
	return map[string]bool{"extract": true, "substring": true, "trim": true, "overlay": true}
})

// fromEnders end a from-list, so that a later comma is not another table.
var fromEnders = sync.OnceValue(func() map[string]bool {
	return map[string]bool{
		"where": true, "group": true, "order": true, "having": true, "limit": true, "offset": true,
		"union": true, "intersect": true, "except": true, "returning": true, "window": true,
		"fetch": true, "for": true, "set": true, "select": true, "values": true, "loop": true,
		"then": true, "else": true, "end": true, "into": true,
	}
})

// catalogSchemas hold no lock the order is about.
var catalogSchemas = sync.OnceValue(func() map[string]bool { return map[string]bool{"pg_catalog": true, "information_schema": true} })

type qframe struct {
	expr, inFrom bool
	want         want
}

// requireQualified returns an error for the first table name that the lock
// analysis could not recognise.
func requireQualified(toks []token) error {
	ctes := cteNames(toks)
	word := func(i int) string {
		if i < 0 || i >= len(toks) || toks[i].k != 'w' {
			return ""
		}
		return toks[i].s
	}
	frames := []qframe{{}}
	for i, tk := range toks {
		fr := &frames[len(frames)-1]
		if fr.want != wantNone {
			switch {
			case tk.k == '(':
				// A subquery or a function call; its own frame reads what is inside.
				if fr.want == wantTarget {
					return fmt.Errorf("lockrank: the target of a write must be a table of ctrlz, not a parenthesis")
				}
				fr.want = wantNone
			case tk.k == 'w' && (tk.s == "only" || tk.s == "lateral"):
				continue
			case tk.k == 'w':
				if err := checkName(tk.s, fr.want, i+1 < len(toks) && toks[i+1].k == '(', ctes); err != nil {
					return err
				}
				fr.want = wantNone
			default:
				return fmt.Errorf("lockrank: a table name is expected here and the text has something else")
			}
		}
		switch tk.k {
		case '(':
			frames = append(frames, qframe{expr: exprFuncs()[word(i-1)]})
		case ')':
			if len(frames) > 1 {
				frames = frames[:len(frames)-1]
			}
		case ';':
			if len(frames) == 1 {
				frames[0] = qframe{}
			}
		case ',':
			if fr.inFrom {
				fr.want = wantFrom
			}
		case 'w':
			switch tk.s {
			case "from":
				switch {
				case fr.expr || word(i-1) == "distinct":
				case word(i-1) == "delete":
					fr.want, fr.inFrom = wantTarget, true
				default:
					fr.want, fr.inFrom = wantFrom, true
				}
			case "join":
				fr.want = wantFrom
			case "using":
				if fr.inFrom && i+1 < len(toks) && toks[i+1].k == 'w' {
					fr.want = wantFrom
				}
			case "update":
				switch word(i - 1) {
				case "for", "key", "do":
				default:
					fr.want = wantTarget
				}
			case "into":
				if p := word(i - 1); p == "insert" || p == "merge" {
					fr.want = wantTarget
				}
			case "truncate":
				return fmt.Errorf("lockrank: TRUNCATE takes an exclusive table lock outside the row lock order")
			case "lock":
				if word(i+1) == "table" {
					return fmt.Errorf("lockrank: LOCK TABLE takes a table lock outside the row lock order")
				}
			default:
				if fromEnders()[tk.s] {
					fr.inFrom = false
				}
			}
		}
	}
	return nil
}

func checkName(name string, w want, call bool, ctes map[string]bool) error {
	if _, ok := tableOf(name); ok {
		return nil
	}
	if w == wantTarget {
		return fmt.Errorf("lockrank: the target %q of a write is not written ctrlz.<table>; the search_path would find it but the lock order would not", name)
	}
	if schema, _, dotted := cutSchema(name); dotted {
		if catalogSchemas()[schema] || schema == "ctrlz_fn" && call {
			return nil
		}
		return fmt.Errorf("lockrank: %q is a table of a schema the lock order does not know", name)
	}
	if call || ctes[name] {
		return nil
	}
	return fmt.Errorf("lockrank: table %q is not written ctrlz.%s; the search_path would find it but the lock order would not", name, name)
}

func cutSchema(name string) (schema, rest string, dotted bool) {
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			return name[:i], name[i+1:], true
		}
	}
	return "", name, false
}

// cteNames collects the names the text gives to WITH queries: a word (or a word
// and a column list) before AS ( or AS [NOT] MATERIALIZED (. Taking too many is
// harmless, because a CTE name is accepted only where a from-list item is, never
// as the target of a write.
func cteNames(toks []token) map[string]bool {
	out := map[string]bool{}
	for i, tk := range toks {
		if tk.k != 'w' || tk.s != "as" {
			continue
		}
		j := i + 1
		if j < len(toks) && toks[j].k == 'w' && toks[j].s == "not" {
			j++
		}
		if j < len(toks) && toks[j].k == 'w' && toks[j].s == "materialized" {
			j++
		}
		if j >= len(toks) || toks[j].k != '(' {
			continue
		}
		k := i - 1
		if k >= 0 && toks[k].k == ')' {
			depth := 0
			for ; k >= 0; k-- {
				if toks[k].k == ')' {
					depth++
				} else if toks[k].k == '(' {
					depth--
					if depth == 0 {
						k--
						break
					}
				}
			}
		}
		if k >= 0 && toks[k].k == 'w' {
			out[toks[k].s] = true
		}
	}
	return out
}
