package lockrank

import (
	"fmt"
	"strings"
)

// SetWrite is one UPDATE (or the DO UPDATE arm of an INSERT ... ON CONFLICT) of a text, with the
// columns its SET list assigns.
type SetWrite struct {
	Table string
	Cols  []string
}

// SetColumns reads one statement or function body and returns, for every UPDATE it contains, the
// table and the columns named in its SET list (a qualifier is dropped; `SET (a, b) = ...` yields
// both). It is the reader behind the second half of catalog check 21: an UPDATE that changes a
// column of a unique index takes a FOR UPDATE strength lock on the row, which `Targets` alone
// cannot see because it reads only the table and the verb (db-r9-5).
//
// It fails closed, like Targets and on the same lexer: a table that is not a plain
// ctrlz.<lower case table>, a SET that cannot be found after the table (and an optional alias), a
// DO UPDATE with no INSERT before it, and every text Targets refuses (MERGE, dynamic SQL) are
// errors, never "assigns nothing". It may over-read (a word in an array literal is taken for a
// column); the callers only compare the names with a list, so an extra name cannot hide a write.
func SetColumns(sql string) ([]SetWrite, error) {
	toks, err := lex(sql)
	if err != nil {
		return nil, err
	}
	if err := requireQualified(toks); err != nil {
		return nil, err
	}
	word := func(i int) string {
		if i < 0 || i >= len(toks) || toks[i].k != 'w' {
			return ""
		}
		return toks[i].s
	}
	var out []SetWrite
	lastInsert := ""
	for i, tk := range toks {
		if tk.k != 'w' {
			continue
		}
		switch tk.s {
		case "execute":
			return nil, fmt.Errorf("lockrank: dynamic SQL (EXECUTE) is not read")
		case "merge":
			if word(i+1) == "into" {
				return nil, fmt.Errorf("lockrank: MERGE is not read; write INSERT ... ON CONFLICT or UPDATE")
			}
		case "insert":
			if word(i+1) == "into" {
				t, ok := tableOf(word(i + 2))
				if !ok {
					return nil, fmt.Errorf("lockrank: the target of an insert is %q, not a plain ctrlz.<table>", word(i+2))
				}
				lastInsert = t
			}
		case "update":
			var table string
			setAt := -1
			switch word(i - 1) {
			case "for", "key":
				continue // a lock clause, not a write
			case "do":
				if lastInsert == "" {
					return nil, fmt.Errorf("lockrank: DO UPDATE with no INSERT before it")
				}
				table, setAt = lastInsert, i+1
			default:
				t, ok := tableOf(word(i + 1))
				if !ok || t == "" || t != lowerPlain(t) {
					return nil, fmt.Errorf("lockrank: the target of an update is %q, not a plain ctrlz.<table>", word(i+1))
				}
				table = t
				// An alias is `AS x` or `x`, so SET is at most two words after the table.
				for j := i + 2; j <= i+4 && j < len(toks); j++ {
					if word(j) == "set" {
						setAt = j
						break
					}
				}
			}
			if setAt < 0 || word(setAt) != "set" {
				return nil, fmt.Errorf("lockrank: the SET list of an update of %s cannot be found", table)
			}
			out = append(out, SetWrite{Table: table, Cols: setList(toks, setAt+1)})
		}
	}
	return out, nil
}

// setList reads the assigned columns of a SET list that starts at toks[i]: the word that opens
// each assignment at depth 0 (or every word of a parenthesised column list), up to WHERE, FROM,
// RETURNING, a semicolon or the parenthesis that closes the enclosing query.
func setList(toks []token, i int) []string {
	var cols []string
	add := func(w string) {
		if k := strings.LastIndex(w, "."); k >= 0 {
			w = w[k+1:]
		}
		cols = append(cols, strings.Trim(w, `"`))
	}
	depth := 0
	expect := true
	for ; i < len(toks); i++ {
		tk := toks[i]
		switch {
		case tk.k == '(':
			if depth == 0 && expect {
				// (a, b) = (...): every word up to the matching parenthesis is a column.
				d := 1
				for i++; i < len(toks) && d > 0; i++ {
					switch toks[i].k {
					case '(':
						d++
					case ')':
						d--
					case 'w':
						add(toks[i].s)
					}
				}
				i--
				expect = false
				continue
			}
			depth++
		case tk.k == ')':
			if depth == 0 {
				return cols
			}
			depth--
		case tk.k == 'o' && tk.s == "[":
			depth++
		case tk.k == 'o' && tk.s == "]":
			if depth > 0 {
				depth--
			}
		case tk.k == ';' && depth == 0:
			return cols
		case tk.k == ',' && depth == 0:
			expect = true
		case tk.k == 'w' && depth == 0:
			switch tk.s {
			case "where", "returning":
				return cols
			case "from":
				if i > 0 && toks[i-1].k == 'w' && toks[i-1].s == "distinct" {
					continue // IS DISTINCT FROM is an operator
				}
				return cols
			}
			if expect {
				add(tk.s)
				expect = false
			}
		}
	}
	return cols
}
