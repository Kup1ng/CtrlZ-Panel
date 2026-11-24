package lockrank

import "fmt"

// Verb is what a statement does to a table.
type Verb string

const (
	VerbInsert Verb = "insert"
	VerbUpdate Verb = "update"
	VerbDelete Verb = "delete"
)

// Target is one table a text writes, and how.
type Target struct {
	Table string
	Verb  Verb
}

// Targets reads one statement or one function body and returns every table it inserts
// into, updates or deletes from, with the verb. It is the reader behind catalog check 23
// (does a function that writes a guarded table say what it leaves behind), built on the same
// lexer as Analyze so that the two cannot disagree about one body: comments, quoting,
// spacing, ONLY and upper case are read the one way (db-r6-2).
//
// It fails closed, like requireQualified: an error means the text has a write whose target it
// cannot name as a plain ctrlz.<lower case table>, or a way to write that it does not read
// (MERGE, TRUNCATE, LOCK TABLE, dynamic SQL), and the caller must refuse the body instead of
// reporting that it writes nothing.
func Targets(sql string) ([]Target, error) {
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
	var out []Target
	add := func(i int, v Verb) error {
		name := word(i + 1)
		table, ok := tableOf(name)
		if !ok || table == "" || table != lowerPlain(table) {
			return fmt.Errorf("lockrank: the target of a %s is %q, not a plain ctrlz.<table>", v, name)
		}
		out = append(out, Target{Table: table, Verb: v})
		return nil
	}
	for i, tk := range toks {
		if tk.k != 'w' {
			continue
		}
		switch tk.s {
		case "insert":
			if word(i+1) == "into" {
				if err := add(i+1, VerbInsert); err != nil {
					return nil, err
				}
			}
		case "update":
			// FOR UPDATE and FOR NO KEY UPDATE are lock clauses, and DO UPDATE has the
			// target of its INSERT: none of them is a write of its own.
			switch word(i - 1) {
			case "for", "key", "do":
			default:
				if err := add(i, VerbUpdate); err != nil {
					return nil, err
				}
			}
		case "delete":
			if word(i+1) == "from" {
				if err := add(i+1, VerbDelete); err != nil {
					return nil, err
				}
			}
		case "merge":
			if word(i+1) == "into" {
				return nil, fmt.Errorf("lockrank: MERGE is not read; write INSERT ... ON CONFLICT or UPDATE")
			}
		case "execute":
			// plpgsql EXECUTE runs a string the lexer cannot read.
			return nil, fmt.Errorf("lockrank: dynamic SQL (EXECUTE) is not read")
		}
	}
	return out, nil
}

// lowerPlain is s in lower case when it is made of the characters of a plain identifier, and
// something else (it keeps quotes, dots and capitals as they are) when it is not, so the
// comparison with the original fails for a quoted or capitalised name.
func lowerPlain(s string) string {
	for _, c := range []byte(s) {
		switch {
		case c >= 'A' && c <= 'Z':
			return "\x00" + s // never equal to s
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_':
		default:
			return "\x00" + s
		}
	}
	return s
}
