package caps

import (
	"strings"
	"unicode"
)

// WholeRowOfLimitTable is the guard that no Go statement reads a whole row of a limit table
// (P1 auth review round 17, sms-r17-10 and sms-r17-19; rule caps-and-endings).
//
// A row of system_settings, plans or tenant_entitlements holds every limit and names
// none of them, so the text-level question of ReadsLimit ("which limit does this text name outside
// ctrlz.cap_reached?") cannot see Go compare a field of a row it scanned whole. The first form of this
// guard was a list of spellings of a whole row (a star, a qualified star, RETURNING *, to_jsonb,
// row_to_json, ROW(, %ROWTYPE); each round found another spelling (a bare alias as a select item, s::text,
// TABLE name), which is the class of guard the review method forbids.
//
// It is now an allow list over what a statement may do with a relation that is a limit table, so a
// spelling nobody thought of fails. A statement that names a limit table (after the calls of
// ctrlz.cap_reached are cut out):
//
//  1. begins with SELECT, WITH, INSERT, UPDATE or DELETE, and nothing else (TABLE t, VALUES, EXPLAIN,
//     COPY and the rest are refused);
//  2. uses a relation that is a limit table, by its name or by its alias (FROM s, JOIN s, UPDATE s,
//     INTO s, USING s, with or without AS), only qualified, as s.column. A bare s is the row: it is
//     the item of a list, the argument of a call (to_jsonb(s)), the operand of a cast (s::text), a
//     parenthesis ((s).x), and every other place a value can stand, and each fails the same way
//     because the rule names no place and no spelling;
//  3. has no star item (* or x.*) in the select list of a select whose FROM names a limit table, nor in
//     a RETURNING list, and no qualified star of a limit relation anywhere.
//
// Contract. It judges the text of one Go statement as written. It does not see a limit reached through
// a name the text never holds (a built query, EXECUTE), and it does not judge a plpgsql body: a
// function that holds a row variable is judged by ReadsLimit by name, because the comparison is in the
// same text (see LimitFunctions, which pins each function that names a limit). A column a statement
// names is not judged here: a limit column named beside a call is ReadsLimit's, and a statement that
// names one is a pinned LimitStatement or fails there. A column or an alias that is called like a limit
// relation is refused as a bare use (a false refusal that costs a rename, never a hole).
func WholeRowOfLimitTable(sql string) string {
	toks := lexSQL(stripShared(sql))
	if !namesLimitTable(toks) {
		return ""
	}
	if first := firstWord(toks); !isOneOf(first, "select", "with", "insert", "update", "delete") { // clause 1
		return "a statement over a limit table that begins with " + quote(first) + ", not SELECT, WITH, INSERT, UPDATE or DELETE"
	}
	names, decl, aliasLists := limitRelations(toks)
	if len(aliasLists) > 0 { // clause 4
		return "a column alias list on the limit relation " + quote(aliasLists[0]) + ", which reads every limit under a name no guard knows (FROM t AS s(a, b, c)); name the columns instead"
	}
	for i, t := range toks { // clause 2
		if t.kind != tokIdent || !names[t.s] || decl[i] {
			continue
		}
		if i+1 >= len(toks) || toks[i+1].kind != tokPunct || toks[i+1].s != "." {
			return "a bare " + quote(t.s) + " in a statement over a limit table, which is the whole row of a limit relation (name its columns: " + t.s + ".column)"
		}
		if i+2 < len(toks) && toks[i+2].kind == tokPunct && toks[i+2].s == "*" { // clause 3, qualified
			return "a qualified star of the limit relation " + quote(t.s)
		}
	}
	for i, t := range toks { // clause 3
		if t.kind != tokIdent || (t.s != "select" && t.s != "returning") {
			continue
		}
		if t.s == "select" && !fromNamesLimitTable(toks, i) {
			continue
		}
		for _, item := range listItems(toks, i+1) {
			if len(item) == 1 && item[0].kind == tokPunct && item[0].s == "*" || len(item) == 3 && item[1].s == "." && item[2].s == "*" {
				return "a star in the " + t.s + " list of a statement over a limit table"
			}
		}
	}
	return ""
}

type tokKind byte

const (
	tokIdent tokKind = 'i' // a word or a quoted identifier, lower case
	tokNum   tokKind = 'n'
	tokStr   tokKind = 's'
	tokParam tokKind = 'p'
	tokPunct tokKind = 'x'
)

type token struct {
	kind tokKind
	s    string
}

// lexSQL splits a SQL text into the few kinds of token the guard needs. A comment is dropped, a string
// and a number keep their kind and lose their text, and a quoted identifier is an identifier.
func lexSQL(src string) []token {
	var out []token
	rs := []rune(src)
	for i := 0; i < len(rs); {
		r := rs[i]
		switch {
		case unicode.IsSpace(r):
			i++
		case r == '-' && i+1 < len(rs) && rs[i+1] == '-':
			for i < len(rs) && rs[i] != '\n' {
				i++
			}
		case r == '/' && i+1 < len(rs) && rs[i+1] == '*':
			i += 2
			for i+1 < len(rs) && !(rs[i] == '*' && rs[i+1] == '/') {
				i++
			}
			i += 2
		case r == '\'':
			i++
			for i < len(rs) {
				if rs[i] == '\'' {
					if i+1 < len(rs) && rs[i+1] == '\'' {
						i += 2
						continue
					}
					break
				}
				i++
			}
			i++
			out = append(out, token{tokStr, ""})
		case r == '"':
			j := i + 1
			for j < len(rs) && rs[j] != '"' {
				j++
			}
			out = append(out, token{tokIdent, strings.ToLower(string(rs[i+1 : min(j, len(rs))]))})
			i = j + 1
		case r == '$' && i+1 < len(rs) && unicode.IsDigit(rs[i+1]):
			j := i + 1
			for j < len(rs) && unicode.IsDigit(rs[j]) {
				j++
			}
			out = append(out, token{tokParam, ""})
			i = j
		case unicode.IsDigit(r):
			j := i
			for j < len(rs) && (unicode.IsDigit(rs[j]) || rs[j] == '.') {
				j++
			}
			out = append(out, token{tokNum, ""})
			i = j
		case unicode.IsLetter(r) || r == '_':
			j := i
			for j < len(rs) && (unicode.IsLetter(rs[j]) || unicode.IsDigit(rs[j]) || rs[j] == '_' || rs[j] == '$') {
				j++
			}
			out = append(out, token{tokIdent, strings.ToLower(string(rs[i:j]))})
			i = j
		case r == ':' && i+1 < len(rs) && rs[i+1] == ':':
			out = append(out, token{tokPunct, "::"})
			i += 2
		default:
			out = append(out, token{tokPunct, string(r)})
			i++
		}
	}
	return out
}

func namesLimitTable(toks []token) bool {
	for _, t := range toks {
		if t.kind != tokIdent {
			continue
		}
		for _, lt := range LimitTables() {
			if t.s == lt {
				return true
			}
		}
	}
	return false
}

// firstWord is the first token that is not an opening parenthesis, as text: "" for none, and a mark for a
// token that is not a word.
func firstWord(toks []token) string {
	for _, t := range toks {
		if t.kind == tokPunct && t.s == "(" {
			continue
		}
		if t.kind == tokIdent {
			return t.s
		}
		return "a token that is not a word"
	}
	return ""
}

func isOneOf(s string, words ...string) bool {
	for _, w := range words {
		if s == w {
			return true
		}
	}
	return false
}

func quote(s string) string { return `"` + s + `"` }

// listEnd are the words that end a select list at its own depth.
func listEnd() []string {
	return []string{"from", "where", "group", "order", "limit", "offset", "having", "union", "intersect", "except", "for", "window", "into", "fetch", "returning", "on", "set"}
}

// listItems returns the items of the list that begins at toks[from]: split at top-level commas, up to
// the first word of listEnd at the list's own depth, an unmatched closing parenthesis, a semicolon or the end.
func listItems(toks []token, from int) [][]token {
	i := from
	if i < len(toks) && toks[i].kind == tokIdent && (toks[i].s == "distinct" || toks[i].s == "all") {
		isDistinct := toks[i].s == "distinct"
		i++
		if isDistinct && i < len(toks) && toks[i].kind == tokIdent && toks[i].s == "on" {
			i++
			for depth := 0; i < len(toks); i++ { // DISTINCT ON ( ... ) is a clause, not an item
				if toks[i].kind == tokPunct && toks[i].s == "(" {
					depth++
				} else if toks[i].kind == tokPunct && toks[i].s == ")" {
					depth--
					if depth == 0 {
						i++
						break
					}
				}
			}
		}
	}
	var items [][]token
	var cur []token
	depth := 0
	for ; i < len(toks); i++ {
		t := toks[i]
		if t.kind == tokPunct {
			switch t.s {
			case "(":
				depth++
			case ")":
				depth--
				if depth < 0 {
					return append(items, cur)
				}
			case ";":
				if depth == 0 {
					return append(items, cur)
				}
			case ",":
				if depth == 0 {
					items = append(items, cur)
					cur = nil
					continue
				}
			}
		}
		if depth == 0 && t.kind == tokIdent && isOneOf(t.s, listEnd()...) {
			break
		}
		cur = append(cur, t)
	}
	return append(items, cur)
}

// noAlias are the words that can follow a relation and are not its alias.
func noAlias() []string {
	return []string{"where", "set", "join", "left", "right", "inner", "outer", "full", "cross", "natural", "on", "using", "group", "order", "limit", "offset", "having", "union", "intersect", "except", "returning", "values", "select", "for", "window", "lateral", "tablesample", "with", "from", "into", "as", "default"}
}

// limitRelations returns the names a statement gives to its limit tables (the table itself, and its alias
// with or without AS), and the positions of the tokens that declare them. Every other position of a name is
// a use.
func limitRelations(toks []token) (names map[string]bool, decl map[int]bool, aliasLists []string) {
	names, decl = map[string]bool{}, map[int]bool{}
	for _, lt := range LimitTables() {
		names[lt] = true
	}
	for i, t := range toks {
		if t.kind != tokIdent || !isOneOf(t.s, "from", "join", "update", "into", "using") {
			continue
		}
		j := i + 1
		if j >= len(toks) || toks[j].kind != tokIdent {
			continue
		}
		for j+2 < len(toks) && toks[j+1].kind == tokPunct && toks[j+1].s == "." && toks[j+2].kind == tokIdent {
			j += 2 // schema.table: the table is the last name
		}
		if !isLimitTable(toks[j].s) {
			continue
		}
		decl[j] = true
		last := j
		k := j + 1
		if k < len(toks) && toks[k].kind == tokIdent && toks[k].s == "as" {
			k++
		}
		if k < len(toks) && toks[k].kind == tokIdent && !isOneOf(toks[k].s, noAlias()...) {
			names[toks[k].s] = true
			decl[k] = true
			last = k
		}
		// A list of column names after the relation or its alias renames every column by position, so the
		// statement names no limit column and every guard that looks for one is blind to it. After INTO the
		// parenthesis is the column list of an INSERT, whose names are real columns, which ReadsLimit sees.
		if t.s != "into" && last+1 < len(toks) && toks[last+1].kind == tokPunct && toks[last+1].s == "(" {
			aliasLists = append(aliasLists, toks[last].s)
		}
	}
	return names, decl, aliasLists
}

func isLimitTable(s string) bool {
	for _, lt := range LimitTables() {
		if s == lt {
			return true
		}
	}
	return false
}

// fromNamesLimitTable reports whether the FROM region of the select at toks[sel] names a limit table: the
// tokens from its FROM up to the word that ends the clause at the select's own depth.
func fromNamesLimitTable(toks []token, sel int) bool {
	depth, i := 0, sel+1
	for ; i < len(toks); i++ { // find the FROM of this select
		t := toks[i]
		if t.kind == tokPunct && t.s == "(" {
			depth++
		} else if t.kind == tokPunct && t.s == ")" {
			depth--
			if depth < 0 {
				return false
			}
		} else if depth == 0 && t.kind == tokIdent && t.s == "from" {
			break
		} else if depth == 0 && t.kind == tokPunct && t.s == ";" {
			return false
		}
	}
	for i++; i < len(toks); i++ {
		t := toks[i]
		if t.kind == tokPunct && t.s == "(" {
			depth++
		} else if t.kind == tokPunct && t.s == ")" {
			depth--
			if depth < 0 {
				return false
			}
		} else if t.kind == tokPunct && t.s == ";" {
			return false
		} else if depth == 0 && t.kind == tokIdent && isOneOf(t.s, "where", "group", "order", "limit", "offset", "having", "union", "intersect", "except", "for", "window", "returning") {
			return false
		}
		if t.kind == tokIdent && isLimitTable(t.s) {
			return true
		}
	}
	return false
}

// NamesLimitTable returns the first limit table a SQL text or a function body names as a whole word, or
// "" (sms-r18-6). A function that returns a whole row of a limit table, or to_jsonb of it, names the
// table and no limit column, so the question that asks for a column (ReadsLimit) never sees it; the
// catalog check asks this one of every function body too.
//
// Contract (sms-r18-21): it judges the words of the text as written. It does not see a table named inside
// a string literal or assembled by EXECUTE (the text never holds the name), a composite or array type that wraps a limit row, or a domain
// over one: those reach a caller by a type and not by a name, and limitRelationProblems of the catalog
// check reads the views and the signatures that carry the row type itself.
func NamesLimitTable(src string) string {
	for _, t := range lexSQL(src) {
		if t.kind == tokIdent && isLimitTable(t.s) {
			return t.s
		}
	}
	return ""
}
