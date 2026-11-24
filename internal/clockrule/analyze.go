package clockrule

import (
	"fmt"
	"sort"
	"strings"
)

type tok struct {
	k byte // 'w' word, 's' string, 'o' operator, '(' ')' ',' ';' punctuation
	s string
}

func isWordByte(c byte) bool {
	return c == '_' || c == '$' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}

func isOpByte(c byte) bool { return strings.IndexByte("<>=!:|+-*/%^~&@#?", c) >= 0 }

// lex reads a statement as the server does for this package's purposes: comments
// are dropped, a string is one token with its (lower case) text kept, a quoted name
// is a word, and a word is lower case with its dots (ctrlz.users.id is one word).
func lex(sql string) []tok {
	var out []tok
	n := len(sql)
	for i := 0; i < n; {
		c := sql[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
			i++
		case c == '-' && i+1 < n && sql[i+1] == '-':
			for i < n && sql[i] != '\n' && sql[i] != '\r' {
				i++
			}
		case c == '/' && i+1 < n && sql[i+1] == '*':
			depth := 0
			for i < n {
				if strings.HasPrefix(sql[i:], "/*") {
					depth++
					i += 2
				} else if strings.HasPrefix(sql[i:], "*/") {
					depth--
					i += 2
					if depth == 0 {
						break
					}
				} else {
					i++
				}
			}
		case c == '\'':
			var sb strings.Builder
			j := i + 1
			for j < n {
				if sql[j] == '\'' {
					if j+1 < n && sql[j+1] == '\'' {
						sb.WriteByte('\'')
						j += 2
						continue
					}
					break
				}
				sb.WriteByte(sql[j])
				j++
			}
			out = append(out, tok{'s', strings.ToLower(sb.String())})
			i = j + 1
		case c == '"':
			j := strings.IndexByte(sql[i+1:], '"')
			if j < 0 {
				j = n - i - 1
			}
			out = append(out, tok{'w', strings.ToLower(sql[i+1 : i+1+j])})
			i += j + 2
		case c == '(' || c == ')' || c == ',' || c == ';':
			out = append(out, tok{c, string(c)})
			i++
		case isWordByte(c):
			j := i
			for j < n && (isWordByte(sql[j]) || sql[j] == '.' && j+1 < n && isWordByte(sql[j+1])) {
				j++
			}
			out = append(out, tok{'w', strings.ToLower(sql[i:j])})
			i = j
		case isOpByte(c):
			j := i
			for j < n && isOpByte(sql[j]) {
				j++
			}
			out = append(out, tok{'o', sql[i:j]})
			i = j
		case c == '.':
			out = append(out, tok{'.', "."})
			i++
		default:
			i++
		}
	}
	return joinDots(out)
}

// joinDots turns word . word into one word, so "ctrlz"."sessions", ctrlz . sessions
// and ctrlz.sessions are the same name, as the server reads them.
func joinDots(ts []tok) []tok {
	var out []tok
	for i := 0; i < len(ts); i++ {
		if ts[i].k == '.' && len(out) > 0 && out[len(out)-1].k == 'w' && i+1 < len(ts) && ts[i+1].k == 'w' {
			out[len(out)-1].s += "." + ts[i+1].s
			i++
			continue
		}
		if ts[i].k == '.' {
			continue
		}
		out = append(out, ts[i])
	}
	return out
}

// split cuts a token list at the semicolons into statements.
func split(ts []tok) [][]tok {
	var out [][]tok
	var cur []tok
	for _, t := range ts {
		if t.k == ';' {
			if len(cur) > 0 {
				out = append(out, cur)
			}
			cur = nil
			continue
		}
		cur = append(cur, t)
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// clockCalls are the functions that read a database clock; clockKeywords are the
// ones spelled without parentheses.
func clockCalls() map[string]bool {
	return map[string]bool{"now": true, "clock_timestamp": true, "statement_timestamp": true, "transaction_timestamp": true, "timeofday": true}
}
func clockKeywords() map[string]bool {
	return map[string]bool{"current_timestamp": true, "current_date": true, "current_time": true, "localtimestamp": true, "localtime": true}
}
func clockStrings() map[string]bool {
	return map[string]bool{"now": true, "today": true, "tomorrow": true, "yesterday": true}
}

func bare(w string) string { return strings.TrimPrefix(w, "pg_catalog.") }

// clockHelpers are the functions of schema ctrlz that read the database clock inside:
// ctrlz.credential_state compares an expiry with now(). A statement that calls one reads
// a database clock as surely as one that writes now(), so it may not also name an
// application-clock column (rule one-time-state).
func clockHelpers() map[string]bool {
	return map[string]bool{"ctrlz.credential_state": true, "ctrlz.one_time_expiry": true}
}

func hasClock(ts []tok) bool {
	for i, t := range ts {
		switch t.k {
		case 'w':
			w := bare(t.s)
			if clockKeywords()[w] {
				return true
			}
			if (clockCalls()[w] || clockHelpers()[t.s]) && i+1 < len(ts) && ts[i+1].k == '(' {
				return true
			}
		case 's':
			if clockStrings()[t.s] {
				return true
			}
		}
	}
	return false
}

func hasParam(ts []tok) bool {
	for _, t := range ts {
		if t.k == 'w' && len(t.s) > 1 && t.s[0] == '$' && t.s[1] >= '0' && t.s[1] <= '9' {
			return true
		}
	}
	return false
}

// stopWords end a table reference: the next word is a keyword, not an alias.
func stopWords() map[string]bool {
	return map[string]bool{
		"where": true, "set": true, "on": true, "join": true, "left": true, "right": true, "inner": true,
		"outer": true, "cross": true, "full": true, "natural": true, "using": true, "group": true,
		"order": true, "limit": true, "returning": true, "values": true, "select": true, "union": true,
		"for": true, "offset": true, "having": true, "window": true, "when": true, "and": true,
		"or": true, "lateral": true, "do": true, "from": true, "as": true, "into": true, "then": true,
		"else": true, "end": true, "is": true, "in": true, "not": true, "if": true, "loop": true,
		"default": true, "conflict": true, "except": true, "intersect": true, "fetch": true, "with": true,
	}
}

// refs are the tables a statement names and the aliases that stand for them.
type refs struct {
	tables map[string]bool
	alias  map[string]string // alias or table name -> table
}

func tableName(w string) (string, bool) {
	t, ok := strings.CutPrefix(w, "ctrlz.")
	if !ok || t == "" || strings.Contains(t, ".") {
		return "", false
	}
	return t, true
}

func tableRefs(ts []tok) refs {
	r := refs{tables: map[string]bool{}, alias: map[string]string{}}
	for i := 0; i < len(ts); i++ {
		if ts[i].k != 'w' {
			continue
		}
		switch ts[i].s {
		case "from", "join", "update", "into", "using":
		default:
			continue
		}
		// A reference list: a, b x, c as y.
		for j := i + 1; j < len(ts); {
			t, ok := tableName(ts[j].s)
			if ts[j].k != 'w' || !ok {
				break
			}
			r.tables[t] = true
			r.alias[t] = t
			j++
			if j < len(ts) && ts[j].k == 'w' && ts[j].s == "as" {
				j++
			}
			if j < len(ts) && ts[j].k == 'w' && !stopWords()[ts[j].s] && !strings.Contains(ts[j].s, ".") {
				r.alias[ts[j].s] = t
				j++
			}
			if ts[i].s == "from" && j < len(ts) && ts[j].k == ',' {
				j++
				continue
			}
			break
		}
	}
	return r
}

// mention is one use of a registered column in a statement.
type mention struct {
	table, col string
	class      Class
	at         int // token index
}

// mentions finds every use of a registered column. A qualified name (alias.col,
// ctrlz.table.col) is resolved through the references; a bare name belongs to every
// touched table that has a column of that name. Function calls are skipped.
func (reg *Registry) mentions(ts []tok, rf refs) []mention {
	var out []mention
	for i, t := range ts {
		if t.k != 'w' || (i+1 < len(ts) && ts[i+1].k == '(') {
			continue
		}
		if _, isTable := tableName(t.s); isTable {
			continue
		}
		parts := strings.Split(t.s, ".")
		col := parts[len(parts)-1]
		var tables []string
		switch {
		case len(parts) == 1:
			for tb := range rf.tables {
				tables = append(tables, tb)
			}
		case len(parts) == 2:
			if tb, ok := rf.alias[parts[0]]; ok {
				tables = []string{tb}
			}
		case len(parts) == 3 && parts[0] == "ctrlz":
			tables = []string{parts[1]}
		}
		sort.Strings(tables)
		for _, tb := range tables {
			if k := reg.Tables[tb][col]; k != "" {
				out = append(out, mention{tb, col, k, i})
			}
		}
	}
	return out
}

// Options say where a statement goes, which decides the rules that apply to it.
type Options struct {
	// GoBound is a statement Go runs and reads the result of: the select list and
	// RETURNING list reach a Go value, and a $n is a Go value.
	GoBound bool
}

// Finding is one violation.
type Finding struct {
	Rule string // app-clock, db-selected, db-from-go
	Msg  string
}

func (f Finding) String() string { return f.Rule + ": " + f.Msg }

// Analyze judges SQL text (a Go constant, or the body of a function) and returns
// the violations of the clock rule. It cuts the text into statements and judges each.
func (reg *Registry) Analyze(sql string, o Options) []Finding {
	var out []Finding
	for _, st := range split(lex(sql)) {
		out = append(out, reg.analyzeStatement(st, o)...)
	}
	return out
}

func (reg *Registry) analyzeStatement(ts []tok, o Options) []Finding {
	rf := tableRefs(ts)
	ms := reg.mentions(ts, rf)
	if len(ms) == 0 && !hasStar(ts) {
		return nil
	}
	var out []Finding
	seen := map[string]bool{}
	add := func(rule, format string, args ...any) {
		m := rule + ": " + fmt.Sprintf(format, args...)
		if !seen[m] {
			seen[m] = true
			out = append(out, Finding{rule, fmt.Sprintf(format, args...)})
		}
	}

	// app-clock: the statement names an application-clock column and reads a database
	// clock. Whole statement, not a guess at which expression the clock belongs to: a
	// statement that needs both passes the application time as a parameter instead.
	if hasClock(ts) {
		for _, m := range ms {
			if m.class == App {
				add("app-clock", "%s.%s is on the application clock, and the statement reads a database clock; pass the application time as a parameter", m.table, m.col)
			}
		}
	}
	if !o.GoBound {
		return out
	}

	// db-from-go: a database-clock column compared with a parameter, or stamped from one.
	for _, m := range ms {
		if m.class != DB {
			continue
		}
		if reg.Carry[m.table+"."+m.col] == "" && !inSetList(ts, m.at) && comparedWithParam(ts, m.at) {
			add("db-from-go", "%s.%s is on the database clock and is compared with a Go value", m.table, m.col)
		}
	}
	for _, a := range assignments(ts, rf, reg) {
		if a.class == DB && reg.Carry[a.table+"."+a.col] == "" && hasParam(a.expr) && !hasClock(a.expr) {
			add("db-from-go", "%s.%s is on the database clock and is written from a Go value", a.table, a.col)
		}
	}

	// db-selected: the statement hands a database-clock column to Go as a time.
	for _, item := range outputItems(ts) {
		if hasClock(item) || hasComparison(item) {
			continue
		}
		if isStar(item) {
			for tb := range rf.tables {
				for col, k := range reg.Tables[tb] {
					if k == DB && reg.Read[tb+"."+col] == "" {
						add("db-selected", "* reads %s.%s, a database-clock column, into Go", tb, col)
					}
				}
			}
			continue
		}
		for _, m := range reg.mentions(item, rf) {
			if m.class == DB && reg.Read[m.table+"."+m.col] == "" {
				add("db-selected", "%s.%s is on the database clock and is selected into Go; decide in SQL (a boolean, a count) or list it under read in clocks.yaml with the reason", m.table, m.col)
			}
		}
	}
	return out
}

func hasStar(ts []tok) bool {
	for i, t := range ts {
		if t.k == 'o' && t.s == "*" && i > 0 && (ts[i-1].k == ',' || ts[i-1].s == "select" || ts[i-1].s == "returning" || ts[i-1].k == 'w' && strings.HasSuffix(ts[i-1].s, ".")) {
			return true
		}
	}
	return false
}

func isStar(item []tok) bool {
	if len(item) == 0 {
		return false
	}
	last := item[len(item)-1]
	return last.k == 'o' && last.s == "*" && len(item) <= 2
}

func comparisonOps() map[string]bool {
	return map[string]bool{"<": true, ">": true, "=": true, "<=": true, ">=": true, "<>": true, "!=": true}
}
func comparisonWords() map[string]bool {
	return map[string]bool{"is": true, "in": true, "between": true, "like": true, "exists": true, "not": true, "and": true, "or": true}
}

func hasComparison(item []tok) bool {
	for _, t := range item {
		if t.k == 'o' && comparisonOps()[t.s] || t.k == 'w' && comparisonWords()[t.s] {
			return true
		}
	}
	return false
}

// comparedWithParam reports whether the column at index i is an operand of a
// comparison whose other side is a $n parameter (possibly cast).
func comparedWithParam(ts []tok, i int) bool {
	isParam := func(j int) bool {
		return j >= 0 && j < len(ts) && ts[j].k == 'w' && len(ts[j].s) > 1 && ts[j].s[0] == '$' && ts[j].s[1] >= '0' && ts[j].s[1] <= '9'
	}
	if i+2 < len(ts) && ts[i+1].k == 'o' && comparisonOps()[ts[i+1].s] {
		j := i + 2
		if ts[j].k == '(' {
			j++
		}
		if isParam(j) {
			return true
		}
	}
	if i-2 >= 0 && ts[i-1].k == 'o' && comparisonOps()[ts[i-1].s] {
		j := i - 2
		if ts[j].k == ')' {
			j--
		}
		// $3::timestamptz <op> col
		if j-2 >= 0 && ts[j-1].k == 'o' && ts[j-1].s == "::" {
			j -= 2
		}
		if isParam(j) {
			return true
		}
	}
	return false
}

// assignment is "column = expr" of an UPDATE SET list, or a column and its value
// in an INSERT.
type assignment struct {
	table, col string
	class      Class
	expr       []tok
}

func splitTop(ts []tok) [][]tok {
	var out [][]tok
	depth, from := 0, 0
	for i, t := range ts {
		switch t.k {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, ts[from:i])
				from = i + 1
			}
		}
	}
	return append(out, ts[from:])
}

// endOfList is the index where a clause list that started at i ends.
func endOfList(ts []tok, i int) int {
	depth := 0
	for j := i; j < len(ts); j++ {
		switch ts[j].k {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return j
			}
		case 'w':
			if depth == 0 {
				switch ts[j].s {
				case "where", "from", "returning", "on", "limit", "order", "group":
					return j
				}
			}
		}
	}
	return len(ts)
}

func assignments(ts []tok, rf refs, reg *Registry) []assignment {
	var out []assignment
	lookup := func(name string) (string, string, Class) {
		parts := strings.Split(name, ".")
		col := parts[len(parts)-1]
		var tb string
		switch len(parts) {
		case 1:
			// A single touched table with the column.
			for t := range rf.tables {
				if reg.Tables[t][col] != "" {
					tb = t
				}
			}
		case 2:
			tb = rf.alias[parts[0]]
		}
		return tb, col, reg.Tables[tb][col]
	}
	depth := 0
	for i := 0; i < len(ts); i++ {
		switch ts[i].k {
		case '(':
			depth++
		case ')':
			depth--
		}
		if ts[i].k != 'w' {
			continue
		}
		switch {
		case ts[i].s == "set" && depth == 0:
			end := endOfList(ts, i+1)
			for _, item := range splitTop(ts[i+1 : end]) {
				if len(item) >= 3 && item[0].k == 'w' && item[1].k == 'o' && item[1].s == "=" {
					tb, col, k := lookup(item[0].s)
					out = append(out, assignment{tb, col, k, item[2:]})
				}
			}
		case ts[i].s == "into" && i+2 < len(ts) && ts[i+2].k == '(' && depth == 0:
			// INSERT INTO t (c1, c2) VALUES (e1, e2) | SELECT e1, e2 ...
			tbName, ok := tableName(ts[i+1].s)
			if !ok {
				continue
			}
			closeAt := matching(ts, i+2)
			if closeAt < 0 {
				continue
			}
			var cols []string
			for _, c := range splitTop(ts[i+3 : closeAt]) {
				if len(c) == 1 {
					cols = append(cols, c[0].s)
				} else {
					cols = append(cols, "")
				}
			}
			var vals [][]tok
			j := closeAt + 1
			switch {
			case j < len(ts) && ts[j].s == "values" && j+1 < len(ts) && ts[j+1].k == '(':
				if e := matching(ts, j+1); e > 0 {
					vals = splitTop(ts[j+2 : e])
				}
			case j < len(ts) && ts[j].s == "select":
				vals = splitTop(ts[j+1 : endOfList(ts, j+1)])
			}
			for n, c := range cols {
				if n < len(vals) && c != "" {
					out = append(out, assignment{tbName, c, reg.Tables[tbName][c], vals[n]})
				}
			}
		}
	}
	return out
}

func matching(ts []tok, open int) int {
	depth := 0
	for j := open; j < len(ts); j++ {
		switch ts[j].k {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return j
			}
		}
	}
	return -1
}

// outputItems returns the items that reach the Go caller: the select list of a
// statement that is a SELECT (not an INSERT ... SELECT), and a RETURNING list, both
// at the top level.
func outputItems(ts []tok) [][]tok {
	var out [][]tok
	// The statement kind is the first keyword after any WITH list.
	depth, kind := 0, ""
	for _, t := range ts {
		switch t.k {
		case '(':
			depth++
		case ')':
			depth--
		case 'w':
			if depth == 0 && kind == "" {
				switch t.s {
				case "select", "insert", "update", "delete", "values", "merge":
					kind = t.s
				}
			}
		}
		if kind != "" {
			break
		}
	}
	depth = 0
	for i, t := range ts {
		switch t.k {
		case '(':
			depth++
		case ')':
			depth--
		case 'w':
			if depth != 0 {
				continue
			}
			if t.s == "returning" || t.s == "select" && kind == "select" {
				end := len(ts)
				d := 0
			scan:
				for j := i + 1; j < len(ts); j++ {
					switch ts[j].k {
					case '(':
						d++
					case ')':
						d--
					case 'w':
						if d == 0 && (ts[j].s == "from" || ts[j].s == "into" || ts[j].s == "union") {
							end = j
							break scan
						}
					}
				}
				for _, it := range splitTop(ts[i+1 : end]) {
					out = append(out, trimAlias(it))
				}
			}
		}
	}
	return out
}

// trimAlias drops a trailing "AS name" (or a bare alias after a closing paren or word
// that is not an operator) from a select item.
func trimAlias(it []tok) []tok {
	for i := len(it) - 2; i >= 1; i-- {
		if it[i].k == 'w' && it[i].s == "as" {
			return it[:i]
		}
	}
	return it
}

// inSetList reports whether the token at i is the target of an UPDATE SET item (or
// of the DO UPDATE SET of an upsert): its "=" is an assignment, not a comparison.
func inSetList(ts []tok, i int) bool {
	if i+1 >= len(ts) || ts[i+1].k != 'o' || ts[i+1].s != "=" {
		return false
	}
	depth := 0
	for j := i - 1; j >= 0; j-- {
		switch ts[j].k {
		case ')':
			depth++
		case '(':
			depth--
			if depth < 0 {
				return false
			}
		case 'w':
			if depth == 0 {
				switch ts[j].s {
				case "set":
					return true
				case "where", "on", "from", "returning", "select", "and", "or":
					return false
				}
			}
		}
	}
	return false
}
