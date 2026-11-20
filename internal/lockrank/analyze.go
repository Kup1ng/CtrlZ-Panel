package lockrank

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Mode is how strongly a statement holds a row. The order matters: a lock
// already held at a mode that satisfies the request is not a new acquisition.
type Mode uint8

const (
	// KeyShare is FOR KEY SHARE, which an insert takes on each foreign key
	// parent. It conflicts only with FOR UPDATE and DELETE.
	KeyShare Mode = iota + 1
	// Insert adds a row nobody else can see yet. It takes no contended lock, so
	// it neither raises the highest rank nor can break the order; it only means
	// that this transaction owns the rows of that table it created.
	Insert
	// Write is an UPDATE, DELETE, ON CONFLICT DO UPDATE, or any FOR clause
	// other than FOR KEY SHARE.
	Write
)

// Touch is one lock a statement takes, as far as its text shows.
type Touch struct {
	Table string
	Mode  Mode
	// Clause is the explicit lock clause ("update", "no key update", "share",
	// "key share"), empty for a lock that DML or an advisory lock takes.
	Clause string
	// NoWait marks SKIP LOCKED and NOWAIT: the statement never waits for the
	// row, so it cannot be the waiting side of a cycle. It still holds what it
	// got.
	NoWait   bool
	Advisory bool
}

// advisoryKeys maps the text an advisory lock hashes to the table whose rank it
// takes. A key that is not here is refused, so a new advisory lock has to be
// ranked on purpose.
func advisoryKeys() map[string]string {
	return map[string]string{
		"ctrlz.audit_log":         "audit_log",
		"ctrlz.ip_claim_request:": "ip_claims",
	}
}

type token struct {
	k byte // 'w' word, 's' string literal, '(' ')' ';' ',' or 'o' other
	s string
}

// lex reads SQL the way the server's lexer does for the purposes of this
// package: comments are dropped, a quoted string is one token (its text kept,
// for advisory keys), and a word is lower case with its dots (so ctrlz.users
// is one word). Dollar quoting is not supported; no statement or function body
// of the system needs it, and a text that does is refused by the caller.
func lex(sql string) ([]token, error) {
	var out []token
	i, n := 0, len(sql)
	for i < n {
		c := sql[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '-' && i+1 < n && sql[i+1] == '-':
			for i < n && sql[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && sql[i+1] == '*':
			j := strings.Index(sql[i+2:], "*/")
			if j < 0 {
				return nil, fmt.Errorf("lockrank: unterminated comment")
			}
			i += j + 4
		case c == '\'':
			j := i + 1
			var sb strings.Builder
			for {
				if j >= n {
					return nil, fmt.Errorf("lockrank: unterminated string")
				}
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
			out = append(out, token{'s', sb.String()})
			i = j + 1
		case c == '$' && i+1 < n && (sql[i+1] == '$' || isLetter(sql[i+1])):
			return nil, fmt.Errorf("lockrank: dollar quoting is not supported")
		case c == '(' || c == ')' || c == ';' || c == ',':
			out = append(out, token{c, string(c)})
			i++
		case isWordByte(c) || c == '"':
			// A name is one token however it is written: ctrlz.users, "ctrlz"."users"
			// and ctrlz . users are the same table. A quoted part keeps its case, as
			// Postgres does, so "Users" is not users. Reading the quoted form as one
			// name is what keeps a quoted table from slipping past the table checks
			// as two unrelated words.
			w, next, err := readName(sql, i)
			if err != nil {
				return nil, err
			}
			// ONLY (UPDATE ONLY t, DELETE FROM ONLY t, FROM ONLY t) says "not the child
			// tables" and names the same table, so it is not part of the statement's shape: the
			// readers below look at the word before a table name, and a table written after ONLY
			// was a write nobody saw (db-r6-2). ONLY is a reserved word, so no bare identifier
			// is lost by dropping it.
			if !(w == "only" && sql[i] != '"') {
				out = append(out, token{'w', w})
			}
			i = next
		default:
			out = append(out, token{'o', string(c)})
			i++
		}
	}
	return out, nil
}

// readName reads one possibly qualified name that starts at sql[i]: parts that
// are bare words (lower-cased) or double-quoted (kept as written), joined by
// dots that may have white space around them. It returns the name with single
// dots and the index after it.
func readName(sql string, i int) (string, int, error) {
	n := len(sql)
	var parts []string
	for {
		switch {
		case i < n && sql[i] == '"':
			var sb strings.Builder
			j := i + 1
			for {
				if j >= n {
					return "", 0, fmt.Errorf("lockrank: unterminated identifier")
				}
				if sql[j] == '"' {
					if j+1 < n && sql[j+1] == '"' {
						sb.WriteByte('"')
						j += 2
						continue
					}
					break
				}
				sb.WriteByte(sql[j])
				j++
			}
			// A quoted part that is not plain lower case can name no table of the
			// schema; the dot marks it so that no table lookup matches it.
			part := sb.String()
			if part != strings.ToLower(part) || strings.ContainsAny(part, ". \t\n") {
				part = "\"" + part + "\""
			}
			parts = append(parts, part)
			i = j + 1
		case i < n && isWordByte(sql[i]):
			j := i
			for j < n && isWordByte(sql[j]) {
				j++
			}
			parts = append(parts, strings.ToLower(sql[i:j]))
			i = j
		default:
			return "", 0, fmt.Errorf("lockrank: a name is expected")
		}
		// A dot continues the name when a name part follows it.
		k := i
		for k < n && (sql[k] == ' ' || sql[k] == '\t' || sql[k] == '\n' || sql[k] == '\r') {
			k++
		}
		if k >= n || sql[k] != '.' {
			break
		}
		k++
		for k < n && (sql[k] == ' ' || sql[k] == '\t' || sql[k] == '\n' || sql[k] == '\r') {
			k++
		}
		if k >= n || !(isWordByte(sql[k]) || sql[k] == '"') {
			break
		}
		i = k
	}
	return strings.Join(parts, "."), i, nil
}

func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' }
func isWordByte(c byte) bool {
	return isLetter(c) || c >= '0' && c <= '9' || c == '$'
}

// tableOf returns the table name of a word of the form ctrlz.name.
func tableOf(w string) (string, bool) {
	t, ok := strings.CutPrefix(w, "ctrlz.")
	if !ok || t == "" || strings.Contains(t, ".") {
		return "", false
	}
	return t, true
}

func fnOf(w string) (string, bool) {
	t, ok := strings.CutPrefix(w, "ctrlz_fn.")
	if !ok || t == "" || strings.Contains(t, ".") {
		return "", false
	}
	return t, true
}

// notAlias are the words that can follow a table name without being its alias.
func notAlias(w string) bool {
	return notAliasWords()[w]
}

var notAliasWords = sync.OnceValue(func() map[string]bool {
	return map[string]bool{
		"join": true, "left": true, "right": true, "inner": true, "outer": true, "full": true, "cross": true,
		"natural": true, "on": true, "where": true, "set": true, "using": true, "group": true, "order": true,
		"limit": true, "offset": true, "for": true, "union": true, "returning": true, "values": true,
		"select": true, "having": true, "except": true, "intersect": true, "window": true, "fetch": true,
		"when": true, "then": true, "else": true, "end": true, "and": true, "or": true, "not": true,
		"from": true, "into": true, "as": true, "default": true, "lateral": true, "tablesample": true,
		"do": true, "conflict": true, "is": true, "in": true, "exists": true, "loop": true, "if": true,
		"begin": true, "exception": true, "return": true,
	}
})

type ref struct{ table, alias string }

// Analyze reads one statement or one function body and returns the locks it
// takes, in the order they appear in the text. An error means the text cannot
// be classified (an unranked table, an unknown function or advisory key, a
// lock clause with no table), which callers treat as a refusal: a statement
// that cannot be ranked cannot be shown to respect the order.
func Analyze(sql string) ([]Touch, error) {
	toks, err := lex(sql)
	if err != nil {
		return nil, err
	}
	if err := requireQualified(toks); err != nil {
		return nil, err
	}
	var out []Touch
	stack := [][]ref{nil}
	prev := func(i, back int) string {
		if i-back < 0 || toks[i-back].k != 'w' {
			return ""
		}
		return toks[i-back].s
	}
	emit := func(t Touch) { out = append(out, t) }
	unranked := func(table, why string) error {
		if _, ok := Of(table); !ok {
			return fmt.Errorf("lockrank: table %q is not ranked (%s)", table, why)
		}
		return nil
	}
	for i := 0; i < len(toks); i++ {
		tk := toks[i]
		switch tk.k {
		case '(':
			stack = append(stack, nil)
		case ')':
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		case ';':
			if len(stack) == 1 {
				stack[0] = nil
			}
		case 'w':
			if tk.s == "merge" && i+1 < len(toks) && toks[i+1].k == 'w' && toks[i+1].s == "into" {
				// MERGE writes, updates and deletes in one statement and the order below does not
				// read its WHEN clauses. A write that cannot be read is refused, as dynamic SQL is
				// (db-r6-2); INSERT ... ON CONFLICT or UPDATE says the same in a shape that is.
				return nil, fmt.Errorf("lockrank: MERGE is not supported by the lock analysis")
			}
			cur := &stack[len(stack)-1]
			if t, ok := tableOf(tk.s); ok && (isRanked(t) || !(i+1 < len(toks) && toks[i+1].k == '(')) {
				alias := ""
				if i+1 < len(toks) && toks[i+1].k == 'w' {
					nx := toks[i+1].s
					if nx == "as" && i+2 < len(toks) && toks[i+2].k == 'w' {
						alias = toks[i+2].s
					} else if !notAlias(nx) && !strings.Contains(nx, ".") {
						alias = nx
					}
				}
				*cur = append(*cur, ref{t, alias})
				p1, p2 := prev(i, 1), prev(i, 2)
				switch {
				case p1 == "into" && p2 == "insert":
					if err := unranked(t, "insert"); err != nil {
						return nil, err
					}
					for _, parent := range sortedParents(t) {
						emit(Touch{Table: parent, Mode: KeyShare})
					}
					// An upsert locks the row it conflicts with, which is somebody
					// else's: it is a write, not a trusted insert.
					if upsertUpdates(toks, i) {
						emit(Touch{Table: t, Mode: Write})
					} else {
						emit(Touch{Table: t, Mode: Insert})
					}
				case p1 == "update" && p2 != "for" && p2 != "key":
					if err := unranked(t, "update"); err != nil {
						return nil, err
					}
					emit(Touch{Table: t, Mode: Write})
				case p1 == "from" && p2 == "delete":
					if err := unranked(t, "delete"); err != nil {
						return nil, err
					}
					emit(Touch{Table: t, Mode: Write})
					for _, c := range deleteReach(t) {
						emit(c)
					}
				}
				continue
			}
			if name, ok := fnOf(tk.s); ok && i+1 < len(toks) && toks[i+1].k == '(' {
				ts, ok := definerTouches(name)
				if !ok {
					return nil, fmt.Errorf("lockrank: function ctrlz_fn.%s has no declared ranks in functions.yaml", name)
				}
				for _, t := range ts {
					emit(t)
				}
				continue
			}
			if strings.HasSuffix(tk.s, "pg_advisory_xact_lock") && i+1 < len(toks) && toks[i+1].k == '(' {
				table, err := advisoryTable(toks, i+1)
				if err != nil {
					return nil, err
				}
				emit(Touch{Table: table, Mode: Write, Advisory: true})
				continue
			}
			if strings.Contains(tk.s, "advisory") {
				return nil, fmt.Errorf("lockrank: advisory lock call %q is not supported", tk.s)
			}
			if tk.s == "for" {
				clause, next := lockClause(toks, i)
				if clause == "" {
					continue
				}
				refs := *cur
				var of []string
				noWait := false
				j := next
				if j < len(toks) && toks[j].k == 'w' && toks[j].s == "of" {
					j++
					for j < len(toks) && toks[j].k == 'w' {
						of = append(of, toks[j].s)
						j++
						if j < len(toks) && toks[j].k == ',' {
							j++
							continue
						}
						break
					}
				}
				if j < len(toks) && toks[j].k == 'w' && (toks[j].s == "nowait" || toks[j].s == "skip") {
					noWait = true
				}
				var targets []string
				for _, r := range refs {
					if len(of) == 0 || contains(of, r.alias) || contains(of, r.table) || contains(of, "ctrlz."+r.table) {
						targets = append(targets, r.table)
					}
				}
				if len(targets) == 0 {
					return nil, fmt.Errorf("lockrank: lock clause %q names no table of its query", clause)
				}
				mode := Write
				if clause == "key share" {
					mode = KeyShare
				}
				seen := map[string]bool{}
				for _, t := range targets {
					if seen[t] {
						continue
					}
					seen[t] = true
					if err := unranked(t, "lock clause"); err != nil {
						return nil, err
					}
					emit(Touch{Table: t, Mode: mode, Clause: clause, NoWait: noWait})
				}
			}
		}
	}
	return claimedRows(out), nil
}

// claimedRows marks the writes of a table that the same text locks with SKIP
// LOCKED as never waiting: "UPDATE t ... WHERE id IN (SELECT ... FOR UPDATE SKIP
// LOCKED)" writes only rows the inner select has locked already, so the outer
// update cannot wait for anyone.
func claimedRows(ts []Touch) []Touch {
	skipped := map[string]bool{}
	for _, t := range ts {
		if t.NoWait && t.Clause != "" {
			skipped[t.Table] = true
		}
	}
	for i := range ts {
		if skipped[ts[i].Table] && ts[i].Mode == Write && ts[i].Clause == "" {
			ts[i].NoWait = true
		}
	}
	return ts
}

func contains(l []string, s string) bool {
	if s == "" {
		return false
	}
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// lockClause recognises FOR UPDATE, FOR NO KEY UPDATE, FOR SHARE and FOR KEY
// SHARE at tokens[i] and returns the clause and the index after it. Any other
// FOR (a plpgsql loop) is "".
func lockClause(toks []token, i int) (string, int) {
	w := func(k int) string {
		if i+k < len(toks) && toks[i+k].k == 'w' {
			return toks[i+k].s
		}
		return ""
	}
	switch {
	case w(1) == "update":
		return "update", i + 2
	case w(1) == "share":
		return "share", i + 2
	case w(1) == "no" && w(2) == "key" && w(3) == "update":
		return "no key update", i + 4
	case w(1) == "key" && w(2) == "share":
		return "key share", i + 3
	}
	return "", i + 1
}

// upsertUpdates reports whether the INSERT whose table is at tokens[i] has an
// ON CONFLICT ... DO UPDATE in the same statement.
func upsertUpdates(toks []token, i int) bool {
	depth := 0
	for j := i + 1; j < len(toks); j++ {
		switch toks[j].k {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return false
			}
		case ';':
			return false
		case 'w':
			if depth == 0 && toks[j].s == "do" && j+1 < len(toks) && toks[j+1].k == 'w' && toks[j+1].s == "update" {
				return true
			}
		}
	}
	return false
}

// advisoryTable reads the first string literal inside the call that opens at
// toks[open] and maps its prefix to a table.
func advisoryTable(toks []token, open int) (string, error) {
	depth := 0
	for j := open; j < len(toks); j++ {
		switch toks[j].k {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return "", fmt.Errorf("lockrank: advisory lock with no constant key")
			}
		case 's':
			for prefix, table := range advisoryKeys() {
				if strings.HasPrefix(toks[j].s, prefix) {
					return table, nil
				}
			}
			return "", fmt.Errorf("lockrank: advisory key is not ranked")
		}
	}
	return "", fmt.Errorf("lockrank: advisory lock call is not closed")
}

// deleteReach lists what deleting a row of the table locks through foreign
// keys: children that cascade or are set to null are written, the others are
// checked with a key share. Order is by rank, parents before children.
func deleteReach(table string) []Touch {
	var out []Touch
	seen := map[string]bool{table: true}
	queue := []string{table}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, c := range Children(cur) {
			if seen[c.Table] {
				continue
			}
			seen[c.Table] = true
			switch c.OnDelete {
			case "cascade":
				out = append(out, Touch{Table: c.Table, Mode: Write})
				queue = append(queue, c.Table)
			case "set_null":
				out = append(out, Touch{Table: c.Table, Mode: Write})
			default:
				out = append(out, Touch{Table: c.Table, Mode: KeyShare})
			}
		}
	}
	sort.SliceStable(out, func(a, b int) bool {
		ra, _ := Of(out[a].Table)
		rb, _ := Of(out[b].Table)
		return ra < rb
	})
	return out
}

func isRanked(table string) bool { _, ok := Of(table); return ok }

// sortedParents lists the parents an insert takes FOR KEY SHARE on, lowest rank
// first, leaving out the inert ones. The server checks the foreign keys in an
// order of its own; key shares do not conflict with each other, so the order
// among them can only matter to a writer that takes FOR UPDATE on a parent, and
// the rule forbids that on the tables where it would (users).
func sortedParents(table string) []string {
	var out []string
	for _, p := range Parents(table) {
		if !Inert(p) {
			out = append(out, p)
		}
	}
	sort.SliceStable(out, func(a, b int) bool {
		ra, _ := Of(out[a])
		rb, _ := Of(out[b])
		return ra < rb
	})
	return out
}
