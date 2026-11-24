package lint_test

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// The SQL rules (R5, review F09 and F07). Four things must hold for every
// database call anywhere in the module outside the places that are allowed to
// build SQL on purpose:
//
//  1. The SQL argument is a constant, decided by go/types, not by name: a local
//     variable that shadows a package constant is not one.
//  2. The constant text is a query, and it keeps to the known ways a query can
//     leave the session changed: this is a list of words, not a proof that no
//     query can (SELECT ... INTO TEMP, a sequence function and the like are not
//     examined; what stands behind the list is that every constant is written
//     by a developer and reviewed). Its first
//     word, read past comments, is select, insert, update, delete, with, values
//     or merge: an allow list, because a list of refused words (SET, RESET,
//     DISCARD, LISTEN, COMMIT, DO, ...) missed ALTER ROLE ... SET, whose effect
//     outlives the connection, and PREPARE, DECLARE and LOCK. Inside a query,
//     no set_config outside the one file that sets the tenant, and no mention of
//     the tenant setting at all outside it. That file may do those two things and
//     nothing else. In no file, the tenant file included: any of the functions that
//     run a string as SQL (query_to_xml and its two relatives, ts_stat, ts_rewrite:
//     they can build the setter's name, or the name of anything below, at run
//     time), pg_settings (its ON UPDATE rule is a session-level set_config), a
//     session-level advisory lock, pg_terminate_backend, pg_cancel_backend or a
//     large object function: sessionReach says why each is on the list. Fail-closed depends on
//     every setter being transaction-local, and one stray session-level
//     set_config scopes later jobs on that connection to another tenant. The
//     text is read past SQL comments, because sqlc puts "-- name: X :exec" in
//     front of every statement, and with quotes and spaces around dots removed,
//     which is how the server reads a name. (Those functions were found by
//     calling every function of pg_catalog and information_schema that takes a
//     text argument with a query that counts in a sequence; no other one ran it.)
//  3. A constant is one statement. pgx runs an Exec with no arguments over the
//     simple protocol, so "SELECT 1; COMMIT" is two statements, and the check
//     of point 2 reads only the first word of a text. sqlShape reads the text
//     the way the server's lexer does, outside quotes, dollar quotes and
//     comments, and refuses a semicolon that is followed by anything but
//     whitespace and comments, a leading semicolon, the U&"..." spelling of a
//     name, which can write set_config past the word check, and a string that
//     is continued on the next line, whose escape mode the server carries over.
//  4. Nothing escapes the check: method values (f := db.Exec), CopyFrom (which
//     takes no SQL text) and the opt-out marker outside the two places that
//     need it.
//
// The scan used to cover internal/store, internal/app and cmd only, while
// Tx.DB() hands a raw Exec to any package, so a new package could concatenate
// SQL without a test noticing. It now covers every package of the module
// except the ones that build SQL as their job.

// sqlSinks maps a call name to the index of its SQL argument. A negative index
// means the call takes no SQL text and cannot be checked, so it is refused.
func sqlSinks() map[string]int {
	return map[string]int{
		"Exec": 1, "Query": 1, "QueryRow": 1, // pgx and DBTX
		"ExecContext": 1, "QueryContext": 1, "QueryRowContext": 1, // database/sql
		"Prepare":    2, // pgx Conn.Prepare(ctx, name, sql)
		"Queue":      0, // pgx Batch.Queue(sql, args...)
		"ExecParams": 1, // pgconn.PgConn.ExecParams(ctx, sql, ...)
		"one":        2, // the helper in internal/store/auth.go
		// These take no SQL text: a copy stream, a prepared statement's name, a
		// batch built elsewhere. They cannot be checked, so they are refused.
		"CopyFrom":     -1,
		"ExecPrepared": -1, // pgconn.PgConn.ExecPrepared(ctx, stmtName, ...)
		"SendBatch":    -1, // pgx.Conn/Tx.SendBatch(ctx, batch)
	}
}

// rawConnAccessors are the methods that hand back the raw connection: pgx.Rows
// and pgx.Tx have Conn(), pgx.Conn has PgConn(). With one of them a caller runs
// SQL the sink check never sees, such as a session-level set_config that scopes
// the next request on the pooled connection to another tenant (review L1-F09).
// Only internal/store may call them.
func rawConnAccessors() map[string]bool { return map[string]bool{"Conn": true, "PgConn": true} }

// sqlExempt are the packages that build SQL as their job: the migration runner,
// the test database, the generator, and the catalog and auth test support (imported only
// from tests) and the pg_catalog reader the migrate step shares with the catalog tests
// (internal/reachcheck: its SQL names system catalogs, never a ctrlz table, and is constant).
func sqlExempt(path string) bool {
	for _, p := range []string{"internal/testpg/", "internal/migrate/", "internal/migrategen/", "tools/", "internal/store/catalogtest/", "internal/reachcheck/", "internal/authtest/", "internal/lint/"} {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// optOutPlaces are the only functions where `lint:sql-const` is honoured: the
// helper whose SQL is a parameter every caller fills with a constant, the six
// forwarding methods of the narrow DB handle. There is no Listen any more (db-r15-1).
func optOutPlaces() map[string]map[string]bool {
	return map[string]map[string]bool{
		"internal/store/auth.go":  {"one": true},
		"internal/store/tx.go":    {"Exec": true, "Query": true, "QueryRow": true},
		"internal/store/locks.go": {"Exec": true, "Query": true, "QueryRow": true},
	}
}

// tenantSettingFile is the one file that may name the tenant setting and call
// set_config.
const tenantSettingFile = "internal/store/tx.go"

var (
	// A constant starts with a word of this list, read after its comments: the
	// statements a repository query is made of. A list of the words to refuse
	// had to be complete against everything Postgres can start a statement with
	// (ALTER ROLE ... SET outlives the connection, PREPARE and DECLARE keep state
	// on it, DO runs statements of its own), and it was not. The server's
	// whitespace is space, tab, newline, return, form feed and vertical tab;
	// Go's \s has no vertical tab.
	allowedStmt = regexp.MustCompile(`(?is)^[\s\v]*(select|insert|update|delete|with|values|merge)\b`)
	// setConfig is the word check for the tenant setting's setter. Only this and
	// the setting's name are allowed in the tenant file.
	setConfig = regexp.MustCompile(`(?i)\bset_config\b`)
	// runsString is the word check for the functions that run a string as SQL: a
	// constant can build the setter's name, or any name of sessionReach, at run
	// time inside one of them, so the word never appears in the text. It has no
	// exemption, the tenant file included, because that file needs none of them
	// and a word check cannot see into the string they run.
	runsString = regexp.MustCompile(`(?i)\b(query_to_xml|query_to_xml_and_xmlschema|query_to_xmlschema|ts_stat|ts_rewrite)\b`)
	dotSpace   = regexp.MustCompile(`\s*\.\s*`)
	// sessionReach is the word check for what a plain query can still do to the
	// connection or to other sessions, all of it open to PUBLIC. pg_settings has an
	// ON UPDATE rule that runs set_config(name, setting, false). A session-level
	// advisory lock outlives the transaction and stays with the pooled connection,
	// so it can hold another tenant's claim lock; the _xact_ forms end with the
	// transaction and are not listed. All tenants share one login, so
	// pg_terminate_backend and pg_cancel_backend reach another tenant's backend,
	// and a large object lives outside row level security. The \b around the
	// alternatives keeps pg_advisory_xact_lock and a column called lo_values clear.
	sessionReach = regexp.MustCompile(`(?i)\b(pg_settings|pg_advisory_lock|pg_advisory_lock_shared|pg_try_advisory_lock|pg_try_advisory_lock_shared|pg_terminate_backend|pg_cancel_backend|pg_notify|lo_create|lo_creat|lo_open|lo_close|lo_unlink|lo_import|lo_export|lo_from_bytea|lo_get|lo_put|lo_lseek|lo_lseek64|lo_tell|lo_tell64|lo_truncate|lo_truncate64|loread|lowrite)\b`)
)

// stripSQLComments replaces every comment of a SQL text with one space: a
// -- comment to the end of its line (the server ends it at a newline or at a
// carriage return), and a /* */ comment, which Postgres lets nest. sqlc starts every statement with "-- name: X :exec", so a check
// anchored at the start of the text has to look past comments, and a comment
// inside a statement is whitespace to the server just the same.
func stripSQLComments(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		switch {
		case strings.HasPrefix(s[i:], "--"):
			for i < len(s) && s[i] != '\n' && s[i] != '\r' {
				i++
			}
			b.WriteByte(' ')
		case strings.HasPrefix(s[i:], "/*"):
			depth := 0
			for i < len(s) {
				if strings.HasPrefix(s[i:], "/*") {
					depth++
					i += 2
				} else if strings.HasPrefix(s[i:], "*/") {
					depth--
					i += 2
					if depth == 0 {
						break
					}
				} else {
					i++
				}
			}
			b.WriteByte(' ')
		default:
			b.WriteByte(s[i])
			i++
		}
	}
	return b.String()
}

// sqlSpace is the server's whitespace.
func sqlSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}

// sqlIdentChar is a byte that can continue an identifier.
func sqlIdentChar(c byte) bool {
	return c == '_' || c == '$' || c >= 0x80 || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// skipSQLComment returns the index after the comment that starts at i, or i if
// none does. A block comment nests, and one that is never closed runs to the end.
func skipSQLComment(s string, i int) int {
	switch {
	case strings.HasPrefix(s[i:], "--"):
		for i < len(s) && s[i] != '\n' && s[i] != '\r' {
			i++
		}
	case strings.HasPrefix(s[i:], "/*"):
		depth := 0
		for i < len(s) {
			if strings.HasPrefix(s[i:], "/*") {
				depth++
				i += 2
			} else if strings.HasPrefix(s[i:], "*/") {
				depth--
				i += 2
				if depth == 0 {
					break
				}
			} else {
				i++
			}
		}
	}
	return i
}

// continuedString reports whether the closing quote just before index i is
// followed by a newline (with white space and comments around it) and then by
// another quote, which the server reads as the same string continued.
func continuedString(s string, i int) bool {
	newline := false
	for i < len(s) {
		switch {
		case s[i] == '\n' || s[i] == '\r':
			newline = true
			i++
		case sqlSpace(s[i]):
			i++
		default:
			j := skipSQLComment(s, i)
			if j == i {
				return newline && s[i] == '\''
			}
			// The server allows only a line comment here. Being stricter about a
			// block comment that holds the newline costs nothing.
			if strings.ContainsAny(s[i:j], "\n\r") {
				newline = true
			}
			i = j
		}
	}
	return false
}

// sqlShape reads a constant the way the server's lexer does and returns what
// is wrong with its shape. A statement must be the only thing in the text; one
// semicolon after it is fine. Quoted text is skipped (single quotes, with
// backslash escapes after an E, double quotes, dollar quotes) and so are
// comments, so a semicolon in a string or in the body of a DO block is not
// a separator.
func sqlShape(s string) []string {
	var out []string
	add := func(msg string) {
		for _, m := range out {
			if m == msg {
				return
			}
		}
		out = append(out, msg)
	}
	started, afterSemicolon := false, false
	for i := 0; i < len(s); {
		c := s[i]
		if sqlSpace(c) {
			i++
			continue
		}
		if j := skipSQLComment(s, i); j != i {
			i = j
			continue
		}
		if afterSemicolon {
			add("something follows a semicolon")
		}
		if c == ';' {
			if !started {
				add("a leading semicolon")
			}
			afterSemicolon = true
			i++
			continue
		}
		started = true
		prevIdent := i > 0 && sqlIdentChar(s[i-1])
		switch {
		case c == '\'':
			escapes := i > 0 && (s[i-1] == 'e' || s[i-1] == 'E') && (i < 2 || !sqlIdentChar(s[i-2]))
			i++
			for i < len(s) {
				if escapes && s[i] == '\\' {
					i += 2
				} else if s[i] == '\'' {
					if i+1 < len(s) && s[i+1] == '\'' {
						i += 2
					} else {
						i++
						break
					}
				} else {
					i++
				}
			}
			// The server joins two string segments that are apart by nothing but
			// white space with a newline in it (comments allowed), and keeps the
			// escape mode of the first across the join. The mode is decided here
			// from the byte before the opening quote, so the second segment would
			// be read in the wrong mode and a quote it escapes would end it early.
			// Refusing the join is simpler than tracking it, and no query needs one.
			if continuedString(s, i) {
				add("a string continued on another line")
			}
		case c == '"':
			i++
			for i < len(s) {
				if s[i] == '"' {
					if i+1 < len(s) && s[i+1] == '"' {
						i += 2
						continue
					}
					i++
					break
				}
				i++
			}
		case c == '$' && !prevIdent:
			// $tag$ ... $tag$, where the tag is empty or an identifier that does
			// not start with a digit. $1 is a parameter.
			j := i + 1
			if j < len(s) && s[j] != '$' && (s[j] == '_' || s[j] >= 0x80 || s[j] >= 'a' && s[j] <= 'z' || s[j] >= 'A' && s[j] <= 'Z') {
				for j < len(s) && s[j] != '$' && sqlIdentChar(s[j]) {
					j++
				}
			}
			if j < len(s) && s[j] == '$' {
				tag := s[i : j+1]
				if end := strings.Index(s[j+1:], tag); end >= 0 {
					i = j + 1 + end + len(tag)
				} else {
					i = len(s)
				}
			} else {
				i++
			}
		case (c == 'u' || c == 'U') && !prevIdent && i+2 < len(s) && s[i+1] == '&' && (s[i+2] == '"' || s[i+2] == '\''):
			add("a U& escape spelling")
			i += 2
		default:
			i++
		}
	}
	return out
}

// sqlVariants are the readings of a constant the checks run on. The raw text
// comes first, because stripping can hide something: a '--' inside a string
// literal is not a comment, and removing "the rest of the line" would remove a
// call that follows it. The other two are the text without comments, and that
// again without quotes and with no space around dots, which is how Postgres
// reads "ctrlz" . "tenant_id".
func sqlVariants(text string) []string {
	stripped := stripSQLComments(text)
	plain := dotSpace.ReplaceAllString(strings.ReplaceAll(stripped, "\"", ""), ".")
	return []string{text, stripped, plain}
}

// sqlProblems returns what is wrong with the database calls in files.
func sqlProblems(fset *token.FileSet, files []file) []string {
	info, ok := typeInfo(fset, files)
	if !ok {
		return []string{"type information unavailable"}
	}
	var out []string
	add := func(f file, pos token.Pos, format string, args ...any) {
		out = append(out, fmt.Sprintf("%s:%d: %s", f.path, fset.Position(pos).Line, fmt.Sprintf(format, args...)))
	}
	for _, f := range files {
		if f.test || sqlExempt(f.path) {
			continue
		}
		markers := map[int]bool{}
		for _, cg := range f.ast.Comments {
			for _, c := range cg.List {
				if strings.Contains(c.Text, "lint:sql-const") {
					markers[fset.Position(c.Pos()).Line] = true
				}
			}
		}
		sinks := sqlSinks()

		// Inspect function by function, so a call knows its enclosing function.
		var enclosing string
		inspect := func(root ast.Node, fn string) {
			enclosing = fn
			calleeOf := map[ast.Node]bool{}
			ast.Inspect(root, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					calleeOf[call.Fun] = true
					if ix, ok := call.Fun.(*ast.IndexExpr); ok { // one[T](...)
						calleeOf[ix.X] = true
					}
					if ix, ok := call.Fun.(*ast.IndexListExpr); ok {
						calleeOf[ix.X] = true
					}
				}
				return true
			})
			ast.Inspect(root, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.SelectorExpr:
					if _, isSink := sinks[x.Sel.Name]; isSink && !calleeOf[x] && x.Sel.Name != "one" {
						// A method value escapes the argument check.
						if recvMayBeDB(x) {
							add(f, x.Pos(), "%s used as a value; call it directly so its SQL argument can be checked", x.Sel.Name)
						}
					}
				case *ast.CallExpr:
					name := calleeName(x.Fun)
					if sel, ok := x.Fun.(*ast.SelectorExpr); ok && rawConnAccessors()[name] && len(x.Args) == 0 && !strings.HasPrefix(f.path, "internal/store/") {
						add(f, x.Pos(), "%s() hands out the raw database connection; only internal/store may call it (%s)", name, exprText(sel.X))
					}
					idx, isSink := sinks[name]
					if !isSink {
						return true
					}
					line := fset.Position(x.Pos()).Line
					if idx < 0 {
						add(f, x.Pos(), "%s takes no SQL text and cannot be checked; not allowed", name)
						return true
					}
					if len(x.Args) <= idx {
						return true
					}
					arg := x.Args[idx]
					if markers[line] || markers[line-1] {
						if !optOutPlaces()[f.path][enclosing] {
							add(f, x.Pos(), "lint:sql-const is only honoured in %v, not in %s", optOutPlaces(), enclosing)
						}
						return true
					}
					tv, known := info.Types[arg]
					if !known || tv.Value == nil || tv.Value.Kind() != constant.String {
						add(f, x.Pos(), "argument %d of %s is not a constant; build no SQL at run time", idx+1, name)
						return true
					}
					text := constant.StringVal(tv.Value)
					if shape := sqlShape(text); len(shape) > 0 {
						add(f, x.Pos(), "SQL that is not one plain statement (%s): %.40q", strings.Join(shape, ", "), text)
					}
					// Only the comment-free reading decides the first word: the other
					// readings are for the words below, where hiding is the risk.
					var setting, reach, runs bool
					for _, v := range sqlVariants(text) {
						setting = setting || setConfig.MatchString(v) || strings.Contains(strings.ToLower(v), "ctrlz.tenant_id")
						reach = reach || sessionReach.MatchString(v)
						runs = runs || runsString.MatchString(v)
					}
					if !allowedStmt.MatchString(stripSQLComments(text)) {
						add(f, x.Pos(), "SQL that does not start with select, insert, update, delete, with, values or merge: %.40q", text)
					}
					// Not exempt in the tenant file, which needs set_config and nothing here:
					// not the session-reaching words, not the string-running functions.
					if reach {
						add(f, x.Pos(), "SQL that changes the session or acts across sessions (pg_settings, a session-level advisory lock, pg_terminate_backend, pg_cancel_backend, a large object function): %.60q", text)
					}
					if runs {
						add(f, x.Pos(), "SQL that runs a string as SQL (query_to_xml and its relatives, ts_stat, ts_rewrite); refused in every file: %.60q", text)
					}
					if f.path != tenantSettingFile && setting {
						add(f, x.Pos(), "only %s may set or name the tenant setting: %.60q", tenantSettingFile, text)
					}
				}
				return true
			})
		}
		for _, d := range f.ast.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Body != nil {
					inspect(d.Body, d.Name.Name)
				}
			case *ast.GenDecl:
				inspect(d, "")
			}
		}
	}
	sort.Strings(out)
	return out
}

// exprText names the receiver of a call for the message.
func exprText(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return exprText(x.X) + "." + x.Sel.Name
	case *ast.CallExpr:
		return exprText(x.Fun) + "()"
	}
	return "expression"
}

// calleeName is the name of the function or method a call expression calls,
// looking through explicit instantiation one[T](...) and one[A, B](...).
func calleeName(fun ast.Expr) string {
	switch fn := fun.(type) {
	case *ast.SelectorExpr:
		return fn.Sel.Name
	case *ast.Ident:
		return fn.Name
	case *ast.IndexExpr:
		return calleeName(fn.X)
	case *ast.IndexListExpr:
		return calleeName(fn.X)
	case *ast.ParenExpr:
		return calleeName(fn.X)
	}
	return ""
}

// recvMayBeDB limits the method-value rule to receivers that can be a database
// handle, so unrelated things named Query (url.Values has none; templates have
// Execute) do not trip it. A selector on a package name (pkg.Exec) is a plain
// function and is covered by the call rule.
func recvMayBeDB(x *ast.SelectorExpr) bool {
	switch r := x.X.(type) {
	case *ast.Ident:
		return r.Obj == nil || r.Obj.Kind != ast.Pkg
	}
	return true
}

// typeInfo type-checks the non-test files of each package of the module and
// returns one merged Info. Imports outside the module are replaced by empty
// stubs: only constants matter here, and a constant never depends on an
// imported type. Type errors from the stubs are expected and ignored.
func typeInfo(fset *token.FileSet, files []file) (*types.Info, bool) {
	return typeInfoReal(fset, files)
}

// typeInfoReal is typeInfo with the named standard-library packages type-checked
// from source instead of stubbed, for a rule that must know a value is a
// *slog.Logger (closed-values-in-logs). Everything else stays a stub.
func typeInfoReal(fset *token.FileSet, files []file, stdlib ...string) (*types.Info, bool) {
	// A directory can hold files of more than one package clause (a `//go:build ignore` generator that
	// is package main beside the real files). go/types takes the name from the first file and drops
	// every file that does not match, so the files are grouped by package name and each group is
	// checked as a package of its own; otherwise one odd file that sorts first leaves the real files
	// with no type information and every lint that reads it goes blind in that directory (q9-11).
	byDir := map[string]map[string][]*ast.File{}
	for _, f := range files {
		if f.test {
			continue
		}
		dir := filepath.ToSlash(filepath.Dir(f.path))
		if byDir[dir] == nil {
			byDir[dir] = map[string][]*ast.File{}
		}
		byDir[dir][f.ast.Name.Name] = append(byDir[dir][f.ast.Name.Name], f.ast)
	}
	info := &types.Info{
		Types: map[ast.Expr]types.TypeAndValue{}, Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
		Instances:  map[*ast.Ident]types.Instance{},
	}
	done := map[string]*types.Package{}
	src := stdlibImporter()
	var check func(dir string) *types.Package
	imp := importerFunc(func(path string) (*types.Package, error) {
		if strings.HasPrefix(path, module+"/") {
			if p := check(strings.TrimPrefix(path, module+"/")); p != nil {
				return p, nil
			}
		}
		for _, r := range stdlib {
			if r == path {
				return src.Import(path)
			}
		}
		p := types.NewPackage(path, filepath.Base(path))
		p.MarkComplete()
		return p, nil
	})
	check = func(dir string) *types.Package {
		if p, ok := done[dir]; ok {
			return p
		}
		groups, ok := byDir[dir]
		if !ok {
			return nil
		}
		done[dir] = nil // import cycles cannot happen in compiling code; this stops a loop in broken input
		// Every group is checked, so every file gets its Uses and Types. The package an importer gets is
		// the one that is not main (a main package cannot be imported), the first by name otherwise.
		names := make([]string, 0, len(groups))
		for n := range groups {
			names = append(names, n)
		}
		sort.Slice(names, func(i, j int) bool {
			if (names[i] == "main") != (names[j] == "main") {
				return names[j] == "main"
			}
			return names[i] < names[j]
		})
		var chosen *types.Package
		for i, n := range names {
			conf := types.Config{Importer: imp, Error: func(error) {}, FakeImportC: true}
			p, _ := conf.Check(module+"/"+dir, fset, groups[n], info)
			if i == 0 {
				chosen = p
			}
		}
		done[dir] = chosen
		return chosen
	}
	for dir := range byDir {
		check(dir)
	}
	return info, len(done) > 0
}

type importerFunc func(string) (*types.Package, error)

func (f importerFunc) Import(path string) (*types.Package, error) { return f(path) }

func TestNoDynamicSQL(t *testing.T) {
	fset, files := parseRepo(t)
	for _, p := range sqlProblems(fset, files) {
		t.Error(p)
	}
	// The check must have looked at something. Count the calls it examines by
	// planting nothing: every sink call outside the exempt places.
	calls := 0
	for _, f := range files {
		if f.test || sqlExempt(f.path) {
			continue
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if idx, isSink := sqlSinks()[calleeName(c.Fun)]; isSink && idx >= 0 && len(c.Args) > idx {
					calls++
				}
			}
			return true
		})
	}
	if calls < 10 {
		t.Errorf("the check saw only %d database calls; it is probably looking in the wrong place", calls)
	}
}

// TestSQLLintCatchesWhatItShouldNot is the lint's own test: a planted violation
// in each shape must be reported, and clean code must pass. Reproduced from the
// review: a call tx.DB().Exec(ctx, "..."+name) in a new package compiled,
// passed go vet and left TestNoDynamicSQL green.
func TestSQLLintCatchesWhatItShouldNot(t *testing.T) {
	const header = "package pkg\nimport \"context\"\ntype DB struct{}\nfunc (DB) Exec(context.Context, string, ...any) {}\nfunc (DB) Query(context.Context, string, ...any) {}\nfunc (DB) Queue(string, ...any) {}\nfunc (DB) Prepare(context.Context, string, string) {}\nfunc (DB) CopyFrom(context.Context, string) {}\nfunc one[T any](context.Context, any, string) T { var z T; return z }\nconst qOK = \"SELECT 1\"\nvar ctx = context.Background()\nvar db DB\nvar name string\n"
	cases := []struct {
		name string
		path string
		src  string
		bad  int // number of problems expected
	}{
		{"clean constants", "internal/api/a.go", `func f() { db.Exec(ctx, qOK); db.Query(ctx, "SELECT " + "2"); db.Queue(qOK + " WHERE true") }`, 0},
		{"concatenated name in a new package", "internal/api/dyn.go", `func f() { db.Exec(ctx, "SELECT 1 WHERE k = '" + name + "'") }`, 1},
		{"a variable", "internal/api/dyn.go", `func f(q string) { db.Query(ctx, q) }`, 1},
		{"explicit generic instantiation", "internal/api/gen.go", `func f(q string) { _ = one[int](ctx, nil, q) }`, 1},
		{"a local that shadows a package constant", "internal/api/shadow.go", `func f() { qOK := "SELECT " + name; db.Exec(ctx, qOK) }`, 1},
		{"Prepare with a dynamic statement", "internal/api/prep.go", `func f(q string) { db.Prepare(ctx, "n", q) }`, 1},
		{"Batch.Queue with a dynamic statement", "internal/api/queue.go", `func f(q string) { db.Queue(q) }`, 1},
		{"CopyFrom takes no SQL text", "internal/api/copy.go", `func f() { db.CopyFrom(ctx, "t") }`, 1},
		{"a method value", "internal/api/val.go", `func f() { x := db.Exec; _ = x }`, 1},
		{"a session-level set_config", "internal/api/sess.go", `func f() { db.Exec(ctx, "SELECT set_config('ctrlz.tenant_id', 'x', false)") }`, 1},
		{"SET on the session", "internal/api/set.go", `func f() { db.Exec(ctx, "SET ctrlz.tenant_id = 'x'") }`, 2},
		{"SET ROLE", "internal/api/role.go", `func f() { db.Exec(ctx, "  set role ctrlz_admin") }`, 1},
		{"RESET and DISCARD", "internal/api/reset.go", `func f() { db.Exec(ctx, "RESET ALL"); db.Exec(ctx, "DISCARD ALL") }`, 2},
		{"COMMIT from inside the callback", "internal/api/commit.go", `func f() { db.Exec(ctx, "COMMIT") }`, 1},
		// P0 gate review, B8 and D10: a comment in front of, or inside, the statement.
		{"COMMIT behind an empty comment", "internal/api/c1.go", `func f() { db.Exec(ctx, "/**/ COMMIT") }`, 1},
		{"COMMIT behind a comment line", "internal/api/c2.go", `func f() { db.Exec(ctx, "-- not a statement\nCOMMIT") }`, 1},
		{"SET of the quoted tenant setting behind a comment", "internal/api/c3.go", `func f() { db.Exec(ctx, "/**/ SET \"ctrlz\".\"tenant_id\" = 'x'") }`, 2},
		{"SET ROLE behind a comment", "internal/api/c4.go", `func f() { db.Exec(ctx, "/**/ SET ROLE ctrlz_admin") }`, 1},
		{"a DO block", "internal/api/c5.go", `func f() { db.Exec(ctx, "DO $$ BEGIN COMMIT; END $$") }`, 1},
		{"a DO block behind a comment", "internal/api/c5b.go", `func f() { db.Exec(ctx, "/* x */ do language plpgsql $$ begin commit; end $$") }`, 1},
		{"the sqlc header, then COMMIT", "internal/api/c6.go", `func f() { db.Exec(ctx, "-- name: Done :exec\nCOMMIT") }`, 1},
		{"the sqlc header, then SET ROLE", "internal/api/c7.go", `func f() { db.Exec(ctx, "-- name: Become :exec\nSET ROLE ctrlz_admin") }`, 1},
		{"the sqlc header, then RESET ALL", "internal/api/c8.go", `func f() { db.Exec(ctx, "-- name: Wipe :exec\nRESET ALL") }`, 1},
		// P0 gate review, second round: a second statement, and ways to hide the first.
		// A text that starts with a semicolon counts twice from the third round on: the shape
		// (a leading semicolon) and the first word (a semicolon is no statement).
		{"a line comment ended by a carriage return, then COMMIT", "internal/api/d1.go", `func f() { db.Exec(ctx, "-- x\rCOMMIT") }`, 1},
		{"a leading semicolon, then COMMIT", "internal/api/d2.go", `func f() { db.Exec(ctx, ";COMMIT") }`, 2},
		{"a leading semicolon and a space, then COMMIT", "internal/api/d3.go", `func f() { db.Exec(ctx, "; COMMIT") }`, 2},
		{"an empty comment, a semicolon, then COMMIT", "internal/api/d4.go", `func f() { db.Exec(ctx, "/**/;COMMIT") }`, 2},
		{"a comment with spaces, a semicolon, then COMMIT", "internal/api/d5.go", `func f() { db.Exec(ctx, "/* c */ ; COMMIT") }`, 2},
		{"a vertical tab, then COMMIT", "internal/api/d6.go", `func f() { db.Exec(ctx, "\vCOMMIT") }`, 1},
		{"a form feed, then COMMIT", "internal/api/d7.go", `func f() { db.Exec(ctx, "\fCOMMIT") }`, 1},
		{"a leading semicolon, then a role change", "internal/api/d8.go", `func f() { db.Exec(ctx, "; SET ROLE ctrlz_admin") }`, 2},
		{"the sqlc header, a semicolon, then RESET ALL", "internal/api/d9.go", `func f() { db.Exec(ctx, "-- name: X :exec\n;RESET ALL") }`, 2},
		{"a query, then COMMIT", "internal/api/d10.go", `func f() { db.Exec(ctx, "SELECT 1; COMMIT") }`, 1},
		{"a query, then a role change", "internal/api/d11.go", `func f() { db.Exec(ctx, "SELECT 1; SET ROLE ctrlz_admin") }`, 1},
		{"an UPDATE, then RESET ALL", "internal/api/d12.go", `func f() { db.Exec(ctx, "UPDATE t SET a = 1; RESET ALL") }`, 1},
		{"two plain queries", "internal/api/d13.go", `func f() { db.Exec(ctx, "SELECT 1; SELECT 2") }`, 1},
		{"an empty statement after a query", "internal/api/d14.go", `func f() { db.Exec(ctx, "SELECT 1;;") }`, 1},
		{"a semicolon alone", "internal/api/d15.go", `func f() { db.Exec(ctx, ";") }`, 2},
		{"a vertical tab after the semicolon, then COMMIT", "internal/api/d16.go", `func f() { db.Exec(ctx, "SELECT 1;\vCOMMIT") }`, 1},
		{"a carriage return ends the comment after the semicolon", "internal/api/d17.go", `func f() { db.Exec(ctx, "SELECT 1; -- c\rCOMMIT") }`, 1},
		{"a nested comment after the semicolon, then COMMIT", "internal/api/d18.go", `func f() { db.Exec(ctx, "SELECT 1; /* a /* b */ c */ COMMIT") }`, 1},
		{"a semicolon after a string, then COMMIT", "internal/api/d19.go", `func f() { db.Exec(ctx, "SELECT ';' ; COMMIT") }`, 1},
		{"a quote that an escape string does not close", "internal/api/d20.go", `func f() { db.Exec(ctx, "SELECT E'a\\'; COMMIT --'") }`, 0},
		{"a function name spelled with a U& escape", "internal/api/d21.go", `func f() { db.Exec(ctx, "SELECT U&\"set\\005fconfig\"('app.x', 'y', false)") }`, 1},
		{"the same with a split setting name", "internal/api/d22.go", `func f() { db.Exec(ctx, "SELECT u&\"set\\005fconfig\"('ctrlz.' || 'tenant_id', 'x', false)") }`, 1},
		{"a U& string", "internal/api/d23.go", `func f() { db.Exec(ctx, "SELECT U&'d\\0061t\\0061'") }`, 1},
		// P0 gate review, third round: a string continued on the next line keeps its
		// escape mode on the server, so the lint refuses the continuation.
		{"an E string continued, then COMMIT", "internal/api/f1.go", `func f() { db.Exec(ctx, "SELECT E'a'\n'\\' x '; COMMIT; --'") }`, 1},
		{"the same with a comment before the newline", "internal/api/f2.go", `func f() { db.Exec(ctx, "SELECT E'a' -- c\n'\\' x '; COMMIT; --'") }`, 1},
		{"an E string continued, an escaped quote, then COMMIT", "internal/api/f3.go", `func f() { db.Exec(ctx, "SELECT E'a'\n'b\\'c'; COMMIT --'") }`, 1},
		{"the same, then RESET ALL", "internal/api/f4.go", `func f() { db.Exec(ctx, "SELECT E'a'\n'b\\'c'; RESET ALL --'") }`, 1},
		{"the same with a comment line between the segments", "internal/api/f5.go", `func f() { db.Exec(ctx, "SELECT E'a'\n-- c\n'b\\'c'; COMMIT --'") }`, 1},
		{"a plain string continued", "internal/api/f6.go", `func f() { db.Exec(ctx, "SELECT 'a'\n'b'") }`, 1},
		{"a carriage return continues a string too", "internal/api/f7.go", `func f() { db.Exec(ctx, "SELECT 'a'\r'b'") }`, 1},
		{"a string, a newline, then something that is not a quote", "internal/api/f8.go", `func f() { db.Query(ctx, "SELECT 'a'\nFROM t WHERE b = 'c'\n  AND d = 'e'") }`, 0},
		{"two strings on one line", "internal/api/f9.go", `func f() { db.Query(ctx, "SELECT 'a' 'b'") }`, 0},
		// SQL-running functions: the tenant setting's name can be built inside the
		// string they run, so the word set_config is nowhere in the constant.
		{"query_to_xml builds the setter", "internal/api/g1.go", `func f() { db.Query(ctx, "SELECT query_to_xml('SELECT set_'||'config(''ctrlz.ten'||'ant_id'', '||quote_literal($1::text)||', true)', true, true, '')") }`, 1},
		{"query_to_xml_and_xmlschema", "internal/api/g2.go", `func f() { db.Query(ctx, "SELECT query_to_xml_and_xmlschema('SELECT 1', true, true, '')") }`, 1},
		{"query_to_xmlschema", "internal/api/g3.go", `func f() { db.Query(ctx, "SELECT query_to_xmlschema('SELECT 1', true, true, '')") }`, 1},
		{"ts_stat", "internal/api/g4.go", `func f() { db.Query(ctx, "SELECT * FROM ts_stat('SELECT set_'||'config(''ctrlz.ten'||'ant_id'', ''x'', true)::tsvector')") }`, 1},
		{"ts_rewrite", "internal/api/g5.go", `func f() { db.Query(ctx, "SELECT ts_rewrite('a'::tsquery, 'SELECT null::tsquery, set_'||'config(''ctrlz.ten'||'ant_id'', ''x'', true)::tsquery')") }`, 1},
		{"a quoted function name", "internal/api/g6.go", `func f() { db.Query(ctx, "SELECT \"Query_To_Xml\"('SELECT 1', true, true, '')") }`, 1},
		{"a name that only starts like one", "internal/api/g7.go", `func f() { db.Query(ctx, "SELECT ts_statistics FROM t") }`, 0},
		// Statements that are not queries, even as one clean statement.
		{"ALTER ROLE CURRENT_USER SET", "internal/api/h1.go", `func f() { db.Exec(ctx, "ALTER ROLE CURRENT_USER SET statement_timeout = 0") }`, 1},
		{"ALTER USER with a comment in front", "internal/api/h2.go", `func f() { db.Exec(ctx, "/* x */ alter user current_user set search_path = pg_temp") }`, 1},
		{"PREPARE", "internal/api/h3.go", `func f() { db.Exec(ctx, "PREPARE p AS SELECT 1") }`, 1},
		{"PREPARE TRANSACTION", "internal/api/h4.go", `func f() { db.Exec(ctx, "PREPARE TRANSACTION 'x'") }`, 1},
		{"LOCK", "internal/api/h5.go", `func f() { db.Exec(ctx, "LOCK TABLE ctrlz.clients IN ACCESS EXCLUSIVE MODE") }`, 1},
		{"DECLARE ... WITH HOLD", "internal/api/h6.go", `func f() { db.Exec(ctx, "DECLARE c CURSOR WITH HOLD FOR SELECT 1") }`, 1},
		{"CALL", "internal/api/h7.go", `func f() { db.Exec(ctx, "CALL x()") }`, 1},
		{"CREATE TEMP TABLE", "internal/api/h8.go", `func f() { db.Exec(ctx, "CREATE TEMP TABLE t (a int)") }`, 1},
		{"a word that only starts like an allowed one", "internal/api/h9.go", `func f() { db.Exec(ctx, "SELECTED x") }`, 1},
		{"an empty text", "internal/api/h10.go", `func f() { db.Exec(ctx, "-- nothing") }`, 1},
		{"WITH", "internal/api/i1.go", `func f() { db.Query(ctx, "WITH x AS (SELECT 1) SELECT * FROM x") }`, 0},
		{"VALUES", "internal/api/i2.go", `func f() { db.Query(ctx, "values (1), (2)") }`, 0},
		{"MERGE", "internal/api/i3.go", `func f() { db.Exec(ctx, "-- name: M :exec\nMERGE INTO t USING s ON t.a = s.a WHEN MATCHED THEN DELETE") }`, 0},
		{"INSERT and DELETE", "internal/api/i4.go", `func f() { db.Exec(ctx, "INSERT INTO t (a) VALUES (1)"); db.Exec(ctx, "\n DELETE FROM t") }`, 0},
		// The identifier rules: each of these is two statements to the server.
		{"a dollar sign inside an identifier is not a quote", "internal/api/j1.go", `func f() { db.Exec(ctx, "SELECT a$b$ ; COMMIT --$b$") }`, 1},
		{"a type name before a quote is not an E prefix", "internal/api/j2.go", `func f() { db.Exec(ctx, "SELECT date'\\'; COMMIT --'") }`, 1},
		{"a lower-case e prefix", "internal/api/j3.go", `func f() { db.Exec(ctx, "SELECT e'\\''; COMMIT --'") }`, 1},
		{"dollar signs after an identifier", "internal/api/j4.go", `func f() { db.Exec(ctx, "SELECT a$$$ ; COMMIT --$$") }`, 1},
		{"dollar signs after a non-ASCII identifier", "internal/api/j5.go", `func f() { db.Exec(ctx, "SELECT é$$ ; COMMIT --$$") }`, 1},
		// What is allowed: one statement, with or without its closing semicolon.
		{"a trailing semicolon", "internal/api/e1.go", `func f() { db.Exec(ctx, "SELECT 1;") }`, 0},
		{"a trailing semicolon and a comment", "internal/api/e2.go", `func f() { db.Exec(ctx, "SELECT 1; -- done\n") }`, 0},
		{"a trailing semicolon and white space of every kind", "internal/api/e3.go", `func f() { db.Exec(ctx, "SELECT 1;\t\r\n\f\v /* x */ ") }`, 0},
		{"semicolons in strings, a quoted name and a dollar quote", "internal/api/e4.go", `func f() { db.Query(ctx, "SELECT ';', '--;', $$a;b$$, \"c;d\", $t$ ; $$ ; $t$ FROM t") }`, 0},
		{"a semicolon in an escape string", "internal/api/e5.go", `func f() { db.Query(ctx, "SELECT E'a\\';b' FROM t") }`, 0},
		{"the sqlc header and a statement with a semicolon", "internal/api/e6.go", `func f() { db.Query(ctx, "-- name: GetThing :one\nSELECT 1;\n") }`, 0},
		{"a parameter and a bit operator on a name that ends in u", "internal/api/e7.go", `func f() { db.Query(ctx, "SELECT $1, flagu&1 FROM t WHERE a = $2;") }`, 0},
		{"a nested comment after the semicolon that hides a statement", "internal/api/e8.go", `func f() { db.Exec(ctx, "SELECT 1; /* a /* b */ ; COMMIT */") }`, 0},
		{"a block comment, then DISCARD ALL", "internal/api/c9.go", `func f() { db.Exec(ctx, "/* c */ DISCARD ALL") }`, 1},
		{"a nested block comment, then COMMIT", "internal/api/c10.go", `func f() { db.Exec(ctx, "/* a /* b */ still a comment */ COMMIT") }`, 1},
		{"the tenant setting with a comment inside its name", "internal/api/c11.go", `func f() { db.Exec(ctx, "SET ctrlz./**/tenant_id = 'x'") }`, 2},
		{"the tenant setting with spaces around the dot", "internal/api/c12.go", `func f() { db.Exec(ctx, "SET \"ctrlz\" . \"tenant_id\" TO 'x'") }`, 2},
		{"set_config as a quoted name", "internal/api/c13.go", `func f() { db.Exec(ctx, "SELECT \"set_config\"('app.x', 'y', false)") }`, 1},
		{"a call after a string that looks like a comment", "internal/api/c14.go", `func f() { db.Exec(ctx, "SELECT '--', set_config('app.x', 'y', false)") }`, 1},
		{"sqlc header, then a plain query", "internal/api/c15.go", `func f() { db.Query(ctx, "-- name: GetThing :one\nSELECT 1") }`, 0},
		{"a comment that names a statement", "internal/api/c16.go", `func f() { db.Exec(ctx, "/* UPDATE */ UPDATE t SET a = 1 -- commit later") }`, 0},
		{"UPDATE ... SET is fine", "internal/api/upd.go", `func f() { db.Exec(ctx, "UPDATE t SET a = 1") }`, 0},
		{"reading the tenant setting elsewhere", "internal/api/read.go", `func f() { db.Query(ctx, "SELECT current_setting('ctrlz.tenant_id')") }`, 1},
		{"set_config is allowed in the tenant file", "internal/store/tx.go", `func f() { db.Exec(ctx, "SELECT pg_catalog.set_config('ctrlz.tenant_id', $1, true)") }`, 0},
		// The tenant file is exempt for set_config and the tenant setting only. The
		// functions that run a string as SQL can build a session-level call from
		// pieces, which no word check sees, so they are refused in every file.
		{"query_to_xml builds a session lock in the tenant file", "internal/store/tx.go", `func f() { db.Query(ctx, "SELECT pg_catalog.query_to_xml('SELECT pg_' || 'advisory_lock(424242)', false, false, '')::text") }`, 1},
		{"query_to_xml with format and a split name in the tenant file", "internal/store/tx.go", `func f() { db.Query(ctx, "SELECT query_to_xml(format('SELECT pg_%s(1)', 'terminate_backend'), false, false, '')") }`, 1},
		{"ts_stat builds a large object call in the tenant file", "internal/store/tx.go", `func f() { db.Query(ctx, "SELECT ts_stat('SELECT lo_' || 'unlink(1)::text::tsvector')") }`, 1},
		{"query_to_xml_and_xmlschema in the tenant file", "internal/store/tx.go", `func f() { db.Query(ctx, "SELECT query_to_xml_and_xmlschema('SELECT 1', false, false, '')") }`, 1},
		{"query_to_xmlschema in the tenant file", "internal/store/tx.go", `func f() { db.Query(ctx, "SELECT query_to_xmlschema('SELECT 1', false, false, '')") }`, 1},
		{"ts_rewrite in the tenant file", "internal/store/tx.go", `func f() { db.Query(ctx, "SELECT ts_rewrite('a'::tsquery, 'SELECT 1, 2')") }`, 1},
		{"query_to_xml elsewhere", "internal/api/q1.go", `func f() { db.Query(ctx, "SELECT query_to_xml('SELECT 1', false, false, '')") }`, 1},
		// P0 gate review, fourth round: pg_settings has an ON UPDATE rule that runs
		// set_config(name, setting, false), and PUBLIC may update it, so a constant
		// UPDATE changes the session of a pooled connection.
		{"UPDATE pg_settings", "internal/api/k1.go", `func f() { db.Exec(ctx, "UPDATE pg_settings SET setting = '0' WHERE name = 'statement_timeout'") }`, 1},
		{"UPDATE pg_catalog.pg_settings", "internal/api/k2.go", `func f() { db.Exec(ctx, "UPDATE pg_catalog.pg_settings SET setting = 'off' WHERE name = 'row_security'") }`, 1},
		{"UPDATE pg_settings inside a WITH", "internal/api/k3.go", `func f() { db.Exec(ctx, "WITH x AS (SELECT 1) UPDATE pg_settings SET setting = '0' WHERE name = 'statement_timeout'") }`, 1},
		{"UPDATE a quoted pg_settings", "internal/api/k4.go", `func f() { db.Exec(ctx, "UPDATE pg_catalog.\"pg_settings\" SET setting = '0' WHERE name = 'statement_timeout'") }`, 1},
		{"a read of pg_settings is refused too", "internal/api/k5.go", `func f() { db.Query(ctx, "SELECT setting FROM pg_settings WHERE name = 'statement_timeout'") }`, 1},
		{"a name that only starts like pg_settings", "internal/api/k6.go", `func f() { db.Query(ctx, "SELECT pg_settings_x FROM t") }`, 0},
		{"pg_settings is refused in the tenant file as well", "internal/store/tx.go", `func f() { db.Exec(ctx, "UPDATE pg_settings SET setting = '0' WHERE name = 'statement_timeout'") }`, 1},
		// The same round: session-level advisory locks outlive the transaction and
		// stay with the pooled connection. The _xact_ forms end with it and are what
		// the claim functions use.
		{"pg_advisory_lock", "internal/api/l1.go", `func f() { db.Query(ctx, "SELECT pg_advisory_lock(1)") }`, 1},
		{"pg_advisory_lock on another tenant's claim key", "internal/api/l2.go", `func f() { db.Query(ctx, "SELECT pg_catalog.pg_advisory_lock(pg_catalog.hashtextextended('ctrlz.ip_claim_request:' || $1, 0))") }`, 1},
		{"pg_advisory_lock_shared", "internal/api/l3.go", `func f() { db.Query(ctx, "SELECT pg_advisory_lock_shared(1)") }`, 1},
		{"pg_try_advisory_lock", "internal/api/l4.go", `func f() { db.Query(ctx, "SELECT pg_try_advisory_lock(1)") }`, 1},
		{"pg_try_advisory_lock_shared", "internal/api/l5.go", `func f() { db.Query(ctx, "SELECT pg_try_advisory_lock_shared(1)") }`, 1},
		{"a quoted pg_advisory_lock", "internal/api/l6.go", `func f() { db.Query(ctx, "SELECT \"pg_advisory_lock\"(1)") }`, 1},
		{"pg_advisory_xact_lock is the allowed form", "internal/api/l7.go", `func f() { db.Query(ctx, "SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('ctrlz.ip_claim_request:' || $1, 0))") }`, 0},
		{"pg_advisory_xact_lock_shared", "internal/api/l8.go", `func f() { db.Query(ctx, "SELECT pg_advisory_xact_lock_shared(1)") }`, 0},
		{"pg_try_advisory_xact_lock", "internal/api/l9.go", `func f() { db.Query(ctx, "SELECT pg_try_advisory_xact_lock(1)") }`, 0},
		{"pg_try_advisory_xact_lock_shared", "internal/api/l10.go", `func f() { db.Query(ctx, "SELECT pg_try_advisory_xact_lock_shared(1)") }`, 0},
		// All tenants share one login, so these reach another tenant's backend or a
		// store that row level security does not cover.
		{"pg_terminate_backend", "internal/api/m1.go", `func f() { db.Query(ctx, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity") }`, 1},
		{"pg_cancel_backend", "internal/api/m2.go", `func f() { db.Query(ctx, "SELECT pg_cancel_backend($1)") }`, 1},
		// db-r15-1: one session that stops reading fills the cluster's notification queue and every
		// transaction that notified then fails at commit. Nothing sends or hears a notification.
		{"pg_notify in a query", "internal/api/nt1.go", `func f() { db.Exec(ctx, "SELECT pg_catalog.pg_notify('ctrlz_sms', '')") }`, 1},
		{"pg_notify hidden in a CTE", "internal/api/nt2.go", `func f() { db.Exec(ctx, "WITH x AS (SELECT pg_notify('c', '')) SELECT 1") }`, 1},
		{"a NOTIFY statement", "internal/api/nt3.go", `func f() { db.Exec(ctx, "NOTIFY ctrlz_sms") }`, 1},
		{"a LISTEN statement in the store, where it used to be allowed", "internal/store/store.go", `func Listen() { conn.Exec(ctx, "LISTEN ctrlz_sms") }`, 1},
		{"a column that starts like a large object function", "internal/api/m3.go", `func f() { db.Query(ctx, "SELECT lo_values, loreader, pg_cancel_backends FROM t") }`, 0},
		{"the opt-out marker in a new package", "internal/api/opt.go", `func f(q string) { db.Exec(ctx, q) // lint:sql-const trust me
}`, 1},
		{"the opt-out marker in the one helper", "internal/store/auth.go", `func one(q string) { db.Exec(ctx, q) // lint:sql-const callers pass constants
}`, 0},
		// Review L1-F09, round two: the raw connection reachable from a Rows.
		{"ExecParams with a dynamic statement", "internal/api/ep.go", `func f() { db.ExecParams(ctx, "SELECT "+name) }`, 1},
		{"ExecParams with a constant", "internal/api/ep.go", `func f() { db.ExecParams(ctx, qOK) }`, 0},
		{"ExecPrepared takes no SQL text", "internal/api/epp.go", `func f() { db.ExecPrepared(ctx, "stmt") }`, 1},
		{"SendBatch takes no SQL text", "internal/api/sb.go", `func f() { db.SendBatch(ctx, nil) }`, 1},
		{"Conn() outside the store", "internal/api/conn.go", `func f() { _ = db.Conn() }`, 1},
		{"PgConn() outside the store", "internal/api/pgconn.go", `func f() { _ = db.PgConn() }`, 1},
		{"rows.Conn().PgConn().ExecParams with a session set_config", "internal/api/exploit.go", `func f(rows DB) { rows.Conn().PgConn().ExecParams(ctx, "SELECT pg_catalog.set_config('ctrlz.tenant_id', 'x', false)") }`, 3},
		{"the same chain with a dynamic statement", "internal/api/exploit2.go", `func f(rows DB) { rows.Conn().PgConn().ExecParams(ctx, "SELECT set_config('x', '"+name+"', false)") }`, 3},
		{"Conn() inside the store", "internal/store/anyfile.go", `func f() { _ = db.Conn() }`, 0},
	}
	// One row for each large object function, so that a name dropped from the
	// word check shows up as the row that names it.
	for i, fn := range []string{"lo_create", "lo_creat", "lo_open", "lo_close", "lo_unlink", "lo_import", "lo_export", "lo_from_bytea", "lo_get", "lo_put", "lo_lseek", "lo_lseek64", "lo_tell", "lo_tell64", "lo_truncate", "lo_truncate64", "loread", "lowrite"} {
		cases = append(cases, struct {
			name string
			path string
			src  string
			bad  int
		}{"large object function " + fn, fmt.Sprintf("internal/api/n%d.go", i), `func f() { db.Query(ctx, "SELECT ` + fn + `(1)") }`, 1})
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		af, err := parser.ParseFile(fset, c.path, header+c.src, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		// The planted file stands alone in its package, plus a stub for the
		// helper's name so the generic case type-checks.
		got := sqlProblems(fset, []file{{path: c.path, ast: af}, filler(t, fset)})
		if len(got) != c.bad {
			t.Errorf("%s: %d problems %v, want %d", c.name, len(got), got, c.bad)
		}
	}
}

// filler is a second, clean file so the planted package is not the only one the
// importer sees, as in the real module.
func filler(t *testing.T, fset *token.FileSet) file {
	t.Helper()
	af, err := parser.ParseFile(fset, "internal/other/o.go", "package other\nconst X = \"SELECT 1\"\n", 0)
	if err != nil {
		t.Fatal(err)
	}
	return file{path: "internal/other/o.go", ast: af}
}

// stdlibImporter type-checks a standard-library package from source once for the
// whole test binary: log/slog costs about ten seconds, and the can-fail tests build
// dozens of small programs. The packages it returns carry no positions that matter
// to a caller, so one importer (with its own file set) can serve every file set.
var stdlibImporter = sync.OnceValue(func() types.Importer {
	return importer.ForCompiler(token.NewFileSet(), "source", nil)
})

// notifyWord finds a LISTEN, UNLISTEN or NOTIFY statement and pg_notify in a Go string. The sink lint
// above judges only the argument of a database call; this one reads every string literal of the module,
// so a statement built into a variable, a helper in a package the sink lint exempts or a Config field
// cannot carry one either. A statement starts the string or follows a semicolon; pg_notify is a word.
var notifyWord = regexp.MustCompile(`(?is)(^|;)[\s\v]*(listen|unlisten|notify)[\s\v]+["*a-z_]|\bpg_notify\b`)

// notifyProblems lists the constant strings of the non-test files that send or wait for a notification.
//
// Contract: it judges the VALUE of every maximal constant string expression, as go/types computes it,
// so a concatenation of constants ("LIS" + "TEN x"), a named constant declared in one file and used in
// another, a typed constant and a constant built from other constants are all read as the text they are
// and not as the literals they were written with (db-r16-17: the earlier version read each *ast.BasicLit
// alone and a constant concatenation passed). A string that is not constant cannot reach a database
// call at all (TestNoDynamicSQL: every SQL argument is a constant), so the sink rules and this one cover
// the same set. It does not judge the lint's own sources or the catalog checks, which name the words to
// forbid them. The database half is the privilege: pg_notify is revoked from every login role (family
// wal-writes-and-notifications of catalog_reach.yaml), and the behaviour test
// catalogtest TestNoFunctionNotifies listens as every role.
func notifyProblems(fset *token.FileSet, files []file) []string {
	info, ok := typeInfo(fset, files)
	if !ok {
		return []string{"type information unavailable"}
	}
	var out []string
	for _, f := range files {
		if f.test || strings.HasPrefix(f.path, "internal/lint/") || strings.HasPrefix(f.path, "internal/store/catalogtest/") {
			continue
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			e, isExpr := n.(ast.Expr)
			if !isExpr {
				return true
			}
			var text string
			if tv, known := info.Types[e]; known && tv.Value != nil && tv.Value.Kind() == constant.String {
				text = constant.StringVal(tv.Value)
			} else if lit, isLit := e.(*ast.BasicLit); isLit && lit.Kind == token.STRING {
				// An expression go/types did not record (a package it stubs): the literal as written.
				s, err := strconv.Unquote(lit.Value)
				if err != nil {
					return true
				}
				text = s
			} else {
				return true
			}
			for _, v := range sqlVariants(text) {
				if notifyWord.MatchString(v) {
					out = append(out, fmt.Sprintf("%s:%d: a constant string that sends or waits for a notification: %.40q", f.path, fset.Position(e.Pos()).Line, text))
					break
				}
			}
			return false // the whole constant expression is judged once, not its parts
		})
	}
	return out
}

// TestNoNotifyAndNoListen is the Go half of the rule of db-r15-1 (the database half is catalogtest
// TestNoFunctionNotifies). Postgres has one notification queue for the whole cluster and no privilege
// for LISTEN or NOTIFY. Any login role can listen, stop reading and send until the queue is full, and
// from then on every transaction that notified fails at COMMIT, for every tenant: the issue of an OTP
// and the admin outbox insert did. Nothing the module commits may depend on a notification, so nothing
// sends one and nothing listens; the worker polls.
func TestNoNotifyAndNoListen(t *testing.T) {
	fset, files := parseRepo(t)
	if p := notifyProblems(fset, files); len(p) > 0 {
		t.Errorf("%d notification statements:\n%s", len(p), strings.Join(p, "\n"))
	}
	// The rule can fail: each of these planted strings is reported.
	for _, c := range []struct {
		src  string
		want int
	}{
		{`"LISTEN ctrlz_sms"`, 1},
		{`"notify ctrlz_sms, 'x'"`, 1},
		{"`SELECT 1; NOTIFY x`", 1},
		{`"SELECT pg_catalog.pg_notify('c', '')"`, 1},
		{`"UNLISTEN *"`, 1},
		{`"-- a comment\nLISTEN x"`, 1},
		{`"SELECT 1"`, 0},
		{`"failed to listen on the address"`, 0},
		{`"SELECT notify_at FROM t"`, 0},
		// db-r16-17: what a literal-by-literal reading missed. The value of the constant is judged.
		{`"LIS" + "TEN ctrlz_sms"`, 1},
		{`"NOT" + "IFY x"`, 1},
		{`"SELECT 1; " + "LISTEN" + " ctrlz_sms"`, 1},
		{`"pg_" + "notify"`, 1},
		{`("LISTEN ") + "x"`, 1},
		{`string("LISTEN x")`, 1},
		{`"a" + "b"`, 0},
	} {
		fs := token.NewFileSet()
		af, err := parser.ParseFile(fs, "internal/api/x.go", "package p\nvar s = "+c.src+"\n", 0)
		if err != nil {
			t.Fatalf("%s: %v", c.src, err)
		}
		if got := len(notifyProblems(fs, []file{{path: "internal/api/x.go", ast: af}})); got != c.want {
			t.Errorf("%s: %d problems, want %d", c.src, got, c.want)
		}
	}
	// Declarations the expression cases cannot express: a named constant built from parts, a typed one,
	// the parts in two files of the package, and constants that never make a statement.
	for _, c := range []struct {
		name  string
		files map[string]string
		want  int
	}{
		{"a named constant built from parts", map[string]string{"a.go": "const verb = \"LIS\"\nconst q = verb + \"TEN ctrlz_sms\"\n"}, 1},
		{"a typed constant", map[string]string{"a.go": "type SQL string\nconst q SQL = \"NOTIFY \" + \"x\"\n"}, 1},
		{"the parts in two files", map[string]string{"a.go": "const A = \"UN\"\n", "b.go": "const B = A + \"LISTEN *\"\n"}, 1},
		{"constants that are not a statement", map[string]string{"a.go": "const A = \"LIS\"\nconst B = \"TEN\"\n"}, 0},
	} {
		fs := token.NewFileSet()
		var fl []file
		for name, src := range c.files {
			af, err := parser.ParseFile(fs, "internal/api/"+name, "package p\n"+src, 0)
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			fl = append(fl, file{path: "internal/api/" + name, ast: af})
		}
		if got := len(notifyProblems(fs, fl)); got != c.want {
			t.Errorf("%s: %d problems, want %d", c.name, got, c.want)
		}
	}
}
