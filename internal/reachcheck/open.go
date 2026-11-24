package reachcheck

import (
	"context"
	"fmt"
	"sort"
	"strings"

	catalogfixtures "github.com/Kup1ng/CtrlZ-Panel/migrations/catalog"
)

// OpenGoldenName is the reviewed list of what PUBLIC may use in pg_catalog, one line per function
// ("function name(identity args)") and relation ("relation name"). It lives in migrations/catalog
// beside catalog_reach.yaml, so the binary carries it and the migrate step of a production start can
// ask the question CI asks (check 31; db-r16-11). Regenerate with
// `go test ./internal/store/catalogtest -run TestOpenCatalogGolden -update` and read the diff.
const OpenGoldenName = "pg_catalog_open.golden"

// OpenGolden is the reviewed list as a set of lines.
func OpenGolden() (map[string]bool, error) {
	b, err := catalogfixtures.FS.ReadFile(OpenGoldenName)
	if err != nil {
		return nil, err
	}
	return ParseGolden(b), nil
}

// ParseGolden reads the lines of a golden, leaving out blanks and comments.
func ParseGolden(b []byte) map[string]bool {
	want := map[string]bool{}
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			want[l] = true
		}
	}
	return want
}

// OpenObject is one function or relation of pg_catalog that PUBLIC can use, with the statement that
// takes it away.
type OpenObject struct {
	Line   string // "function name(args)" or "relation name": the key of the golden
	Revoke string
}

// Open lists every function and relation of pg_catalog that PUBLIC can use, sorted by line.
func Open(ctx context.Context, q Querier) ([]OpenObject, error) {
	var out []OpenObject
	for _, s := range []struct{ sql, kind string }{{qOpenFunctions, "FUNCTION"}, {qOpenRelations, "TABLE"}} {
		rows, err := q.Query(ctx, s.sql)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var line, ident string
			if err := rows.Scan(&line, &ident); err != nil {
				rows.Close()
				return nil, err
			}
			priv := "EXECUTE"
			if s.kind == "TABLE" {
				priv = "SELECT"
			}
			out = append(out, OpenObject{Line: line, Revoke: fmt.Sprintf("REVOKE %s ON %s %s FROM PUBLIC", priv, s.kind, ident)})
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Line < out[j].Line })
	return out, nil
}

// JudgeOpen is the security half of catalog check 31: everything PUBLIC can use that the reviewed
// list does not hold. A name the list holds and PUBLIC cannot use any more (a function a release
// dropped, one a person revoked) is a file hygiene finding for CI and does not stop a start.
// Every finding names the statement that closes it, because re-running a bootstrap file cannot
// close a function no family names.
func JudgeOpen(live []OpenObject, golden map[string]bool) []Finding {
	var out []Finding
	for _, o := range live {
		if !golden[o.Line] {
			out = append(out, Finding{
				Text:     fmt.Sprintf("catalog open: PUBLIC can use pg_catalog %s, which no reviewed list holds: as the superuser run `%s` (and name it in catalog_reach.yaml), or accept it in migrations/catalog/%s", o.Line, o.Revoke, OpenGoldenName),
				Security: true,
			})
		}
	}
	return out
}

const qOpenFunctions = `
SELECT 'function ' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')', p.oid::regprocedure::text
FROM pg_proc p
WHERE p.pronamespace = 'pg_catalog'::regnamespace
  AND EXISTS (SELECT 1 FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE')`

const qOpenRelations = `
SELECT 'relation ' || c.relname, c.oid::regclass::text
FROM pg_class c
WHERE c.relnamespace = 'pg_catalog'::regnamespace AND c.relkind IN ('r', 'v', 'm')
  AND EXISTS (SELECT 1 FROM aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) a WHERE a.grantee = 0 AND a.privilege_type = 'SELECT')`
