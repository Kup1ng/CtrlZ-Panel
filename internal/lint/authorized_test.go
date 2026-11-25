package lint_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Check E6 of docs/specs/p3-endpoints.md 11.2: the authorized list has one deleter. Rule 2 of spec 5 (the last row of an
// Endpoint that requires authorized IPs is not deleted) binds the owner's routes, a DDNS host delete, the P4 DDNS worker and
// the P5 cleanup alike, and it is decided by the statement of one store method. So no Go statement outside it may delete from
// the table, and no foreign key may reach the table with a cascade except from the two parents whose own delete is the end of
// the rows (an Endpoint, a tenant): a DDNS host delete must not take rows with it past the rule (spec 2.2 item 7).

var deleteAuthorized = regexp.MustCompile(`(?is)\bdelete\s+from\s+(?:only\s+)?(?:"?ctrlz"?\s*\.\s*)?"?authorized_ips"?\b`)

// authorizedDeleters returns the places of the source that delete from authorized_ips, as "path:line".
func authorizedDeleters(fset *token.FileSet, files []file) []string {
	var out []string
	for _, f := range files {
		if f.test || strings.HasPrefix(f.path, "internal/authtest/") || strings.HasPrefix(f.path, "internal/store/catalogtest/") {
			continue
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			if s, err := strconv.Unquote(lit.Value); err == nil && deleteAuthorized.MatchString(s) {
				out = append(out, f.path+":"+strconv.Itoa(fset.Position(lit.Pos()).Line))
			}
			return true
		})
	}
	return out
}

func TestAuthorizedIPsHaveOneDeleter(t *testing.T) {
	fset, files := parseRepo(t)
	got := authorizedDeleters(fset, files)
	if len(got) != 1 || !strings.HasPrefix(got[0], "internal/store/endpoint_access.go:") {
		t.Errorf("a DELETE of authorized_ips must be the one statement of internal/store/endpoint_access.go (rule 2 of spec 5 is decided there); found %v", got)
	}
}

func TestAuthorizedIPsDeleterLintCanFail(t *testing.T) {
	// A second deleter, in any file, is found.
	fset := token.NewFileSet()
	mk := func(path, src string) []file {
		af, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		return []file{{path: path, ast: af}}
	}
	for _, c := range []struct {
		name, path, src string
		want            int
	}{
		{"a delete elsewhere", "internal/worker/x.go", "package x\nconst q = `DELETE FROM ctrlz.authorized_ips WHERE id = $1`", 1},
		{"a quoted spelling", "internal/api/x.go", "package x\nconst q = `delete from \"ctrlz\".\"authorized_ips\" where true`", 1},
		{"a select is not a delete", "internal/api/x.go", "package x\nconst q = `SELECT 1 FROM ctrlz.authorized_ips`", 0},
		{"another table", "internal/api/x.go", "package x\nconst q = `DELETE FROM ctrlz.authorized_ips_other WHERE true`", 0},
	} {
		files := mk(c.path, c.src)
		if n := len(authorizedDeleters(fset, files)); n != c.want {
			t.Errorf("%s: %d found, want %d", c.name, n, c.want)
		}
	}
}

// The foreign keys of authorized_ips: a cascade only from an Endpoint and from a tenant, and the key to a DDNS host (or to any
// other parent) is NO ACTION, deferred, so a host cannot take rows with it.
func TestAuthorizedIPsKeysDoNotCascadeFromTheHost(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "migrations", "catalog", "foreign_keys.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, p := range authorizedKeyProblems(string(b)) {
		t.Error(p)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.Contains(line, "authorized_ips(") && strings.Contains(line, "->") {
			seen++
		}
	}
	if seen < 3 {
		t.Errorf("%d keys of authorized_ips read; the lint is not reading the catalog", seen)
	}
}

var authorizedKey = regexp.MustCompile(`^\s*-\s*"authorized_ips\([^)]*\)\s*->\s*(\w+)\([^)]*\)\s*(.*?)"\s*$`)

// authorizedKeyProblems judges the lines of foreign_keys.yaml that start at authorized_ips.
func authorizedKeyProblems(yaml string) []string {
	var out []string
	for _, line := range strings.Split(yaml, "\n") {
		m := authorizedKey.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		parent, action := m[1], strings.TrimSpace(m[2])
		switch parent {
		case "endpoints", "tenants":
			if action != "cascade" {
				out = append(out, "authorized_ips -> "+parent+" is "+action+", want cascade: the delete of the parent is the end of the rows")
			}
		default:
			if action != "no_action deferred" {
				out = append(out, "authorized_ips -> "+parent+" is "+action+", want no_action deferred: a delete of the parent must not take authorized rows past rule 2 of spec 5")
			}
		}
	}
	return out
}

func TestAuthorizedKeyLintCanFail(t *testing.T) {
	bad := `  - "authorized_ips(tenant_id,ddns_host_id) -> endpoint_ddns_hosts(tenant_id,id) cascade"
  - "authorized_ips(tenant_id,endpoint_id) -> endpoints(tenant_id,id) restrict"
  - "authorized_ips(tenant_id,x) -> other(tenant_id,id) no_action"`
	if got := authorizedKeyProblems(bad); len(got) != 3 {
		t.Errorf("%d problems for three bad keys: %v", len(got), got)
	}
	good := `  - "authorized_ips(tenant_id,ddns_host_id) -> endpoint_ddns_hosts(tenant_id,id) no_action deferred"
  - "authorized_ips(tenant_id,endpoint_id) -> endpoints(tenant_id,id) cascade"
  - "authorized_ips(tenant_id) -> tenants(id) cascade"`
	if got := authorizedKeyProblems(good); len(got) != 0 {
		t.Errorf("good keys refused: %v", got)
	}
}
