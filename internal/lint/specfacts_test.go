package lint_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
)

// The registries that the spec's fact tables copy (rule spec-fact-drift). Each function
// turns one registry into plain data, and the comparisons in speccompare_test.go take
// that data as a parameter, so TestSpecFactsCanFail can hand them a changed copy.

// ---- audit events (13.2) ----------------------------------------------------

// auditFact is one event as reflection sees it.
type auditFact struct {
	Action string
	// Target is the shape of the target, "" for a tenant event or an event with none:
	// ids are written <id>, a domain name <name>.
	Target string
	// Params are the json keys of the params object, sorted.
	Params []string
}

var (
	uuidRE   = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	sampleID = uuid.MustParse("11111111-2222-7333-8444-555555555555")
)

// paramNames reads the json keys a struct marshals to. A field tagged "-" is not in the
// params (the ids that go in the target are tagged so).
func paramNames(t reflect.Type) []string {
	var out []string
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = t.Field(i).Name
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// targetShape fills the fields that go in the target with a sample id or name and reads
// the target back. Nothing else about the event matters to it.
func targetShape(ev audit.AdminEvent) string {
	v := reflect.New(reflect.TypeOf(ev)).Elem()
	for i := 0; i < v.NumField(); i++ {
		if name, _, _ := strings.Cut(v.Type().Field(i).Tag.Get("json"), ","); name != "-" {
			continue
		}
		switch f := v.Field(i); f.Kind() {
		case reflect.Array:
			if f.Type() == reflect.TypeOf(sampleID) {
				f.Set(reflect.ValueOf(sampleID))
			}
		case reflect.String:
			f.SetString("NAME")
		}
	}
	target := v.Interface().(audit.AdminEvent).Target()
	target = strings.ReplaceAll(target, sampleID.String(), "<id>")
	return strings.ReplaceAll(target, "NAME", "<name>")
}

func auditFacts() (tenant, admin []auditFact) {
	for _, e := range audit.TenantEvents() {
		tenant = append(tenant, auditFact{Action: e.Action(), Params: paramNames(reflect.TypeOf(e))})
	}
	for _, e := range audit.AdminEvents() {
		admin = append(admin, auditFact{Action: e.Action(), Target: targetShape(e), Params: paramNames(reflect.TypeOf(e))})
	}
	return tenant, admin
}

// ---- grants (16.2) ----------------------------------------------------------

// grantFacts is grants.yaml: table to role to privilege notation.
func grantFacts(t *testing.T) map[string]map[string]string {
	t.Helper()
	fx, err := catalogtest.Load()
	if err != nil {
		t.Fatal(err)
	}
	return fx.Grants.Tables
}

// ---- routes (14.2, 15.2) ----------------------------------------------------

// routeFact is one operation of an OpenAPI document as the spec table shows it.
type routeFact struct {
	Key  string // "POST /auth/login", the path relative to the server URL
	Auth string
	Rate string
	// Body is the schema name of the request body ("" for none) and BodyFields its
	// properties with whether each is required. Query lists the query parameters.
	Body       string
	BodyFields map[string]bool
	Query      []string
	// Status is the lowest 2xx; Result is the schema name of its body, or ResultKeys the
	// properties of an inline one.
	Status     string
	Result     string
	ResultKeys []string
	Errors     []string
	// Refs are the names of the shared responses the operation points at (RateLimited, SessionExpired),
	// which document a code without the Errors sentence.
	Refs []string
}

type oaDoc map[string]any

func loadOpenAPI(t *testing.T, b []byte) oaDoc {
	t.Helper()
	// Decoded into a plain map: a named map type would be inherited by every nested
	// mapping and asMap would not recognise them.
	var d map[string]any
	if err := yaml.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	return oaDoc(d)
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// resolve follows a $ref chain and returns the final node with the name of the last
// reference followed ("" if none).
func (d oaDoc) resolve(n map[string]any) (map[string]any, string) {
	name := ""
	for i := 0; i < 8; i++ {
		ref, _ := n["$ref"].(string)
		if ref == "" {
			return n, name
		}
		cur := any(map[string]any(d))
		for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
			cur = asMap(cur)[part]
		}
		next := asMap(cur)
		if next == nil {
			return n, name
		}
		name = ref[strings.LastIndex(ref, "/")+1:]
		n = next
	}
	return n, name
}

// jsonSchema is the application/json schema of a body or response node, resolved.
func (d oaDoc) jsonSchema(n map[string]any) (schema map[string]any, name string) {
	n, _ = d.resolve(n)
	content := asMap(n["content"])
	media := asMap(content["application/json"])
	if media == nil {
		for _, v := range content {
			media = asMap(v)
			break
		}
	}
	if media == nil {
		return nil, ""
	}
	return d.resolve(asMap(media["schema"]))
}

func keysOf(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// errorCodes reads the codes after "Errors:" in a description: backticked words at
// parenthesis depth 0, up to the first full stop outside backticks and parentheses.
// The descriptions are where the OpenAPI documents list an operation's codes (the
// default response is the one shared Problem).
func errorCodes(desc string) []string {
	i := strings.LastIndex(desc, "Errors:")
	if i < 0 {
		return nil
	}
	rest := desc[i+len("Errors:"):]
	var out []string
	depth := 0
	for j := 0; j < len(rest); j++ {
		switch c := rest[j]; {
		case c == '(':
			depth++
		case c == ')':
			depth--
		case c == '`':
			k := strings.IndexByte(rest[j+1:], '`')
			if k < 0 {
				return out
			}
			if depth == 0 {
				out = append(out, rest[j+1:j+1+k])
			}
			j += k + 1
		case c == '.' && depth == 0:
			sort.Strings(out)
			return out
		}
	}
	sort.Strings(out)
	return out
}

func routeFacts(t *testing.T, doc []byte) map[string]routeFact {
	t.Helper()
	d := loadOpenAPI(t, doc)
	out := map[string]routeFact{}
	for path, item := range asMap(d["paths"]) {
		pi := asMap(item)
		for method, opAny := range pi {
			switch method {
			case "get", "put", "post", "delete", "patch":
			default:
				continue
			}
			op := asMap(opAny)
			if tags, _ := op["tags"].([]any); len(tags) > 0 && tags[0] == "health" {
				continue
			}
			f := routeFact{Key: strings.ToUpper(method) + " " + path}
			f.Auth, _ = op["x-ctrlz-auth"].(string)
			f.Rate, _ = op["x-ctrlz-rate"].(string)
			if rb := asMap(op["requestBody"]); rb != nil {
				if sc, name := d.jsonSchema(rb); sc != nil {
					f.Body = name
					f.BodyFields = map[string]bool{}
					req := map[string]bool{}
					for _, r := range anyList(sc["required"]) {
						req[r.(string)] = true
					}
					for _, k := range keysOf(asMap(sc["properties"])) {
						f.BodyFields[k] = req[k]
					}
				}
			}
			var params []any
			params = append(params, anyList(pi["parameters"])...)
			params = append(params, anyList(op["parameters"])...)
			for _, p := range params {
				pn, _ := d.resolve(asMap(p))
				if pn["in"] == "query" {
					f.Query = append(f.Query, pn["name"].(string))
				}
			}
			sort.Strings(f.Query)
			var codes []string
			for code := range asMap(op["responses"]) {
				if strings.HasPrefix(code, "2") {
					codes = append(codes, code)
				}
			}
			sort.Strings(codes)
			if len(codes) > 0 {
				f.Status = codes[0]
				if sc, name := d.jsonSchema(asMap(asMap(op["responses"])[codes[0]])); sc != nil {
					f.Result = name
					f.ResultKeys = keysOf(asMap(sc["properties"]))
				}
			}
			desc, _ := op["description"].(string)
			f.Errors = errorCodes(desc)
			for _, rv := range asMap(op["responses"]) {
				if ref, _ := asMap(rv)["$ref"].(string); strings.HasPrefix(ref, "#/components/responses/") {
					f.Refs = append(f.Refs, strings.TrimPrefix(ref, "#/components/responses/"))
				}
			}
			sort.Strings(f.Refs)
			out[f.Key] = f
		}
	}
	return out
}

func tenantRoutes(t *testing.T) map[string]routeFact { return routeFacts(t, api.Tenant()) }
func adminRoutes(t *testing.T) map[string]routeFact  { return routeFacts(t, api.Admin()) }

// ---- tests (18.7) -----------------------------------------------------------

// testIndex lists the Test functions of every _test.go file of the repository, by
// directory (slash-separated, relative to the root). It reads the source and not
// `go test -list`: the set is the same, a listing needs every test binary built, and
// the source also holds the files a build tag keeps out of the default list (the
// nightly timing tests), which the map names.
type testIndex struct {
	byDir map[string]map[string]bool
	all   map[string]bool
	files map[string]bool // every file and directory below the root that exists
	dirs  map[string]bool
}

func buildTestIndex(t *testing.T) testIndex {
	t.Helper()
	root := repoRoot(t)
	ix := testIndex{byDir: map[string]map[string]bool{}, all: map[string]bool{}, files: map[string]bool{}, dirs: map[string]bool{}}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if de.IsDir() {
			switch de.Name() {
			case "node_modules", ".git", ".codegraph", ".next":
				return filepath.SkipDir
			}
		}
		ix.files[rel] = true
		if de.IsDir() {
			ix.dirs[rel] = true
		}
		if de.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			return err
		}
		dir := filepath.ToSlash(filepath.Dir(rel))
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || !strings.HasPrefix(fd.Name.Name, "Test") || fd.Name.Name == "TestMain" {
				continue
			}
			if ix.byDir[dir] == nil {
				ix.byDir[dir] = map[string]bool{}
			}
			ix.byDir[dir][fd.Name.Name] = true
			ix.all[fd.Name.Name] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return ix
}

func anyList(v any) []any {
	l, _ := v.([]any)
	return l
}

// functionFacts is the security_definer list of functions.yaml.
func functionFacts(t *testing.T) []functionFact {
	t.Helper()
	fx, err := catalogtest.Load()
	if err != nil {
		t.Fatal(err)
	}
	var out []functionFact
	for _, f := range fx.Functions.SecurityDefiner {
		out = append(out, functionFact{Name: f.Name, Args: f.Args, Returns: f.Returns, Execute: f.Execute})
	}
	return out
}
