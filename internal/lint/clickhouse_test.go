package lint_test

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Rule exposure-is-declared, the ClickHouse side of P5 (spec 3.4, 3.5, 6.3, 11.2 A4 and A5). What these
// tests hold, all without Docker: the grants of the five users are the tables of the migrations and nothing
// else, no table or view escapes the row policy or has a sorting key that does not start with tenant_id, the
// reader users cannot change a limit, the memory of one profile adds up under the server's ceiling, and no
// service waits for ClickHouse. The tests that need a server are clickhouse_container_test.go.

// xnode is an XML element with its children, enough to read users.xml and ctrlz.xml.
type xnode struct {
	XMLName xml.Name
	Attrs   []xml.Attr `xml:",any,attr"`
	Nodes   []xnode    `xml:",any"`
	Text    string     `xml:",chardata"`
}

func (n xnode) child(name string) (xnode, bool) {
	for _, c := range n.Nodes {
		if c.XMLName.Local == name {
			return c, true
		}
	}
	return xnode{}, false
}

func (n xnode) attr(name string) string {
	for _, a := range n.Attrs {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

func (n xnode) text() string { return strings.TrimSpace(n.Text) }

func readXML(t *testing.T, rel ...string) xnode {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{repoRoot(t), "deploy", "compose", "clickhouse"}, rel...)...))
	if err != nil {
		t.Fatal(err)
	}
	var n xnode
	if err := xml.Unmarshal(b, &n); err != nil {
		t.Fatalf("%v", err)
	}
	return n
}

// chUsers is the content of users.xml: the grant queries of each user, and each profile as a map from a
// setting to its value, or to "from_env:<NAME>" for a number that comes from the Compose profile.
type chUsers struct {
	grants   map[string][]string
	profile  map[string]string // the profile a user runs under
	mgmt     map[string]bool   // access_management
	settings map[string]map[string]string
	consts   map[string]map[string]string // profile -> constrained setting -> what its constraint says
}

func loadCHUsers(t *testing.T) chUsers {
	t.Helper()
	root := readXML(t, "users.xml")
	out := chUsers{
		grants: map[string][]string{}, profile: map[string]string{}, mgmt: map[string]bool{},
		settings: map[string]map[string]string{}, consts: map[string]map[string]string{},
	}
	users, ok := root.child("users")
	if !ok {
		t.Fatal("users.xml has no <users>")
	}
	for _, u := range users.Nodes {
		name := u.XMLName.Local
		if p, ok := u.child("profile"); ok {
			out.profile[name] = p.text()
		}
		if m, ok := u.child("access_management"); ok {
			out.mgmt[name] = m.text() == "1"
		}
		if g, ok := u.child("grants"); ok {
			for _, q := range g.Nodes {
				out.grants[name] = append(out.grants[name], q.text())
			}
		}
		if pw, ok := u.child("password_sha256_hex"); ok || pw.text() != "" {
			t.Errorf("users.xml gives %s a password: the passwords are written by the wrapper from the secrets", name)
		}
	}
	profiles, ok := root.child("profiles")
	if !ok {
		t.Fatal("users.xml has no <profiles>")
	}
	for _, p := range profiles.Nodes {
		name := p.XMLName.Local
		out.settings[name] = map[string]string{}
		out.consts[name] = map[string]string{}
		for _, s := range p.Nodes {
			if s.XMLName.Local == "constraints" {
				for _, c := range s.Nodes {
					var parts []string
					for _, k := range c.Nodes {
						v := k.XMLName.Local
						if k.text() != "" {
							v += "=" + k.text()
						}
						parts = append(parts, v)
					}
					sort.Strings(parts)
					out.consts[name][c.XMLName.Local] = strings.Join(parts, ",")
				}
				continue
			}
			if env := s.attr("from_env"); env != "" {
				out.settings[name][s.XMLName.Local] = "from_env:" + env
			} else {
				out.settings[name][s.XMLName.Local] = s.text()
			}
		}
	}
	return out
}

var chGrantRe = regexp.MustCompile(`^GRANT (ALTER DELETE|SELECT|INSERT)(\([^)]*\))? ON ctrlz\.([a-z_0-9]+)$`)

// grantedTables returns the tables ctrlz.<t> a user holds the privilege on, at table level (a column list
// is a different grant).
func (u chUsers) grantedTables(user, priv string) []string {
	var out []string
	for _, q := range u.grants[user] {
		if m := chGrantRe.FindStringSubmatch(q); m != nil && m[1] == priv && m[2] == "" {
			out = append(out, m[3])
		}
	}
	sort.Strings(out)
	return out
}

// chSchema reads the migrations: the tables, the views and the target of each view, and the sorting key of
// each table.
type chSchema struct {
	tables  map[string]string // table -> the text of its CREATE statement
	views   map[string]string // view -> its target table
	files   map[string]string
	all     string
	ordered []string
}

func loadCHSchema(t *testing.T) chSchema {
	t.Helper()
	dir := filepath.Join(repoRoot(t), "migrations", "clickhouse")
	files, err := filepath.Glob(filepath.Join(dir, "0*.sql"))
	if err != nil || len(files) < 3 {
		t.Fatalf("migrations/clickhouse: %d files (%v)", len(files), err)
	}
	sort.Strings(files)
	s := chSchema{tables: map[string]string{}, views: map[string]string{}, files: map[string]string{}}
	create := regexp.MustCompile(`(?s)CREATE TABLE IF NOT EXISTS ctrlz\.([a-z_0-9]+) \(.*?;`)
	view := regexp.MustCompile(`CREATE MATERIALIZED VIEW IF NOT EXISTS ctrlz\.([a-z_0-9]+) TO ctrlz\.([a-z_0-9]+)\b`)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		up := string(b)
		if i := strings.Index(up, "-- +goose Down"); i >= 0 {
			up = up[:i]
		}
		s.files[filepath.Base(f)] = up
		s.ordered = append(s.ordered, filepath.Base(f))
		s.all += up
		for _, m := range create.FindAllStringSubmatch(up, -1) {
			s.tables[m[1]] = m[0]
		}
		for _, m := range view.FindAllStringSubmatch(up, -1) {
			s.views[m[1]] = m[2]
		}
	}
	return s
}

func (s chSchema) tableNames() []string {
	var out []string
	for n := range s.tables {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func (s chSchema) viewTargets() map[string]bool {
	out := map[string]bool{}
	for _, tgt := range s.views {
		out[tgt] = true
	}
	return out
}

// TestClickHouseMigrationsShape: every table of ctrlz has tenant_id as its first column and the first
// element of its sorting key (11.2 A4), keeps the three table settings of 3.5, and every statement is
// idempotent and runs outside a transaction, because a run that stopped half way is run again and
// ClickHouse has no transaction to roll it back.
func TestClickHouseMigrationsShape(t *testing.T) {
	s := loadCHSchema(t)
	want := []string{"agg_category", "agg_counts", "agg_domain", "agg_geo", "agg_reason", "counts_5m", "dns_raw"}
	if got := s.tableNames(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("the migrations make the tables %v, 3.5 names %v", got, want)
	}
	for name, ddl := range s.tables {
		if !regexp.MustCompile(`\(\s*tenant_id\s+UUID,`).MatchString(ddl) {
			t.Errorf("%s: tenant_id is not the first column", name)
		}
		if !regexp.MustCompile(`ORDER BY \(tenant_id,`).MatchString(ddl) {
			t.Errorf("%s: the sorting key does not start with tenant_id", name)
		}
		for _, setting := range []string{"non_replicated_deduplication_window = 10000", "ttl_only_drop_parts = 1", "min_free_disk_ratio_to_perform_insert = 0.1"} {
			if !strings.Contains(ddl, setting) {
				t.Errorf("%s lacks the table setting %q", name, setting)
			}
		}
	}
	want5 := map[string]string{"mv_counts": "agg_counts", "mv_reason": "agg_reason", "mv_geo_src": "agg_geo", "mv_geo_dst": "agg_geo", "mv_domain": "agg_domain"}
	for v, tgt := range want5 {
		if s.views[v] != tgt {
			t.Errorf("the view %s feeds %q, want %q", v, s.views[v], tgt)
		}
	}
	for name, body := range s.files {
		if !strings.HasPrefix(strings.TrimSpace(body), "-- +goose NO TRANSACTION") {
			t.Errorf("%s does not start with -- +goose NO TRANSACTION", name)
		}
		for _, stmt := range strings.Split(body, ";") {
			code := stripSQLComments(stmt)
			if !regexp.MustCompile(`(?m)^\s*(CREATE|DROP)\b`).MatchString(code) {
				continue
			}
			if !strings.Contains(code, "IF NOT EXISTS") {
				t.Errorf("%s: a CREATE without IF NOT EXISTS: %.60s", name, strings.TrimSpace(code))
			}
		}
	}
	for v := range s.views {
		if !regexp.MustCompile(`ctrlz\.` + v + `\s+TO ctrlz\.[a-z_0-9]+\s+DEFINER = ctrlz_migrator SQL SECURITY DEFINER`).MatchString(s.all) {
			t.Errorf("the view %s is not SQL SECURITY DEFINER with the definer ctrlz_migrator", v)
		}
	}
}

// TestClickHouseGrantsMatchTheMigrations: the reader users may read every table and no view, the janitor may
// delete from every table, and the hub's user may insert only into the tables nothing feeds (3.4). A table
// added by a migration and forgotten here is unreadable (closed side); a grant on a view or a table that
// does not exist is the mistake this refuses.
func TestClickHouseGrantsMatchTheMigrations(t *testing.T) {
	s, u := loadCHSchema(t), loadCHUsers(t)
	tables := s.tableNames()
	join := func(x []string) string { return strings.Join(x, ",") }
	if got := u.grantedTables("ctrlz_api", "SELECT"); join(got) != join(tables) {
		t.Errorf("ctrlz_api may SELECT on %v, the tables are %v", got, tables)
	}
	if got := u.grantedTables("ctrlz_janitor", "ALTER DELETE"); join(got) != join(tables) {
		t.Errorf("ctrlz_janitor may ALTER DELETE on %v, the tables are %v", got, tables)
	}
	var written []string
	targets := s.viewTargets()
	for _, n := range tables {
		if !targets[n] {
			written = append(written, n)
		}
	}
	if got := u.grantedTables("ctrlz_ingest", "INSERT"); join(got) != join(written) {
		t.Errorf("ctrlz_ingest may INSERT into %v, the tables no view feeds are %v", got, written)
	}
	if got := join(u.grantedTables("ctrlz_preview", "SELECT")); got != "agg_counts,agg_reason,dns_raw" {
		t.Errorf("ctrlz_preview may SELECT on %v, 3.4 says dns_raw, agg_counts and agg_reason", got)
	}
	// Nobody has anything on a view, on a database as a whole, or on a table the migrations do not make.
	exists := map[string]bool{}
	for _, n := range tables {
		exists[n] = true
	}
	for user, qs := range u.grants {
		for _, q := range qs {
			if strings.Contains(q, " ON ctrlz.mv_") {
				t.Errorf("%s: %q is a grant on a view", user, q)
			}
			if m := regexp.MustCompile(` ON ctrlz\.([a-z_0-9]+)$`).FindStringSubmatch(q); m != nil && !exists[m[1]] {
				t.Errorf("%s: %q names a table the migrations do not make", user, q)
			}
			if user != "ctrlz_migrator" && (strings.HasSuffix(q, " ON *.*") || strings.HasSuffix(q, " ON ctrlz.*") || strings.Contains(q, "ALL")) {
				t.Errorf("%s: %q is wider than a table", user, q)
			}
		}
	}
}

// TestClickHouseUsersAndConstraints holds 3.4 and 6.3: five users, none with <access_management> (the server
// refuses that element beside <grants> and does not start; the migrator holds the six rights it needs as
// grants), the readers read-only with every limit constant and the two settings the constraints let them change.
func TestClickHouseUsersAndConstraints(t *testing.T) {
	u := loadCHUsers(t)
	users := []string{"ctrlz_api", "ctrlz_ingest", "ctrlz_janitor", "ctrlz_migrator", "ctrlz_preview"}
	var got []string
	for n := range u.grants {
		got = append(got, n)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(users, ",") {
		t.Fatalf("users.xml has the users %v, want %v", got, users)
	}
	for _, name := range users {
		if _, set := u.mgmt[name]; set {
			t.Errorf("%s: users.xml has <access_management>; ClickHouse refuses it beside <grants> (BAD_ARGUMENTS) and the server does not start", name)
		}
	}
	// What the migrator needs to make the policies and the quota of access.sql, as grants and nothing wider.
	for _, want := range []string{
		"GRANT CREATE ROW POLICY, ALTER ROW POLICY, DROP ROW POLICY ON *.*",
		"GRANT CREATE QUOTA, ALTER QUOTA, DROP QUOTA ON *.*",
	} {
		found := false
		for _, q := range u.grants["ctrlz_migrator"] {
			found = found || q == want
		}
		if !found {
			t.Errorf("ctrlz_migrator is not granted %q", want)
		}
	}
	for _, q := range u.grants["ctrlz_migrator"] {
		if strings.Contains(q, "ACCESS MANAGEMENT") || strings.Contains(q, "ON *.*") && !strings.Contains(q, "ROW POLICY") && !strings.Contains(q, "QUOTA") {
			t.Errorf("ctrlz_migrator: %q is a global right beyond the policies and the quota", q)
		}
	}
	// The wrapper writes the password of the same five and no other.
	wrapper := strings.Join(loadCompose(t).Services["clickhouse"].Entrypoint, "\n")
	for _, name := range users {
		if !strings.Contains(wrapper, "<"+name+"><password_sha256_hex>") {
			t.Errorf("the wrapper writes no password for %s", name)
		}
	}
	if n := strings.Count(wrapper, "<password_sha256_hex>"); n != len(users) {
		t.Errorf("the wrapper writes %d passwords for %d users", n, len(users))
	}
	// The generated file names each user's profile as well, the one users.xml gives it: an install whose
	// users.xml is missing then stops on an undefined profile even if the wrapper's file check were bypassed,
	// and a user is never left on the default profile with every right.
	for _, name := range users {
		if want := "</password_sha256_hex><profile>" + u.profile[name] + "</profile></" + name + ">"; !strings.Contains(wrapper, want) {
			t.Errorf("the wrapper's user file does not give %s the profile %q of users.xml", name, u.profile[name])
		}
	}

	limits := []string{"max_threads", "max_memory_usage", "max_memory_usage_for_user", "max_bytes_before_external_group_by",
		"max_bytes_before_external_sort", "max_temporary_data_on_disk_size_for_query", "max_temporary_data_on_disk_size_for_user", "max_result_rows", "max_result_bytes", "max_rows_to_read", "max_concurrent_queries_for_user", "readonly"}
	for _, reader := range []string{"ctrlz_api", "ctrlz_preview"} {
		prof := u.profile[reader]
		if prof != reader {
			t.Errorf("%s runs under the profile %q", reader, prof)
		}
		if u.settings[prof]["readonly"] != "1" {
			t.Errorf("%s: readonly is %q, want 1 (the fallback of 3.4 is readonly 2 and only a failed proof makes it)", reader, u.settings[prof]["readonly"])
		}
		for _, l := range limits {
			if _, set := u.settings[prof][l]; !set && l != "readonly" {
				t.Errorf("%s: the limit %s is not set", reader, l)
			}
			if u.consts[prof][l] != "const" {
				t.Errorf("%s: the limit %s is %q, want const", reader, l, u.consts[prof][l])
			}
		}
		if got := u.consts[prof]["SQL_tenant_id"]; got != "changeable_in_readonly" {
			t.Errorf("%s: SQL_tenant_id is %q, want changeable_in_readonly", reader, got)
		}
		maxExec := map[string]string{"ctrlz_api": "15", "ctrlz_preview": "70"}[reader]
		if got := u.consts[prof]["max_execution_time"]; got != "changeable_in_readonly,max="+maxExec+",min=1" {
			// 0 means no limit, and a constraint with a maximum only lets it through.
			t.Errorf("%s: max_execution_time is constrained as %q, want min 1, max %s and changeable_in_readonly", reader, got, maxExec)
		}
		if got := u.settings[prof]["max_execution_time"]; got != map[string]string{"ctrlz_api": "10", "ctrlz_preview": "60"}[reader] {
			t.Errorf("%s: max_execution_time is %q", reader, got)
		}
		for n, v := range map[string]string{"max_result_rows": "60000", "max_result_bytes": "33554432", "max_rows_to_read": "500000000", "max_concurrent_queries_for_user": "24"} {
			if u.settings[prof][n] != v {
				t.Errorf("%s: %s is %q, 6.3 says %s", reader, n, u.settings[prof][n], v)
			}
		}
		if len(u.consts[prof]) != len(limits)+2 {
			t.Errorf("%s has %d constraints, want the %d limits, SQL_tenant_id and max_execution_time", reader, len(u.consts[prof]), len(limits))
		}
	}
	if u.settings["ctrlz_ingest"]["async_insert"] != "0" {
		t.Error("ctrlz_ingest may use async_insert: the hub's deduplication tokens need whole blocks (5.4)")
	}
	if u.settings["ctrlz_janitor"]["lightweight_deletes_sync"] != "0" {
		t.Error("ctrlz_janitor waits for its deletes: 7.3 polls system.mutations instead")
	}
}

// TestClickHouseServerConfig holds the server-wide part of 3.4.
func TestClickHouseServerConfig(t *testing.T) {
	root := readXML(t, "ctrlz.xml")
	acc, ok := root.child("access_control_improvements")
	if !ok {
		t.Fatal("ctrlz.xml has no access_control_improvements")
	}
	if v, _ := acc.child("users_without_row_policies_can_read_rows"); v.text() != "false" {
		t.Errorf("users_without_row_policies_can_read_rows is %q, want false", v.text())
	}
	// The system tables: without these a reader may SELECT system.processes and system.errors, which carry the
	// text and the last error of other tenants' queries, and no row policy covers them. Written out so that the
	// default of a release cannot reopen them.
	for _, name := range []string{"select_from_system_db_requires_grant", "select_from_information_schema_requires_grant"} {
		if v, ok := acc.child(name); !ok || v.text() != "true" {
			t.Errorf("ctrlz.xml: %s is %q, want true (system tables would be readable by the reader users)", name, v.text())
		}
	}
	// changeable_in_readonly works only while this is true; written out so that a changed default cannot fail
	// every analytics query.
	if v, ok := acc.child("settings_constraints_replace_previous"); !ok || v.text() != "true" {
		t.Errorf("ctrlz.xml: settings_constraints_replace_previous is %q, want true (changeable_in_readonly needs it)", v.text())
	}
	if v, _ := root.child("custom_settings_prefixes"); v.text() != "SQL_" {
		t.Errorf("custom_settings_prefixes is %q, want SQL_", v.text())
	}
	for _, name := range []string{"query_log", "query_thread_log", "query_views_log", "text_log", "trace_log", "processors_profile_log", "asynchronous_insert_log", "opentelemetry_span_log", "error_log", "crash_log"} {
		n, ok := root.child(name)
		if !ok || n.attr("remove") == "" {
			t.Errorf("ctrlz.xml does not remove %s: a search term or a domain would be kept in it", name)
		}
	}
	// The logs with no query text and no TTL in the image: left on they fill the disk that Postgres shares.
	for _, name := range []string{"metric_log", "asynchronous_metric_log", "part_log", "query_metric_log", "background_schedule_pool_log"} {
		n, ok := root.child(name)
		if !ok || n.attr("remove") == "" {
			t.Errorf("ctrlz.xml does not remove %s: it has no TTL and would grow on the disk every tenant and Postgres share", name)
		}
	}
	// The server log: a failed query is logged at Error with its whole text (the searched name and the tenant),
	// so the loggers that write query text are off, and the image's file logs are removed, because the
	// console log is Docker's and these would be a second, unrotated copy in the container layer.
	lg, ok := root.child("logger")
	if !ok {
		t.Fatal("ctrlz.xml has no logger section")
	}
	for _, name := range []string{"log", "errorlog"} {
		if n, ok := lg.child(name); !ok || n.attr("remove") == "" {
			t.Errorf("ctrlz.xml does not remove the file log <%s>: failed queries would be kept in the container's writable layer", name)
		}
	}
	levels := map[string]string{}
	if lv, ok := lg.child("levels"); ok {
		for _, l := range lv.Nodes {
			nm, _ := l.child("name")
			lvl, _ := l.child("level")
			levels[nm.text()] = lvl.text()
		}
	}
	// BaseDaemon is the handler of a fatal signal: a crash logs the running query's text and its changed
	// settings (SQL_tenant_id) through it.
	for _, name := range []string{"executeQuery", "TCPHandler", "HTTPHandler", "DynamicQueryHandler", "BaseDaemon"} {
		if levels[name] != "none" {
			t.Errorf("ctrlz.xml: the logger %s is at %q, want none (it logs the text of a failed query)", name, levels[name])
		}
	}
	// An empty remote_url_allow_hosts allows every host, so the list holds one name that never resolves.
	r, ok := root.child("remote_url_allow_hosts")
	if !ok || len(r.Nodes) != 1 || !strings.HasSuffix(r.Nodes[0].text(), ".invalid") {
		t.Error("remote_url_allow_hosts must hold exactly one .invalid name (an empty list allows every host)")
	}
}

// TestClickHouseRowPolicies holds migrations/clickhouse/access.sql: tenant_only for the two readers,
// maintenance for the three users that work on every tenant, and the reader quota keyed by the client's key,
// all in the OR REPLACE form (the runner applies the file before the first migration and on every run, so a
// policy lost with the access directory or edited by hand is made again). No numbered migration makes a policy
// or a quota: a table with no policy at all is read without a filter, and a second source would let the two drift.
func TestClickHouseRowPolicies(t *testing.T) {
	s := loadCHSchema(t)
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "migrations", "clickhouse", "access.sql"))
	if err != nil {
		t.Fatal(err)
	}
	flat := regexp.MustCompile(`\s+`).ReplaceAllString(stripSQLComments(string(b)), " ")
	for _, want := range []string{
		"CREATE ROW POLICY OR REPLACE tenant_only ON ctrlz.* FOR SELECT USING tenant_id = toUUID(getSetting('SQL_tenant_id')) TO ctrlz_api, ctrlz_preview;",
		"CREATE ROW POLICY OR REPLACE maintenance ON ctrlz.* FOR SELECT USING 1 TO ctrlz_migrator, ctrlz_janitor, ctrlz_ingest;",
		// Never execution_time: the pinned server charges it only on a final result chunk (access.sql), so it would
		// look like a budget and limit nothing.
		"CREATE QUOTA OR REPLACE reader KEYED BY client_key FOR INTERVAL 1 minute MAX queries = 3000, errors = 200, read_rows = 5000000000, read_bytes = 68719476736 TO ctrlz_api;",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("access.sql lacks: %s", want)
		}
	}
	for name, body := range s.files {
		if regexp.MustCompile(`(?i)\b(ROW POLICY|QUOTA)\b`).MatchString(stripSQLComments(body)) {
			t.Errorf("%s makes a policy or a quota; access.sql is the one place, applied before the first table", name)
		}
	}
}

// TestNoServiceDependsOnClickHouse (11.5 item 3): a ClickHouse that is down, full or whose migration fails
// stops no login, no failover and no revocation, so no service waits for the server or for the one-shot.
func TestNoServiceDependsOnClickHouse(t *testing.T) {
	var doc struct {
		Services map[string]struct {
			DependsOn yaml.Node `yaml:"depends_on"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(realComposeText(t)), &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc.Services["migrate-analytics"]; !ok {
		t.Fatal("the Compose file has no migrate-analytics")
	}
	for name, s := range doc.Services {
		var deps []string
		switch s.DependsOn.Kind {
		case yaml.MappingNode:
			for i := 0; i < len(s.DependsOn.Content); i += 2 {
				deps = append(deps, s.DependsOn.Content[i].Value)
			}
		case yaml.SequenceNode:
			for _, c := range s.DependsOn.Content {
				deps = append(deps, c.Value)
			}
		}
		for _, d := range deps {
			if d == "clickhouse" || d == "migrate-analytics" {
				t.Errorf("%s depends on %s: a ClickHouse that is down would stop it", name, d)
			}
		}
		if name == "migrate-analytics" && strings.Join(deps, ",") != "migrate" {
			t.Errorf("migrate-analytics depends on %v, want migrate alone (for the image)", deps)
		}
	}
}

// chMiB turns a byte count of a profile into MiB.
func chMiB(t *testing.T, env map[string]string, key string) int {
	t.Helper()
	n, err := strconv.ParseInt(env[key], 10, 64)
	if err != nil || n <= 0 || n%(1<<20) != 0 {
		t.Fatalf("%s=%q is not a whole number of MiB", key, env[key])
	}
	return int(n >> 20)
}

// TestClickHouseMemoryAddsUp is the sizes test of 6.3: the second numbers of the table (what each user may
// hold at once), the caches, the server itself and the merge limit stay under the server's ceiling, in both
// profiles, and the numbers the Compose file defaults to are the small profile's.
func TestClickHouseMemoryAddsUp(t *testing.T) {
	dir := filepath.Join(repoRoot(t), "deploy", "compose", "profiles")
	small, std := readEnv(t, filepath.Join(dir, "small.env")), readEnv(t, filepath.Join(dir, "standard.env"))
	// "The server itself" row of 6.3: what ClickHouse needs with no query running.
	for _, c := range []struct {
		name       string
		env        map[string]string
		server     int
		wantSum    int
		wantCaches int
	}{
		{"small", small, 150, 1842, 192},
		{"standard", std, 250, 5612, 512},
	} {
		e := c.env
		users := chMiB(t, e, "CH_API_USER_MAX_MEMORY") + chMiB(t, e, "CH_QUERY_MAX_MEMORY") + chMiB(t, e, "CH_INGEST_USER_MAX_MEMORY")
		caches := chMiB(t, e, "CH_MARK_CACHE_SIZE") + chMiB(t, e, "CH_INDEX_MARK_CACHE_SIZE") + chMiB(t, e, "CH_PRIMARY_INDEX_CACHE_SIZE")
		sum := users + caches + c.server + chMiB(t, e, "CH_MERGES_SOFT_LIMIT")
		if caches != c.wantCaches {
			t.Errorf("%s: the caches are %d MiB, 3.4 says %d", c.name, caches, c.wantCaches)
		}
		if sum != c.wantSum {
			t.Errorf("%s: the memory columns add up to %d MiB, 6.3 says %d", c.name, sum, c.wantSum)
		}
	}
	for _, c := range []struct {
		name    string
		env     map[string]string
		sum     int
		ceiling int
	}{{"small", small, 1842, 1907}, {"standard", std, 5612, 5722}} {
		b, err := strconv.ParseInt(c.env["CH_MAX_SERVER_MEMORY_USAGE"], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		if int(b>>20) != c.ceiling {
			t.Errorf("%s: the ceiling is %d MiB, 6.3 says %d", c.name, b>>20, c.ceiling)
		}
		if c.sum*(1<<20) > int(b) {
			t.Errorf("%s: %d MiB of limits do not fit under the ceiling of %d MiB", c.name, c.sum, b>>20)
		}
		if mem := mib(t, c.env["MEM_CLICKHOUSE"]); mem*(1<<20) <= int(b) {
			t.Errorf("%s: the container limit %d MiB is not above the server ceiling %d MiB", c.name, mem, b>>20)
		}
		// One query is half of the spill point twice, and the spill point is half of one query.
		if q, s := chMiB(t, c.env, "CH_QUERY_MAX_MEMORY"), chMiB(t, c.env, "CH_QUERY_SPILL_BYTES"); q != 2*s {
			t.Errorf("%s: grouping and sorting spill at %d MiB, which is not half of a query's %d (6.3)", c.name, s, q)
		}
		// The temporary files a spilling query may write: bounded, and one query within its user's share.
		if q, u := chMiB(t, c.env, "CH_QUERY_TMP_DISK"), chMiB(t, c.env, "CH_USER_TMP_DISK"); q > u {
			t.Errorf("%s: one query may write %d MiB of temporary files, more than its user's %d", c.name, q, u)
		}
	}
	if small["CH_API_MAX_THREADS"] != "2" || std["CH_API_MAX_THREADS"] != "4" {
		t.Errorf("max_threads is %s and %s, 6.3 says 2 (small) and 4", small["CH_API_MAX_THREADS"], std["CH_API_MAX_THREADS"])
	}
	// Every number the Compose file reads is in both profiles, and its default is the small profile's.
	ch := loadCompose(t).Services["clickhouse"]
	seen := 0
	for k, v := range ch.Environment {
		if !strings.HasPrefix(k, "CH_") {
			continue
		}
		seen++
		m := regexp.MustCompile(`^\$\{` + k + `:-([0-9]+)\}$`).FindStringSubmatch(v)
		if m == nil {
			t.Errorf("clickhouse: %s=%q is not ${%s:-<number>}", k, v, k)
			continue
		}
		if small[k] != m[1] {
			t.Errorf("clickhouse: the default of %s is %s, the small profile says %s", k, m[1], small[k])
		}
		if _, ok := std[k]; !ok {
			t.Errorf("standard.env lacks %s", k)
		}
	}
	if seen != 13 {
		t.Errorf("clickhouse takes %d CH_ numbers, the sizes test knows 13", seen)
	}
	// And every from_env of the two XML files is one of them.
	for _, f := range []string{"users.xml", "ctrlz.xml"} {
		b, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "compose", "clickhouse", f))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range regexp.MustCompile(`from_env="([A-Z_]+)"`).FindAllStringSubmatch(string(b), -1) {
			if _, ok := ch.Environment[m[1]]; !ok {
				t.Errorf("%s reads %s, which the clickhouse service does not have: the server would not start", f, m[1])
			}
		}
	}
}
