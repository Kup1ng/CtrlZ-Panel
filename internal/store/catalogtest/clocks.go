package catalogtest

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/Kup1ng/CtrlZ-Panel/internal/clockrule"
)

// defaultClock finds a database clock in a column default.
var defaultClock = regexp.MustCompile(`(?i)\b(now|clock_timestamp|statement_timestamp|transaction_timestamp|timeofday)\s*\(|\b(current_timestamp|current_date|current_time|localtimestamp|localtime)\b`)

// CheckClocks is catalog check 24, the catalog half of rule clock-source
// (migrations/catalog/clocks.yaml, internal/clockrule). It asks Postgres for
//
//   - the timestamp columns (timestamptz, timestamp, date) of every table listed in
//     clocks.yaml and of every table in guarded.yaml, and fails for one that has no
//     clock or one that is listed and does not exist, so a column added tomorrow has
//     to be given a clock on the day it is made;
//   - the live body of every function in ctrlz_fn and ctrlz, which clockrule judges
//     as it judges a SQL constant of Go (an application-clock column next to a
//     database clock fails);
//   - the argument types of the definer functions: none takes a timestamp, because a
//     time handed in by Go would be the application clock deciding inside the
//     database;
//   - the timestamp columns a definer function returns, each of which must be mapped
//     in clocks.yaml to the column it reads (and a db column handed back raw must be
//     listed under read, with its reason);
//   - the DEFAULT of every application-clock column, which must not read a database
//     clock.
//
// A failure is a defect of the rule or of clocks.yaml, never a reason to add a case.
func CheckClocks(ctx context.Context, q Querier, fx *Fixtures) ([]string, error) {
	reg := fx.Clocks
	var out []string

	// Coverage of the tables.
	listed := map[string]bool{}
	for t := range reg.Tables {
		listed[t] = true
	}
	for t := range fx.Guarded.Write {
		if !listed[t] {
			out = append(out, "clocks.yaml: "+t+" is in guarded.yaml (write) and has no clocks")
		}
	}
	for t := range fx.Guarded.Read {
		if !listed[t] {
			out = append(out, "clocks.yaml: "+t+" is in guarded.yaml (read) and has no clocks")
		}
	}
	for t := range fx.Guarded.Trail {
		if !listed[t] {
			out = append(out, "clocks.yaml: "+t+" is in guarded.yaml (trail) and has no clocks")
		}
	}
	rows, err := q.Query(ctx, `
SELECT c.relname, a.attname, format_type(a.atttypid, a.atttypmod), COALESCE(pg_get_expr(d.adbin, d.adrelid), '')
FROM pg_class c
JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
LEFT JOIN pg_attrdef d ON d.adrelid = c.oid AND d.adnum = a.attnum
WHERE c.relnamespace = 'ctrlz'::regnamespace AND c.relkind IN ('r', 'p')
ORDER BY 1, a.attnum`)
	if err != nil {
		return nil, err
	}
	type col struct{ typ, def string }
	live := map[string]map[string]col{}
	for rows.Next() {
		var t, c, typ, def string
		if err := rows.Scan(&t, &c, &typ, &def); err != nil {
			rows.Close()
			return nil, err
		}
		if live[t] == nil {
			live[t] = map[string]col{}
		}
		live[t][c] = col{typ, def}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	isTime := func(typ string) bool {
		return strings.HasPrefix(typ, "timestamp") || typ == "date"
	}
	for _, t := range sortedKeys(reg.Tables) {
		cols, exists := live[t]
		if !exists {
			out = append(out, "clocks.yaml: table "+t+" does not exist")
			continue
		}
		for _, c := range sortedKeys(reg.Tables[t]) {
			l, ok := cols[c]
			switch {
			case !ok:
				out = append(out, fmt.Sprintf("clocks.yaml: %s.%s does not exist", t, c))
			case !isTime(l.typ):
				out = append(out, fmt.Sprintf("clocks.yaml: %s.%s is %s, not a timestamp", t, c, l.typ))
			case reg.Tables[t][c] == clockrule.App && defaultClock.MatchString(l.def):
				out = append(out, fmt.Sprintf("clock: %s.%s is on the application clock and its DEFAULT reads the database clock (%s); drop the default and pass the time", t, c, l.def))
			}
		}
		for _, c := range sortedKeys(cols) {
			if isTime(cols[c].typ) && reg.Tables[t][c] == "" {
				out = append(out, fmt.Sprintf("clocks.yaml: %s.%s (%s) has no clock; add it as app, db or stamp", t, c, cols[c].typ))
			}
		}
	}

	// Function bodies, argument types and returned timestamps.
	frows, err := q.Query(ctx, `
SELECT n.nspname, p.proname, pg_get_function_identity_arguments(p.oid), p.prosrc, p.prosecdef,
  COALESCE((SELECT array_agg(t::regtype::text) FROM unnest(p.proargtypes::oid[]) t), '{}'),
  COALESCE((SELECT array_agg(n2 || ' ' || t2::regtype::text ORDER BY ord)
            FROM unnest(p.proargnames, p.proallargtypes::oid[], p.proargmodes) WITH ORDINALITY AS u(n2, t2, m2, ord)
            WHERE m2::text IN ('t', 'o')), '{}')
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname IN ('ctrlz', 'ctrlz_fn') AND p.prolang IN (SELECT oid FROM pg_language WHERE lanname IN ('plpgsql', 'sql'))
ORDER BY 1, 2, 3`)
	if err != nil {
		return nil, err
	}
	type fn struct {
		schema, name, args, src string
		definer                 bool
		argTypes, outs          []string
	}
	var fns []fn
	for frows.Next() {
		var f fn
		if err := frows.Scan(&f.schema, &f.name, &f.args, &f.src, &f.definer, &f.argTypes, &f.outs); err != nil {
			frows.Close()
			return nil, err
		}
		fns = append(fns, f)
	}
	frows.Close()
	if err := frows.Err(); err != nil {
		return nil, err
	}
	returned := map[string]bool{}
	for _, f := range fns {
		id := f.schema + "." + f.name
		for _, fd := range reg.Analyze(f.src, clockrule.Options{}) {
			out = append(out, fmt.Sprintf("clock: %s: %s", id, fd))
		}
		if f.schema != "ctrlz_fn" {
			continue
		}
		for _, a := range f.argTypes {
			if strings.HasPrefix(a, "timestamp") || a == "date" {
				out = append(out, fmt.Sprintf("clock: %s takes a %s; a time handed in by Go would be the application clock deciding inside the database", id, a))
			}
		}
		for _, o := range f.outs {
			name, typ, _ := strings.Cut(o, " ")
			if !isTime(typ) {
				continue
			}
			key := f.name + "." + name
			returned[key] = true
			src, ok := reg.Functions[key]
			switch {
			case !ok:
				out = append(out, fmt.Sprintf("clocks.yaml: functions has no entry for %s, which returns a %s to Go; map it to the column it reads", key, typ))
			case src != "none":
				t, c, _ := strings.Cut(src, ".")
				if cc, ok := live[t][c]; !ok || !isTime(cc.typ) {
					out = append(out, fmt.Sprintf("clocks.yaml: functions.%s reads %s, which is not a timestamp column", key, src))
				}
			}
		}
	}
	var stale []string
	for key := range reg.Functions {
		if !returned[key] {
			stale = append(stale, "clocks.yaml: functions."+key+" names a column no definer function returns; remove it")
		}
	}
	sort.Strings(stale)
	return append(out, stale...), nil
}
