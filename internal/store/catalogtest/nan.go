package catalogtest

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// NaNExempt is a numeric column that may accept NaN, with the reason (tables.yaml nan_exempt).
type NaNExempt struct {
	Table  string `yaml:"table"`
	Column string `yaml:"column"`
	Reason string `yaml:"reason"`
}

// nonFinite are the three values a numeric or floating point column can hold besides numbers
// (Postgres 14 and later: an unbounded numeric holds infinity too).
func nonFinite() []string { return []string{"NaN", "Infinity", "-Infinity"} }

// CheckNaN is catalog check 27, the enforcement of "a value a cap compares with is judged where it
// is stored" (rule caps-and-endings, db-r11-1, db-r12-1, db-r12-3, db-r13-2).
//
// Postgres sorts NaN above every number, so `CHECK (x >= 0)` accepts it, and a NaN spend or a NaN
// price either parks a daily cap at "reached" for good or, as a cap, never stops anything. Infinity
// does the same two things in a column that holds it: as a cap it is never reached, as a spend it is
// always reached and no UPDATE can lower it. Round 11 closed NaN for one column, round 12 found two
// more with the same text and round 13 saw that the probe knew only NaN, so the question is asked of
// the schema and of every non-finite value, not of a list of known columns or one spelling: EVERY
// numeric, real and double precision column of the ctrlz and river tables must refuse NaN, Infinity
// and -Infinity, or be named in tables.yaml nan_exempt with the reason none of them is harmful there.
//
// A column refuses a value in one of two ways. (1) Its type does: numeric(p, s) with a precision
// cannot hold an infinity (the cast raises 22003), so a typed numeric(14, 4) needs only the NaN line.
// (2) A CHECK on the column alone is FALSE for it, judged by the constraint's own text evaluated for
// the value (pg_get_expr, in a one-row subquery whose column has the column's name and type), not a
// search for a word, so `<> 'NaN'`, `< 'Infinity'`, `BETWEEN 0 AND 1` and any other spelling count and
// a lower bound alone does not. Only a CHECK that is enforced and validated counts: a NOT ENFORCED
// or NOT VALID one holds nothing (db-r13-3). A constraint that cannot be evaluated is reported rather
// than skipped. An exemption that names a column that does not exist or that does refuse all three
// is reported too, so the list stays true. An array of numbers cannot be judged this way and needs
// an exemption.
func CheckNaN(ctx context.Context, q Querier, fx *Fixtures) ([]string, error) {
	type col struct {
		table, name, typ string
		attnum           int16
		array, typed     bool
		rel              string
	}
	rows, err := q.Query(ctx, `
SELECT n.nspname, c.relname, a.attname, format_type(a.atttypid, a.atttypmod), a.attnum, c.oid::regclass::text,
       t.typcategory = 'A',
       -- A numeric with a declared precision refuses an infinity by its type; a domain carries its own typmod.
       b.typname = 'numeric' AND t.typcategory <> 'A' AND (CASE WHEN t.typtype = 'd' THEN t.typtypmod ELSE a.atttypmod END) <> -1
FROM pg_attribute a
JOIN pg_class c ON c.oid = a.attrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_type t ON t.oid = a.atttypid
-- A domain is judged by its base type; an array by its element type.
JOIN pg_type b ON b.oid = CASE WHEN t.typtype = 'd' THEN t.typbasetype WHEN t.typcategory = 'A' THEN t.typelem ELSE t.oid END
WHERE n.nspname IN ('ctrlz', 'river') AND c.relkind IN ('r', 'p') AND a.attnum > 0 AND NOT a.attisdropped
  AND b.typname IN ('numeric', 'float4', 'float8')
ORDER BY 1, 2, 3`)
	if err != nil {
		return nil, err
	}
	var cols []col
	for rows.Next() {
		var schema string
		var c col
		if err := rows.Scan(&schema, &c.table, &c.name, &c.typ, &c.attnum, &c.rel, &c.array, &c.typed); err != nil {
			rows.Close()
			return nil, err
		}
		if schema == "river" {
			c.table = "river." + c.table
		}
		cols = append(cols, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	exempt := map[string]string{}
	for _, e := range fx.Tables.NaNExempt {
		if e.Reason == "" {
			return []string{fmt.Sprintf("nan_exempt %s.%s has no reason", e.Table, e.Column)}, nil
		}
		exempt[e.Table+"."+e.Column] = e.Reason
	}

	var out []string
	seen := map[string]bool{}
	for _, c := range cols {
		key := c.table + "." + c.name
		seen[key] = true
		accepts, why, err := acceptedNonFinite(ctx, q, c.rel, c.name, c.typ, c.attnum, c.array, c.typed)
		if err != nil {
			return nil, err
		}
		_, isExempt := exempt[key]
		switch {
		case why != "":
			out = append(out, fmt.Sprintf("%s: %s", key, why))
		case len(accepts) > 0 && !isExempt:
			out = append(out, fmt.Sprintf("%s (%s) accepts %s: give it CHECKs on the column alone that are false for them (`<> 'NaN'::numeric` and `< 'Infinity'` with `> '-Infinity'`, or a BETWEEN, which refuses all three; `>= 0` alone passes NaN and Infinity; a numeric(p, s) refuses the infinities by its type), or list it in tables.yaml nan_exempt with the reason", key, c.typ, strings.Join(accepts, ", ")))
		case len(accepts) == 0 && isExempt:
			out = append(out, fmt.Sprintf("%s is listed in nan_exempt but already refuses NaN and both infinities; remove the entry", key))
		}
	}
	for k := range exempt {
		if !seen[k] {
			out = append(out, fmt.Sprintf("nan_exempt names %s, which is not a numeric column of the schema", k))
		}
	}
	sort.Strings(out)
	return out, nil
}

// acceptedNonFinite lists the non-finite values the column accepts. why is set when the question
// could not be asked (a constraint that does not evaluate); an array is left to the exemption list.
func acceptedNonFinite(ctx context.Context, q Querier, rel, name, typ string, attnum int16, array, typed bool) (accepts []string, why string, err error) {
	if array {
		return []string{"an array of numbers cannot be probed"}, "", nil
	}
	// Only a constraint that is enforced AND validated holds anything (db-r13-3).
	exprs, err := strs(ctx, q, `
SELECT pg_get_expr(conbin, conrelid) FROM pg_constraint
WHERE conrelid = $1::regclass AND contype = 'c' AND conkey = ARRAY[$2::smallint] AND conenforced AND convalidated`, rel, attnum)
	if err != nil {
		return nil, "", err
	}
	for _, v := range nonFinite() {
		if typed && v != "NaN" {
			continue // numeric(p, s) cannot hold an infinity; its type is the refusal
		}
		refused := false
		for _, e := range exprs {
			// The expression names the column unqualified. It comes from our own catalog, and a
			// failure to evaluate is a finding, so nothing here is skipped silently.
			var ok *bool
			sql := fmt.Sprintf(`SELECT (%s) FROM (SELECT '%s'::%s AS %s) AS probe`, e, v, typ, quoteIdent(name))
			if err := q.QueryRow(ctx, sql).Scan(&ok); err != nil {
				return nil, fmt.Sprintf("the CHECK %q could not be evaluated for %s: %v", e, v, err), nil
			}
			if ok != nil && !*ok {
				refused = true
				break
			}
		}
		if !refused {
			accepts = append(accepts, v)
		}
	}
	return accepts, "", nil
}

func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}
