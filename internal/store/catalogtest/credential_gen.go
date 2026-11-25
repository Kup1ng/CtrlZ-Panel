package catalogtest

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// credentialGenFunction is the trigger function of rule credential-generation. Check
// 11 leaves its triggers to check 25, which reads their arguments.
const credentialGenFunction = "credential_gen_bump"

// CheckCredentialGen is catalog check 25, the enforcement of rule credential-generation
// (guarded.yaml, credential_gen; spec 3.7, 5.5, 5.7, 10.2, 16.1).
//
// users and admin_users carry one credential_gen counter that a trigger moves when a
// credential column changes. The trigger's argument list IS the list of credential
// columns, so this check compares the live trigger with guarded.yaml, and it compares
// guarded.yaml with the live columns:
//
//   - every guarded column (a live column that is not `free` in the write section) is
//     either a credential column or has a reason in `other`, and none is both, so a
//     column added later forces the decision;
//   - the trigger of each table is the one function, BEFORE UPDATE, FOR EACH ROW, with
//     no WHEN clause and no column list (either would let a write skip it), enabled,
//     and its arguments are exactly the credential columns;
//   - credential_gen is a bigint NOT NULL, and no table carries it that guarded.yaml
//     does not list.
//
// A failure here is a defect of the rule or of guarded.yaml, never a reason to add a
// case to this check.
func CheckCredentialGen(ctx context.Context, q Querier, fx *Fixtures) ([]string, error) {
	cols, err := liveColumns(ctx, q)
	if err != nil {
		return nil, err
	}
	var out []string
	tables := make([]string, 0, len(fx.Guarded.CredentialGen))
	for t := range fx.Guarded.CredentialGen {
		tables = append(tables, t)
	}
	sort.Strings(tables)

	withColumn, err := strs(ctx, q, `
SELECT c.relname FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
WHERE c.relnamespace = 'ctrlz'::regnamespace AND c.relkind IN ('r','p') AND a.attname = 'credential_gen'
  AND a.attnum > 0 AND NOT a.attisdropped`)
	if err != nil {
		return nil, err
	}
	out = append(out, diff("tables with a credential_gen column", tables, withColumn)...)

	for _, table := range tables {
		spec := fx.Guarded.CredentialGen[table]
		live, ok := cols[table]
		if !ok {
			out = append(out, "guarded.yaml: credential_gen lists "+table+", which does not exist")
			continue
		}
		have := map[string]column{}
		for _, c := range live {
			have[c.Name] = c
		}
		free := map[string]bool{}
		for _, c := range fx.Guarded.Write[table].Free {
			free[c] = true
		}
		listed, other := map[string]bool{}, map[string]bool{}
		for _, c := range spec.Columns {
			listed[c] = true
			if _, ok := have[c]; !ok {
				out = append(out, fmt.Sprintf("guarded.yaml: credential_gen.%s.columns names %s, which does not exist", table, c))
			} else if free[c] {
				out = append(out, fmt.Sprintf("guarded.yaml: credential_gen.%s.columns names %s, which is a free column of the write section", table, c))
			}
		}
		for c, why := range spec.Other {
			other[c] = true
			if _, ok := have[c]; !ok {
				out = append(out, fmt.Sprintf("guarded.yaml: credential_gen.%s.other names %s, which does not exist", table, c))
			}
			if strings.TrimSpace(why) == "" {
				out = append(out, fmt.Sprintf("guarded.yaml: credential_gen.%s.other.%s has no reason", table, c))
			}
			if listed[c] {
				out = append(out, fmt.Sprintf("guarded.yaml: credential_gen.%s: %s is both a credential column and in other", table, c))
			}
		}
		for _, c := range live {
			if free[c.Name] || listed[c.Name] || other[c.Name] {
				continue
			}
			out = append(out, fmt.Sprintf("%s.%s is a guarded column with no decision: add it to credential_gen.%s.columns (a change must end every artefact derived from a past verification) or to other with the reason it need not", table, c.Name, table))
		}
		if g, ok := have["credential_gen"]; !ok {
			out = append(out, table+" has no credential_gen column")
		} else if g.Type != "bigint" || !g.NotNull {
			out = append(out, fmt.Sprintf("%s.credential_gen is %s (not null %v), want bigint NOT NULL", table, g.Type, g.NotNull))
		}

		args, problems, err := credentialTrigger(ctx, q, table)
		if err != nil {
			return nil, err
		}
		out = append(out, problems...)
		if len(problems) == 0 {
			out = append(out, diff("credential_gen trigger arguments of "+table, spec.Columns, args)...)
		}
	}
	return out, nil
}

// credentialTrigger reads the live trigger of a table and returns its arguments.
func credentialTrigger(ctx context.Context, q Querier, table string) (args []string, problems []string, err error) {
	rows, err := q.Query(ctx, `
SELECT t.tgenabled, t.tgtype, t.tgqual IS NOT NULL, t.tgattr::text, encode(t.tgargs, 'hex')
FROM pg_trigger t
WHERE t.tgrelid = ('ctrlz.' || $1)::regclass AND NOT t.tgisinternal
  AND t.tgfoid = (SELECT p.oid FROM pg_proc p WHERE p.proname = $2 AND p.pronamespace = 'ctrlz'::regnamespace)`, table, credentialGenFunction)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var enabled string
		var typ int16
		var hasWhen bool
		var attr, hexArgs string
		if err := rows.Scan(&enabled, &typ, &hasWhen, &attr, &hexArgs); err != nil {
			return nil, nil, err
		}
		n++
		const rowBeforeUpdate = 1 | 2 | 16 // FOR EACH ROW, BEFORE, UPDATE and nothing else
		if enabled != "O" {
			problems = append(problems, fmt.Sprintf("the credential_gen trigger of %s is not enabled (%q): a disabled trigger is as good as a missing one", table, enabled))
		}
		if typ != rowBeforeUpdate {
			problems = append(problems, fmt.Sprintf("the credential_gen trigger of %s has type %d, want BEFORE UPDATE FOR EACH ROW (%d)", table, typ, rowBeforeUpdate))
		}
		if hasWhen {
			problems = append(problems, fmt.Sprintf("the credential_gen trigger of %s has a WHEN clause, which lets a write skip it", table))
		}
		if strings.TrimSpace(attr) != "" {
			problems = append(problems, fmt.Sprintf("the credential_gen trigger of %s is limited to UPDATE OF columns, which lets a write skip it", table))
		}
		raw, derr := hex.DecodeString(hexArgs)
		if derr != nil {
			return nil, nil, derr
		}
		// tgargs is each argument followed by a NUL.
		for _, a := range strings.Split(strings.TrimSuffix(string(raw), "\x00"), "\x00") {
			if a != "" {
				args = append(args, a)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	switch {
	case n == 0:
		problems = append(problems, fmt.Sprintf("%s has no credential_gen trigger", table))
	case n > 1:
		problems = append(problems, fmt.Sprintf("%s has %d credential_gen triggers, want one", table, n))
	}
	sort.Strings(args)
	return args, problems, nil
}
