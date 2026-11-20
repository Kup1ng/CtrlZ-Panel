package catalogtest

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/Kup1ng/CtrlZ-Panel/internal/caps"
)

// CheckCaps is catalog check 26, the enforcement of rule caps-and-endings that lives in
// the database (internal/caps; spec 9.5, 9.6).
//
//   - Every column named *_cap* of a ctrlz table is a cap in internal/caps, and every
//     setting an entry names is a live column, so a cap added by a migration cannot
//     miss the race harness.
//   - Every cap is compared with ctrlz.cap_reached. A definer function whose body holds
//     any other comparison against a *_cap* value fails, so the plpgsql of an OTP issue
//     and the SQL of the worker cannot drift apart again (sms-r2-6).
func CheckCaps(ctx context.Context, q Querier, _ *Fixtures) ([]string, error) {
	live, err := strs(ctx, q, `
SELECT c.relname || '.' || a.attname FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
WHERE c.relnamespace = 'ctrlz'::regnamespace AND c.relkind IN ('r','p') AND a.attnum > 0 AND NOT a.attisdropped
  AND a.attname LIKE '%\_cap%'`)
	if err != nil {
		return nil, err
	}
	var want []string
	for _, e := range caps.Entries() {
		for _, s := range e.Settings {
			// This is the net of the spelling; a limit that is not called *_cap* (the cooldown) is
			// found by limitColumnProblems, which reads every numeric column.
			if strings.Contains(s, "_cap") {
				want = append(want, "system_settings."+s)
			}
		}
	}
	want = dedupe(want)
	out := diff("columns named *_cap* (internal/caps)", want, live)

	out = append(out, limitColumnProblems(ctx, q)...)

	rows, err := q.Query(ctx, `
SELECT n.nspname || '.' || p.proname, p.prosrc
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname IN ('ctrlz', 'ctrlz_fn')
  AND p.prolang IN (SELECT oid FROM pg_language WHERE lanname IN ('plpgsql', 'sql'))`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	usesShared := false
	seenFn := map[string]bool{}
	for rows.Next() {
		var name, src string
		if err := rows.Scan(&name, &src); err != nil {
			return nil, err
		}
		if name == "ctrlz.cap_reached" {
			continue
		}
		if strings.Contains(src, "ctrlz.cap_reached(") {
			usesShared = true
		}
		if col := caps.NamesLimit(src); col != "" && !strings.Contains(src, caps.Shared) {
			switch f, ok := limitFunction(name); {
			case !ok:
				out = append(out, fmt.Sprintf("%s names the limit %s and does not call ctrlz.cap_reached; call it, or list the function in caps.LimitFunctions with the reason", name, col))
			case f.Digest != caps.Digest(src):
				out = append(out, fmt.Sprintf("%s is listed in caps.LimitFunctions but its text is not the one that was reviewed; read it again, and if it is still no spend set its Digest to %s", name, caps.Digest(src)))
			}
		}
		seenFn[name] = true
		if bad := caps.UnsharedCompare(src); bad != "" {
			out = append(out, fmt.Sprintf("%s compares a *_cap* value without ctrlz.cap_reached: %q", name, bad))
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !usesShared {
		out = append(out, "no function uses ctrlz.cap_reached; the OTP issue must")
	}
	for _, f := range caps.LimitFunctions() {
		if !seenFn[f.Name] {
			out = append(out, "caps.LimitFunctions lists "+f.Name+", which is not a function of the database")
		}
	}
	sort.Strings(out)
	return out, nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func limitFunction(name string) (caps.LimitFunction, bool) {
	for _, f := range caps.LimitFunctions() {
		if f.Name == name {
			return f, true
		}
	}
	return caps.LimitFunction{}, false
}

// limitColumnProblems is the half of check 26 that reads no name: every numeric column of every table
// of caps.LimitTables is a limit with a registry entry (a Settings column of internal/caps), a column
// that limits nothing with the reason (caps.NotLimits), or a limit a later phase enforces
// (caps.PendingLimits, in the entitlement tables), and every entry names a live column
// (sms-r16-4, sms-r16-17, sms-r16-28). The *_cap* query above finds a cap by its spelling; this one
// finds every number these tables can hold, so a limit called anything else, in the settings or in
// the per-tenant entitlements, is still met by a person's decision. The first version read
// system_settings only, and the ten per-tenant ceilings were in no registry at all.
func limitColumnProblems(ctx context.Context, q Querier) []string {
	tables := caps.LimitTables()
	quoted := make([]string, len(tables))
	for i, t := range tables {
		quoted[i] = "'" + t + "'"
	}
	live, err := strs(ctx, q, `
SELECT c.relname || '.' || a.attname FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
WHERE c.relnamespace = 'ctrlz'::regnamespace AND c.relname IN (`+strings.Join(quoted, ", ")+`) AND a.attnum > 0 AND NOT a.attisdropped
  AND a.atttypid IN ('int2'::regtype, 'int4'::regtype, 'int8'::regtype, 'numeric'::regtype, 'float4'::regtype, 'float8'::regtype)`)
	if err != nil {
		return []string{"numeric columns of " + strings.Join(tables, ", ") + " could not be read: " + err.Error()}
	}
	var want []string
	for _, e := range caps.Entries() {
		for _, s := range e.Settings {
			want = append(want, "system_settings."+s)
		}
		for _, c := range e.Entitlements {
			for _, t := range caps.PendingTables() {
				want = append(want, t+"."+c)
			}
		}
	}
	for _, n := range caps.NotLimits() {
		if strings.TrimSpace(n.Reason) == "" {
			return []string{"caps.NotLimits: " + n.Column + " has no reason"}
		}
		want = append(want, "system_settings."+n.Column)
	}
	for _, p := range caps.PendingLimits() {
		if strings.TrimSpace(p.Reason) == "" || strings.TrimSpace(p.Phase) == "" {
			return []string{"caps.PendingLimits: " + p.Column + " has no reason or no phase"}
		}
		for _, t := range caps.PendingTables() {
			want = append(want, t+"."+p.Column)
		}
	}
	return diff("numeric columns of "+strings.Join(tables, ", ")+" (a Settings column of internal/caps, a caps.NotLimits or a caps.PendingLimits entry with a reason)", dedupe(want), dedupe(live))
}
