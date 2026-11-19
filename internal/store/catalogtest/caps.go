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
			want = append(want, "system_settings."+s)
		}
	}
	want = dedupe(want)
	out := diff("columns named *_cap* (internal/caps)", want, live)

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
