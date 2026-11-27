package lint_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// Rule boundary-input, round 5 (admin-r5-4): "integers have real bounds" means the bounds of the
// table. The SMS limits were documented with minimum 0 on every cap and on the cooldown and the
// soft percentage, and the table (0011) refuses a cap below 1, a cooldown outside 10 to 3600 and a
// percentage outside 1 to 100. The schema let a legal-looking value through to the CHECK, which
// answered one 422 on a field called "limits", so the page could not say which number was wrong.
// This reads the CHECK of every column behind a property of SmsLimits and requires the schema to
// carry the same range. It reads the migration text, so it needs no database.

var (
	checkAtLeast = regexp.MustCompile(`(?i)CHECK \((\w+) >= (\d+)\)`)
	checkBetween = regexp.MustCompile(`(?i)CHECK \((\w+) BETWEEN (\d+) AND (\d+)\)`)
)

// tableRanges returns the [min, max] of every column that a CHECK of the migration bounds; a max
// of -1 means no upper bound is stated.
func tableRanges(sql string) map[string][2]int64 {
	out := map[string][2]int64{}
	for _, m := range checkAtLeast.FindAllStringSubmatch(sql, -1) {
		lo, _ := strconv.ParseInt(m[2], 10, 64)
		out[m[1]] = [2]int64{lo, -1}
	}
	for _, m := range checkBetween.FindAllStringSubmatch(sql, -1) {
		lo, _ := strconv.ParseInt(m[2], 10, 64)
		hi, _ := strconv.ParseInt(m[3], 10, 64)
		out[m[1]] = [2]int64{lo, hi}
	}
	return out
}

// compareLimits returns what differs between the SmsLimits schema of the document and the table.
func compareLimits(raw []byte, sql string) ([]string, error) {
	doc, err := openapi3.NewLoader().LoadFromData(raw)
	if err != nil {
		return nil, err
	}
	ref := doc.Components.Schemas["SmsLimits"]
	if ref == nil || ref.Value == nil {
		return []string{"SmsLimits is not in the document"}, nil
	}
	ranges := tableRanges(sql)
	var out []string
	for _, name := range sortedKeys(ref.Value.Properties) {
		p := ref.Value.Properties[name].Value
		if p == nil || !strings.Contains(strings.Join(p.Type.Slice(), ","), "integer") {
			continue
		}
		want, ok := ranges[name]
		if !ok {
			out = append(out, name+": no CHECK of the table bounds this column, or the migration names it differently")
			continue
		}
		if p.Min == nil || int64(*p.Min) != want[0] {
			out = append(out, name+": the schema's minimum is not the table's "+strconv.FormatInt(want[0], 10))
		}
		if want[1] >= 0 && (p.Max == nil || int64(*p.Max) != want[1]) {
			out = append(out, name+": the schema's maximum is not the table's "+strconv.FormatInt(want[1], 10))
		}
	}
	return out, nil
}

func TestSmsLimitsSchemaCarriesTheBoundsOfTheTable(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "api", "admin-openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	sql, err := os.ReadFile(filepath.Join(root, "migrations", "postgres", "0011_auth.sql"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := compareLimits(raw, string(sql))
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range got {
		t.Errorf("SmsLimits.%s", g)
	}

	// The check can fail: the bounds the review found, put back one at a time.
	doc := string(raw)
	for label, c := range map[string]struct{ old, new, want string }{
		"a cap may be zero":  {"otp_cap_phone: {type: integer, minimum: 1,", "otp_cap_phone: {type: integer, minimum: 0,", "otp_cap_phone: the schema's minimum"},
		"cooldown from zero": {"otp_cooldown_s: {type: integer, minimum: 10, maximum: 3600}", "otp_cooldown_s: {type: integer, minimum: 0, maximum: 3600}", "otp_cooldown_s: the schema's minimum"},
		"cooldown unbounded": {"otp_cooldown_s: {type: integer, minimum: 10, maximum: 3600}", "otp_cooldown_s: {type: integer, minimum: 10, maximum: 2147483647}", "otp_cooldown_s: the schema's maximum"},
		"percentage from 0":  {"otp_soft_pct: {type: integer, minimum: 1, maximum: 100}", "otp_soft_pct: {type: integer, minimum: 0, maximum: 100}", "otp_soft_pct: the schema's minimum"},
	} {
		if !strings.Contains(doc, c.old) {
			t.Fatalf("%s: the mutant does not apply", label)
		}
		got, err := compareLimits([]byte(strings.Replace(doc, c.old, c.new, 1)), string(sql))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(strings.Join(got, "\n"), c.want) {
			t.Errorf("%s: findings %v, want one containing %q", label, got, c.want)
		}
	}
	if got, _ := compareLimits(raw, "-- no checks at all"); len(got) == 0 {
		t.Error("a table with no CHECK was accepted for every column")
	}
}
