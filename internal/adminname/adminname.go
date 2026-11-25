// Package adminname is the one rule for what an admin username may be (spec 10.1 step 1, rule
// boundary-input). The admin login schema (api/admin-openapi.yaml, the `content` pattern) refuses a
// name before any handler runs, and ctrlz-admin bootstrap writes the name into the table without
// going through that schema, so a name the CLI took and the schema refused made an account nobody
// could sign in to, with bootstrap refusing to run a second time (round 6, admin-r6-2). Both
// entries now ask this package, and a test compares Pattern with the document's own text and walks
// every code point through both.
package adminname

import (
	"regexp"
	"unicode"
	"unicode/utf8"
)

// Pattern is the schema's pattern `content`: the first character is not a control, format,
// surrogate, private-use or unassigned code point (\p{C}) and not a separator (\p{Z}), and no
// character is in \p{C}. A test fails if api/admin-openapi.yaml says anything else.
const Pattern = `^[^\p{C}\p{Z}][^\p{C}]*$`

// LimitRunes is the length the table accepts (the CHECK of migration 0002).
const LimitRunes = 64

var pattern = regexp.MustCompile(Pattern)

// Valid says the name can be written by the CLI: it is a name the login schema accepts, and a
// stricter one, for the console must be able to read it back to the operator and the operator to
// type it: no separator anywhere, not only at the front (a space inside a name is valid for the
// schema and is the kind of thing nobody sees in a terminal). Stricter than the schema is safe; a
// name the schema refuses is not, so the test asserts the implication and not the equality.
func Valid(u string) bool {
	if n := utf8.RuneCountInString(u); n < 1 || n > LimitRunes || !utf8.ValidString(u) {
		return false
	}
	if !pattern.MatchString(u) {
		return false
	}
	for _, r := range u {
		if unicode.IsSpace(r) || unicode.Is(unicode.Z, r) {
			return false
		}
	}
	return true
}
