package caps

import (
	"regexp"
	"strings"
)

// Shared is the one expression every cap is compared with (migration 0023):
//
//	ctrlz.cap_reached(spent, cap)  =  cap IS NOT NULL AND (cap = 'NaN' OR COALESCE(spent, 0) >= cap)
//
// A NULL cap is no cap, a missing counter is 0, and a cap of 0 is reached before the
// first spend. A NaN cap is reached too (migration 0044: nothing can be compared with it,
// and failing open would leave the money cap silently off). The Go statements of the store
// and the plpgsql of the OTP issue both call it, and UnsharedCompare is how the lint and the
// catalog check prove that nothing compares a cap another way.
const Shared = "ctrlz.cap_reached("

// compare finds an ordering operator next to a name that holds a cap. Only orderings: a
// cap is reached when spent >= cap, and "x = $1" next to a cap column is an assignment.
var compare = regexp.MustCompile(`(?i)(<=|>=|<|>)\s*(\(\s*SELECT\s+)?[\w.\[\]()]*(_cap|\bcap\b)|(\w*_cap\w*|\bcap\b)(\[[^\]]*\])?(::\w+)?(\s*[*+/-]\s*[\w.]+(::\w+)?)*\s*(<=|>=|<|>)|\(\s*SELECT\s+[\w.]*_cap\w*\s+FROM[^()]*\)\s*(<=|>=|<|>)`)

// UnsharedCompare returns the first comparison of a *_cap* value in a SQL text that is
// not an argument of ctrlz.cap_reached, or "" when there is none. A text that names no
// cap is clean. Assignments (:=) are not comparisons.
func UnsharedCompare(sql string) string {
	if !strings.Contains(strings.ToLower(sql), "cap") {
		return ""
	}
	s := strings.ReplaceAll(stripShared(sql), ":=", " ASSIGN ")
	return compare.FindString(s)
}

// stripShared cuts every call of ctrlz.cap_reached(...), with its balanced
// arguments, out of a SQL text.
func stripShared(src string) string {
	for {
		i := strings.Index(src, Shared)
		if i < 0 {
			return src
		}
		depth, j := 1, i+len(Shared)
		for j < len(src) && depth > 0 {
			switch src[j] {
			case '(':
				depth++
			case ')':
				depth--
			}
			j++
		}
		src = src[:i] + " TRUE " + src[j:]
	}
}
