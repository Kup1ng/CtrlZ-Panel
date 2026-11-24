package httpx

import (
	"bytes"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// The request check (openapi3filter) decodes the whole JSON body into a tree before it looks at maxItems or at an
// unknown member, and the tree of a body of small values holds about twenty times its bytes: a 6 MiB body of {} keeps 129
// MiB live (p2-B3-r6-4). The schema of a route says how many values a
// legal body has at most, so the count of the values of the raw bytes is compared with that before any tree is built. The
// count is a scan of the bytes that allocates nothing.

// unbounded is the budget of a schema that does not bound the number of values in it.
const unbounded = -1

// valueBudget is the most values (every key, string, number, literal, object and array counts one) a document that
// satisfies s can have, or unbounded. A union (allOf, oneOf, anyOf) adds its branches, which is an upper bound.
func valueBudget(s *openapi3.Schema, depth int) int64 {
	if s == nil || depth > 24 {
		return unbounded
	}
	total := int64(1)
	add := func(n int64) bool {
		if n < 0 || total > 1<<40 {
			return false
		}
		total += n
		return true
	}
	scalar := s.Type != nil && !s.Type.IsEmpty() && !s.Type.Permits("object") && !s.Type.Permits("array")
	if scalar {
		return 1
	}
	if s.Type == nil || s.Type.IsEmpty() {
		// No type and nothing that says what is inside: any value.
		if len(s.Properties) == 0 && s.Items == nil && len(s.AllOf)+len(s.OneOf)+len(s.AnyOf) == 0 {
			return unbounded
		}
	}
	if s.Type == nil || s.Type.Permits("object") {
		for _, p := range s.Properties {
			var b int64 = unbounded
			if p != nil {
				b = valueBudget(p.Value, depth+1)
			}
			if !add(1) || !add(b) { // the key, then the value
				return unbounded
			}
		}
		if ap := s.AdditionalProperties; ap.Has == nil || *ap.Has || ap.Schema != nil || len(s.PatternProperties) > 0 {
			// A map. Its keys are bounded by maxProperties, or by nothing.
			if s.MaxProps == nil {
				return unbounded
			}
			var b int64 = 1
			switch {
			case ap.Schema != nil:
				b = valueBudget(ap.Schema.Value, depth+1)
			case len(s.PatternProperties) > 0:
				for _, p := range s.PatternProperties {
					if pb := valueBudget(p.Value, depth+1); pb < 0 {
						return unbounded
					} else if pb > b {
						b = pb
					}
				}
			default:
				return unbounded // additional members of any kind
			}
			if b < 0 || int64(*s.MaxProps) > 1<<30 {
				return unbounded
			}
			if !add(int64(*s.MaxProps) * (1 + b)) {
				return unbounded
			}
		}
	}
	if s.Type == nil || s.Type.Permits("array") {
		if s.Items != nil || s.Type != nil {
			if s.MaxItems == nil || s.Items == nil || *s.MaxItems > 1<<30 {
				return unbounded
			}
			b := valueBudget(s.Items.Value, depth+1)
			if b < 0 || !add(int64(*s.MaxItems)*b) {
				return unbounded
			}
		}
	}
	for _, list := range [][]*openapi3.SchemaRef{s.AllOf, s.OneOf, s.AnyOf} {
		for _, c := range list {
			if c == nil || !add(valueBudget(c.Value, depth+1)) {
				return unbounded
			}
		}
	}
	return total
}

// bodyBudget is the budget of the JSON body of an operation, or unbounded when it has none or does not bound it.
func bodyBudget(op *openapi3.Operation) int64 {
	if op == nil || op.RequestBody == nil || op.RequestBody.Value == nil {
		return unbounded
	}
	var most int64
	for ct, mt := range op.RequestBody.Value.Content {
		if !isJSONType(ct) || mt == nil || mt.Schema == nil {
			continue
		}
		b := valueBudget(mt.Schema.Value, 0)
		if b < 0 {
			return unbounded
		}
		if b > most {
			most = b
		}
	}
	if most == 0 {
		return unbounded
	}
	return most
}

func isJSONType(ct string) bool {
	mt, _, _ := strings.Cut(ct, ";")
	mt = strings.ToLower(strings.TrimSpace(mt))
	return mt == "application/json" || strings.HasSuffix(mt, "+json")
}

// shape is what scanShape holds a JSON text to, before any tree is built of it (docs/specs/p2-profiles.md 6.5 property 6).
// A zero depth, members or digits is no limit.
type shape struct {
	// values is the most values the text has (every key, string, number, literal, object and array counts one); negative is
	// no limit.
	values int64
	// depth is the deepest nesting of objects and arrays.
	depth int
	// members is the most members of one object.
	members int
	// digits makes every number an integer of at most that many digits, with no sign but a leading minus, no fraction and no
	// exponent: the schema engine makes a big.Rat of every number it looks at, so one literal of a million digits, or 1e-999999,
	// costs seconds or megabytes.
	digits int
}

// heavyShape is the shape of the request body of a heavy operation: nesting 8, 32 members in one object, integers of at
// most 10 digits. The number of values is the operation's own. A function and not a variable: nothing may change it.
func heavyShape() shape { return shape{values: -1, depth: 8, members: 32, digits: 10} }

const maxScanStack = 64

// scanShape reads the bytes of a JSON text once, allocates nothing, and says whether it is within s. It does not check
// the syntax (the decoder does, and says 400); it refuses at the first cap passed, and no text within the caps is refused.
func scanShape(raw []byte, s shape) bool {
	track := s.depth > 0 || s.members > 0
	if track && (s.depth <= 0 || s.depth >= maxScanStack) {
		s.depth = maxScanStack - 1
	}
	type frame struct {
		obj, key bool
		members  int
	}
	var stack [maxScanStack]frame
	sp := 0
	var n int64
	count := func() bool {
		n++
		return s.values < 0 || n <= s.values
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch c {
		case '"':
			if !count() {
				return false
			}
			if track && sp > 0 && stack[sp-1].obj && stack[sp-1].key {
				top := &stack[sp-1]
				top.key = false
				if top.members++; s.members > 0 && top.members > s.members {
					return false
				}
			}
			// Skip to the closing quote: a quote that is escaped has an odd number of backslashes before it.
			for {
				j := bytes.IndexByte(raw[i+1:], '"')
				if j < 0 {
					return true // unterminated: the decoder refuses it
				}
				i += 1 + j
				k := 0
				for p := i - 1; p >= 0 && raw[p] == '\\'; p-- {
					k++
				}
				if k%2 == 0 {
					break
				}
			}
		case '{', '[':
			if !count() {
				return false
			}
			if track {
				if sp >= s.depth {
					return false
				}
				stack[sp] = frame{obj: c == '{', key: c == '{'}
				sp++
			}
		case '}', ']':
			if track && sp > 0 {
				sp--
			}
		case ',':
			if track && sp > 0 && stack[sp-1].obj {
				stack[sp-1].key = true
			}
		case ':', ' ', '\t', '\n', '\r':
		default:
			// A literal: a number, true, false or null. It runs to the next delimiter.
			start := i
			for i+1 < len(raw) && !isDelim(raw[i+1]) {
				i++
			}
			if !count() {
				return false
			}
			if s.digits > 0 && (c == '-' || c >= '0' && c <= '9') && !isSmallInt(raw[start:i+1], s.digits) {
				return false
			}
		}
	}
	return true
}

func isDelim(c byte) bool {
	switch c {
	case ',', '}', ']', '{', '[', ':', ' ', '\t', '\n', '\r', '"':
		return true
	}
	return false
}

// isSmallInt says whether lit is an optional minus and one to max digits and nothing else.
func isSmallInt(lit []byte, max int) bool {
	if len(lit) > 0 && lit[0] == '-' {
		lit = lit[1:]
	}
	if len(lit) == 0 || len(lit) > max {
		return false
	}
	for _, c := range lit {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// withinValues counts the values of a JSON text and says whether there are no more than max. It does not check the
// syntax (the decoder does, and says 400); it is enough that a text with more values than max is refused before it is
// decoded, and that no text with at most max values is.
func withinValues(raw []byte, max int64) bool { return scanShape(raw, shape{values: max}) }
