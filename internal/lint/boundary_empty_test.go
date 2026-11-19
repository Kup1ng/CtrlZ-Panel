package lint_test

import (
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/digits"
)

// TestEmptyLintCanFail checks the empty and blank half of the boundary lint (round 5,
// admin-r5-1): a request string that accepts "" or "   " fails, one that refuses both
// passes, a field named in mayBeEmpty is let through, and a response string (which no
// client sends) is not judged.
func TestEmptyLintCanFail(t *testing.T) {
	doc := func(prop string) []byte {
		return []byte("openapi: 3.1.0\ninfo: {title: t, version: '1'}\ncomponents:\n  schemas:\n    Body:\n      type: object\n      additionalProperties: false\n      properties:\n        " + prop + "\npaths:\n  /x:\n    post:\n      requestBody:\n        content:\n          application/json:\n            schema: {$ref: '#/components/schemas/Body'}\n      responses:\n        '200': {description: ok}\n")
	}
	const text = `'^[^\p{C}]*$'`
	const content = `'^[^\p{C}\p{Z}][^\p{C}]*$'`
	cases := map[string]struct {
		prop string
		want string
	}{
		"empty accepted":       {`username: {type: string, maxLength: 8, pattern: ` + text + `}`, `accepts ""`},
		"blank accepted":       {`username: {type: string, minLength: 1, maxLength: 8, pattern: ` + text + `}`, `accepts "   "`},
		"enum is a closed set": {`username: {type: string, maxLength: 8, enum: [a]}`, ""},
		"content refuses both": {`username: {type: string, maxLength: 8, pattern: ` + content + `}`, ""},
		"named exception":      {`password: {type: string, maxLength: 8, pattern: ` + text + `}`, ""},
		"nested in an array":   {`names: {type: array, maxItems: 2, items: {type: string, maxLength: 8, pattern: ` + text + `}}`, `accepts ""`},
		// Round 14 (primitives-r14-3): a typed code or a phone on the strict pattern makes the
		// fold of internal/auth/digits dead code for the marks it drops, so it fails; the pasted
		// patterns pass for those fields; the same pattern on a field that is not a code is judged
		// by the control and format probes and fails.
		"code on the strict pattern":   {`totp_code: {type: string, maxLength: 8, pattern: ` + text + `}`, `must use the pasted`},
		"phone on the strict pattern":  {`phone: {type: string, maxLength: 8, pattern: ` + content + `}`, `must use the pasted`},
		"code on a pattern of its own": {`code: {type: string, minLength: 1, maxLength: 8, pattern: '^[0-9]+$'}`, `must use the pasted`},
		"code on the pasted pattern":   {`totp_code: {type: string, maxLength: 8, pattern: '` + digits.PastePattern + `'}`, ""},
		"phone on pastedcontent":       {`phone: {type: string, maxLength: 8, pattern: '` + digits.PasteContentPattern + `'}`, ""},
		"pasted on a username":         {`username: {type: string, maxLength: 8, pattern: '` + digits.PastePattern + `'}`, `accepts U+`},
	}
	for name, c := range cases {
		found, err := checkBounds(doc(c.prop))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		switch {
		case c.want == "" && len(found) != 0:
			t.Errorf("%s: unexpected findings %v", name, found)
		case c.want != "" && !strings.Contains(strings.Join(found, "\n"), c.want):
			t.Errorf("%s: findings %v, want one containing %q", name, found, c.want)
		}
	}
	// A component that no request reaches is not a request string.
	resp := []byte("openapi: 3.1.0\ninfo: {title: t, version: '1'}\ncomponents:\n  schemas:\n    R:\n      type: object\n      properties:\n        a: {type: string, maxLength: 8, pattern: " + text + "}\npaths: {}\n")
	if found, err := checkBounds(resp); err != nil || len(found) != 0 {
		t.Errorf("a response-only string was judged: %v %v", found, err)
	}
}
