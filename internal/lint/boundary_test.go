package lint_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/digits"
)

// Rule boundary-input (P1 auth review round 5, rules.md topic 9, spec 14.2 and
// 18.5). Every value a client sends is bounded where it enters, and "where it
// enters" is the OpenAPI document: the pipeline validates each request against
// it before any handler runs (httpx.Validator), so a field the document does
// not bound is a field nothing bounds. Bounds used to be added one field at a
// time after a 500 or a bloated row (a cursor time, a NUL in a name, passkey
// transports, a padded param name), and nothing made the next field carry one.
//
// This lint is the other half of the rule: it fails for any schema, in either
// document, that is not bounded, so a field added next year is covered the day it
// is added. The fuzz in internal/authtest/boundary (run by the api and adminapi
// tests) is the check that the validator really refuses what the document says.
//
// What "bounded" means here:
//
//   - a string has maxLength and an enum, a const or a pattern that matches none of
//     the control, format and private-use characters. A format alone is not enough:
//     the library treats format as an annotation on a 3.1 document and checks
//     nothing, so a uuid or a date-time carries a pattern as well;
//   - an integer or number has minimum and maximum;
//   - an array has maxItems and items;
//   - an object with no declared properties (a map) has maxProperties and its keys
//     and values declared: patternProperties with additionalProperties false, each
//     key pattern one that rejects control and format characters and a long key,
//     because every key of a map is a string the client chose (the library does not
//     enforce propertyNames, so a map that relies on it has unbounded keys);
//   - a schema has a type, so nothing is "any value".
//
// The pattern is judged by what it accepts, not by how it is written: it must
// reject a string holding any probe character below. A pattern like [a-z]+ with no
// anchors would match "a<NUL>a" and fails here.

// boundaryProbes are the characters a bounded text may not contain: C0 and C1
// controls, the format characters people use to hide or reorder text (zero width
// space, joiners, bidi marks and overrides, the byte order mark, the soft hyphen,
// the tag block) and a private-use code point. Category Cs cannot be written in a
// Go string and invalid UTF-8 is refused before the schema is consulted.
var boundaryProbes = []rune{
	0x00, 0x07, 0x09, 0x0a, 0x0d, 0x1b, 0x1f, 0x7f, 0x80, 0x85, 0x9f,
	0xad, 0x061c, 0x180e,
	0x200b, 0x200c, 0x200d, 0x200e, 0x200f,
	0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
	0x2060, 0x2066, 0x2067, 0x2068, 0x2069,
	0xfeff, 0xfff9, 0xe0001, 0xe0020, 0xe000,
}

// zwnj is the zero width non-joiner. Persian needs it inside words, and the SMS
// template text an operator edits is Persian prose, so a field that carries prose
// may accept it and nothing else of the format characters. The fields are the ones
// named "body" (an SMS template, an announcement) and the half-space fields below; every
// other text field refuses it.
const zwnj rune = 0x200c

// proseField says whether a field carries Persian prose, which keeps the zero width non-joiner (U+200C): the SMS template and
// announcement bodies, and (P2 spec 12) the profile name, the folder name, the rule comment and the lock message of the
// profile routes and schemas. A name or a comment elsewhere (a passkey name) still refuses it.
func proseField(at string) bool {
	if strings.HasSuffix(at, ".body") {
		return true
	}
	switch fieldName(at) {
	case "name", "name_fa", "comment", "message", "lock_message", "alias", "group_name", "names[]":
		return p2Location(at)
	}
	return false
}

// p2Schemas are the components of the profile routes whose names, comments and messages are prose.
func p2Schemas() map[string]bool {
	return map[string]bool{"CatalogFilter": true, "CatalogService": true, "CatalogServiceList": true, "Category": true, "DocFolder": true, "DocRule": true, "RulesDocument": true, "RulesDocumentRule": true,
		"EndpointRef": true, "Folder": true, "FolderCreate": true, "FolderPatch": true, "NewFolder": true, "Profile": true, "ProfileCreate": true,
		"ProfileDocument": true, "ProfileDuplicate": true, "ProfileLock": true, "ProfileRename": true, "Rule": true, "RuleEditSet": true,
		"RulePatch": true, "RulesCreate": true, "ProfileList": true, "ProfileCreated": true, "RulePage": true, "RuleList": true, "FolderList": true, "Job": true,
		// The Endpoint routes (P3 spec 3.8): the ZWNJ exception extends to an Endpoint, a group, a client alias and its group name, and a comment.
		"Endpoint": true, "EndpointCreate": true, "EndpointCreated": true, "EndpointPage": true, "EndpointPatch": true, "EndpointType": true, "EndpointTypeList": true,
		"Group": true, "GroupList": true, "GroupCreate": true, "GroupRename": true, "Client": true, "ClientPage": true, "ClientCreate": true, "ClientPatch": true,
		"ClientBatch": true, "ClientBatchSet": true}
}

// p2Location says the path of the schema (at) is below an operation of /profiles or one of the components above.
func p2Location(at string) bool {
	if strings.Contains(at, " /profiles") || strings.Contains(at, " /endpoints") || strings.Contains(at, " /endpoint-groups") {
		return true
	}
	if rest, ok := strings.CutPrefix(at, "components.schemas."); ok {
		name, _, _ := strings.Cut(rest, ".")
		return p2Schemas()[name]
	}
	return false
}

// halfSpaceFieldNames are the request fields a person types on a Persian keyboard that types U+200C
// inside words and that the server drops it from (round 18, primitives-r18-3, D64 zwnj-fields): a password
// (password.Normalize, the one function every hash and every check goes through) and the name of a
// passkey (RenamePasskey). They take the `prose` pattern, which lets only U+200C through of the format
// characters, and the lint holds both directions: a field of this set on a pattern that refuses the
// half-space fails (a Persian user would be sent into a loop of refusals for a key they did not know they
// pressed), and the half-space is exempt from the probes only for a field of this set.
var halfSpaceFieldNames = map[string]bool{"password": true, "new_password": true, "current_password": true}

// halfSpaceField says whether the schema at "at" is one of those fields. The passkey name is told apart
// from the other fields called name by the schema that holds it.
func halfSpaceField(at string) bool {
	return halfSpaceFieldNames[fieldName(at)] || (fieldName(at) == "name" && strings.Contains(at, "RenamePasskeyRequest"))
}

// codeFields is the floor of the request strings the server folds with the paste fold of
// internal/auth/digits (digits.Typed for a code, the phone parser for a number), by the last name of
// the path to them. The set is derived from the code (foldfields_test.go: every generated request
// field that reaches a fold) and codeField asks the union, so a new folded field is held without
// anyone remembering to list it (round 15, primitives-r15-1: the Users filter was missed by the
// hand-kept list). The floor stays for what the derivation cannot see, such as a call through an
// interface, and TestFoldDerivationSeesTheKnownFolds fails when the derivation stops finding it.
// Such a field takes the `pasted` pattern (the `text` rule plus the paste marks,
// digits.PastePattern) and no other: the fold drops a mark a paste carries, and a schema that refuses
// the mark first made the fold dead code for the marks it was written for (round 14,
// primitives-r14-3). The lint holds both directions: a field of the set on another pattern fails, and
// the pattern is exempt from the control and format probes only for a field of the set.
var codeFields = map[string]bool{
	"code": true, "totp_code": true, "recovery_code": true, "otp_code": true, "old_code": true, "new_code": true,
	"phone": true, "new_phone": true, "invite_token": true, "token": true,
}

func fieldName(at string) string {
	name := at[strings.LastIndexAny(at, ".(")+1:]
	return strings.TrimSuffix(name, ")")
}

func codeField(at string) bool {
	name := fieldName(at)
	if codeFields[name] {
		return true
	}
	derived, err := derivedFoldNames()
	if err != nil {
		panic("deriving the folded request fields: " + err.Error())
	}
	return derived[name]
}

// pastePattern reports one of the two patterns the digits package owns.
func pastePattern(p string) bool {
	return p == digits.PastePattern || p == digits.PasteContentPattern
}

// pasteField is the exemption: a field of the list on one of the two patterns.
func pasteField(at, pattern string) bool { return codeField(at) && pastePattern(pattern) }

// checkBounds returns one finding per unbounded schema of the document.
func checkBounds(raw []byte) ([]string, error) {
	out, _, err := checkBoundsUsed(raw)
	return out, err
}

// checkBoundsUsed is checkBounds that also returns the emptyGrandfathered entries it met.
func checkBoundsUsed(raw []byte) ([]string, map[string]bool, error) {
	doc, err := openapi3.NewLoader().LoadFromData(raw)
	if err != nil {
		return nil, nil, err
	}
	c := &boundsCheck{seen: map[*openapi3.Schema]bool{}}

	// Named schemas first, so a finding names the component and not the first
	// place that happened to reach it.
	if doc.Components != nil {
		for _, name := range sortedKeys(doc.Components.Schemas) {
			c.schema("components.schemas."+name, doc.Components.Schemas[name])
		}
		for _, name := range sortedKeys(doc.Components.Parameters) {
			c.param("components.parameters."+name, doc.Components.Parameters[name])
		}
		for _, name := range sortedKeys(doc.Components.RequestBodies) {
			c.body("components.requestBodies."+name, doc.Components.RequestBodies[name])
		}
		for _, name := range sortedKeys(doc.Components.Responses) {
			c.response("components.responses."+name, doc.Components.Responses[name])
		}
	}
	for _, p := range sortedKeys(doc.Paths.Map()) {
		item := doc.Paths.Value(p)
		for i, pr := range item.Parameters {
			c.param(fmt.Sprintf("%s.parameters[%d]", p, i), pr)
		}
		for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
			op := item.GetOperation(m)
			if op == nil {
				continue
			}
			at := m + " " + p
			for i, pr := range op.Parameters {
				c.param(fmt.Sprintf("%s.parameters[%d]", at, i), pr)
			}
			c.body(at+".requestBody", op.RequestBody)
			for _, code := range sortedKeys(op.Responses.Map()) {
				c.response(at+".responses."+code, op.Responses.Value(code))
			}
		}
	}
	// The second half of the rule, for request bodies only: every object is closed. A
	// schema that declares properties and says nothing about the rest does not reject
	// "NAME" beside "name", the library then checks nothing about "NAME", and
	// encoding/json binds that key to the field `name` without regard to case (and lets
	// the later key win), so a value the schema never saw reaches the handler (round 5,
	// tenant-r5-7). additionalProperties: false turns the case variant into a 400.
	closed := &closedCheck{seen: map[*openapi3.Schema]bool{}, add: c.add}
	for _, p := range sortedKeys(doc.Paths.Map()) {
		item := doc.Paths.Value(p)
		for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
			if op := item.GetOperation(m); op != nil && op.RequestBody != nil && op.RequestBody.Value != nil {
				for _, mt := range sortedKeys(op.RequestBody.Value.Content) {
					closed.schema(m+" "+p+".requestBody."+mt, op.RequestBody.Value.Content[mt].Schema)
				}
			}
		}
	}
	// The third half, for requests only: a string a client sends does not accept the empty
	// or the blank value unless the field is on the reviewed list (round 5, admin-r5-1).
	empty := &emptyCheck{seen: map[*openapi3.Schema]bool{}, add: c.add, used: map[string]bool{}}
	for _, p := range sortedKeys(doc.Paths.Map()) {
		item := doc.Paths.Value(p)
		for i, pr := range item.Parameters {
			if pr != nil && pr.Value != nil {
				empty.schema(fmt.Sprintf("%s.parameters[%d](%s)", p, i, pr.Value.Name), pr.Value.Schema)
			}
		}
		for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
			op := item.GetOperation(m)
			if op == nil {
				continue
			}
			for i, pr := range op.Parameters {
				if pr != nil && pr.Value != nil {
					empty.schema(fmt.Sprintf("%s %s.parameters[%d](%s)", m, p, i, pr.Value.Name), pr.Value.Schema)
				}
			}
			if op.RequestBody != nil && op.RequestBody.Value != nil {
				for _, mt := range sortedKeys(op.RequestBody.Value.Content) {
					empty.schema(m+" "+p+".requestBody."+mt, op.RequestBody.Value.Content[mt].Schema)
				}
			}
		}
	}
	sort.Strings(c.out)
	return c.out, empty.used, nil
}

// emptyGrandfathered is the tenant document's strings that still accept the empty or the
// blank value, by location. Each one is answered with a 4xx by its handler (the tenant fuzz
// sends "" and "   " to every one and requires no 5xx), but none was bounded in the
// declared here so it can only shrink. An entry that no longer matches fails
// TestOpenAPIBoundsEveryInput, so the day a field is bounded its entry has to go.
var emptyGrandfathered = map[string]bool{}

// emptyCheck walks what a request can carry and asks every string that is not an enum or a
// constant to refuse the empty string and the blank one. Round 5 found a login that
// answered 500 for a username of "   ": the schema bounded the length from above and the
// alphabet, and nothing said a value must be there at all, so an identifier that the
// handler trims reached a keyed step as the empty key. The fuzz sends the same two values
// to every string the document lets through (internal/authtest/boundary, "empty" and
// "blank"); this is the document half, so a new identifier is covered the day it is added.
type emptyCheck struct {
	seen map[*openapi3.Schema]bool
	add  func(at, format string, args ...any)
	used map[string]bool
}

// mayBeEmpty names the request strings that are allowed to be empty or blank, by the last
// name of the path to them, each with the reason. Everything else is an identifier, a name
// or a value the server keys on or stores.
var mayBeEmpty = map[string]string{
	"password":           "a password is any text; an empty or blank one is a wrong password and answers like one",
	"totp_code":          "an empty code is a wrong code (the login treats a missing code as one)",
	"current_password":   "a password is any text; an empty one is a wrong password and answers like one",
	"new_password":       "any text reaches the strength gate, whose length rules refuse an empty or blank one with 422 before anything is stored",
	"q":                  "an empty search is the unfiltered list",
	"userHandle":         "an authenticator that holds no user handle sends it empty, which is the same as absent (the field is nullable); a login with none is a discoverable one and the handle is not a key anything is looked up by (tenant-r18-3)",
	"publicKey":          "the public key a registration carries is nullable, and an empty value is the same as absent: the library reads the key from the attestation (tenant-r18-3)",
	"cost_per_message":   "an empty string clears the price (documented on the field)",
	"sms_cost_cap_daily": "an empty string means no money cap (documented on the field)",
}

func (c *emptyCheck) schema(at string, ref *openapi3.SchemaRef) {
	if ref == nil || ref.Value == nil || c.seen[ref.Value] {
		return
	}
	s := ref.Value
	c.seen[s] = true
	if slices.Contains(s.Type.Slice(), "string") && len(s.Enum) == 0 && s.Const == nil {
		if codeField(at) && !pastePattern(s.Pattern) {
			c.add(at, "a typed code or phone number must use the pasted or pastedcontent pattern (digits.PastePattern, digits.PasteContentPattern): the fold of internal/auth/digits and the phone parser drop the marks of a paste, and a schema that refuses them first makes the fold dead code (round 14, primitives-r14-3)")
		}
		for _, v := range []string{"", "   "} {
			if s.MinLength > 0 && v == "" {
				continue
			}
			if s.Pattern != "" {
				if re, err := regexp.Compile(s.Pattern); err == nil && !re.MatchString(v) {
					continue
				}
			}
			if emptyGrandfathered[at] {
				c.used[at] = true
				break
			}
			name := at[strings.LastIndexAny(at, ".(")+1:]
			name = strings.TrimSuffix(name, ")")
			if _, ok := mayBeEmpty[name]; ok {
				break
			}
			c.add(at, "string accepts %q: add minLength and a pattern whose first character is not blank, or name the field in mayBeEmpty with its reason", v)
			break
		}
	}
	if s.Items != nil {
		c.schema(at+"[]", s.Items)
	}
	for _, name := range sortedKeys(s.Properties) {
		c.schema(at+"."+name, s.Properties[name])
	}
	if s.AdditionalProperties.Schema != nil {
		c.schema(at+".{*}", s.AdditionalProperties.Schema)
	}
	for _, pat := range sortedKeys(s.PatternProperties) {
		c.schema(at+".{"+pat+"}", s.PatternProperties[pat])
	}
	for i, sub := range s.AllOf {
		c.schema(fmt.Sprintf("%s.allOf[%d]", at, i), sub)
	}
	for i, sub := range s.OneOf {
		c.schema(fmt.Sprintf("%s.oneOf[%d]", at, i), sub)
	}
	for i, sub := range s.AnyOf {
		c.schema(fmt.Sprintf("%s.anyOf[%d]", at, i), sub)
	}
}

// closedCheck walks what a request body can contain and asks every object that
// declares properties for additionalProperties: false. A map (no declared property)
// is judged by boundsCheck.object, which already needs its keys declared.
type closedCheck struct {
	seen map[*openapi3.Schema]bool
	add  func(at, format string, args ...any)
}

func (c *closedCheck) schema(at string, ref *openapi3.SchemaRef) {
	if ref == nil || ref.Value == nil || c.seen[ref.Value] {
		return
	}
	s := ref.Value
	c.seen[s] = true
	isObject := slices.Contains(s.Type.Slice(), "object") || len(s.Properties) > 0
	open := s.AdditionalProperties.Has == nil || *s.AdditionalProperties.Has
	if isObject && len(s.Properties) > 0 && (open || s.AdditionalProperties.Schema != nil) {
		c.add(at, "request object without additionalProperties: false: a key in another letter case is not seen by the schema and is bound by encoding/json to the declared field")
	}
	if s.Items != nil {
		c.schema(at+"[]", s.Items)
	}
	for _, name := range sortedKeys(s.Properties) {
		c.schema(at+"."+name, s.Properties[name])
	}
	if s.AdditionalProperties.Schema != nil {
		c.schema(at+".{*}", s.AdditionalProperties.Schema)
	}
	for _, pat := range sortedKeys(s.PatternProperties) {
		c.schema(at+".{"+pat+"}", s.PatternProperties[pat])
	}
	for i, sub := range s.AllOf {
		c.schema(fmt.Sprintf("%s.allOf[%d]", at, i), sub)
	}
	for i, sub := range s.OneOf {
		c.schema(fmt.Sprintf("%s.oneOf[%d]", at, i), sub)
	}
	for i, sub := range s.AnyOf {
		c.schema(fmt.Sprintf("%s.anyOf[%d]", at, i), sub)
	}
}

type boundsCheck struct {
	seen map[*openapi3.Schema]bool
	out  []string
}

func (c *boundsCheck) add(at, format string, args ...any) {
	c.out = append(c.out, at+": "+fmt.Sprintf(format, args...))
}

func (c *boundsCheck) param(at string, p *openapi3.ParameterRef) {
	if p == nil || p.Value == nil {
		return
	}
	c.schema(at+"("+p.Value.Name+")", p.Value.Schema)
}

func (c *boundsCheck) body(at string, b *openapi3.RequestBodyRef) {
	if b == nil || b.Value == nil {
		return
	}
	for _, mt := range sortedKeys(b.Value.Content) {
		c.schema(at+"."+mt, b.Value.Content[mt].Schema)
	}
}

func (c *boundsCheck) response(at string, r *openapi3.ResponseRef) {
	if r == nil || r.Value == nil {
		return
	}
	for _, name := range sortedKeys(r.Value.Headers) {
		if h := r.Value.Headers[name]; h != nil && h.Value != nil {
			c.schema(at+".headers."+name, h.Value.Schema)
		}
	}
	for _, mt := range sortedKeys(r.Value.Content) {
		c.schema(at+"."+mt, r.Value.Content[mt].Schema)
	}
}

func (c *boundsCheck) schema(at string, ref *openapi3.SchemaRef) {
	if ref == nil || ref.Value == nil {
		c.add(at, "no schema")
		return
	}
	s := ref.Value
	if c.seen[s] {
		return
	}
	c.seen[s] = true

	types := s.Type.Slice()
	if len(types) == 0 && len(s.AllOf)+len(s.OneOf)+len(s.AnyOf) == 0 && s.Const == nil {
		c.add(at, "no type: the schema accepts any value")
	}
	for _, t := range types {
		switch t {
		case "string":
			c.str(at, s)
		case "integer", "number":
			if s.Min == nil || s.Max == nil {
				c.add(at, "%s without minimum and maximum", t)
			}
		case "array":
			if s.MaxItems == nil {
				c.add(at, "array without maxItems")
			}
			if s.Items == nil {
				c.add(at, "array without items")
			}
		case "object":
			c.object(at, s)
		case "boolean", "null":
		default:
			c.add(at, "unknown type %q", t)
		}
	}

	if s.Items != nil {
		c.schema(at+"[]", s.Items)
	}
	for _, name := range sortedKeys(s.Properties) {
		c.schema(at+"."+name, s.Properties[name])
	}
	if s.AdditionalProperties.Schema != nil {
		c.schema(at+".{*}", s.AdditionalProperties.Schema)
	}
	for _, pat := range sortedKeys(s.PatternProperties) {
		c.schema(at+".{"+pat+"}", s.PatternProperties[pat])
	}
	for i, sub := range s.AllOf {
		c.schema(fmt.Sprintf("%s.allOf[%d]", at, i), sub)
	}
	for i, sub := range s.OneOf {
		c.schema(fmt.Sprintf("%s.oneOf[%d]", at, i), sub)
	}
	for i, sub := range s.AnyOf {
		c.schema(fmt.Sprintf("%s.anyOf[%d]", at, i), sub)
	}
}

func (c *boundsCheck) str(at string, s *openapi3.Schema) {
	if s.MaxLength == nil {
		c.add(at, "string without maxLength")
	}
	switch {
	case len(s.Enum) > 0:
		for _, v := range s.Enum {
			if str, ok := v.(string); ok && hasProbe(str) {
				c.add(at, "enum value %q holds a control or format character", str)
			}
		}
	case s.Const != nil:
	case s.Pattern != "":
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			c.add(at, "pattern does not compile: %v", err)
			return
		}
		if halfSpaceField(at) && !re.MatchString("a"+string(zwnj)+"a") {
			c.add(at, "pattern %q refuses U+200C, which the server drops from this field: a person on a Persian keyboard is refused for a key they did not know they pressed (round 18, primitives-r18-3)", s.Pattern)
		}
		for _, p := range boundaryProbes {
			if p == zwnj && (proseField(at) || halfSpaceField(at)) {
				continue
			}
			if pasteField(at, s.Pattern) && digits.PasteMark(p) {
				continue
			}
			for _, probe := range []string{"a" + string(p) + "a", "1" + string(p) + "1", string(p)} {
				if re.MatchString(probe) {
					c.add(at, "pattern %q accepts U+%04X (a control, format or private-use character)", s.Pattern, p)
					return
				}
			}
		}
	default:
		c.add(at, "string with no enum, const or pattern (a format is not checked)")
	}
}

func (c *boundsCheck) object(at string, s *openapi3.Schema) {
	if len(s.Properties) > 0 {
		return
	}
	closed := s.AdditionalProperties.Has != nil && !*s.AdditionalProperties.Has && s.AdditionalProperties.Schema == nil
	if closed && len(s.PatternProperties) == 0 {
		return // an object that must be empty
	}
	// No declared properties: a map. Its keys are client strings too, and the only
	// way the validator bounds them is patternProperties with additionalProperties
	// false (the library does not enforce propertyNames, so a map that relies on it
	// is a map with unbounded keys).
	if s.MaxProps == nil {
		c.add(at, "map without maxProperties")
	}
	if len(s.PatternProperties) == 0 || !closed {
		c.add(at, "map whose keys are not bounded: use patternProperties and additionalProperties: false (propertyNames is not enforced)")
	}
	long := strings.Repeat("a", 200)
	for _, pat := range sortedKeys(s.PatternProperties) {
		re, err := regexp.Compile(pat)
		if err != nil {
			c.add(at, "key pattern does not compile: %v", err)
			continue
		}
		if re.MatchString(long) {
			c.add(at, "key pattern %q accepts a 200 character key", pat)
		}
		for _, p := range boundaryProbes {
			hit := false
			for _, probe := range []string{"a" + string(p) + "a", "k" + string(p), string(p)} {
				hit = hit || re.MatchString(probe)
			}
			if hit {
				c.add(at, "key pattern %q accepts U+%04X", pat, p)
				break
			}
		}
	}
}

func hasProbe(s string) bool {
	for _, r := range s {
		if slices.Contains(boundaryProbes, r) {
			return true
		}
	}
	return false
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestOpenAPIBoundsEveryInput is the lint over both documents.
func TestOpenAPIBoundsEveryInput(t *testing.T) {
	root := repoRoot(t)
	met := map[string]bool{}
	for _, name := range []string{"openapi.yaml", "admin-openapi.yaml"} {
		raw, err := os.ReadFile(filepath.Join(root, "api", name))
		if err != nil {
			t.Fatal(err)
		}
		found, used, err := checkBoundsUsed(raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, f := range found {
			t.Errorf("api/%s: %s", name, f)
		}
		for k := range used {
			met[k] = true
		}
	}
	for _, k := range sortedKeys(emptyGrandfathered) {
		if !met[k] {
			t.Errorf("emptyGrandfathered entry %q matches no string that accepts an empty value any more: delete it", k)
		}
	}
}

// TestBoundsLintCanFail checks the checker: each rule, applied to a small
// document, and then the real document with the bounds the review named taken
// off one at a time. A lint that never fires would pass for ever.
func TestBoundsLintCanFail(t *testing.T) {
	const head = "openapi: 3.1.0\ninfo: {title: t, version: '1'}\npaths: {}\ncomponents:\n  schemas:\n    S:\n"
	const mapHead = "      type: object\n      maxProperties: 2\n"
	cases := map[string]struct {
		schema string
		want   string // substring of the one finding; empty means clean
	}{
		"clean string":       {"      type: string\n      maxLength: 8\n      pattern: '^[a-z]+$'\n", ""},
		"clean text":         {"      type: string\n      maxLength: 8\n      pattern: '^[^\\p{C}]*$'\n", ""},
		"clean enum":         {"      type: string\n      maxLength: 4\n      enum: [aa, bb]\n", ""},
		"clean uuid":         {"      type: string\n      maxLength: 36\n      format: uuid\n      pattern: '^[0-9a-f-]{36}$'\n", ""},
		"no maxLength":       {"      type: string\n      pattern: '^[a-z]+$'\n", "without maxLength"},
		"no pattern":         {"      type: string\n      maxLength: 8\n", "no enum, const or pattern"},
		"unanchored pattern": {"      type: string\n      maxLength: 8\n      pattern: '[a-z]+'\n", "accepts U+0000"},
		"any pattern":        {"      type: string\n      maxLength: 8\n      pattern: '.*'\n", "accepts"},
		"cc only":            {"      type: string\n      maxLength: 8\n      pattern: '^[^\\p{Cc}]*$'\n", "accepts U+00AD"},
		"format alone":       {"      type: string\n      maxLength: 36\n      format: uuid\n", "a format is not checked"},
		"enum with NUL":      {"      type: string\n      maxLength: 4\n      enum: [\"a\\u0000\"]\n", "control or format"},
		"integer no max":     {"      type: integer\n      minimum: 0\n", "without minimum and maximum"},
		"number no bounds":   {"      type: number\n", "without minimum and maximum"},
		"array no maxItems":  {"      type: array\n      items: {type: boolean}\n", "without maxItems"},
		"free object":        {"      type: object\n      additionalProperties: true\n", "map without maxProperties"},
		"map with propertyNames only": {mapHead + "      additionalProperties: {type: boolean}\n" +
			"      propertyNames: {type: string, maxLength: 4, pattern: '^[a-z]+$'}\n", "keys are not bounded"},
		"map key pattern too wide": {mapHead + "      patternProperties:\n        '^[a-z]+$': {type: boolean}\n" +
			"      additionalProperties: false\n", "accepts a 200 character key"},
		"map key pattern with controls": {mapHead + "      patternProperties:\n        '^.{1,8}$': {type: boolean}\n" +
			"      additionalProperties: false\n", "accepts U+0000"},
		"clean map": {mapHead + "      patternProperties:\n        '^[a-z]{1,8}$': {type: boolean}\n" +
			"      additionalProperties: false\n", ""},
		"map value unbounded": {mapHead + "      patternProperties:\n        '^[a-z]{1,8}$': {type: string}\n" +
			"      additionalProperties: false\n", "string without maxLength"},
		"no type":             {"      description: anything\n", "no type"},
		"nested string":       {"      type: object\n      properties:\n        a: {type: string, pattern: '^a$'}\n", "S.a: string without maxLength"},
		"nullable bounded":    {"      type: object\n      properties:\n        a: {type: [string, 'null'], maxLength: 2, pattern: '^a$'}\n", ""},
		"empty object":        {"      type: object\n      additionalProperties: false\n", ""},
		"allOf member":        {"      allOf:\n        - {type: string, maxLength: 3}\n", "no enum, const or pattern"},
		"items of an array":   {"      type: array\n      maxItems: 2\n      items: {type: string}\n", "string without maxLength"},
		"query integer clean": {"      type: integer\n      minimum: 1\n      maximum: 100\n", ""},
		// Round 18 (primitives-r18-3): a password takes the half-space and no other format character.
		"a password on the prose pattern":        {"      type: object\n      properties:\n        password: {type: string, maxLength: 9, pattern: '^(?:[^\\p{C}]|\\x{200C})*$'}\n", ""},
		"a password that refuses the half-space": {"      type: object\n      properties:\n        password: {type: string, maxLength: 9, pattern: '^[^\\p{C}]*$'}\n", "refuses U+200C"},
		"a password that accepts every format":   {"      type: object\n      properties:\n        password: {type: string, maxLength: 9, pattern: '^[^\\p{Cc}]*$'}\n", "accepts U+00AD"},
		"another field on the prose pattern":     {"      type: object\n      properties:\n        title: {type: string, maxLength: 9, pattern: '^(?:[^\\p{C}]|\\x{200C})*$'}\n", "accepts U+200C"},
	}
	for name, c := range cases {
		found, err := checkBounds([]byte(head + c.schema))
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

	// The mutants of the review, applied to the real document.
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "api", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	const anchor = "    RenamePasskeyRequest:\n      type: object\n      additionalProperties: false\n      required: [name]\n      properties:\n"
	const name = "        name: {type: string, minLength: 1, maxLength: 64, pattern: *prosecontent, x-ctrlz-rowref: false}\n"
	for label, m := range map[string]struct{ new, want string }{
		"passkey name loses maxLength": {
			"        name: {type: string, minLength: 1, pattern: *content, x-ctrlz-rowref: false}\n",
			"RenamePasskeyRequest.name: string without maxLength",
		},
		"passkey name refuses the half-space": {
			"        name: {type: string, minLength: 1, maxLength: 64, pattern: *text, x-ctrlz-rowref: false}\n",
			"RenamePasskeyRequest.name: pattern",
		},
		"passkey name loses its pattern": {
			"        name: {type: string, minLength: 1, maxLength: 64, x-ctrlz-rowref: false}\n",
			"RenamePasskeyRequest.name: string with no enum, const or pattern",
		},
		"passkey name accepts anything": {
			"        name: {type: string, minLength: 1, maxLength: 64, pattern: '.*', x-ctrlz-rowref: false}\n",
			"RenamePasskeyRequest.name: pattern",
		},
	} {
		old := anchor + name
		if !strings.Contains(doc, old) {
			t.Fatalf("%s: the mutant does not apply: the text it replaces is not in api/openapi.yaml", label)
		}
		found, err := checkBounds([]byte(strings.Replace(doc, old, anchor+m.new, 1)))
		if err != nil {
			t.Errorf("%s: %v", label, err)
			continue
		}
		if !strings.Contains(strings.Join(found, "\n"), m.want) {
			t.Errorf("%s: findings %v, want one containing %q", label, found, m.want)
		}
	}
}

// The provider half of the rule: a gateway's reply is decoded only into sms.Field
// (field.go), which is bounded and in a closed alphabet. The type system does most
// of it, because sms.Result holds Fields and nothing else; this lint keeps it that
// way and stops a driver from reading a reply into a plain string it then stores,
// logs or compares.

// outgoingStructs are the structs a driver writes to the provider or reads its own
// sealed credentials into. They carry strings, and none of them is a reply.
func outgoingStructs() []string {
	return []string{"credentialsJSON", "verifyBody", "parameter"}
}

// replyStringFields returns "file:line: Field" for each JSON-tagged struct field of
// a driver, in a named type or in an anonymous one declared inside a function, that
// is a string, a []string or a json.Number, unless it sits inside one of the outgoing
// structs. A tag is what makes a struct a decoding target; the credentials and the
// config are never decoded from a reply and carry none.
func replyStringFields(fset *token.FileSet, f *ast.File) []string {
	type span struct{ from, to token.Pos }
	var allowed []span
	ast.Inspect(f, func(n ast.Node) bool {
		if ts, ok := n.(*ast.TypeSpec); ok && slices.Contains(outgoingStructs(), ts.Name.Name) {
			allowed = append(allowed, span{ts.Pos(), ts.End()})
		}
		return true
	})
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		st, ok := n.(*ast.StructType)
		if !ok || slices.ContainsFunc(allowed, func(s span) bool { return st.Pos() >= s.from && st.End() <= s.to }) {
			return true
		}
		for _, fld := range st.Fields.List {
			if fld.Tag != nil && strings.Contains(fld.Tag.Value, "json:") && isTextType(fld.Type) {
				name := "(embedded)"
				if len(fld.Names) > 0 {
					name = fld.Names[0].Name
				}
				out = append(out, fset.Position(fld.Pos()).String()+": "+name)
			}
		}
		return true
	})
	return out
}

func isTextType(e ast.Expr) bool {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name == "string"
	case *ast.ArrayType:
		return isTextType(t.Elt)
	case *ast.SelectorExpr:
		x, ok := t.X.(*ast.Ident)
		return ok && x.Name == "json" && t.Sel.Name == "Number"
	}
	return false
}

func TestProviderRepliesOnlyThroughField(t *testing.T) {
	fset, files := parseRepo(t)
	seen := 0
	for _, f := range files {
		if f.test {
			continue
		}
		switch {
		case f.path == "internal/sms/sms.go":
			// Result may hold Fields and nothing else.
			ast.Inspect(f.ast, func(n ast.Node) bool {
				ts, ok := n.(*ast.TypeSpec)
				if !ok || ts.Name.Name != "Result" {
					return true
				}
				seen++
				for _, fld := range ts.Type.(*ast.StructType).Fields.List {
					if id, ok := fld.Type.(*ast.Ident); !ok || id.Name != "Field" {
						t.Errorf("%s: sms.Result holds a value that is not an sms.Field", fset.Position(fld.Pos()))
					}
				}
				return true
			})
		case strings.HasPrefix(f.path, "internal/sms/smsir/"), strings.HasPrefix(f.path, "internal/sms/melipayamak/"):
			for _, s := range replyStringFields(fset, f.ast) {
				t.Errorf("%s: a driver struct holds provider text as a string; decode it into sms.Field (rule boundary-input)", s)
			}
		}
	}
	if seen != 1 {
		t.Fatalf("found sms.Result %d times", seen)
	}
}

func TestReplyFieldLintCanFail(t *testing.T) {
	cases := map[string]int{
		"type reply struct{ ID string `json:\"id\"` }":                  1,
		"type reply struct{ ID string }":                                0, // no tag: not a decoding target
		"type reply struct{ Cost json.Number `json:\"c\"` }":            1,
		"type reply struct{ Ids []string `json:\"i\"` }":                1,
		"type reply struct{ ID sms.Field; Status int }":                 0,
		"type verifyBody struct{ Mobile string `json:\"m\"` }":          0,
		"type reply struct{ Data json.RawMessage }":                     0,
		"type reply struct{ Inner struct{ Name string `json:\"n\"` } }": 1,
		"type credentialsJSON struct{ Key string `json:\"k\"` }":        0,
		"func f() { var d struct{ ID string `json:\"id\"` }; _ = d }":   1,
		"type Config struct{ BaseURL string }":                          0,
	}
	for body, want := range cases {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "x.go", "package x\n"+body, 0)
		if err != nil {
			t.Fatal(err)
		}
		if got := replyStringFields(fset, f); len(got) != want {
			t.Errorf("%q: %d findings %v, want %d", body, len(got), got, want)
		}
	}
}

// The wiring half of the rule: the validator only bounds what it is given, so a
// service that builds its pipeline without the document would run with no bounds at
// all. httpx.Pipeline.Build already refuses a pipeline with neither Doc nor
// SkipRequestCheck; this lint keeps SkipRequestCheck, the opt-out the tests of the
// pipeline itself use, out of every file that is not a test.

// pipelineOptOuts returns the places a non-test file names SkipRequestCheck or
// builds an httpx.Pipeline without a Doc.
func pipelineOptOuts(fset *token.FileSet, f *ast.File, path string) []string {
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.Ident:
			if x.Name == "SkipRequestCheck" && path != "internal/httpx/pipeline.go" {
				out = append(out, fset.Position(x.Pos()).String()+": SkipRequestCheck")
			}
		case *ast.CompositeLit:
			sel, ok := x.Type.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Pipeline" {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "httpx" {
				return true
			}
			hasDoc := false
			for _, e := range x.Elts {
				if kv, ok := e.(*ast.KeyValueExpr); ok {
					if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Doc" {
						hasDoc = true
					}
				}
			}
			if !hasDoc {
				out = append(out, fset.Position(x.Pos()).String()+": httpx.Pipeline without Doc")
			}
		}
		return true
	})
	return out
}

func TestPipelinesCheckTheirRequests(t *testing.T) {
	fset, files := parseRepo(t)
	built := 0
	for _, f := range files {
		if f.test {
			continue
		}
		for _, s := range pipelineOptOuts(fset, f.ast, f.path) {
			t.Errorf("%s: a service pipeline must carry its OpenAPI document and may not skip the request check (rule boundary-input)", s)
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			if cl, ok := n.(*ast.CompositeLit); ok {
				if sel, ok := cl.Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "Pipeline" {
					built++
				}
			}
			return true
		})
	}
	if built != 2 {
		t.Fatalf("found %d service pipelines, want the tenant and the admin one", built)
	}
}

func TestPipelineLintCanFail(t *testing.T) {
	cases := map[string]int{
		"var p = httpx.Pipeline{Doc: d}":                          0,
		"var p = &httpx.Pipeline{Log: l}":                         1,
		"var p = &httpx.Pipeline{Doc: d, SkipRequestCheck: true}": 1,
		"var p = other.Pipeline{Log: l}":                          0,
	}
	for src, want := range cases {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "x.go", "package x\n"+src, 0)
		if err != nil {
			t.Fatal(err)
		}
		if got := pipelineOptOuts(fset, f, "internal/api/server.go"); len(got) != want {
			t.Errorf("%q: %d findings %v, want %d", src, len(got), got, want)
		}
	}
}

// TestClosedObjectsLintCanFail plants the break of tenant-r5-7: a request object that
// declares properties and does not close the rest, at the top of a body and nested.
func TestClosedObjectsLintCanFail(t *testing.T) {
	doc := func(body string) []byte {
		return []byte("openapi: 3.1.0\ninfo: {title: t, version: '1'}\npaths:\n  /x:\n    post:\n      operationId: x\n" +
			"      requestBody:\n        content:\n          application/json:\n            schema:\n" + body +
			"      responses:\n        '204': {description: ok}\n")
	}
	const top = "              type: object\n              properties:\n                a: {type: string, maxLength: 2, pattern: '^a$'}\n"
	cases := map[string]struct {
		body string
		want string
	}{
		"closed":      {top + "              additionalProperties: false\n", ""},
		"open":        {top, "request object without additionalProperties: false"},
		"open true":   {top + "              additionalProperties: true\n", "request object without additionalProperties: false"},
		"nested open": {"              type: object\n              additionalProperties: false\n              properties:\n                n:\n                  type: object\n                  properties:\n                    a: {type: string, maxLength: 2, pattern: '^a$'}\n", ".n: request object without"},
	}
	for name, c := range cases {
		found, err := checkBounds(doc(c.body))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		all := strings.Join(found, "\n")
		switch {
		case c.want == "" && all != "":
			t.Errorf("%s: unexpected findings %v", name, found)
		case c.want != "" && !strings.Contains(all, c.want):
			t.Errorf("%s: findings %v, want one containing %q", name, found, c.want)
		}
	}
}
