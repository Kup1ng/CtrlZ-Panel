package profiles

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	shared "github.com/Kup1ng/CtrlZ-Shared/locations"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Profile and rules documents, version 1 (docs/specs/p2-profiles.md 6). A document is the content of a profile and
// nothing of its identity: no id, tenant, version, timestamps, lock fields, Disable or system flags (T-133). A location
// is named by its key, a folder by a ref local to the document, and the canonical form is fixed so that an export of the
// same profile gives the same bytes.

// The document constants (D31). Named so that none starts with "max": they are bounds of one decoder and not caps.
const (
	// DocFormat and RulesFormat are the `format` members.
	DocFormat   = "ctrlz-profile"
	RulesFormat = "ctrlz-rules"
	// DocVersion is the one version this build reads and writes. A later one comes with an upgrade function from every
	// earlier one; block page content joins in P4b as version 2.
	DocVersion = 1
	// DocFileBytes is the size of the file before base64 (spec 6.2): 4 MiB.
	DocFileBytes = 4 << 20
	// DocDepth is how deep a document may nest. The schema needs 6 (document, array, rule, target, location), so 8 leaves
	// room and stops an adversarial tree before it is built.
	DocDepth = 8
	// DocValues bounds the values and object members of one file, derived from the schema: 10,000 rules of at most
	// 24 values each, 500 folders, the filters, the services and the fixed part, with room to spare (spec 6.2).
	DocValues = 300000
)

// DocLoc names a location by its key.
type DocLoc struct {
	Country string `json:"country,omitempty"`
	City    string `json:"city,omitempty"`
	Label   string `json:"label,omitempty"`
}

// DocTarget is where a Redirect goes, as a document states it.
type DocTarget struct {
	Kind     string  `json:"kind"`
	Location *DocLoc `json:"location,omitempty"`
	IPv4     string  `json:"ipv4,omitempty"`
	IPv6     string  `json:"ipv6,omitempty"`
	Host     string  `json:"host,omitempty"`
}

// DocFilter is the state of one filter.
type DocFilter struct {
	ID      string `json:"id"`
	Enabled *bool  `json:"enabled,omitempty"`
	Mode    string `json:"mode,omitempty"`
}

// DocService is the state of one service.
type DocService struct {
	Slug    string     `json:"slug"`
	Enabled *bool      `json:"enabled,omitempty"`
	Action  string     `json:"action"`
	Target  *DocTarget `json:"target,omitempty"`
}

// DocFolder is a rule folder; Ref names it inside the document.
type DocFolder struct {
	Ref    string     `json:"ref"`
	Name   string     `json:"name"`
	Kind   string     `json:"kind"`
	Action string     `json:"action,omitempty"`
	Target *DocTarget `json:"target,omitempty"`
}

// DocRule is one rule.
type DocRule struct {
	Pattern   string     `json:"pattern"`
	Folder    string     `json:"folder,omitempty"`
	Action    string     `json:"action"`
	Target    *DocTarget `json:"target,omitempty"`
	Enabled   *bool      `json:"enabled,omitempty"`
	ExpiresAt string     `json:"expires_at,omitempty"`
	Comment   string     `json:"comment,omitempty"`
}

// DocDefaultRule is the Default Rule option.
type DocDefaultRule struct {
	Action string     `json:"action"`
	Target *DocTarget `json:"target,omitempty"`
}

// DocBlockResponse is the Block Response option.
type DocBlockResponse struct {
	Mode string `json:"mode"`
	V4   string `json:"v4,omitempty"`
	V6   string `json:"v6,omitempty"`
}

// DocECS is the ECS option.
type DocECS struct {
	Mode string `json:"mode"`
	V4   string `json:"v4,omitempty"`
	V6   string `json:"v6,omitempty"`
}

// DocOptions are the options that are set; an option that is not set is absent (spec 6.1).
type DocOptions struct {
	DefaultRule       *DocDefaultRule   `json:"default_rule,omitempty"`
	BlockExfiltration *bool             `json:"block_exfiltration,omitempty"`
	RebindProtection  *bool             `json:"rebind_protection,omitempty"`
	DisableDNSSEC     *bool             `json:"disable_dnssec,omitempty"`
	BlockTTL          *int              `json:"block_ttl,omitempty"`
	RedirectTTL       *int              `json:"redirect_ttl,omitempty"`
	BypassTTL         *int              `json:"bypass_ttl,omitempty"`
	BlockResponse     *DocBlockResponse `json:"block_response,omitempty"`
	ECS               *DocECS           `json:"ecs,omitempty"`
	DNS64             *bool             `json:"dns64,omitempty"`
	CNAMEFlattening   *bool             `json:"cname_flattening,omitempty"`
	SafeSearch        *bool             `json:"safe_search,omitempty"`
	RestrictedYouTube *bool             `json:"restricted_youtube,omitempty"`
}

// Document is a profile document. A type (spec 5) is one without a name.
type Document struct {
	Format   string       `json:"format"`
	Version  int          `json:"version"`
	Name     string       `json:"name,omitempty"`
	Kind     string       `json:"kind"`
	Filters  []DocFilter  `json:"filters"`
	Services []DocService `json:"services"`
	Folders  []DocFolder  `json:"folders"`
	Rules    []DocRule    `json:"rules"`
	Options  DocOptions   `json:"options"`
}

// RulesDocument is the file of Export Rules and Upload Folder (spec 6.3): rule items without a folder.
type RulesDocument struct {
	Format  string    `json:"format"`
	Version int       `json:"version"`
	Rules   []DocRule `json:"rules"`
}

func on(p *bool) bool { return p == nil || *p }

// ---------------------------------------------------------------------------
// Canonical encoding (spec 6.1): keys in the order of the struct, arrays sorted by the bytes of their key, no
// insignificant space, UTF-8, no HTML escaping. The slices must already be sorted: Canonical does it.

// Canonical sorts the arrays by their keys and assigns the refs f1 to fN in folder order. Folders are ordered by name
// and then by the id they had (idOf), so two folders of one name keep a stable order; a document with no ids (an
// imported one) keeps the order it has among equal names.
func (d *Document) Canonical(idOf func(ref string) uuid.UUID) {
	sort.SliceStable(d.Filters, func(i, j int) bool { return d.Filters[i].ID < d.Filters[j].ID })
	sort.SliceStable(d.Services, func(i, j int) bool { return d.Services[i].Slug < d.Services[j].Slug })
	sort.SliceStable(d.Folders, func(i, j int) bool {
		a, b := d.Folders[i], d.Folders[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if idOf == nil {
			return false
		}
		x, y := idOf(a.Ref), idOf(b.Ref)
		return bytes.Compare(x[:], y[:]) < 0
	})
	refs := map[string]string{}
	for i := range d.Folders {
		n := "f" + strconv.Itoa(i+1)
		refs[d.Folders[i].Ref] = n
		d.Folders[i].Ref = n
	}
	for i := range d.Rules {
		if d.Rules[i].Folder != "" {
			d.Rules[i].Folder = refs[d.Rules[i].Folder]
		}
	}
	sort.SliceStable(d.Rules, func(i, j int) bool { return d.Rules[i].Pattern < d.Rules[j].Pattern })
}

// Canonical sorts the rules of a rules document by pattern.
func (d *RulesDocument) Canonical() {
	sort.SliceStable(d.Rules, func(i, j int) bool { return d.Rules[i].Pattern < d.Rules[j].Pattern })
}

type enc struct{ b bytes.Buffer }

func (e *enc) raw(s string) { e.b.WriteString(s) }

func (e *enc) str(s string) {
	var t bytes.Buffer
	x := json.NewEncoder(&t)
	x.SetEscapeHTML(false)
	_ = x.Encode(s) // a string always marshals
	e.b.Write(bytes.TrimRight(t.Bytes(), "\n"))
}

// field writes `"name":` with a comma when it is not the first.
func (e *enc) field(first *bool, name string) {
	if !*first {
		e.raw(",")
	}
	*first = false
	e.str(name)
	e.raw(":")
}

func (e *enc) boolean(v bool) { e.raw(strconv.FormatBool(v)) }

func (e *enc) target(t *DocTarget) {
	e.raw("{")
	first := true
	e.field(&first, "kind")
	e.str(t.Kind)
	if t.Location != nil {
		e.field(&first, "location")
		e.raw("{")
		f := true
		if t.Location.Country != "" {
			e.field(&f, "country")
			e.str(t.Location.Country)
		}
		if t.Location.City != "" {
			e.field(&f, "city")
			e.str(t.Location.City)
		}
		if t.Location.Label != "" {
			e.field(&f, "label")
			e.str(t.Location.Label)
		}
		e.raw("}")
	}
	for _, kv := range [][2]string{{"ipv4", t.IPv4}, {"ipv6", t.IPv6}, {"host", t.Host}} {
		if kv[1] != "" {
			e.field(&first, kv[0])
			e.str(kv[1])
		}
	}
	e.raw("}")
}

func (e *enc) rule(r DocRule, withFolder bool) {
	e.raw("{")
	first := true
	e.field(&first, "pattern")
	e.str(r.Pattern)
	if withFolder && r.Folder != "" {
		e.field(&first, "folder")
		e.str(r.Folder)
	}
	e.field(&first, "action")
	e.str(r.Action)
	if r.Target != nil {
		e.field(&first, "target")
		e.target(r.Target)
	}
	e.field(&first, "enabled")
	e.boolean(on(r.Enabled))
	if r.ExpiresAt != "" {
		e.field(&first, "expires_at")
		e.str(r.ExpiresAt)
	}
	if r.Comment != "" {
		e.field(&first, "comment")
		e.str(r.Comment)
	}
	e.raw("}")
}

func (e *enc) pair(name string, mode string, v4, v6 string, first *bool) {
	e.field(first, name)
	e.raw("{")
	f := true
	e.field(&f, "mode")
	e.str(mode)
	if v4 != "" {
		e.field(&f, "v4")
		e.str(v4)
	}
	if v6 != "" {
		e.field(&f, "v6")
		e.str(v6)
	}
	e.raw("}")
}

func (e *enc) options(o DocOptions) {
	e.raw("{")
	first := true
	if o.DefaultRule != nil {
		e.field(&first, "default_rule")
		e.raw("{")
		f := true
		e.field(&f, "action")
		e.str(o.DefaultRule.Action)
		if o.DefaultRule.Target != nil {
			e.field(&f, "target")
			e.target(o.DefaultRule.Target)
		}
		e.raw("}")
	}
	flag := func(name string, v *bool) {
		if v != nil {
			e.field(&first, name)
			e.boolean(*v)
		}
	}
	num := func(name string, v *int) {
		if v != nil {
			e.field(&first, name)
			e.raw(strconv.Itoa(*v))
		}
	}
	flag("block_exfiltration", o.BlockExfiltration)
	flag("rebind_protection", o.RebindProtection)
	flag("disable_dnssec", o.DisableDNSSEC)
	num("block_ttl", o.BlockTTL)
	num("redirect_ttl", o.RedirectTTL)
	num("bypass_ttl", o.BypassTTL)
	if o.BlockResponse != nil {
		e.pair("block_response", o.BlockResponse.Mode, o.BlockResponse.V4, o.BlockResponse.V6, &first)
	}
	if o.ECS != nil {
		e.pair("ecs", o.ECS.Mode, o.ECS.V4, o.ECS.V6, &first)
	}
	flag("dns64", o.DNS64)
	flag("cname_flattening", o.CNAMEFlattening)
	flag("safe_search", o.SafeSearch)
	flag("restricted_youtube", o.RestrictedYouTube)
	e.raw("}")
}

// Encode writes the canonical bytes of the document. It does not sort: call Canonical first.
func (d Document) Encode() []byte {
	var e enc
	e.raw("{")
	first := true
	e.field(&first, "format")
	e.str(DocFormat)
	e.field(&first, "version")
	e.raw(strconv.Itoa(DocVersion))
	if d.Name != "" {
		e.field(&first, "name")
		e.str(d.Name)
	}
	e.field(&first, "kind")
	e.str(d.Kind)
	e.field(&first, "filters")
	e.raw("[")
	for i, f := range d.Filters {
		if i > 0 {
			e.raw(",")
		}
		e.raw("{")
		ff := true
		e.field(&ff, "id")
		e.str(f.ID)
		e.field(&ff, "enabled")
		e.boolean(on(f.Enabled))
		if f.Mode != "" {
			e.field(&ff, "mode")
			e.str(f.Mode)
		}
		e.raw("}")
	}
	e.raw("]")
	e.field(&first, "services")
	e.raw("[")
	for i, s := range d.Services {
		if i > 0 {
			e.raw(",")
		}
		e.raw("{")
		sf := true
		e.field(&sf, "slug")
		e.str(s.Slug)
		e.field(&sf, "enabled")
		e.boolean(on(s.Enabled))
		e.field(&sf, "action")
		e.str(s.Action)
		if s.Target != nil {
			e.field(&sf, "target")
			e.target(s.Target)
		}
		e.raw("}")
	}
	e.raw("]")
	e.field(&first, "folders")
	e.raw("[")
	for i, f := range d.Folders {
		if i > 0 {
			e.raw(",")
		}
		e.raw("{")
		ff := true
		e.field(&ff, "ref")
		e.str(f.Ref)
		e.field(&ff, "name")
		e.str(f.Name)
		e.field(&ff, "kind")
		e.str(f.Kind)
		if f.Action != "" {
			e.field(&ff, "action")
			e.str(f.Action)
		}
		if f.Target != nil {
			e.field(&ff, "target")
			e.target(f.Target)
		}
		e.raw("}")
	}
	e.raw("]")
	e.field(&first, "rules")
	e.raw("[")
	for i, r := range d.Rules {
		if i > 0 {
			e.raw(",")
		}
		e.rule(r, true)
	}
	e.raw("]")
	e.field(&first, "options")
	e.options(d.Options)
	e.raw("}")
	return e.b.Bytes()
}

// Encode writes the canonical bytes of a rules document.
func (d RulesDocument) Encode() []byte {
	var e enc
	e.raw(`{"format":"` + RulesFormat + `","version":` + strconv.Itoa(DocVersion) + `,"rules":[`)
	for i, r := range d.Rules {
		if i > 0 {
			e.raw(",")
		}
		e.rule(r, false)
	}
	e.raw("]}")
	return e.b.Bytes()
}

// ---------------------------------------------------------------------------
// Reading a file (spec 6.2).

// Document field codes beyond the closed set of 3.7 (spec 3.7, last paragraph).
const (
	CodeJSONSyntax         = "json_syntax"
	CodeFormatUnknown      = "format_unknown"
	CodeVersionUnsupported = "version_unsupported"
	CodeUnknownMember      = "unknown_member"
	CodeType               = "type"
)

// DocumentCodes is the closed list of field codes only a document can give (spec 6.2); a test has a case for each.
func DocumentCodes() []string {
	return []string{CodeJSONSyntax, CodeFormatUnknown, CodeVersionUnsupported, CodeUnknownMember, CodeType}
}

// documentMembers is every member name of the two document schemas. ScanJSON puts a key into a pointer only if it is one
// of these: the scanner sees keys the schema does not know, and the file's own text must not come back in an answer
// (spec 6.2). A function and not a variable (no package-level state); a test pins it to what Encode writes.
func documentMembers() map[string]struct{} {
	out := map[string]struct{}{}
	for _, n := range []string{
		"format", "version", "name", "kind", "filters", "services", "folders", "rules", "options",
		"id", "enabled", "mode", "slug", "action", "target", "ref", "pattern", "folder", "expires_at", "comment",
		"location", "country", "city", "label", "ipv4", "ipv6", "host",
		"default_rule", "block_exfiltration", "rebind_protection", "disable_dnssec", "block_ttl", "redirect_ttl", "bypass_ttl",
		"block_response", "ecs", "v4", "v6", "dns64", "cname_flattening", "safe_search", "restricted_youtube",
	} {
		out[n] = struct{}{}
	}
	return out
}

type scanFrame struct {
	obj  bool
	keys map[string]struct{}
	idx  int    // index of the next element of an array
	seg  string // the segment of this container in the pointer ("" for the root or an unnamed one)
}

// ScanJSON reads the file as a token stream before any tree is built: valid UTF-8, no duplicate key, a nesting depth of
// DocDepth at most and a cap on the values (spec 6.2). The one problem it finds is returned as a field pointing at the
// parent of the problem, built from member names and indexes only.
func ScanJSON(raw []byte) *Field {
	if !utf8.Valid(raw) {
		return &Field{"", CodeJSONSyntax}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	members := documentMembers()
	var stack []scanFrame
	values := 0
	pointer := func() string {
		var b strings.Builder
		for _, f := range stack {
			b.WriteString(f.seg)
		}
		return b.String()
	}
	var pendingKey string
	havePending := false
	// childSeg is the pointer segment of the value that starts now: the key it sits under, or the index in its array.
	childSeg := func() string {
		if len(stack) == 0 {
			return ""
		}
		top := &stack[len(stack)-1]
		if top.obj {
			if _, known := members[pendingKey]; havePending && known {
				return "/" + pendingKey
			}
			return ""
		}
		return "/" + strconv.Itoa(top.idx)
	}
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return &Field{pointer(), CodeJSONSyntax}
		}
		values++
		if values > DocValues {
			return &Field{pointer(), CodeJSONSyntax}
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				seg := childSeg()
				if len(stack) >= DocDepth {
					return &Field{pointer(), CodeJSONSyntax}
				}
				stack = append(stack, scanFrame{obj: t == '{', keys: map[string]struct{}{}, seg: seg})
				havePending = false
			default: // '}' or ']'
				stack = stack[:len(stack)-1]
				if len(stack) > 0 {
					if top := &stack[len(stack)-1]; !top.obj {
						top.idx++
					}
				}
				havePending = false
			}
		case string:
			if len(stack) > 0 && stack[len(stack)-1].obj && !havePending {
				top := &stack[len(stack)-1]
				if _, dup := top.keys[t]; dup {
					return &Field{pointer(), CodeJSONSyntax}
				}
				top.keys[t] = struct{}{}
				pendingKey, havePending = t, true
				continue
			}
			scalarDone(stack, &havePending)
		default:
			scalarDone(stack, &havePending)
		}
	}
	if len(stack) != 0 {
		return &Field{pointer(), CodeJSONSyntax}
	}
	return nil
}

func scalarDone(stack []scanFrame, havePending *bool) {
	if len(stack) > 0 {
		if top := &stack[len(stack)-1]; !top.obj {
			top.idx++
		}
	}
	*havePending = false
}

// Schema checks a value against a component of the OpenAPI document and returns its problems as fields, at most 100,
// in document order. The api passes httpx.Validator.CheckComponent.
type Schema func(component string, raw []byte) []Field

// DecodeDocument reads a profile document: the token stream, the format and version, the schema and then the typed
// value. Every problem is a field; none echoes a value or a name from the file.
func DecodeDocument(raw []byte, check Schema) (Document, error) {
	var d Document
	if err := decodeInto(raw, check, "ProfileDocument", DocFormat, &d); err != nil {
		return Document{}, err
	}
	if d.Format != DocFormat {
		return Document{}, invalid(Field{"/format", CodeFormatUnknown})
	}
	return d, nil
}

// DecodeRulesDocument is DecodeDocument for the file of Upload Folder.
func DecodeRulesDocument(raw []byte, check Schema) (RulesDocument, error) {
	var d RulesDocument
	if err := decodeInto(raw, check, "RulesDocument", RulesFormat, &d); err != nil {
		return RulesDocument{}, err
	}
	return d, nil
}

func decodeInto(raw []byte, check Schema, component, format string, dst any) error {
	if len(raw) > DocFileBytes {
		return invalid(Field{"", CodeTooLong})
	}
	if f := ScanJSON(raw); f != nil {
		return invalid(*f)
	}
	var head struct {
		Format  json.RawMessage `json:"format"`
		Version json.RawMessage `json:"version"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		// Valid JSON that is not an object.
		return invalid(Field{"", CodeType})
	}
	var f string
	if len(head.Format) == 0 || json.Unmarshal(head.Format, &f) != nil || f != format {
		if len(head.Format) == 0 {
			return invalid(Field{"/format", CodeRequired})
		}
		return invalid(Field{"/format", CodeFormatUnknown})
	}
	if len(head.Version) == 0 {
		return invalid(Field{"/version", CodeRequired})
	}
	var v int
	if json.Unmarshal(head.Version, &v) != nil || v != DocVersion {
		return invalid(Field{"/version", CodeVersionUnsupported})
	}
	if check != nil {
		if fs := check(component, raw); len(fs) > 0 {
			return invalid(fs...)
		}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(dst); err != nil {
		// The schema passed, so this is a value the typed form cannot hold (a number out of range).
		return invalid(Field{"", CodeType})
	}
	return nil
}

// parseExpiry reads the RFC 3339 text of an expires_at member. A moment before year 1 in UTC is refused here:
// the schema pattern and time.Parse accept year 0000, and a positive offset on year 0001 converts to it, but the
// timestamptz cast of the write has no year 0 and fails with 22008, which is no profiles.Error and answers 500.
func parseExpiry(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	t = t.UTC()
	if t.Year() < 1 {
		return time.Time{}, false
	}
	return t, true
}

// formatExpiry is the canonical text of a stored expiry: UTC, microseconds at most, the precision of the column.
func formatExpiry(t time.Time) string {
	return t.UTC().Truncate(time.Microsecond).Format("2006-01-02T15:04:05.999999Z07:00")
}

// docTarget turns a stored target into the target of a document, naming a location by its key.
func docTarget(t store.Target, key func(uuid.UUID) (shared.Key, bool)) *DocTarget {
	switch t.Kind {
	case "":
		return nil
	case "location":
		k, _ := key(t.LocationID)
		return &DocTarget{Kind: "location", Location: &DocLoc{Country: k.Country, City: k.City, Label: k.Label}}
	case "auto", "random":
		return &DocTarget{Kind: t.Kind}
	case "ip":
		return &DocTarget{Kind: "ip", IPv4: t.IPv4, IPv6: t.IPv6}
	case "host":
		return &DocTarget{Kind: "host", Host: t.Host}
	}
	return nil
}

// pointerf builds a pointer from a prefix and a format.
func pointerf(prefix, format string, a ...any) string { return prefix + fmt.Sprintf(format, a...) }
