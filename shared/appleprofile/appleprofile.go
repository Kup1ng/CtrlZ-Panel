// Package appleprofile is the part of the Apple DNS profile that must be the
// same wherever it is judged: what a request may ask for, the one stored form
// of an accepted request, and the identifiers that make a reinstall replace
// the old profile (contract section 14, P3 section 7.3).
//
// Building the .mobileconfig stays on the panel (internal/mobileconfig). This
// package has no resolver values in it: it never sees a host, a DoH token or an
// address, so nothing here can leak one.
package appleprofile

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"unicode"
	"unicode/utf8"

	"github.com/Kup1ng/CtrlZ-Shared/names"
)

const (
	ProtocolDoH = "doh"
	ProtocolDoT = "dot"

	// MaxSSIDs and MaxSSIDBytes bound the Wi-Fi networks a profile names. 32
	// bytes is the length of an SSID in 802.11.
	MaxSSIDs     = 50
	MaxSSIDBytes = 32
	// MaxUserDomains bounds the domains a person gives, folder domains
	// included, counted after duplicates are removed (Plan T-246).
	MaxUserDomains = 100
	// MaxExpandedDomains bounds the one list that params holds once the common
	// domains are added (P3 7.3, D31). It keeps the stored params under the
	// 65,536 byte CHECK of profile_download_tokens whatever size a catalog
	// version's common list has.
	MaxExpandedDomains = 200
	// MaxParamsBytes is that CHECK.
	MaxParamsBytes = 65536
)

// Codes of Error, the two the API turns into 422 (P3 section 3.7).
const (
	CodeInvalid  = "invalid"
	CodeExceeded = "exceeded"
)

// Error says which part of a request was refused. Pointer is a JSON pointer
// into the request (the API prefixes it with /params when the request is a
// share link's). Reason is fixed text: it never holds the refused value, so an
// error can be logged and returned as it is.
type Error struct {
	Pointer string
	Code    string
	Reason  string
}

func (e *Error) Error() string { return e.Pointer + ": " + e.Code + ": " + e.Reason }

func invalid(pointer, reason string) *Error {
	return &Error{Pointer: pointer, Code: CodeInvalid, Reason: reason}
}

func exceeded(pointer, reason string) *Error {
	return &Error{Pointer: pointer, Code: CodeExceeded, Reason: reason}
}

// Request is what a person asks for. The API resolves from_folder_id into
// ExcludedDomains before it calls Validate, so folder domains count toward the
// same bound as typed ones.
type Request struct {
	Client              string   `json:"client,omitempty"`
	Protocol            string   `json:"protocol"`
	ExcludedSSIDs       []string `json:"excluded_ssids,omitempty"`
	ExcludedDomains     []string `json:"excluded_domains,omitempty"`
	ExcludeCommon       bool     `json:"exclude_common,omitempty"`
	ProhibitDisablement bool     `json:"prohibit_disablement,omitempty"`
}

// Params is the expanded request the download link stores: one canonical
// domain list (typed, folder and common domains together) and no folder id, so
// a download reads no profile or catalog row and params_hash covers all of it.
type Params struct {
	Client              string   `json:"client"`
	Protocol            string   `json:"protocol"`
	ExcludedSSIDs       []string `json:"excluded_ssids"`
	ExcludedDomains     []string `json:"excluded_domains"`
	ProhibitDisablement bool     `json:"prohibit_disablement"`
}

// Validate checks a request. It reports the first problem in the order
// protocol, client, SSIDs, domains, so the answer is the same every time.
func Validate(req Request) error {
	if err := checkProtocol(req.Protocol); err != nil {
		return err
	}
	if err := checkClient(req.Client); err != nil {
		return err
	}
	if _, err := checkSSIDs(req.ExcludedSSIDs); err != nil {
		return err
	}
	_, err := checkDomains(req.ExcludedDomains, "/excluded_domains", MaxUserDomains, false)
	return err
}

// Expand validates a request and returns the Params a download link stores.
// common is the domain list of the current common-domains catalog version; it
// is used only when the request asks for it, and it is validated like typed
// domains because an admin can edit it. Over MaxExpandedDomains the request is
// refused as exceeded on /exclude_common.
func Expand(req Request, common []string) (Params, error) {
	if err := Validate(req); err != nil {
		return Params{}, err
	}
	ssids, _ := checkSSIDs(req.ExcludedSSIDs)
	typed, _ := checkDomains(req.ExcludedDomains, "/excluded_domains", MaxUserDomains, false)
	set := make(map[string]bool, len(typed))
	for _, d := range typed {
		set[d] = true
	}
	if req.ExcludeCommon {
		// A catalog list that is itself too long is refused before it is parsed,
		// so a bad version cannot cost more than the bound.
		if len(common) > MaxExpandedDomains {
			return Params{}, exceeded("/exclude_common", "the common domains are more than a profile can hold")
		}
		for i, c := range common {
			d, err := canonicalDomain(c)
			if err != nil {
				return Params{}, invalid("/exclude_common", "the common domain list holds a name that is not valid (entry "+strconv.Itoa(i)+")")
			}
			set[d] = true
			if len(set) > MaxExpandedDomains {
				return Params{}, exceeded("/exclude_common", "the domains and the common domains are more than a profile can hold")
			}
		}
	}
	return Params{
		Client:              req.Client,
		Protocol:            req.Protocol,
		ExcludedSSIDs:       ssids,
		ExcludedDomains:     sortedKeys(set),
		ProhibitDisablement: req.ProhibitDisablement,
	}, nil
}

// Validate checks stored params, which a download re-reads from the database:
// the same rules as a request, the one domain list bounded by
// MaxExpandedDomains, and every domain already in canonical form, because
// canonical JSON means one spelling per meaning.
func (p Params) Validate() error {
	if err := checkProtocol(p.Protocol); err != nil {
		return err
	}
	if err := checkClient(p.Client); err != nil {
		return err
	}
	ssids, err := checkSSIDs(p.ExcludedSSIDs)
	if err != nil {
		return err
	}
	if len(ssids) != len(p.ExcludedSSIDs) {
		return invalid("/excluded_ssids", "a network is listed twice")
	}
	doms, err := checkDomains(p.ExcludedDomains, "/excluded_domains", MaxExpandedDomains, true)
	if err != nil {
		return err
	}
	if len(doms) != len(p.ExcludedDomains) {
		return invalid("/excluded_domains", "a domain is listed twice")
	}
	// One spelling per meaning: Expand writes the list sorted, so a stored list
	// in another order is a second spelling of the same set and would hash
	// differently.
	if !sort.StringsAreSorted(p.ExcludedDomains) {
		return invalid("/excluded_domains", "the stored domains are not sorted")
	}
	return nil
}

// Canonical is the one JSON form of valid params: fixed field order, no
// whitespace, empty lists as [], and no HTML escaping (an SSID with < or & is
// stored as typed, which also keeps the worst case far under MaxParamsBytes).
func (p Params) Canonical() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if p.ExcludedSSIDs == nil {
		p.ExcludedSSIDs = []string{}
	}
	if p.ExcludedDomains == nil {
		p.ExcludedDomains = []string{}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(p); err != nil {
		return nil, err
	}
	out := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	if len(out) > MaxParamsBytes {
		return nil, exceeded("", "the params are larger than the stored form allows")
	}
	return out, nil
}

// Hash is the SHA-256 of Canonical, the params_hash of the download link.
func (p Params) Hash() ([32]byte, error) {
	b, err := p.Canonical()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// ParseParams reads stored params: unknown fields, a key spelled in another
// case, a repeated key, trailing data and an invalid value are all refused
// (encoding/json alone would match keys case-insensitively and keep the last of
// a repeated key, a second spelling of one meaning). params_hash is compared
// with Hash of the parsed value, never with a hash of the stored text: a jsonb
// column re-spaces and reorders keys, so its text is not the canonical bytes.
func ParseParams(b []byte) (Params, error) {
	if len(b) > MaxParamsBytes {
		return Params{}, exceeded("", "the params are larger than the stored form allows")
	}
	if err := checkKeys(b); err != nil {
		return Params{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var p Params
	if err := dec.Decode(&p); err != nil {
		return Params{}, invalid("", "the params are not valid JSON of the expected shape")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Params{}, invalid("", "the params have data after the object")
	}
	if err := p.Validate(); err != nil {
		return Params{}, err
	}
	return p, nil
}

// checkKeys walks the top-level keys of the object and accepts only the exact
// field names of Params, each once. Values are skipped here; the struct decode
// that follows judges them.
func checkKeys(b []byte) error {
	bad := invalid("", "the params are not valid JSON of the expected shape")
	dec := json.NewDecoder(bytes.NewReader(b))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return bad
	}
	known := map[string]bool{
		"client": true, "protocol": true, "excluded_ssids": true,
		"excluded_domains": true, "prohibit_disablement": true,
	}
	seen := make(map[string]bool, len(known))
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return bad
		}
		k, ok := t.(string)
		if !ok || !known[k] || seen[k] {
			return bad
		}
		seen[k] = true
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return bad
		}
	}
	return nil
}

func checkProtocol(p string) error {
	if p != ProtocolDoH && p != ProtocolDoT {
		return invalid("/protocol", "the protocol is doh or dot")
	}
	return nil
}

func checkClient(c string) error {
	if c != "" && !names.ValidClientLabel(c) {
		return invalid("/client", "the client is 1 to 36 lowercase letters, digits and inner hyphens")
	}
	return nil
}

// checkSSIDs validates the list and returns it without repeats, in the order
// first given. An SSID is bytes to the radio but text to a profile, and a
// profile is XML, so it must be UTF-8 with no control character and none of
// the two noncharacters XML 1.0 forbids: anything else cannot be written
// faithfully, and the encoder would otherwise replace it silently.
func checkSSIDs(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for i, s := range in {
		ptr := "/excluded_ssids/" + strconv.Itoa(i)
		if s == "" || len(s) > MaxSSIDBytes {
			return nil, invalid(ptr, "a network name is 1 to 32 bytes")
		}
		if !utf8.ValidString(s) {
			return nil, invalid(ptr, "a network name is UTF-8 text")
		}
		for _, r := range s {
			if refusedInSSID(r) {
				return nil, invalid(ptr, "a network name has no control or invisible character")
			}
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
		if len(out) > MaxSSIDs {
			return nil, exceeded("/excluded_ssids", "at most 50 networks")
		}
	}
	return out, nil
}

// refusedInSSID is the rune set P3 11.5 refuses: controls (Cc, C1 included),
// the two XML noncharacters, and the invisible and bidi format characters (Cf:
// U+200B, U+202E, U+2066 to U+2069, U+FEFF ...) with the line and paragraph
// separators, which would reorder or hide part of the list shown to a person.
// U+200C stays allowed: it is the half-space of Persian network names (the
// ZWNJ exception of RULES 9).
func refusedInSSID(r rune) bool {
	if r == 0x200C {
		return false
	}
	return unicode.IsControl(r) || r == 0xFFFE || r == 0xFFFF ||
		unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r)
}

func canonicalDomain(s string) (string, error) {
	n, err := names.ParseUser(s)
	if err != nil {
		return "", err
	}
	return n.String(), nil
}

// checkDomains validates the list and returns the canonical names without
// repeats. With strict the input must already be canonical. It stops at the
// first name past the bound, so a long list costs at most max parses of new
// names.
func checkDomains(in []string, pointer string, limit int, strict bool) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for i, s := range in {
		d, err := canonicalDomain(s)
		if err != nil {
			return nil, invalid(pointer+"/"+strconv.Itoa(i), "a domain is not a valid name")
		}
		if strict && d != s {
			return nil, invalid(pointer+"/"+strconv.Itoa(i), "a stored domain is not in canonical form")
		}
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
		if len(out) > limit {
			return nil, exceeded(pointer, fmt.Sprintf("at most %d domains", limit))
		}
	}
	return out, nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
