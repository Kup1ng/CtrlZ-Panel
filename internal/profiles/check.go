package profiles

import (
	"errors"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	shared "github.com/Kup1ng/CtrlZ-Shared/locations"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/noredirect"
	"github.com/Kup1ng/CtrlZ-Shared/rules"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/locations"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Env is what the write path needs besides the transaction.
type Env struct {
	// Catalog feeds the location sets (spec 4.1).
	Catalog locations.LocationCatalog
	// Clock is the application clock, which stamps every time the write path decides on (expiry, Disable).
	Clock appclock.Func

	// gate runs after the first lock of a write (the guard, or the tenant lock of a new profile), so a job that was ended
	// between its claim and its work does nothing (spec 3.5). Only the job runner sets it.
	gate func(store.Tx) error
}

func (e *Env) now() time.Time { return appclock.Or(e.Clock)() }

// ---------------------------------------------------------------------------
// Patterns.

// PatternCode maps what the rule parser says to the closed set of field codes (spec 3.7). A test walks the
// error cases of the tokens vectors and fails for a parser error that has no code of its own.
func PatternCode(err error) string {
	switch {
	case errors.Is(err, rules.ErrEmpty):
		return "pattern_empty"
	case errors.Is(err, rules.ErrIPLiteral), errors.Is(err, names.ErrIPLiteral), errors.Is(err, names.ErrNumeric):
		return "pattern_ip_literal"
	case errors.Is(err, rules.ErrBadGeo):
		return "pattern_bad_geo"
	case errors.Is(err, rules.ErrSourceASN):
		return "pattern_source_asn"
	case errors.Is(err, rules.ErrBadCC):
		return "pattern_bad_cc"
	case errors.Is(err, rules.ErrBadASN):
		return "pattern_bad_asn"
	case errors.Is(err, rules.ErrStarCount):
		return "pattern_star_count"
	case errors.Is(err, rules.ErrStarUnicode):
		return "pattern_star_unicode"
	case errors.Is(err, rules.ErrNoRegistrable):
		return "pattern_no_registrable"
	case errors.Is(err, rules.ErrNegatedName):
		return "pattern_negated_name"
	case errors.Is(err, rules.ErrPunycode):
		return "pattern_punycode"
	case errors.Is(err, names.ErrInputLen):
		return "pattern_too_long"
	case errors.Is(err, names.ErrBadByte):
		return "pattern_bad_byte"
	case errors.Is(err, names.ErrEmptyLbl):
		return "pattern_empty_label"
	case errors.Is(err, names.ErrLabelLen):
		return "pattern_label_too_long"
	case errors.Is(err, names.ErrNameLen):
		return "pattern_name_too_long"
	}
	// What the IDNA library says about a name it cannot convert.
	return "pattern_invalid"
}

// PatternCodes is the closed set PatternCode answers from.
func PatternCodes() []string {
	return []string{"pattern_empty", "pattern_ip_literal", "pattern_bad_geo", "pattern_source_asn", "pattern_bad_cc", "pattern_bad_asn",
		"pattern_star_count", "pattern_star_unicode", "pattern_no_registrable", "pattern_negated_name", "pattern_punycode",
		"pattern_too_long", "pattern_bad_byte", "pattern_empty_label", "pattern_label_too_long", "pattern_name_too_long", "pattern_invalid"}
}

// parsed is a pattern that passed the parser.
type parsed struct {
	p   rules.Pattern
	key string
}

func parse(input string) (parsed, error) {
	p, err := rules.Parse(input)
	if err != nil {
		return parsed{}, err
	}
	return parsed{p: p, key: p.Key()}, nil
}

// SearchText turns the text typed in a search box into what is matched as a substring of rule_key: lowered,
// split on dots, a label with a non-ASCII letter converted to its A-label by the shared name function, so a
// Unicode name finds the rules stored by their Punycode form by whole labels.
func SearchText(q string) string {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return ""
	}
	parts := strings.Split(q, ".")
	for i, l := range parts {
		ascii := true
		for j := 0; j < len(l); j++ {
			if l[j] >= utf8.RuneSelf {
				ascii = false
				break
			}
		}
		if ascii || l == "" {
			continue
		}
		if n, err := names.ParseUserPart(l); err == nil && n.Labels() == 1 {
			parts[i] = n.String()
		}
	}
	return strings.Join(parts, ".")
}

// ---------------------------------------------------------------------------
// Text bounds.

func checkName(name, field string, limit int) *Field {
	switch n := utf8.RuneCountInString(name); {
	case n < 1:
		return &Field{field, CodeRequired}
	case n > limit:
		return &Field{field, CodeTooLong}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Expiry and Disable.

// Expiry is the time a rule stops acting: either a shortcut or a moment (T-184).
type Expiry struct {
	In string    // "", 1h, 1d, 1w, 1m
	At time.Time // read with hasAt
	// HasAt says the member was sent. A moment of year 0001 decodes to the zero time, so the time alone cannot
	// tell "not given" from "given and long past"; the second is in_past on an item write, never "no expiry".
	HasAt bool
}

func (x Expiry) hasAt() bool { return x.HasAt || !x.At.IsZero() }

// yearAhead is how far an expiry or a Disable may reach (T-184, T-138).
const yearAhead = 366 * 24 * time.Hour

func (e *Env) expiry(field string, x Expiry, doc bool) (*time.Time, *Field) {
	now := e.now()
	switch {
	case x.In != "" && x.hasAt():
		return nil, &Field{field, CodeInvalid}
	case x.In != "":
		var d time.Duration
		switch x.In {
		case "1h":
			d = time.Hour
		case "1d":
			d = 24 * time.Hour
		case "1w":
			d = 7 * 24 * time.Hour
		case "1m":
			d = 30 * 24 * time.Hour
		default:
			return nil, &Field{field, CodeInvalid}
		}
		t := now.Add(d)
		return &t, nil
	case x.hasAt():
		// A document keeps a past moment: the rule is inert until the purge of P4, so an export with expired
		// rules imports again.
		if !doc && !x.At.After(now) {
			return nil, &Field{field, CodeInPast}
		}
		if x.At.After(now.Add(yearAhead)) {
			return nil, &Field{field, CodeInvalid}
		}
		t := x.At
		return &t, nil
	}
	return nil, nil
}

// DisableUntil resolves the two forms of Disable (T-138): for 5m, 1h or 1d, or until a moment after now and at
// most a year ahead. until is a pointer because a moment of year 0001 decodes to the zero time: only nil means
// the member was not sent, and a sent zero time is in_past (the same rule as Expiry.HasAt).
func (e *Env) DisableUntil(forText string, until *time.Time) (time.Time, *Error) {
	now := e.now()
	switch {
	case forText != "" && until != nil:
		return time.Time{}, invalid(Field{"/until", CodeInvalid})
	case forText != "":
		switch forText {
		case "5m":
			return now.Add(5 * time.Minute), nil
		case "1h":
			return now.Add(time.Hour), nil
		case "1d":
			return now.Add(24 * time.Hour), nil
		}
		return time.Time{}, invalid(Field{"/for", CodeInvalid})
	case until != nil:
		if !until.After(now) {
			return time.Time{}, invalid(Field{"/until", CodeInPast})
		}
		if until.After(now.Add(yearAhead)) {
			return time.Time{}, invalid(Field{"/until", CodeInvalid})
		}
		return *until, nil
	}
	return time.Time{}, invalid(Field{"/for", CodeRequired})
}

// ---------------------------------------------------------------------------
// Targets.

// LocKey names a location by its key, as a document does (ids differ between installs).
type LocKey struct{ Country, City, Label string }

func (k LocKey) shared() shared.Key {
	return shared.Key{Country: k.Country, City: k.City, Label: k.Label}
}

// Target is where a Redirect goes, as a request or a document states it. An item write names a location by
// id, a document by key.
type Target struct {
	Kind        string // "", location, auto, random, ip, host
	LocationID  uuid.UUID
	LocationKey *LocKey
	IPv4, IPv6  string
	Host        string
}

// Act is what a rule, a folder, a service or the Default Rule does: an action and, for a Redirect, a target.
type Act struct {
	Action string // block, bypass, redirect, inherit ("" is none, for a Folder Rule or the Default Rule)
	Target Target
}

// resolved is a checked target, ready for the store.
type resolved struct {
	t       store.Target
	flagged bool
}

func parseIP(s string, v4 bool) bool {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return false
	}
	if v4 {
		return a.Is4()
	}
	return a.Is6()
}

// target checks a Redirect target against the location set and the shape rules (spec 3.7, 4.2).
// Item writes refuse a location outside the set; document writes keep it and flag it. A location with no
// row at all cannot be stored and is refused by both.
func (w *wtx) target(field string, a Act, doc bool, set func() ([]shared.Key, error)) (resolved, []Field, error) {
	t := a.Target
	if a.Action != "redirect" {
		if t.Kind != "" {
			return resolved{}, []Field{{field + "/target", CodeInvalid}}, nil
		}
		return resolved{}, nil, nil
	}
	if err := w.load(); err != nil {
		return resolved{}, nil, err
	}
	var out resolved
	out.t.Kind = t.Kind
	switch t.Kind {
	case "location":
		var row locations.Row
		var ok bool
		switch {
		case doc && t.LocationKey != nil:
			row, ok = w.snap.Find(t.LocationKey.shared())
		case t.LocationID != uuid.Nil:
			row, ok = w.snap.ByID(t.LocationID)
		}
		if !ok {
			return resolved{}, []Field{{field + "/target/location", CodeUnknown}}, nil
		}
		s, err := set()
		if err != nil {
			return resolved{}, nil, err
		}
		if !locations.Contains(s, row.Key) {
			if !doc {
				return resolved{}, []Field{{field + "/target/location", CodeLocationNotAllowed}}, nil
			}
			out.flagged = true
		}
		out.t.LocationID = row.ID
	case "auto", "random":
		s, err := set()
		if err != nil {
			return resolved{}, nil, err
		}
		if len(s) == 0 {
			if !doc {
				return resolved{}, []Field{{field + "/target/kind", CodeNoSharedDestination}}, nil
			}
			out.flagged = true
		}
	case "ip":
		if t.IPv4 == "" && t.IPv6 == "" {
			return resolved{}, []Field{{field + "/target/ipv4", CodeRequired}}, nil
		}
		var fs []Field
		if t.IPv4 != "" && !parseIP(t.IPv4, true) {
			fs = append(fs, Field{field + "/target/ipv4", CodeInvalid})
		}
		if t.IPv6 != "" && !parseIP(t.IPv6, false) {
			fs = append(fs, Field{field + "/target/ipv6", CodeInvalid})
		}
		if fs != nil {
			return resolved{}, fs, nil
		}
		out.t.IPv4, out.t.IPv6 = t.IPv4, t.IPv6
	case "host":
		n, err := names.ParseUser(t.Host)
		if err != nil {
			return resolved{}, []Field{{field + "/target/host", CodeInvalid}}, nil
		}
		out.t.Host = n.String()
	default:
		return resolved{}, []Field{{field + "/target/kind", CodeInvalid}}, nil
	}
	return out, nil, nil
}

// storedTarget is the stored target of a row as the Target the checks compare (a location by id).
func storedTarget(t store.Target) Target {
	return Target{Kind: t.Kind, LocationID: t.LocationID, IPv4: t.IPv4, IPv6: t.IPv6, Host: t.Host}
}

// sameTarget compares what a request sets with what is stored, so a value equal to the stored one is not
// checked again (spec 3.7, first paragraph).
func sameTarget(a Target, b store.Target) bool {
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case "location":
		return a.LocationID == b.LocationID
	case "ip":
		return a.IPv4 == b.IPv4 && a.IPv6 == b.IPv6
	case "host":
		n, err := names.ParseUser(a.Host)
		return err == nil && n.String() == b.Host
	}
	return true
}

// ---------------------------------------------------------------------------
// D42: names that are never proxied (spec 3.6).

// lookupChunk is how many patterns one lookup of the list covers (D31).
const lookupChunk = 500

// iranian says, for each pattern, whether it is Iranian by the shared predicate. The list is read through the
// one lookup of the store per chunk, by exact canonical suffixes, and only the booleans leave this function.
func (w *wtx) iranian(ps []rules.Pattern) ([]bool, error) {
	out := make([]bool, len(ps))
	for from := 0; from < len(ps); from += lookupChunk {
		to := min(from+lookupChunk, len(ps))
		seen := map[string]bool{}
		var cands []string
		for _, p := range ps[from:to] {
			for _, s := range noredirect.PatternSuffixes(p) {
				if !seen[s] {
					seen[s] = true
					cands = append(cands, s)
				}
			}
		}
		entries := noredirect.Entries{}
		if len(cands) > 0 {
			rows, err := w.tx.NoRedirectLookup(cands)
			if err != nil {
				return nil, err
			}
			for _, r := range rows {
				if r.Host {
					entries[r.Pattern] = noredirect.ScopeHost
				} else {
					entries[r.Pattern] = noredirect.ScopeDomain
				}
			}
		}
		for i := from; i < to; i++ {
			out[i] = noredirect.Pattern(ps[i], entries)
		}
	}
	return out, nil
}
