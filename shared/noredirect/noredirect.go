// Package noredirect is the one definition of "a name that is never proxied" (D42,
// contract 10.5). The panel's write path calls Pattern to refuse a Redirect on such a
// pattern, and the evaluator calls Name to turn a Redirect on such a name into Bypass, so
// the two cannot disagree about which names are Iranian.
//
// The package holds no list. The list is catalog_no_redirect_domain, and the caller
// brings the rows that matter to the question in hand as Entries: Suffixes and
// PatternSuffixes say which canonical texts to look up, so a caller with a database asks
// for exactly those and a caller with a table in memory passes all of it.
package noredirect

import (
	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/rules"
)

// MaxLabels is the most labels an entry may have (the CHECK of catalog_no_redirect_domain),
// so it is also the deepest suffix a lookup has to try.
const MaxLabels = 8

// Scope says what an entry covers.
type Scope uint8

const (
	// ScopeDomain covers the name and everything under it.
	ScopeDomain Scope = 1
	// ScopeHost covers that exact name only.
	ScopeHost Scope = 2
)

// Entries maps the canonical text of an entry (lower case, LDH labels, an IDN as its
// A-label, no dots at the ends) to its scope.
type Entries map[string]Scope

// The two built-in top-level domains: .ir, and .ایران in its A-label form. A U-label is
// turned into the A-label by names.ParseUser before it reaches any function here, so the
// two spellings are one name.
const (
	tldIR   = "ir"
	tldIran = "xn--mgba3a4f16a"
)

func iranianTLD(label []byte) bool {
	s := string(label)
	return s == tldIR || s == tldIran
}

// Suffixes returns the canonical texts of the suffixes of n that an entry can equal: the
// last 1 to MaxLabels labels, and so n itself when it is short enough, longest first.
func Suffixes(n names.Name) []string {
	var out []string
	for _, k := range n.Suffixes(MaxLabels) {
		s, err := names.FromCanonicalWire(n.SuffixWire(k))
		if err != nil {
			continue
		}
		out = append(out, s.String())
	}
	return out
}

// Name reports whether n is Iranian: at or under .ir or .ایران, at or under a domain
// entry, or equal to a host entry.
func Name(n names.Name, e Entries) bool {
	if n.Labels() == 0 {
		return false
	}
	if iranianTLD(n.Label(n.Labels() - 1)) {
		return true
	}
	for _, k := range n.Suffixes(MaxLabels) {
		s, err := names.FromCanonicalWire(n.SuffixWire(k))
		if err != nil {
			continue
		}
		switch e[s.String()] {
		case ScopeDomain:
			return true
		case ScopeHost:
			// A host entry is an exact name: only the whole of n can equal it.
			if k == n.Labels() {
				return true
			}
		}
	}
	return false
}

// literal returns the name a pattern is judged by: the name itself for a domain, the
// literal suffix right of the star for a wildcard. ok is false for a pattern that
// matches no name (a country or an AS).
func literal(p rules.Pattern) (names.Name, bool) {
	switch p.Kind {
	case rules.KindDomain, rules.KindSubdomains, rules.KindGlob:
		n, err := names.FromCanonicalWire(p.LiteralSuffix())
		return n, err == nil
	}
	return names.Name{}, false
}

// PatternSuffixes returns the canonical texts Pattern will look up in Entries, so a caller
// can fetch only those rows.
func PatternSuffixes(p rules.Pattern) []string {
	n, ok := literal(p)
	if !ok {
		return nil
	}
	return Suffixes(n)
}

// Pattern reports whether a rule pattern is Iranian, which is what the write path refuses
// a Redirect for:
//
//   - a domain pattern whose own name is Iranian (Name);
//   - a wildcard whose literal suffix is at or under .ir or .ایران or at or under a domain
//     entry. A host entry does not count: the wildcard never matches its suffix itself, and
//     the names below the suffix that are Iranian are left to the evaluator;
//   - a destination country pattern @IR. A negated one (!@IR) is not.
func Pattern(p rules.Pattern, e Entries) bool {
	switch p.Kind {
	case rules.KindDestCC:
		return !p.Negated && string(p.CC[:]) == "IR"
	case rules.KindDomain:
		n, ok := literal(p)
		return ok && Name(n, e)
	case rules.KindSubdomains, rules.KindGlob:
		n, ok := literal(p)
		if !ok || n.Labels() == 0 {
			return false
		}
		if iranianTLD(n.Label(n.Labels() - 1)) {
			return true
		}
		for _, k := range n.Suffixes(MaxLabels) {
			s, err := names.FromCanonicalWire(n.SuffixWire(k))
			if err == nil && e[s.String()] == ScopeDomain {
				return true
			}
		}
	}
	return false
}
