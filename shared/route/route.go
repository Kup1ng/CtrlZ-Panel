// Package route is the hybrid-resolver rule schema and matcher (contract 11).
// A rule list maps a query to a named group of upstreams; the first rule in
// order wins, and a final default catches the rest. Health checks and failover
// inside a group are node glue.
package route

import (
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/Kup1ng/CtrlZ-Shared/names"
)

// Cond is the kind of condition a rule tests.
type Cond uint8

const (
	CondDomain  Cond = 1 // exact name
	CondSuffix  Cond = 2 // the name or anything below
	CondGeosite Cond = 3 // membership in a catalog hash set
	CondQType   Cond = 4
	CondTLD     Cond = 5 // last label
)

// Rule is a parsed resolver rule.
type Rule struct {
	Order        uint32
	Cond         Cond
	Name         names.Name // CondDomain, CondSuffix
	Tag          string     // CondGeosite, for example "geosite:ir"
	QType        uint16     // CondQType
	TLD          string     // CondTLD, one lowercase label
	Group        string
	FinalDefault bool // matches everything; normally the last rule
}

var (
	ErrMatchType = errors.New("route: unknown match_type")
	ErrMatchVal  = errors.New("route: bad match_value")
	ErrNoGroup   = errors.New("route: a rule needs a group")
)

func mnemonic(s string) (uint16, bool) {
	switch s {
	case "A":
		return 1, true
	case "NS":
		return 2, true
	case "CNAME":
		return 5, true
	case "SOA":
		return 6, true
	case "PTR":
		return 12, true
	case "MX":
		return 15, true
	case "TXT":
		return 16, true
	case "AAAA":
		return 28, true
	case "SRV":
		return 33, true
	case "DS":
		return 43, true
	case "RRSIG":
		return 46, true
	case "DNSKEY":
		return 48, true
	case "SVCB":
		return 64, true
	case "HTTPS":
		return 65, true
	case "ANY":
		return 255, true
	}
	return 0, false
}

// ParseQType accepts a number from 1 to 65535 or a mnemonic.
func ParseQType(s string) (uint16, bool) {
	if v, ok := mnemonic(strings.ToUpper(s)); ok {
		return v, true
	}
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil || n == 0 {
		return 0, false
	}
	return uint16(n), true
}

// ParseRule validates one rule as it arrives in NodeConfig.
func ParseRule(order uint32, matchType, matchValue, group string, finalDefault bool) (Rule, error) {
	r := Rule{Order: order, Group: group, FinalDefault: finalDefault}
	if group == "" {
		return r, ErrNoGroup
	}
	if finalDefault && matchType == "" {
		return r, nil
	}
	switch matchType {
	case "domain", "suffix":
		n, err := names.ParseUser(matchValue)
		if err != nil {
			return r, ErrMatchVal
		}
		r.Name = n
		r.Cond = CondDomain
		if matchType == "suffix" {
			r.Cond = CondSuffix
		}
	case "geosite":
		tag, ok := strings.CutPrefix(matchValue, "geosite:")
		if !ok || tag == "" {
			return r, ErrMatchVal
		}
		for i := 0; i < len(tag); i++ {
			c := tag[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '!' || c == '@') {
				return r, ErrMatchVal
			}
		}
		r.Cond, r.Tag = CondGeosite, matchValue
	case "qtype":
		q, ok := ParseQType(matchValue)
		if !ok {
			return r, ErrMatchVal
		}
		r.Cond, r.QType = CondQType, q
	case "tld":
		n, err := names.ParseUser(matchValue)
		if err != nil || n.Labels() != 1 {
			return r, ErrMatchVal
		}
		r.Cond, r.TLD = CondTLD, string(n.Label(0))
	default:
		return r, ErrMatchType
	}
	return r, nil
}

// GeoSites answers geosite membership from the catalog's hash sets.
type GeoSites interface {
	Has(tag string, n *names.Name) bool
}

func (r *Rule) matches(n *names.Name, qtype uint16, geo GeoSites) bool {
	if r.FinalDefault && r.Cond == 0 {
		return true
	}
	switch r.Cond {
	case CondDomain:
		return n.Equal(&r.Name)
	case CondSuffix:
		return n.Labels() >= r.Name.Labels() && string(n.SuffixWire(r.Name.Labels())) == string(r.Name.Wire())
	case CondGeosite:
		return geo != nil && geo.Has(r.Tag, n)
	case CondQType:
		return qtype == r.QType
	case CondTLD:
		return n.Labels() > 0 && string(n.Label(n.Labels()-1)) == r.TLD
	}
	return false
}

// Match returns the group of the first matching rule in Order. Rules are
// sorted by Order here, stable, so input order breaks a tie the same way on
// every node. A list with no match and no final default returns false, and
// the node falls back to its default mode.
func Match(rules []Rule, n *names.Name, qtype uint16, geo GeoSites) (string, bool) {
	sorted := rules
	if !sort.SliceIsSorted(rules, func(i, j int) bool { return rules[i].Order < rules[j].Order }) {
		sorted = append([]Rule(nil), rules...)
		sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Order < sorted[j].Order })
	}
	for i := range sorted {
		if sorted[i].matches(n, qtype, geo) {
			return sorted[i].Group, true
		}
	}
	return "", false
}
