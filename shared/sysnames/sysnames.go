// Package sysnames is the system-names table (contract section 8): names the
// service must answer correctly no matter what a profile says.
//
// Phones and laptops probe a handful of well-known hostnames to decide
// whether the network works, whether it is captive, and whether Private DNS
// is usable. If a Default Block profile answered those with 0.0.0.0, the
// device would show "no internet" or refuse the DNS server, and users would
// blame the service. So the lookup runs before identity and before any
// profile (R24), and its answers never depend on tenant policy.
//
// The table is compiled in. Changing it needs a release of panel and node,
// and Version says which table a binary carries.
package sysnames

import (
	"github.com/Kup1ng/CtrlZ-Shared/names"
)

// Version is the table version, reported in the catalog (sysnames_version).
const Version = 1

// Kind is the table row kind of the contract.
type Kind uint8

const (
	KindTrueAnswer    Kind = 1 // never blocked or redirected
	KindIsolatedSynth Kind = 2 // true answer, but a local one in Isolated mode or on failure
	KindLocal         Kind = 3 // fixed records
	KindNoData        Kind = 4 // NODATA with SOA
	KindLocalNX       Kind = 5 // NXDOMAIN with SOA, never forwarded
)

// Outcome says what the node does with this name.
type Outcome uint8

const (
	// OutcomeTrue: resolve normally and return the answer untouched.
	OutcomeTrue Outcome = iota + 1
	// OutcomeSynthDNSIP: answer A with the node's own DNS_IP (glue supplies it),
	// everything else NODATA. TTL is Entry.TTL.
	OutcomeSynthDNSIP
	// OutcomeLocal: answer Entry.Records; no records means NODATA with SOA.
	OutcomeLocal
	// OutcomeNXDomain: NXDOMAIN with SOA.
	OutcomeNXDomain
)

// Record is one fixed answer record. RData is wire form.
type Record struct {
	Type  uint16
	RData []byte
}

// Entry is the result of a lookup.
type Entry struct {
	// Pattern is the table row that matched, for logs and tests.
	Pattern string
	Kind    Kind
	Outcome Outcome
	// Records holds the answer for OutcomeLocal, already filtered by qtype.
	Records []Record
	TTL     uint32
	// FallbackSynth is set on an isolated_synth row when the node is not
	// Isolated: serve the true answer, but if the resolve fails, answer as
	// OutcomeSynthDNSIP instead of SERVFAIL. That keeps Android's check passing
	// while the upstream is down.
	FallbackSynth bool
	// Wildcard is true when the row matched a name it does not list itself: a
	// star pattern ("*.localhost", the glob row) or an "and below" row asked
	// below its own name. Such a row lets the asker pick a name that misses every
	// cache, so the node must not answer a true_answer or isolated_synth one for a
	// source with no identity except as a free query (contract 8, Queries with no
	// identity). The node used to read this from a leading star in Pattern; a
	// field cannot drift from the table the way a string test can.
	Wildcard bool
}

// Type numbers used here, kept local so this package needs only names.
const (
	typeA    = 1
	typePTR  = 12
	typeAAAA = 28
)

type matchKind uint8

const (
	mSub     matchKind = iota // strictly below the name
	mAtBelow                  // the name or anything below
	mGlob                     // one label ending in glob suffix, then the name
	mExact
)

type row struct {
	pattern string
	match   matchKind
	name    names.Name // for mGlob: the parent name
	labels  int
	glob    string // mGlob: required label suffix
	kind    Kind
	// local rows
	a, aaaa, ptr [][]byte
}

func (r *row) score() int { return r.labels*4 + int(r.match) }

// wildcardFor says whether n, which r matches, is a name the row does not list
// itself. An exact row lists only its own name. A strictly-below row and a glob
// row never match their own name. An "and below" row lists its own name and
// matches everything under it, so only a longer name is a wildcard hit.
func (r *row) wildcardFor(n *names.Name) bool {
	switch r.match {
	case mSub, mGlob:
		return true
	case mAtBelow:
		return n.Labels() > r.labels
	}
	return false
}

func (r *row) matches(n *names.Name) bool {
	switch r.match {
	case mExact:
		return n.Equal(&r.name)
	case mSub:
		return n.Labels() > r.labels && string(n.SuffixWire(r.labels)) == string(r.name.Wire())
	case mAtBelow:
		return n.Labels() >= r.labels && string(n.SuffixWire(r.labels)) == string(r.name.Wire())
	case mGlob:
		if n.Labels() != r.labels+1 || string(n.SuffixWire(r.labels)) != string(r.name.Wire()) {
			return false
		}
		l := n.Label(0)
		return len(l) >= len(r.glob) && string(l[len(l)-len(r.glob):]) == r.glob
	}
	return false
}

func mk(pattern string, m matchKind, name string, k Kind) row {
	n := names.MustString(name)
	return row{pattern: pattern, match: m, name: n, labels: n.Labels(), kind: k}
}

// table is built once at package initialisation and never modified. Names are
// the known set at the date of the contract; the Android rows must be checked
// against AOSP in P4 (contract 8, R24).
var table = buildTable()

func buildTable() []row {
	var t []row
	add := func(r row) { t = append(t, r) }
	true_ := func(name string) { add(mk(name, mExact, name, KindTrueAnswer)) }

	g := mk("*-dnsotls-ds.metric.gstatic.com", mGlob, "metric.gstatic.com", KindIsolatedSynth)
	g.glob = "-dnsotls-ds"
	add(g)
	add(mk("*.metric.gstatic.com", mSub, "metric.gstatic.com", KindTrueAnswer))
	for _, n := range []string{
		"connectivitycheck.gstatic.com", "connectivitycheck.android.com", "clients3.google.com",
		"captive.apple.com", "www.appleiphonecell.com", "www.itools.info", "www.ibook.info", "www.airport.us", "www.thinkdifferent.us",
		"www.msftconnecttest.com", "ipv6.msftconnecttest.com", "dns.msftncsi.com", "www.msftncsi.com",
	} {
		true_(n)
	}

	// ipv4only.arpa (RFC 7050) tells a client which NAT64 prefix to use. The
	// two well-known addresses make a client behind DNS64 detect it correctly.
	r := mk("ipv4only.arpa", mExact, "ipv4only.arpa", KindLocal)
	r.a = [][]byte{{192, 0, 0, 170}, {192, 0, 0, 171}}
	add(r)

	// DDR is not implemented, so say so cleanly instead of forwarding the
	// query: a client that gets NODATA stops asking.
	add(mk("resolver.arpa", mExact, "resolver.arpa", KindNoData))
	add(mk("*.resolver.arpa", mSub, "resolver.arpa", KindNoData))

	r = mk("localhost", mExact, "localhost", KindLocal)
	r.a = [][]byte{{127, 0, 0, 1}}
	r.aaaa = [][]byte{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}
	add(r)
	r = mk("*.localhost", mSub, "localhost", KindLocal)
	r.a, r.aaaa = [][]byte{{127, 0, 0, 1}}, [][]byte{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}
	add(r)

	ptrLocalhost := names.MustString("localhost")
	p4 := mk("1.0.0.127.in-addr.arpa", mExact, "1.0.0.127.in-addr.arpa", KindLocal)
	p4.ptr = [][]byte{append([]byte(nil), ptrLocalhost.Wire()...)}
	add(p4)
	v6 := "1"
	for i := 0; i < 31; i++ {
		v6 += ".0"
	}
	p6 := mk("1.0...0.ip6.arpa", mExact, v6+".ip6.arpa", KindLocal)
	p6.ptr = p4.ptr
	add(p6)

	// RFC 6303 locally served zones: private space must never leave the
	// resolver, and must not be answered by a public server that would log it.
	nx := func(zone string) { add(mk(zone, mAtBelow, zone, KindLocalNX)) }
	nx("10.in-addr.arpa")
	for i := 16; i <= 31; i++ {
		nx(itoa(i) + ".172.in-addr.arpa")
	}
	nx("168.192.in-addr.arpa")
	nx("254.169.in-addr.arpa")
	nx("d.f.ip6.arpa")
	for _, c := range []string{"8", "9", "a", "b"} {
		nx(c + ".e.f.ip6.arpa")
	}
	return t
}

func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return string(rune('0'+i/10)) + string(rune('0'+i%10))
}

const localTTL = 3600
const synthTTL = 60

func (r *row) entry(n *names.Name, qtype uint16, isolated bool) Entry {
	e := Entry{Pattern: r.pattern, Kind: r.kind, TTL: localTTL, Wildcard: r.wildcardFor(n)}
	switch r.kind {
	case KindTrueAnswer:
		e.Outcome = OutcomeTrue
	case KindIsolatedSynth:
		e.TTL = synthTTL
		if isolated {
			e.Outcome = OutcomeSynthDNSIP
		} else {
			e.Outcome = OutcomeTrue
			e.FallbackSynth = true
		}
	case KindNoData:
		e.Outcome = OutcomeLocal
	case KindLocalNX:
		e.Outcome = OutcomeNXDomain
	case KindLocal:
		e.Outcome = OutcomeLocal
		var src [][]byte
		switch qtype {
		case typeA:
			src = r.a
		case typeAAAA:
			src = r.aaaa
		case typePTR:
			src = r.ptr
		}
		for _, d := range src {
			e.Records = append(e.Records, Record{Type: qtype, RData: d})
		}
	}
	return e
}

// Lookup finds the longest-matching static row for name. isolated is the
// node's Isolated mode (panel unreachable and validation off).
func Lookup(n *names.Name, qtype uint16, isolated bool) (Entry, bool) {
	var best *row
	for i := range table {
		r := &table[i]
		if r.matches(n) && (best == nil || r.score() > best.score()) {
			best = r
		}
	}
	if best == nil {
		return Entry{}, false
	}
	return best.entry(n, qtype, isolated), true
}

// Matcher adds the hostnames that only the running node knows: the panel and
// admin hostnames from NodeConfig.panel_hostnames. They always get the true
// answer, or the operator could lock themselves out of the panel with a
// Default Block profile on the same resolver.
type Matcher struct {
	panel []names.Name
}

// NewMatcher copies the runtime hostnames.
func NewMatcher(panelHostnames []names.Name) *Matcher {
	return &Matcher{panel: append([]names.Name(nil), panelHostnames...)}
}

// Lookup is the static lookup plus the runtime hostnames. A runtime hostname
// is an exact match, so it wins over a shorter static row but not over an
// equally long one.
func (m *Matcher) Lookup(n *names.Name, qtype uint16, isolated bool) (Entry, bool) {
	e, ok := Lookup(n, qtype, isolated)
	if m == nil {
		return e, ok
	}
	for i := range m.panel {
		if m.panel[i].Equal(n) {
			if ok && e.Kind != KindTrueAnswer && e.Kind != KindIsolatedSynth {
				return e, ok
			}
			return Entry{Pattern: "panel_hostnames", Kind: KindTrueAnswer, Outcome: OutcomeTrue, TTL: localTTL}, true
		}
	}
	return e, ok
}
