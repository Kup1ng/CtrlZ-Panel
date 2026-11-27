package vectors

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Shared/identity"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/zone"
)

// The zone-answer group (contract 15, 8a.3, 8a.10). A case gives a table (or
// none), a node's local view, a question, and the answer 8a.3 requires. The
// zone is fixed: dns.ctrlz.test, with the SOA below.

const (
	zoneAnswerZone = "dns.ctrlz.test"
	zoneAnswerSOA  = "dns.ctrlz.test. 30 IN SOA ns1.dns.ctrlz.test. hostmaster.dns.ctrlz.test. 1 3600 600 86400 30"
)

// ZoneAnswerNode is a node of a case's table, by name.
type ZoneAnswerNode struct {
	ID        string `json:"id"`
	DNSIP     string `json:"dns_ip"`
	Slot      uint32 `json:"slot"`
	Revoked   bool   `json:"revoked"`
	Withdrawn bool   `json:"withdrawn"`
}

// ZoneAnswerTable is a pair table in plain form.
type ZoneAnswerTable struct {
	Version uint64           `json:"version"`
	Nodes   []ZoneAnswerNode `json:"nodes"`
	Pairs   []FailoverPair   `json:"pairs"`
	Global  string           `json:"global"`
}

// ZoneAnswerLocal is a node's own view (8a.5).
type ZoneAnswerLocal struct {
	Self       string   `json:"self"`
	PanelStale bool     `json:"panel_stale"`
	PeerDown   []string `json:"peer_down"`
}

// ZoneAnswerEndpoint maps a resolver id to the pair its EndpointRecord names.
type ZoneAnswerEndpoint struct {
	RID  string `json:"rid"`
	Pair string `json:"pair"`
}

// ZoneAnswerAcme is an active AcmeChallenge.
type ZoneAnswerAcme struct {
	FQDN  string `json:"fqdn"`
	Value string `json:"value"`
}

// ZoneAnswerExpect is the answer a case requires.
type ZoneAnswerExpect struct {
	Rcode     string   `json:"rcode"`
	AA        bool     `json:"aa"`
	Answer    []string `json:"answer"`
	Authority []string `json:"authority"`
}

// ZoneAnswerCase is one case of the group. A null Table is a node with no
// table in use.
type ZoneAnswerCase struct {
	ID        string               `json:"id"`
	Why       string               `json:"why"`
	Table     *ZoneAnswerTable     `json:"table"`
	Local     ZoneAnswerLocal      `json:"local"`
	Endpoints []ZoneAnswerEndpoint `json:"endpoints"`
	Acme      []ZoneAnswerAcme     `json:"acme"`
	SelfIP    string               `json:"self_ip"`
	QName     string               `json:"qname"`
	QType     string               `json:"qtype"`
	Expect    ZoneAnswerExpect     `json:"expect"`
}

// ZoneQuery is what an answerer gets: the state of 8a.3 and the question.
type ZoneQuery struct {
	Table     *zone.Table
	Local     zone.Local
	Endpoints map[string]zone.PairID // resolver id to the pair its Endpoint names
	Acme      map[string][]string    // active AcmeChallenge values by fqdn
	SelfIP    netip.Addr             // the node's own DNS_IP, for the verify names
	QName     string
	QType     string
}

// ZoneAnswerer answers a ZoneQuery as the zone does. The reference one is in
// this package; the node runs the same cases through its own answerer, which
// builds real DNS messages (8a.10).
type ZoneAnswerer interface {
	Answer(q *ZoneQuery) ZoneAnswerExpect
}

// ReferenceZone is the reference ZoneAnswerer. It is a transcription of 8a.3.
type ReferenceZone struct{}

func nodata() ZoneAnswerExpect {
	return ZoneAnswerExpect{Rcode: "NOERROR", AA: true, Answer: []string{}, Authority: []string{zoneAnswerSOA}}
}

func refused() ZoneAnswerExpect {
	return ZoneAnswerExpect{Rcode: "REFUSED", Answer: []string{}, Authority: []string{}}
}

func addrRR(name string, ttl int, a netip.Addr, qtype string) (ZoneAnswerExpect, bool) {
	switch {
	case a.Is4() && qtype == "A", a.Is6() && qtype == "AAAA":
		return ZoneAnswerExpect{Rcode: "NOERROR", AA: true, Answer: []string{fmt.Sprintf("%s. %d IN %s %s", name, ttl, qtype, a)}, Authority: []string{}}, true
	}
	return ZoneAnswerExpect{}, false
}

// Answer implements ZoneAnswerer.
func (ReferenceZone) Answer(q *ZoneQuery) ZoneAnswerExpect {
	qname := strings.TrimSuffix(strings.ToLower(q.QName), ".")
	zn := names.MustString(zoneAnswerZone)
	// identity.ParseHost does not yet know "_acme-challenge.verify" as a
	// reserved name (8a.3 lists it); until it does the reference answerer
	// classifies it here.
	var h identity.Host
	if qname == "_acme-challenge.verify."+zoneAnswerZone {
		h = identity.Host{Kind: identity.HostReserved, Name: "_acme-challenge.verify"}
	} else {
		h = identity.ParseHost(qname, []names.Name{zn})
	}
	switch h.Kind {
	case identity.HostApex:
		switch q.QType {
		case "SOA":
			return ZoneAnswerExpect{Rcode: "NOERROR", AA: true, Answer: []string{zoneAnswerSOA}, Authority: []string{}}
		case "NS":
			if q.Table == nil {
				return refused()
			}
			var rrs []string
			for _, n := range zone.NameServers(q.Table) {
				rrs = append(rrs, fmt.Sprintf("%s. %d IN NS ns%d.%s.", zoneAnswerZone, zone.NSTTL, n.Slot, zoneAnswerZone))
			}
			return ZoneAnswerExpect{Rcode: "NOERROR", AA: true, Answer: rrs, Authority: []string{}}
		}
		return nodata()
	case identity.HostMalformed:
		return ZoneAnswerExpect{Rcode: "NXDOMAIN", AA: true, Answer: []string{}, Authority: []string{zoneAnswerSOA}}
	case identity.HostVerify:
		if r, ok := addrRR(qname, 0, q.SelfIP, q.QType); ok {
			return r
		}
		return nodata()
	case identity.HostResolver:
		if q.Table == nil {
			return refused()
		}
		pair := q.Endpoints[h.RID] // zero for an unknown rid: Target uses the global pair
		n, ok := zone.Target(q.Table, pair, q.Local)
		if !ok {
			return refused()
		}
		if r, ok := addrRR(qname, zone.HostTTL, n.DNSIP, q.QType); ok {
			return r
		}
		return nodata()
	case identity.HostReserved:
		switch {
		case h.Name == "verify":
			return nodata()
		case h.Name == "_acme-challenge" || h.Name == "_acme-challenge.verify":
			if q.QType == "TXT" {
				var rrs []string
				for _, v := range q.Acme[qname] {
					rrs = append(rrs, fmt.Sprintf("%s. 0 IN TXT %q", qname, v))
				}
				if len(rrs) > 0 {
					return ZoneAnswerExpect{Rcode: "NOERROR", AA: true, Answer: rrs, Authority: []string{}}
				}
			}
			return nodata()
		case strings.HasPrefix(h.Name, "ns"):
			if q.Table == nil {
				return refused()
			}
			for _, n := range zone.NameServers(q.Table) {
				if h.Name == fmt.Sprintf("ns%d", n.Slot) {
					if r, ok := addrRR(qname, zone.NSTTL, n.DNSIP, q.QType); ok {
						return r
					}
				}
			}
			return nodata()
		}
		// myip waits for identity (5.2 step 3); the zone group has no vector for it.
		return refused()
	}
	return refused()
}

// BuildZoneTable turns a case's plain table into a zone.Table through
// zone.Build, so a vector table that the validator would refuse fails the case.
func BuildZoneTable(t *ZoneAnswerTable) (*zone.Table, error) {
	if t == nil {
		return nil, nil
	}
	in := zone.BuildInput{Version: t.Version}
	for _, n := range t.Nodes {
		a, err := netip.ParseAddr(n.DNSIP)
		if err != nil {
			return nil, fmt.Errorf("node %s: %w", n.ID, err)
		}
		id := FailoverNodeID(n.ID)
		in.Nodes = append(in.Nodes, zone.BuildNode{ID: id[:], DNSIP: a.AsSlice(), Slot: n.Slot, Revoked: n.Revoked, Withdrawn: n.Withdrawn})
	}
	for _, p := range t.Pairs {
		id, pr := fPairID(p.ID), FailoverNodeID(p.Primary)
		bp := zone.BuildPair{ID: id[:], Primary: pr[:]}
		if p.Fallback != "" {
			fb := FailoverNodeID(p.Fallback)
			bp.Fallback = fb[:]
		}
		in.Pairs = append(in.Pairs, bp)
	}
	if t.Global != "" {
		g := fPairID(t.Global)
		in.Global = g[:]
	}
	return zone.Build(in)
}

// QueryOf converts a case to the query an answerer gets.
func (c *ZoneAnswerCase) QueryOf() (*ZoneQuery, error) {
	tb, err := BuildZoneTable(c.Table)
	if err != nil {
		return nil, err
	}
	q := &ZoneQuery{Table: tb, QName: c.QName, QType: c.QType, Endpoints: map[string]zone.PairID{}, Acme: map[string][]string{}}
	q.Local.Self, q.Local.PanelStale = FailoverNodeID(c.Local.Self), c.Local.PanelStale
	q.Local.PeerDown = map[zone.NodeID]bool{}
	for _, n := range c.Local.PeerDown {
		q.Local.PeerDown[FailoverNodeID(n)] = true
	}
	for _, e := range c.Endpoints {
		q.Endpoints[e.RID] = fPairID(e.Pair)
	}
	for _, a := range c.Acme {
		q.Acme[a.FQDN] = append(q.Acme[a.FQDN], a.Value)
	}
	if c.SelfIP != "" {
		if q.SelfIP, err = netip.ParseAddr(c.SelfIP); err != nil {
			return nil, err
		}
	}
	return q, nil
}

func runZoneAnswerGroup(t *testing.T, g *GroupFile) { runZoneAnswers(t, g, ReferenceZone{}) }

// RunZoneAnswers runs the zone-answer group through a ZoneAnswerer, for a
// harness whose answerer is not the reference one.
func RunZoneAnswers(t *testing.T, a ZoneAnswerer) {
	t.Helper()
	g, err := ReadGroup("zone-answer")
	if err != nil {
		t.Fatal(err)
	}
	runZoneAnswers(t, g, a)
}

func runZoneAnswers(t *testing.T, g *GroupFile, a ZoneAnswerer) {
	var cases []ZoneAnswerCase
	if err := decodeStrict(g.Cases, &cases); err != nil {
		t.Fatalf("%s: %v", g.Group, err)
	}
	if len(cases) == 0 {
		t.Fatalf("%s has no cases", g.Group)
	}
	seen := map[string]bool{}
	for i := range cases {
		c := &cases[i]
		if c.ID == "" || seen[c.ID] {
			t.Errorf("duplicate or empty case id %q", c.ID)
		}
		seen[c.ID] = true
		t.Run(c.ID, func(t *testing.T) {
			q, err := c.QueryOf()
			if err != nil {
				t.Fatalf("%v\n  case: %s", err, c.Why)
			}
			got := a.Answer(q)
			// The order of an RRset is not part of the contract; compare sorted.
			sort.Strings(got.Answer)
			want := c.Expect
			sort.Strings(want.Answer)
			if got.Rcode != want.Rcode || got.AA != want.AA || strings.Join(got.Answer, "\n") != strings.Join(want.Answer, "\n") ||
				strings.Join(got.Authority, "\n") != strings.Join(want.Authority, "\n") {
				t.Errorf("got %+v\n  want %+v\n  case: %s", got, want, c.Why)
			}
		})
	}
}
