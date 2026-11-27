package vectors

import (
	"fmt"
	"strings"
	"testing"
)

// The grants group (contract 10.4, p4b-proxy 15.1 and 15.5) runs the model of
// grantmodel.go, and the node's table (internal/grant) runs the same file through its
// own harness. A case is a script of steps on one or two nodes:
//
//	put     a Put of 4.2. Fields: name, src, ep, acct, client, origin (the node that
//	        forwarded it, empty for a decision made here), plain (a UDP query without a
//	        valid cookie), claim, claim_id (names the claim, implies claim), open, unsafe, d (the decision). expect: ok, validate or
//	        refused:<reason>.
//	lookup  expect: none, or exact or widened, then the outcome and the holders.
//	open    admit one connection: id, name, src, width, asn. expect: none,
//	        refused:<cap>, charged:<account>/<endpoint> or shared.
//	close   close a connection by id.
//	end     one cause of 4.6: cause, ep, claim_id (for the two claim causes), origin, name. expect: closed=<ids>.
//	sent    the answer to a forward (accepted, refused, unsent) for the holder of ep.
//	state   expect: the dump of the table.
//	stats   expect: the width counters of one client ASN.
//
// t is the time in seconds from the start of the case, kept from step to step.

// GrantCase is one case of the grants group.
type GrantCase struct {
	ID     string      `json:"id"`
	Why    string      `json:"why"`
	Limits GrantLimits `json:"limits"`
	Steps  []GrantStep `json:"steps"`
}

// GrantStep is one step.
type GrantStep struct {
	Op      string            `json:"op"`
	Node    string            `json:"node"`
	T       *int64            `json:"t"`
	Name    string            `json:"name"`
	Src     string            `json:"src"`
	Ep      string            `json:"ep"`
	Acct    string            `json:"acct"`
	Client  string            `json:"client"`
	Origin  string            `json:"origin"`
	Plain   bool              `json:"plain"`
	Claim   bool              `json:"claim"`
	ClaimID string            `json:"claim_id"`
	Open    bool              `json:"open"`
	Unsafe  bool              `json:"unsafe"`
	D       GrantDecision     `json:"d"`
	ID      string            `json:"id"`
	Width   string            `json:"width"`
	ASN     map[string]uint32 `json:"asn"`
	Cause   string            `json:"cause"`
	Result  string            `json:"result"`
	Expect  string            `json:"expect"`
}

func runGrantsGroup(t *testing.T, g *GroupFile) {
	var cases []GrantCase
	if err := decodeStrict(g.Cases, &cases); err != nil {
		t.Fatalf("%s: %v", g.Group, err)
	}
	seen := map[string]bool{}
	for i := range cases {
		c := &cases[i]
		if c.ID == "" || seen[c.ID] {
			t.Errorf("duplicate or empty case id %q", c.ID)
		}
		seen[c.ID] = true
		t.Run(c.ID, func(t *testing.T) {
			if msg := RunGrantCase(c); msg != "" {
				t.Errorf("%s\n  case: %s", msg, c.Why)
			}
		})
	}
}

// RunGrantCase runs one case on the reference model and returns the first step that
// differs from its expectation, or "". The node's harness has its own runner that
// reads the same GrantCase.
func RunGrantCase(c *GrantCase) string {
	nodes := map[string]*GrantNode{}
	node := func(name string) *GrantNode {
		if name == "" {
			name = "n1"
		}
		if nodes[name] == nil {
			nodes[name] = NewGrantNode(c.Limits)
		}
		return nodes[name]
	}
	var now int64
	for i, s := range c.Steps {
		if s.T != nil {
			now = *s.T
		}
		n := node(s.Node)
		var got string
		switch s.Op {
		case "put":
			got = n.Put(now, GrantPut{Name: s.Name, Src: s.Src, Ep: s.Ep, Acct: s.Acct, Client: s.Client, Origin: s.Origin,
				Validated: !s.Plain, Claim: s.Claim, ClaimID: s.ClaimID, Open: s.Open, Unsafe: s.Unsafe, D: normDecision(s.D)})
		case "lookup":
			e, how := n.Lookup(now, s.Src, s.Name, s.Width, s.ASN)
			if e == nil {
				got = "none"
			} else {
				got = how + " " + entryText(e)
			}
		case "open":
			got = n.Open(now, s.ID, s.Src, s.Name, s.Width, s.ASN)
		case "close":
			n.Close(s.ID)
			continue
		case "end":
			ids := n.End(s.Cause, s.Ep, s.ClaimID, s.Origin, s.Name)
			got = "closed=" + strings.Join(ids, ",")
			if len(ids) == 0 {
				got = "closed=-"
			}
		case "sent":
			n.Sent(s.Ep, s.Name, s.Src, s.Result)
			continue
		case "state":
			got = n.Dump(now)
		case "stats":
			got = n.Stats(s.ID)
		case "tick":
			continue
		default:
			return fmt.Sprintf("step %d: unknown op %q", i, s.Op)
		}
		if got != s.Expect {
			return fmt.Sprintf("step %d (%s): got %q, want %q", i, s.Op, got, s.Expect)
		}
	}
	return ""
}

func normDecision(d GrantDecision) GrantDecision {
	if d.Pick == "" {
		d.Pick = "fixed"
	}
	return d
}

// entryText is the entry in the form of the dump, without its key.
func entryText(e *entry) string {
	n := &GrantNode{entries: map[string]*entry{ekey(e.name, e.src): e}, conns: map[string]*conn{}}
	return n.Dump(0)
}
