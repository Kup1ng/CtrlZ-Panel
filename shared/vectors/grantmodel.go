package vectors

import (
	"fmt"
	"sort"
	"strings"
)

// The Grant table of p4b-proxy 4, as a plain model. It is the reference the node's
// table (internal/grant) is checked against through the vectors of the grants group,
// so it favours being obviously right over being fast: maps and slices, no locks, no
// clock (the caller passes the time), and a string for every name and address.
//
// What it models: put (4.2), lookup and width (4.3), charging (4.3), the caps and
// the share rule (5.4, 12), the end of holders and of their connections (4.6), and
// the second node of a pair through forwarded puts (4.5). What it leaves to the
// node: the 200 ms wait for a racing put, the link, sockets and the connection
// limits that need a clock of their own.

// Constants of the model. The first two are the numbers of 4.1 and 4.4.
const (
	GrantLife         = 4 * 3600
	GrantMaxProxyTTL  = 3600
	maxEndpointsEntry = 64
	maxHoldersPerEP   = 8
	maxCountedEPs     = 8
)

// GrantLimits are the caps of 12, at the sizes a vector chooses.
type GrantLimits struct {
	GrantCap      int `json:"grant_cap"`      // holders of one Endpoint
	NodeCap       int `json:"node_cap"`       // holders on the node
	EntryConns    int `json:"entry_conns"`    // connections of an entry per Endpoint in it (at most 8 counted)
	EndpointConns int `json:"endpoint_conns"` // connections charged to one Endpoint
	NodeConns     int `json:"node_conns"`     // connections of kind 1 on the node
}

func (l GrantLimits) withDefaults() GrantLimits {
	if l.GrantCap == 0 {
		l.GrantCap = 64
	}
	if l.NodeCap == 0 {
		l.NodeCap = 1000
	}
	if l.EntryConns == 0 {
		l.EntryConns = 256
	}
	if l.EndpointConns == 0 {
		l.EndpointConns = 2048
	}
	if l.NodeConns == 0 {
		l.NodeConns = 20000
	}
	return l
}

// GrantDecision is what the deciding query of a holder says about the name: the
// Final of the evaluator, reduced to what the table keeps (4.1).
type GrantDecision struct {
	Kind      uint8    `json:"kind"`
	Pick      string   `json:"pick"` // fixed, auto or random
	Loc       uint16   `json:"loc"`
	Eff       []uint16 `json:"eff"` // the set an auto or random pick drew from
	Dial      string   `json:"dial"`
	Page      string   `json:"page"`
	Widenable bool     `json:"widenable"`
}

// GrantPut is one Put of 4.2.
type GrantPut struct {
	Name, Src, Ep, Acct, Client, Origin string
	Validated                           bool
	Claim                               bool // the source is in a claim or an authorized prefix
	// ClaimID names the claim that made the holder; a non-empty one implies Claim. A claim
	// revocation ends the holders of that claim and no other (4.6).
	ClaimID string
	Open    bool // Require Authorized IPs was off when the holder was written
	Unsafe  bool // R9: the name to dial is not public
	D       GrantDecision
}

type outcome struct {
	kind uint8
	loc  uint16
	dial string
	page string
}

func outcomeOf(d GrantDecision) outcome {
	o := outcome{kind: d.Kind, dial: d.Dial}
	if d.Kind == 1 {
		o.loc = d.Loc
	} else {
		o.page = d.Page
	}
	return o
}

type holder struct {
	ep, acct, client, origin string
	claim, open, alone       bool
	claimID                  string
	widenable                bool
	pick                     string
	expires, decided         int64
}

func (h *holder) id() string { return h.ep + "/" + h.client + "@" + h.origin }

type entry struct {
	name, src string
	out       outcome
	holders   []*holder
}

type conn struct {
	id       string
	name     string
	src      string
	charge   string // the account, or "" when shared
	ep       string // the Endpoint charged
	out      outcome
	holders  []holder // up to 8, newest deciding query first
	more     bool
	ended    map[string]bool
	entryKey string
}

// GrantNode is one node's table.
type GrantNode struct {
	lim     GrantLimits
	entries map[string]*entry
	conns   map[string]*conn
	stats   map[string]map[string]int // client ASN -> counter -> count
}

// NewGrantNode makes an empty table.
func NewGrantNode(l GrantLimits) *GrantNode {
	return &GrantNode{lim: l.withDefaults(), entries: map[string]*entry{}, conns: map[string]*conn{}, stats: map[string]map[string]int{}}
}

func ekey(name, src string) string { return name + "|" + src }

// expire drops the holders whose life has ended. The connections are not touched: a
// connection outlives its Grant (4.1).
func (n *GrantNode) expire(now int64) {
	for k, e := range n.entries {
		kept := e.holders[:0]
		for _, h := range e.holders {
			if h.expires > now {
				kept = append(kept, h)
			}
		}
		e.holders = kept
		if len(e.holders) == 0 {
			delete(n.entries, k)
		}
	}
}

func (n *GrantNode) allHolders() []*holder {
	var out []*holder
	for _, e := range n.entries {
		out = append(out, e.holders...)
	}
	return out
}

// allows is the join test of 4.2 step 3 (SC 10.3 with the live outcome as the offer):
// the same kind, a fixed target equal or the location inside the set the pick drew
// from, the same dial host, and for kind 2 the same page.
func allows(d GrantDecision, live outcome) bool {
	if d.Kind != live.kind || d.Dial != live.dial {
		return false
	}
	if d.Kind == 2 {
		return d.Page == live.page
	}
	if d.Pick == "fixed" || d.Pick == "" {
		return d.Loc == live.loc
	}
	for _, l := range d.Eff {
		if l == live.loc {
			return true
		}
	}
	return false
}

// Put is 4.2. It returns ok, validate or refused:<reason>.
func (n *GrantNode) Put(now int64, r GrantPut) string {
	r.Claim = r.Claim || r.ClaimID != ""
	n.expire(now)
	if r.D.Kind == 1 && r.Unsafe {
		return "refused:unsafe"
	}
	k := ekey(r.Name, r.Src)
	e := n.entries[k]
	out := outcomeOf(r.D)
	// A forwarded put is always validated: its sender writes and offers only holders of
	// validated sources (4.2 step 2).
	validated := r.Validated || r.Origin != ""
	if !validated {
		if e != nil {
			for _, h := range e.holders {
				if h.id() == holderID(r) && e.out == out && h.expires-now >= GrantMaxProxyTTL {
					return "ok"
				}
			}
		}
		return "validate"
	}
	newHolder := func() *holder {
		return &holder{ep: r.Ep, acct: r.Acct, client: r.Client, origin: r.Origin, claim: r.Claim, claimID: r.ClaimID, open: r.Open,
			widenable: r.D.Widenable, pick: r.D.Pick, expires: now + GrantLife, decided: now}
	}
	if e != nil {
		// Same holder, same outcome: refresh.
		for _, h := range e.holders {
			if h.id() == holderID(r) && e.out == out {
				h.expires = now + GrantLife
				if r.Origin == "" {
					h.decided = now
				}
				h.claim, h.claimID, h.open, h.widenable, h.pick = r.Claim, r.ClaimID, r.Open, r.D.Widenable, r.D.Pick
				return "ok"
			}
		}
		// Every holder is of this (Endpoint, client): its own newer decision (4.2 step 3).
		// The origin does not matter here: a copy that the pair node forwarded is the
		// same device's older decision, and judging it as another party would leave the
		// device on Bypass at this node after an edit, until the copy expired. What keeps
		// two accounts apart is the Endpoint, and no Endpoint belongs to two accounts.
		own := true
		for _, h := range e.holders {
			if !sameDevice(h, r) {
				own = false
			}
		}
		if own {
			// A refused Put changes nothing (4.2), so the outcome moves only after the holder is
			// in: when only a forwarded copy holds the entry, a new local holder needs admission
			// and a cap may refuse it.
			for _, h := range e.holders {
				if h.id() == holderID(r) {
					e.out = out
					touch(h, r, now)
					return "ok"
				}
			}
			if v := n.admit(now, r, e); v != "" {
				return v
			}
			e.out = out
			e.holders = append(e.holders, newHolder())
			return "ok"
		}
		// Join: this decision allows the live outcome. A holder of this identity that is
		// already in the entry is only refreshed.
		if allows(r.D, e.out) {
			for _, h := range e.holders {
				if h.id() == holderID(r) {
					touch(h, r, now)
					return "ok"
				}
			}
			if v := n.admit(now, r, e); v != "" {
				return v
			}
			e.holders = append(e.holders, newHolder())
			return "ok"
		}
		// Leave: the holders of this (Endpoint, client), of any origin, and for a put
		// decided here the local holders of this account with no deciding query for
		// MaxProxyTTL (a forwarded copy has no deciding query of this node to age).
		// No holder of another account.
		kept := e.holders[:0]
		for _, h := range e.holders {
			leaves := sameDevice(h, r)
			if r.Origin == "" && h.acct == r.Acct && h.origin == "" && now-h.decided >= GrantMaxProxyTTL {
				leaves = true
			}
			if !leaves {
				kept = append(kept, h)
			}
		}
		e.holders = kept
		if len(e.holders) != 0 {
			return "refused:collision"
		}
		if v := n.admit(now, r, e); v != "" {
			return v
		}
		e.out = out
		e.holders = append(e.holders, newHolder())
		return "ok"
	}
	e = &entry{name: r.Name, src: r.Src, out: out}
	if v := n.admit(now, r, e); v != "" {
		return v
	}
	e.holders = append(e.holders, newHolder())
	n.entries[k] = e
	return "ok"
}

// touch renews a holder on a deciding query of its own. A forwarded put renews the
// life but is no deciding query of this node, so it does not move decided.
func touch(h *holder, r GrantPut, now int64) {
	h.expires = now + GrantLife
	if r.Origin == "" {
		h.decided = now
	}
	h.claim, h.claimID, h.open, h.widenable, h.pick = r.Claim, r.ClaimID, r.Open, r.D.Widenable, r.D.Pick
}

// sameDevice is the (Endpoint, client) of 4.2 step 3, whatever node decided it.
func sameDevice(h *holder, r GrantPut) bool { return h.ep == r.Ep && h.client == r.Client }

func holderID(r GrantPut) string { return r.Ep + "/" + r.Client + "@" + r.Origin }

// admit judges the caps of a new holder (4.2 step 4, 12): the entry's shape, the
// Endpoint's cap and its (Endpoint, source) quarter, the last quarter that only a
// source in a claim or an authorized prefix may use, the forwarded room, and the
// node's cap under the share rule. It returns "" when the holder fits.
func (n *GrantNode) admit(now int64, r GrantPut, e *entry) string {
	eps := map[string]bool{r.Ep: true}
	same := 0
	for _, h := range e.holders {
		eps[h.ep] = true
		if h.ep == r.Ep {
			same++
		}
	}
	if len(eps) > maxEndpointsEntry || same >= maxHoldersPerEP {
		return "refused:collision"
	}
	epAll, epSrc, epFwd := 0, 0, 0
	acct := 0
	all := n.allHolders()
	for _, h := range all {
		if h.ep == r.Ep {
			epAll++
			if h.origin != "" {
				epFwd++
			}
		}
		if h.acct == r.Acct {
			acct++
		}
	}
	for _, en := range n.entries {
		if en.src != r.Src {
			continue
		}
		for _, h := range en.holders {
			if h.ep == r.Ep {
				epSrc++
			}
		}
	}
	// The Endpoint's cap counts decided and forwarded holders together, and the
	// forwarded ones may use half of it (12).
	gc := n.lim.GrantCap
	if epAll >= gc || r.Origin != "" && epFwd >= gc/2 {
		return "refused:endpoint_cap"
	}
	if epSrc >= gc/4 {
		return "refused:endpoint_cap"
	}
	if epAll >= gc-gc/4 && !r.Claim {
		return "refused:endpoint_cap"
	}
	total := len(all)
	if free := n.lim.NodeCap - total; free <= 0 || acct*8 >= free {
		return "refused:node_cap"
	}
	return ""
}

// widthKey says which holders of an entry count for a widened match (4.3 step 2): only
// those that can be widened, never a wildcard rule match.
func widenable(e *entry) []*holder {
	var out []*holder
	for _, h := range e.holders {
		if h.widenable {
			out = append(out, h)
		}
	}
	return out
}

func slash24(src string) string {
	parts := strings.Split(src, ".")
	if len(parts) != 4 {
		return ""
	}
	return strings.Join(parts[:3], ".")
}

// widened returns the one entry that a widened lookup of the name gives for the
// width, "unique" or "shared" when there is a candidate, or "" when there is none.
func (n *GrantNode) widened(width, src, name string, asn map[string]uint32) (*entry, string) {
	var cands []*entry
	for _, e := range n.entries {
		if e.name != name || e.src == src || len(e.holders) == 0 {
			continue
		}
		switch width {
		case "prefix24":
			if p := slash24(src); p == "" || slash24(e.src) != p {
				continue
			}
		case "carrier":
			if a := asn[src]; a == 0 || asn[e.src] != a {
				continue
			}
		default:
			return nil, ""
		}
		if len(widenable(e)) == 0 {
			continue
		}
		cands = append(cands, e)
	}
	if len(cands) == 0 {
		return nil, ""
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].src < cands[j].src })
	// The match holds only when every candidate belongs to one Endpoint and all share
	// one outcome.
	ep := widenable(cands[0])[0].ep
	for _, e := range cands {
		if e.out != cands[0].out {
			return nil, "shared"
		}
		for _, h := range widenable(e) {
			if h.ep != ep {
				return nil, "shared"
			}
		}
	}
	return cands[0], "unique"
}

// Lookup is 4.3: exact first, then the width in force. how is exact, widened or
// none. Every lookup that is not an exact hit counts what each width would have said
// for the client's ASN.
func (n *GrantNode) Lookup(now int64, src, name, width string, asn map[string]uint32) (*entry, string) {
	n.expire(now)
	a := fmt.Sprint(asn[src])
	count := func(c string) {
		if n.stats[a] == nil {
			n.stats[a] = map[string]int{}
		}
		n.stats[a][c]++
	}
	if e := n.entries[ekey(name, src)]; e != nil && len(e.holders) != 0 {
		count("exact")
		return e, "exact"
	}
	p, pv := n.widened("prefix24", src, name, asn)
	c, cv := n.widened("carrier", src, name, asn)
	if pv != "" {
		count("prefix24_" + pv)
	}
	if cv != "" {
		count("carrier_" + cv)
	}
	if pv == "" && cv == "" {
		count("miss")
	}
	switch width {
	case "prefix24":
		if p != nil {
			return p, "widened"
		}
	case "carrier":
		if c != nil {
			return c, "widened"
		}
	}
	return nil, "none"
}

// Open admits one connection of a proxied name (4.3 charging, 5.4). It returns none,
// refused:<cap>, charged:<account>/<endpoint> or shared.
func (n *GrantNode) Open(now int64, id, src, name, width string, asn map[string]uint32) string {
	e, how := n.Lookup(now, src, name, width, asn)
	if e == nil {
		return "none"
	}
	accts := map[string]bool{}
	eps := map[string]bool{}
	for _, h := range e.holders {
		accts[h.acct] = true
		eps[h.ep] = true
	}
	counted := len(eps)
	if counted > maxCountedEPs {
		counted = maxCountedEPs
	}
	onEntry, onEp, byAcct, total, shared := 0, map[string]int{}, map[string]int{}, 0, 0
	for _, c := range n.conns {
		total++
		if c.entryKey == ekey(e.name, e.src) {
			onEntry++
		}
		if c.charge == "" {
			shared++
		} else {
			onEp[c.ep]++
			byAcct[c.charge]++
		}
	}
	if onEntry >= n.lim.EntryConns*counted {
		return "refused:entry_cap"
	}
	free := n.lim.NodeConns - total
	c := &conn{id: id, name: name, src: src, out: e.out, entryKey: ekey(e.name, e.src), ended: map[string]bool{}}
	newest := append([]*holder(nil), e.holders...)
	sort.SliceStable(newest, func(i, j int) bool { return newest[i].decided > newest[j].decided })
	for i, h := range newest {
		if i == 8 {
			c.more = true
			break
		}
		c.holders = append(c.holders, *h)
	}
	if len(accts) == 1 {
		h := newest[0]
		if onEp[h.ep] >= n.lim.EndpointConns {
			return "refused:endpoint_cap"
		}
		if free <= 0 || byAcct[h.acct]*8 >= free {
			return "refused:node_cap"
		}
		c.charge, c.ep = h.acct, h.ep
		n.conns[id] = c
		_ = how
		return "charged:" + h.acct + "/" + h.ep
	}
	// Shared: against its entry, and the shared half of the pool, and no Endpoint's cap.
	if shared >= n.lim.NodeConns/2 || free <= 0 {
		return "refused:node_cap"
	}
	n.conns[id] = c
	return "shared"
}

// Close removes a connection.
func (n *GrantNode) Close(id string) { delete(n.conns, id) }

// End applies one cause of 4.6. The causes that end nothing (soft_disabled, a policy
// edit, a lost prefix) are listed so that a vector can pin that they do. It returns
// the sorted ids of the connections that close.
func (n *GrantNode) End(cause, ep, claimMark, origin, name string) []string {
	ends := func(h *holder) bool {
		switch cause {
		case "hard_disabled", "record_gone", "ident_changed", "revocation_endpoint", "revocation_grants_by_endpoint":
			return h.ep == ep
		case "claim_gone", "revocation_claim":
			return h.ep == ep && h.claim && h.claimID == claimMark
		case "authorized_lost":
			return h.ep == ep && h.open && !h.claim
		case "origin_removed":
			return origin != "" && h.origin == origin
		case "never_proxied":
			return false
		}
		return false
	}
	for k, e := range n.entries {
		if cause == "never_proxied" {
			if e.name == name && e.out.kind == 1 {
				e.holders = nil
			}
		} else {
			kept := e.holders[:0]
			for _, h := range e.holders {
				if !ends(h) {
					kept = append(kept, h)
				}
			}
			e.holders = kept
		}
		if len(e.holders) == 0 {
			delete(n.entries, k)
		}
	}
	var closed []string
	for id, c := range n.conns {
		for i := range c.holders {
			h := c.holders[i]
			if cause == "never_proxied" {
				if c.name == name && c.out.kind == 1 {
					c.ended[h.id()] = true
				}
			} else if ends(&h) {
				c.ended[h.id()] = true
			}
		}
		all := true
		for _, h := range c.holders {
			if !c.ended[h.id()] {
				all = false
			}
		}
		if !all {
			continue
		}
		if c.more {
			live := false
			if e := n.entries[ekey(c.name, c.src)]; e != nil && e.out == c.out {
				live = len(e.holders) != 0
			}
			if live {
				continue
			}
		}
		closed = append(closed, id)
		delete(n.conns, id)
	}
	sort.Strings(closed)
	return closed
}

// Sent records the answer to a forward: accepted clears alone, refused and unsent set it.
func (n *GrantNode) Sent(ep, name, src, result string) {
	if e := n.entries[ekey(name, src)]; e != nil {
		for _, h := range e.holders {
			if h.ep == ep && h.origin == "" {
				h.alone = result != "accepted"
			}
		}
	}
}

// Dump is the state in one line: the entries with their outcome and holders, and the
// connections with what they are charged to.
func (n *GrantNode) Dump(now int64) string {
	n.expire(now)
	var keys []string
	for k := range n.entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		e := n.entries[k]
		var hs []string
		for _, h := range e.holders {
			s := h.ep
			if h.client != "" {
				s += "/" + h.client
			}
			if h.origin != "" {
				s += "@" + h.origin
			}
			if h.alone {
				s += "!alone"
			}
			hs = append(hs, s)
		}
		sort.Strings(hs)
		s := fmt.Sprintf("%s %s kind=%d", e.name, e.src, e.out.kind)
		if e.out.kind == 1 {
			s += fmt.Sprintf(" loc=%d", e.out.loc)
		} else if e.out.page != "" {
			s += " page=" + e.out.page
		}
		if e.out.dial != "" {
			s += " dial=" + e.out.dial
		}
		parts = append(parts, s+" holders="+strings.Join(hs, ","))
	}
	var cs []string
	for id, c := range n.conns {
		who := "shared"
		if c.charge != "" {
			who = c.charge + "/" + c.ep
		}
		cs = append(cs, id+":"+who)
	}
	sort.Strings(cs)
	out := "-"
	if len(parts) != 0 {
		out = strings.Join(parts, " ; ")
	}
	if len(cs) != 0 {
		out += " | conns " + strings.Join(cs, ",")
	}
	return out
}

// Stats returns the counters of one client ASN, in a fixed order, zero ones left out.
func (n *GrantNode) Stats(asn string) string {
	var out []string
	for _, k := range []string{"exact", "prefix24_unique", "prefix24_shared", "carrier_unique", "carrier_shared", "miss"} {
		if v := n.stats[asn][k]; v != 0 {
			out = append(out, fmt.Sprintf("%s=%d", k, v))
		}
	}
	if len(out) == 0 {
		return "-"
	}
	return strings.Join(out, " ")
}
