package zone

import "time"

// peers returns the pair peer of every node that has one.
func peers(t *Table) map[NodeID]NodeID {
	m := map[NodeID]NodeID{}
	if t == nil {
		return m
	}
	for _, p := range t.Pairs {
		if p.HasFallback {
			m[p.Primary] = p.Fallback
			m[p.Fallback] = p.Primary
		}
	}
	return m
}

// differing returns the nodes of the hub's latest membership whose pair peer
// differs from their peer in last_table; none counts as a value.
func (e *Evaluator) differing() map[NodeID]bool {
	now, was := peers(e.member), peers(e.last)
	out := map[NodeID]bool{}
	for id := range e.member.Nodes {
		a, aok := now[id]
		b, bok := was[id]
		if aok != bok || a != b {
			out[id] = true
		}
	}
	return out
}

// tickMembership is row F0 (8a.6). It reads no tracker: the flags of
// last_table, the latest membership and revocation decide it, so the start
// event, on which every tracker is unknown, takes the same branches as a tick.
func (e *Evaluator) tickMembership(now time.Time, row Row, out []Output, commit CommitFunc) ([]Output, error) {
	diff := e.differing()
	if len(diff) == 0 {
		return out, nil
	}
	was := peers(e.last)
	cur := peers(e.member)

	// A changed pair is a pair of the latest membership with a node whose
	// peer differs.
	var changed []Pair
	touched := map[NodeID]bool{}
	for _, p := range e.member.Pairs {
		if diff[p.Primary] || (p.HasFallback && diff[p.Fallback]) {
			changed = append(changed, p)
			touched[p.Primary] = true
			if p.HasFallback {
				touched[p.Fallback] = true
			}
		}
	}
	// A leaving node had a peer in last_table and has none now.
	var leaving []NodeID
	for id := range diff {
		if _, had := was[id]; had {
			if _, has := cur[id]; !has {
				leaving = append(leaving, id)
				touched[id] = true
			}
		}
	}

	// Each step decides every changed pair and leaving node from the state the
	// step before left, and applies its changes together, so no order among
	// pairs or nodes inside a step changes the result.
	s0 := e.copyCols()
	s1 := copyMap(s0)
	for _, p := range changed {
		if _, had := was[p.Primary]; !had {
			c := s1[p.Primary]
			c.Withdrawn = true
			s1[p.Primary] = c
		}
		for _, id := range pairNodes(p) {
			if e.member.Nodes[id].Revoked {
				c := s1[id]
				c.Withdrawn = true
				s1[id] = c
			}
		}
	}
	s2 := copyMap(s1)
	for _, p := range changed {
		if !p.HasFallback || !s1[p.Primary].Withdrawn || !s1[p.Fallback].Withdrawn {
			continue
		}
		// Both would be withdrawn: the answer must still be an address of the
		// pair (invariant 2), so the fallback takes it, or the primary beside a
		// revoked fallback.
		who := p.Fallback
		if e.member.Nodes[p.Fallback].Revoked {
			who = p.Primary
		}
		c := s2[who]
		c.Withdrawn, c.Hold = false, false
		s2[who] = c
	}
	s3 := copyMap(s2)
	inPair := map[NodeID]bool{}
	for _, p := range e.member.Pairs {
		for _, id := range pairNodes(p) {
			inPair[id] = true
		}
	}
	for _, id := range leaving {
		old := was[id]
		if inPair[old] && !s2[old].Withdrawn {
			c := s3[id]
			c.Withdrawn = true
			s3[id] = c
		}
	}

	ev := &Event{Row: row.ID, At: now}
	// The alert names each node by what the whole event did to it, so a node
	// that step 1 withdrew and step 2 cleared again is not named.
	for _, id := range e.nodeIDs() {
		a, b := s0[id], s3[id]
		switch {
		case !a.Withdrawn && b.Withdrawn:
			ev.Alerts = append(ev.Alerts, Alert{Kind: row.Alert, Node: id, Named: true, Detail: DetailWithdrawn})
		case a.Withdrawn && !b.Withdrawn && a.Hold:
			ev.Alerts = append(ev.Alerts, Alert{Kind: row.Alert, Node: id, Named: true, Detail: DetailClearedHold})
		case a.Withdrawn && !b.Withdrawn:
			ev.Alerts = append(ev.Alerts, Alert{Kind: row.Alert, Node: id, Named: true, Detail: DetailCleared})
		}
	}
	if len(ev.Alerts) == 0 {
		ev.Alerts = append(ev.Alerts, Alert{Kind: row.Alert})
	}
	if err := e.apply(ev, s3, commit); err != nil {
		return out, err
	}
	// The peer of every node in a changed pair, or one that left, may be new,
	// and so may its view; whatever its inputs did before, the timers of
	// those nodes count from this event (8a.6).
	for k := range e.since {
		if touched[k.node] {
			delete(e.since, k)
		}
	}
	return append(out, Output{Event: ev}), nil
}

func pairNodes(p Pair) []NodeID {
	if p.HasFallback {
		return []NodeID{p.Primary, p.Fallback}
	}
	return []NodeID{p.Primary}
}

func copyMap(m map[NodeID]Columns) map[NodeID]Columns {
	o := make(map[NodeID]Columns, len(m))
	for k, v := range m {
		o[k] = v
	}
	return o
}
