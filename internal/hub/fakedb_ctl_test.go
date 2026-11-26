package hub_test

import (
	"context"
	"net/netip"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The reads of the Control stream and the transfer RPCs, over the same fake rows as the checks at open.

func (d *fakeDB) HubConfigLoad(_ context.Context, id uuid.UUID) (store.HubConfigRead, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := d.nodes[id]
	if n == nil {
		return store.HubConfigRead{}, nil
	}
	return store.HubConfigRead{Found: true, Status: n.status, SPKI: n.spki, ResolveMode: "recursive", DNSZone: d.zones.DNSZone,
		DNSBind: netip.MustParseAddr("10.0.0.5"), DNSAdv: netip.MustParseAddr("203.0.113.5")}, nil
}

func (d *fakeDB) HubLogHeads(_ context.Context, after uint64, limit int) ([]store.HubLogHead, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []store.HubLogHead
	for _, r := range d.log {
		if r.Seq > after && len(out) < limit {
			out = append(out, store.HubLogHead{Seq: r.Seq, Class: r.Class, Hash: r.EntryHash})
		}
	}
	return out, nil
}

func (d *fakeDB) HubLogLatest(context.Context) (store.HubLogHead, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.log) == 0 {
		return store.HubLogHead{}, false, nil
	}
	r := d.log[len(d.log)-1]
	return store.HubLogHead{Seq: r.Seq, Class: r.Class, Hash: r.EntryHash}, true, nil
}

func (d *fakeDB) HubMembership(context.Context) (store.HubMembership, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var m store.HubMembership
	slot := 0
	for id, n := range d.nodes {
		slot++
		m.Nodes = append(m.Nodes, store.MemberNode{ID: id, Status: n.status, Slot: slot})
	}
	return m, nil
}

func (d *fakeDB) HubFreeDNS(context.Context) (bool, uint64, error) { return true, 1, nil }

func (d *fakeDB) HubLogHash(_ context.Context, seq uint64) ([]byte, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, r := range d.log {
		if r.Seq == seq {
			return r.EntryHash, true, nil
		}
	}
	return nil, false, nil
}

func (d *fakeDB) HubLogEntries(_ context.Context, after, upTo uint64, limit, _ int) ([]store.LogRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []store.LogRow
	for _, r := range d.log {
		if r.Seq > after && r.Seq <= upTo && len(out) < limit {
			out = append(out, r)
		}
	}
	return out, nil
}

func (d *fakeDB) HubSnapshots(context.Context, int) ([]store.SnapshotRow, error) { return nil, nil }

func (d *fakeDB) HubLeaseTake(context.Context, string, string, int) (bool, error) { return true, nil }
