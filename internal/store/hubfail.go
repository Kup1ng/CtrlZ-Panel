package store

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/google/uuid"
)

// The failover loop's database work (p4-nodes 5.6, SC 8a.4 State on the hub). Everything here runs on the L4 pool: one
// connection, a statement timeout of 1 s, nothing else on it (L4). The hub is the only writer of the failover columns of
// nodes, of pair_event_state and of the decision of a node_dns_requests row, and writes them only while it holds the
// hub-decider lease, so no statement here locks a row: a second writer would be a defect of the lease, and the one place it
// could show is the version check of HubFailCommit.

// ErrFailMoved says pair_event_state is not at the version the loop believed: another hub wrote it, so this one must read it
// again before it signs anything.
var ErrFailMoved = errors.New("store: pair_event_state moved")

// HubFailNode is the failover state of a node row. A zero time is NULL.
type HubFailNode struct {
	ID             uuid.UUID
	Withdrawn      bool
	Hold           bool
	LastFailbackAt time.Time
	FlapUntil      time.Time
}

// HubFailRequest is a pending row of node_dns_requests. Age is the database's now() - requested_at (8a.4 Requests): the 10 s
// bound is judged by the database clock, so a hub whose clock differs from the database's still honours it.
type HubFailRequest struct {
	ID          uuid.UUID
	Node        uuid.UUID
	Kind        string
	RequestedAt time.Time
	Age         time.Duration
}

// HubFailState is everything a tick reads, in one snapshot.
type HubFailState struct {
	Version   uint64
	LastTable []byte
	Nodes     []HubFailNode
	Requests  []HubFailRequest
}

const (
	qHubFailPair  = `SELECT version, last_table FROM ctrlz.pair_event_state`
	qHubFailNodes = `SELECT id, dns_withdrawn, dns_hold, dns_last_failback_at, dns_flap_until FROM ctrlz.nodes ORDER BY id`
	qHubFailReqs  = `SELECT id, node_id, kind, requested_at, (extract(epoch FROM (now() - requested_at)) * 1000)::bigint
FROM ctrlz.node_dns_requests WHERE state = 'pending' ORDER BY requested_at, id`
)

// HubFailRead reads pair_event_state, the failover columns of every node and the pending requests in one snapshot.
func (s *Store) HubFailRead(ctx context.Context) (st HubFailState, err error) {
	err = s.WithGlobal(ctx, TxOpts{ReadOnly: true, Isolation: RepeatableRead}, func(g GlobalTx) error {
		var v int64
		if err := g.tx.QueryRow(g.ctx, qHubFailPair).Scan(&v, &st.LastTable); err != nil {
			return sanitize(err)
		}
		st.Version = uint64(v)
		rows, err := g.tx.Query(g.ctx, qHubFailNodes)
		if err != nil {
			return sanitize(err)
		}
		for rows.Next() {
			var n HubFailNode
			var lf, fu *time.Time
			if err := rows.Scan(&n.ID, &n.Withdrawn, &n.Hold, &lf, &fu); err != nil {
				rows.Close()
				return sanitize(err)
			}
			if lf != nil {
				n.LastFailbackAt = *lf
			}
			if fu != nil {
				n.FlapUntil = *fu
			}
			st.Nodes = append(st.Nodes, n)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return sanitize(err)
		}
		rr, err := g.tx.Query(g.ctx, qHubFailReqs)
		if err != nil {
			return sanitize(err)
		}
		defer rr.Close()
		for rr.Next() {
			var q HubFailRequest
			var ms int64
			if err := rr.Scan(&q.ID, &q.Node, &q.Kind, &q.RequestedAt, &ms); err != nil {
				return sanitize(err)
			}
			q.Age = time.Duration(ms) * time.Millisecond
			st.Requests = append(st.Requests, q)
		}
		return sanitize(rr.Err())
	})
	return st, err
}

// HubFailChange is the failover state a signing event leaves a node in.
type HubFailChange struct {
	Node           uuid.UUID
	Withdrawn      bool
	Hold           bool
	LastFailbackAt time.Time
	FlapUntil      time.Time
}

// HubFailEvent is one signing event to commit. Table builds the PairTable bytes for the version the transaction chose: the
// version is max(last + 1, now in milliseconds) of the row as the transaction reads it, so the hub never signs from a cached
// version (8a.4 Versions).
type HubFailEvent struct {
	Changed []HubFailChange
	Table   func(version uint64) ([]byte, error)
	// Request is the request this event carries out, written done in the same transaction; uuid.Nil for none.
	Request uuid.UUID
	Now     time.Time
	// Last is the version the loop believes is in force. The commit fails with ErrFailMoved when the row holds another.
	Last uint64
}

const (
	qHubFailVersion = `SELECT version FROM ctrlz.pair_event_state`
	qHubFailNode    = `UPDATE ctrlz.nodes SET dns_withdrawn = $2, dns_hold = $3, dns_last_failback_at = $4, dns_flap_until = $5 WHERE id = $1`
	qHubFailWrite   = `UPDATE ctrlz.pair_event_state SET version = $1, last_table = $2 WHERE singleton AND version = $3`
	qHubFailDone    = `UPDATE ctrlz.node_dns_requests SET state = 'done', decided_at = now() WHERE id = $1 AND state = 'pending'`
)

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// HubFailCommit writes one event in one transaction: the flags of the nodes it changed, pair_event_state with the event's
// version and table, and the request it carried out. It returns the version. Nothing is signed before this returns.
func (s *Store) HubFailCommit(ctx context.Context, ev HubFailEvent) (version uint64, err error) {
	changed := append([]HubFailChange(nil), ev.Changed...)
	sort.Slice(changed, func(i, j int) bool { return lessUUID(changed[i].Node, changed[j].Node) })
	err = s.WithGlobal(ctx, TxOpts{}, func(g GlobalTx) error {
		var cur int64
		if err := g.tx.QueryRow(g.ctx, qHubFailVersion).Scan(&cur); err != nil {
			return sanitize(err)
		}
		if uint64(cur) != ev.Last {
			return ErrFailMoved
		}
		version = nextEventVersion(uint64(cur), ev.Now)
		table, err := ev.Table(version)
		if err != nil {
			return err
		}
		for _, c := range changed {
			if _, err := g.tx.Exec(g.ctx, qHubFailNode, c.Node, c.Withdrawn, c.Hold, nullTime(c.LastFailbackAt), nullTime(c.FlapUntil)); err != nil {
				return sanitize(err)
			}
		}
		tag, err := g.tx.Exec(g.ctx, qHubFailWrite, int64(version), table, cur)
		if err != nil {
			return sanitize(err)
		}
		if tag.RowsAffected() != 1 {
			return ErrFailMoved
		}
		if ev.Request != uuid.Nil {
			if _, err := g.tx.Exec(g.ctx, qHubFailDone, ev.Request); err != nil {
				return sanitize(err)
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return version, nil
}

// nextEventVersion is max(last + 1, now in Unix milliseconds) (8a.4 Versions); it is zone.NextVersion, spelled here so the
// store does not import the zone package for one line.
func nextEventVersion(last uint64, now time.Time) uint64 {
	v := last + 1
	if ms := now.UnixMilli(); ms > 0 && uint64(ms) > v {
		v = uint64(ms)
	}
	return v
}

const qHubFailDecide = `UPDATE ctrlz.node_dns_requests SET state = $2, reason = $3, decided_at = now() WHERE id = $1 AND state = 'pending'`

// HubFailDecide marks a request refused or expired (a request that was carried out is marked in the event's own transaction).
// reason is the closed refusal reason of 8a.6, empty for an expiry.
func (s *Store) HubFailDecide(ctx context.Context, id uuid.UUID, state, reason string) error {
	var r *string
	if reason != "" {
		r = &reason
	}
	return s.WithGlobal(ctx, TxOpts{}, func(g GlobalTx) error {
		_, err := g.tx.Exec(g.ctx, qHubFailDecide, id, state, r)
		return sanitize(err)
	})
}

// HubNodeState is what the hub knows of one node's return and drain, kept for the admin page (migration 0103, T-542). The hub
// decides from its memory and never reads this back: it is a view, and a start of the hub writes every row again. A zero time is
// NULL.
type HubNodeState struct {
	Node uuid.UUID
	// F3Unmet names, in the page's vocabulary, the conditions that keep a withdrawn or held node out (hub_fit, peer_view,
	// stable_period, flapping, held). Empty for a node F3 has nothing to say about.
	F3Unmet []string
	// F3DueAt is the moment F3 acts if its conditions keep holding.
	F3DueAt time.Time
	// Drain is none, draining or done; DrainSince is when the hub saw the node apply the table that stopped advertising it.
	Drain      string
	DrainSince time.Time
}

// qHubNodeState names its row by the whole primary key, so a statement that meets another on a row meets it alone: the loop
// writes the rows one at a time in node id order (HubNodeStateWrite) and the hub-decider lease makes it their only writer.
const qHubNodeState = `INSERT INTO ctrlz.node_dns_state (node_id, f3_unmet, f3_due_at, drain_state, drain_since) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (node_id) DO UPDATE SET f3_unmet = EXCLUDED.f3_unmet, f3_due_at = EXCLUDED.f3_due_at,
  drain_state = EXCLUDED.drain_state, drain_since = EXCLUDED.drain_since`

// HubNodeStateWrite writes the rows in one transaction, in node id order. A node that is not in `nodes` (removed since the hub
// read the membership) fails the batch with a foreign key error and nothing is written; the loop writes again on its next tick.
func (s *Store) HubNodeStateWrite(ctx context.Context, states []HubNodeState) error {
	rows := append([]HubNodeState(nil), states...)
	sort.Slice(rows, func(i, j int) bool { return lessUUID(rows[i].Node, rows[j].Node) })
	return s.WithGlobal(ctx, TxOpts{}, func(g GlobalTx) error {
		for _, r := range rows {
			unmet := r.F3Unmet
			if unmet == nil {
				unmet = []string{}
			}
			if _, err := g.tx.Exec(g.ctx, qHubNodeState, r.Node, unmet, nullTime(r.F3DueAt), r.Drain, nullTime(r.DrainSince)); err != nil {
				return sanitize(err)
			}
		}
		return nil
	})
}
