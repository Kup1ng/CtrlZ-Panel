package adminapi

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/adminapi/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/nodeadmin"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The routes that change the membership of the node table, the addresses of a node and the pairs (p4-nodes 4.5,
// 9.2, SC 8a.4). Each change is one transaction: the lock of the pair rule first, the rows read under it, the table the
// change would give judged by the same code the compiler and the nodes judge it by, the write, the job when one is due,
// and the audit row. No route here writes policy_outbox (T-081): the compiler finds a change of membership by comparing
// the table it would write with the log's.
//
// Lock order (rule lock-order): the pair_change or node_revoked job comes first because admin_jobs ranks before every
// table below it, so a job that is superseded is ended before any row is locked (AdminJobsSupersede); then the
// advisory locks of the two constraint triggers, then rows; the audit row is last.

// jobPairChange is the kind of the job that bumps the pair version of the Endpoints that use a pair and tells their
// tenants (p4-nodes 8). It is a function of the target state, so a newer change supersedes an unfinished job.
const jobPairChange = "pair_change"

func errNodeState() *httpx.Error { return httpx.New(http.StatusConflict, httpx.CodeNodeState) }

// queuePairChange ends the unfinished pair_change job and queues the one that covers the state after this change.
// params carry nothing: the worker reads the state, not the change.
func (s *Server) queuePairChange(g store.GlobalTx, admin uuid.UUID) error {
	if _, err := g.AdminJobInsert(jobPairChange, nil, admin); err != nil {
		return err
	}
	return nil
}

// membership reads the rows a PairTable is built from.
func membership(g store.GlobalTx) (*nodeadmin.Membership, error) {
	nodes, pairs, global, err := g.NodeMembership()
	if err != nil {
		return nil, err
	}
	return &nodeadmin.Membership{Nodes: nodes, Pairs: pairs, Global: global}, nil
}

// judge refuses a membership whose table is not valid (SC 8a.4, Valid table), in the words of the validator.
func judge(m *nodeadmin.Membership, activate uuid.UUID) error {
	if err := nodeadmin.CheckMembership(m, activate); err != nil {
		return tableInvalid(err)
	}
	return nil
}

// nodeViewOf reads a node back inside the transaction that changed it.
func nodeViewOf(g store.GlobalTx, id uuid.UUID) (gen.NodeView, error) {
	n, ok, err := g.NodeGet(id)
	if err != nil {
		return gen.NodeView{}, err
	}
	if !ok {
		return gen.NodeView{}, httpx.NotFound()
	}
	return nodeView(n), nil
}

// ApproveNode is POST /nodes/{id}:approve (4.2 step 5): pending to active, once the table with the node active is
// valid. A node that repeats an address in use is refused here with the validator's reason (SC 8a.9, Replacement order).
func (s *Server) ApproveNode(ctx context.Context, req gen.ApproveNodeRequestObject) (gen.ApproveNodeResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	var out gen.NodeView
	err = s.global(ctx, func(g store.GlobalTx) error {
		if err := g.NodePairsLock(); err != nil {
			return err
		}
		n, ok, err := g.NodeFormLock(req.Id)
		if err != nil {
			return err
		}
		if !ok {
			return httpx.NotFound()
		}
		if n.Status != "pending" {
			return errNodeState()
		}
		m, err := membership(g)
		if err != nil {
			return err
		}
		if err := judge(m, req.Id); err != nil {
			return err
		}
		if moved, err := g.NodeSetStatus(req.Id, "pending", "active"); err != nil {
			return err
		} else if !moved {
			return errNodeState()
		}
		if _, err := audit.Admin(g, s.now(), p.AdminID, httpx.ClientIPFrom(g.Context()), audit.NodeApprove{Node: req.Id}); err != nil {
			return err
		}
		out, err = nodeViewOf(g, req.Id)
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.ApproveNode200JSONResponse(out), nil
}

// RevokeNode is POST /nodes/{id}:revoke (4.5): active to revoked, which is terminal, and the node_revoked job that
// deletes what the node's reports caused. The job carries this node and the nodes of the job it supersedes, so a
// revocation that arrives while the last one's clean-up is unfinished loses nothing.
//
// The table is not judged: a revocation only empties an SPKI, which never makes a valid table invalid (SC 8a.4), and
// the answer to a compromise is never held back by the state of another row.
func (s *Server) RevokeNode(ctx context.Context, req gen.RevokeNodeRequestObject) (gen.RevokeNodeResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	var out gen.NodeView
	err = s.global(ctx, func(g store.GlobalTx) error {
		// A read without a lock decides whether this is a revocation at all, so a request for a node that is
		// not active ends no job. The row is locked below and the state read again.
		pre, ok, err := g.NodeGet(req.Id)
		if err != nil {
			return err
		}
		if !ok {
			return httpx.NotFound()
		}
		if pre.Status != "active" {
			return errNodeState()
		}
		superseded, err := g.AdminJobsSupersedeParams("node_revoked")
		if err != nil {
			return err
		}
		params, dropped, err := nodeadmin.RevokedJobParams(req.Id, superseded)
		if err != nil {
			return err
		}
		if dropped > 0 && s.d.Log != nil {
			// The revocation goes through; only the clean-up list of the oldest unfinished jobs is cut. A worker that cannot
			// finish node_revoked jobs is the cause to look for.
			s.d.Log.Warn("node_revoked clean-up list cut", "dropped", dropped)
		}
		if _, err := g.AdminJobInsert("node_revoked", params, p.AdminID); err != nil {
			return err
		}
		n, ok, err := g.NodeFormLock(req.Id)
		if err != nil {
			return err
		}
		if !ok {
			return httpx.NotFound()
		}
		if n.Status != "active" {
			return errNodeState()
		}
		if moved, err := g.NodeSetStatus(req.Id, "active", "revoked"); err != nil {
			return err
		} else if !moved {
			return errNodeState()
		}
		if _, err := audit.Admin(g, s.now(), p.AdminID, httpx.ClientIPFrom(g.Context()), audit.NodeRevoke{Node: req.Id}); err != nil {
			return err
		}
		out, err = nodeViewOf(g, req.Id)
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.RevokeNode200JSONResponse(out), nil
}

// RemoveNode is DELETE /nodes/{id} (4.5, SC 8a.4 Membership). A node leaves the table only here, and only once the pair
// change that took it out has been published and decided: it is refused while a row of node_pairs holds it, and while
// the last table the log carried or the hub's last signing event pairs it (a pending node, which no table ever held, is
// judged on neither). The addresses it gives up are written to the audit row, which the nodes page reads back.
func (s *Server) RemoveNode(ctx context.Context, req gen.RemoveNodeRequestObject) (gen.RemoveNodeResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	err = s.global(ctx, func(g store.GlobalTx) error {
		// A node that is still pending was never in a table: tables list active and revoked nodes only, a status
		// never goes back to pending, and the pair routes need an active node. Nothing is then judged, so a log
		// that holds no table cannot refuse the removal of a wrong or rogue enrolment.
		pre, ok, err := g.NodeGet(req.Id)
		if err != nil {
			return err
		}
		if !ok {
			return httpx.NotFound()
		}
		// The log is read before any lock is taken: a log that holds no table is read to its first entry, which
		// takes a while, and the node's row and node_pairs_lock must not be held for that. Under the lock only the
		// entries that came after this read are read again.
		var top int64
		var logTable []byte
		var logFound bool
		if pre.Status != "pending" {
			if top, logTable, logFound, err = g.LogLastTable(0, nodeadmin.EntryPairTable); err != nil {
				return tableReadError(err)
			}
		}
		if err := g.NodePairsLock(); err != nil {
			return err
		}
		n, ok, err := g.NodeFormLock(req.Id)
		if err != nil {
			return err
		}
		if !ok {
			return httpx.NotFound()
		}
		if paired, err := g.NodeInPair(req.Id); err != nil {
			return err
		} else if paired {
			return httpx.New(http.StatusConflict, httpx.CodeNodePaired)
		}
		if n.Status != "pending" {
			if pre.Status == "pending" {
				// Approved between the read and the lock, so the log was not read: the whole removal is tried again.
				return store.ErrConflict
			}
			_, newer, newerFound, err := g.LogLastTable(top, nodeadmin.EntryPairTable)
			if err != nil {
				return tableReadError(err)
			}
			if newerFound {
				logTable, logFound = newer, true
			}
			last, err := g.HubLastTable()
			if err != nil {
				return err
			}
			// A log that holds no table anywhere is "in no table" only when it still starts at seq 1: the node_paired
			// check above says the database pairs it nowhere, and an entry carries a table only when the membership
			// changed, so a log with tenant-only entries and no table is the normal state before the first pair. A
			// log the worker has pruned may have lost its last table, and then the hub's last event is the only
			// evidence; with none of it nothing can be judged yet, so the answer is the retry-later one. It
			// clears by itself: the hub's start event is always a signing event (SC 8a.4: F0 or the F7 refresh) that writes
			// last_table before any node is served, and F7 repeats it, so last_table stays NULL only while no hub has ever
			// run, when no table was ever served either.
			if !logFound && last == nil {
				if pruned, err := g.LogPruned(); err != nil {
					return err
				} else if pruned {
					return httpx.New(http.StatusConflict, httpx.CodeNodeInTable)
				}
			}
			inTable, err := nodeadmin.InSomeTable(logTable, last, req.Id)
			if errors.Is(err, nodeadmin.ErrTableDecode) {
				// A table nobody can read is not evidence that the node is out of it.
				return httpx.Internal()
			}
			if err != nil {
				return err
			}
			if inTable {
				return httpx.New(http.StatusConflict, httpx.CodeNodeInTable)
			}
		}
		if err := g.NodeDelete(req.Id); err != nil {
			return err
		}
		_, err = audit.Admin(g, s.now(), p.AdminID, httpx.ClientIPFrom(g.Context()), audit.NodeRemove{
			Node: req.Id, Name: audit.NodeNameOf(n.Name), OldDNSIP: oldAddr(n.DNSAdv), OldProxyIP: oldAddr(n.ProxyAdv),
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.RemoveNode204Response{}, nil
}

// tableReadError answers a stored entry that does not parse with internal, loudly, and passes any other error on.
func tableReadError(err error) error {
	if errors.Is(err, nodeadmin.ErrTableDecode) {
		return httpx.Internal()
	}
	return err
}

// oldAddr is the audit value of an address a node gives up.
func oldAddr(a *netip.Addr) audit.NodeAddr {
	if t := addrText(a); t != nil {
		return audit.NodeAddrOf(*t)
	}
	return ""
}

// PatchNode is PATCH /nodes/{id}: the name and the proxy block. The name is the admin's label, never an identity.
func (s *Server) PatchNode(ctx context.Context, req gen.PatchNodeRequestObject) (gen.PatchNodeResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	var name *string
	if req.Body.Name != nil {
		n := strings.TrimSpace(*req.Body.Name)
		if c := utf8.RuneCountInString(n); c < 1 || c > 64 {
			return nil, errValidation("name", "invalid")
		}
		name = &n
	}
	if name == nil && req.Body.ProxyBlocked == nil {
		return nil, errValidation("body", "empty")
	}
	var out gen.NodeView
	err = s.global(ctx, func(g store.GlobalTx) error {
		n, ok, err := g.NodeFormLock(req.Id)
		if err != nil {
			return err
		}
		if !ok {
			return httpx.NotFound()
		}
		if err := g.NodeUpdateForm(req.Id, name, req.Body.ProxyBlocked); err != nil {
			return err
		}
		out, err = nodeViewOf(g, req.Id)
		if err != nil {
			return err
		}
		_, err = audit.Admin(g, s.now(), p.AdminID, httpx.ClientIPFrom(g.Context()), audit.NodeUpdate{
			Node: req.Id, Renamed: name != nil && *name != n.Name, ProxyBlocked: out.ProxyBlocked,
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.PatchNode200JSONResponse(out), nil
}

// PutNodeAddresses is PUT /nodes/{id}/addresses (SC 8a.4 Admin). The old addresses are given up, and a node that is in
// a pair changes DNS1 or DNS2 for every device of the Endpoints that use the pair, which the pair_change job tells their
// tenants of.
func (s *Server) PutNodeAddresses(ctx context.Context, req gen.PutNodeAddressesRequestObject) (gen.PutNodeAddressesResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	dns, err := nodeadmin.ParseAddr(req.Body.DnsAdvertisedIp)
	if err != nil || nodeadmin.CheckAdvertised(dns) != nil {
		return nil, errAddress("dns_advertised_ip")
	}
	proxy, err := nodeadmin.ParseAddr(req.Body.ProxyAdvertisedIp)
	if err != nil || nodeadmin.CheckAdvertised(proxy) != nil {
		return nil, errAddress("proxy_advertised_ip")
	}
	var out gen.NodeView
	err = s.global(ctx, func(g store.GlobalTx) error {
		// Read without a lock to decide whether a job is due: the supersede must come before any lock.
		pre, ok, err := g.NodeGet(req.Id)
		if err != nil {
			return err
		}
		if !ok {
			return httpx.NotFound()
		}
		paired, err := g.NodeInPair(req.Id)
		if err != nil {
			return err
		}
		// A repeat of the stored addresses changes nothing, so it must also end nothing: a supersede is safe only
		// when this transaction queues the successor, and a no-change edit queues none.
		sameAddrs := func(d, x *netip.Addr) bool { return d != nil && x != nil && *d == dns && *x == proxy }
		preSame := sameAddrs(pre.DNSAdv, pre.ProxyAdv)
		if paired && !preSame {
			if _, err := g.AdminJobsSupersede(jobPairChange); err != nil {
				return err
			}
		}
		if err := g.NodePairsLock(); err != nil {
			return err
		}
		if err := g.NodeUpstreamsLock(); err != nil {
			return err
		}
		n, ok, err := g.NodeFormLock(req.Id)
		if err != nil {
			return err
		}
		if !ok {
			return httpx.NotFound()
		}
		if n.Status == "revoked" || pre.Status == "revoked" {
			return errNodeState()
		}
		if again, err := g.NodeInPair(req.Id); err != nil {
			return err
		} else if again != paired {
			// Another admin changed the pair between the read and the lock; the job decision was made on a
			// state that is gone, so this one is retried as a whole.
			return store.ErrConflict
		}
		if same := sameAddrs(n.DNSAdv, n.ProxyAdv); same != preSame {
			// The row moved between the read and the lock, after the supersede decision was made on it.
			return store.ErrConflict
		} else if same {
			out, err = nodeViewOf(g, req.Id)
			return err
		}
		if loops, err := g.UpstreamLoops(dns); err != nil {
			return err
		} else if loops {
			return httpx.New(http.StatusConflict, httpx.CodeUpstreamLoop)
		}
		if err := g.NodeSetAddresses(req.Id, dns, proxy); err != nil {
			return err
		}
		m, err := membership(g)
		if err != nil {
			return err
		}
		if err := judge(m, uuid.Nil); err != nil {
			return err
		}
		if paired {
			if err := s.queuePairChange(g, p.AdminID); err != nil {
				return err
			}
		}
		// Only an address this edit replaces is given up: the one that stays in service is not, and listing it
		// would start a 30-day wait for an address the node still serves (SC 8a.4, Addresses given up).
		var oldDNS, oldProxy audit.NodeAddr
		if n.DNSAdv == nil || *n.DNSAdv != dns {
			oldDNS = oldAddr(n.DNSAdv)
		}
		if n.ProxyAdv == nil || *n.ProxyAdv != proxy {
			oldProxy = oldAddr(n.ProxyAdv)
		}
		if _, err := audit.Admin(g, s.now(), p.AdminID, httpx.ClientIPFrom(g.Context()), audit.NodeAddressesChange{
			Node: req.Id, Name: audit.NodeNameOf(n.Name), OldDNSIP: oldDNS, OldProxyIP: oldProxy,
		}); err != nil {
			return err
		}
		out, err = nodeViewOf(g, req.Id)
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.PutNodeAddresses200JSONResponse(out), nil
}

// CreateNodeDnsRequest is POST /nodes/{id}/dns-requests (SC 8a.4, Requests). The route writes a request and no
// failover column: the hub decides it on its next tick, or lets it expire after 10 s.
func (s *Server) CreateNodeDnsRequest(ctx context.Context, req gen.CreateNodeDnsRequestRequestObject) (gen.CreateNodeDnsRequestResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	kind, ok := audit.ParseDNSRequestKind(string(req.Body.Kind))
	if !ok {
		return nil, errValidation("kind", "invalid")
	}
	var id uuid.UUID
	err = s.global(ctx, func(g store.GlobalTx) error {
		n, ok, err := g.NodeFormLock(req.Id)
		if err != nil {
			return err
		}
		if !ok {
			return httpx.NotFound()
		}
		// Only an active node has a DNS answer to hold or give back.
		if n.Status != "active" {
			return errNodeState()
		}
		if id, err = g.NodeDNSRequestInsert(req.Id, string(kind), p.AdminID); err != nil {
			return err
		}
		_, err = audit.Admin(g, s.now(), p.AdminID, httpx.ClientIPFrom(g.Context()), audit.NodeDNSRequest{Node: req.Id, Kind: kind})
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.CreateNodeDnsRequest202JSONResponse{RequestId: id}, nil
}

// ---------------------------------------------------------------------------
// Pairs

func pairView(r store.PairRow) gen.PairView {
	return gen.PairView{Id: r.ID, PrimaryNodeId: r.Primary, FallbackNodeId: r.Fallback, IsGlobal: r.IsGlobal, CreatedAt: r.CreatedAt.UTC()}
}

// ListPairs is GET /pairs.
func (s *Server) ListPairs(ctx context.Context, req gen.ListPairsRequestObject) (gen.ListPairsResponseObject, error) {
	after, err := uuidCursor(req.Params.Cursor)
	if err != nil {
		return nil, err
	}
	limit := pageLimit(req.Params.Limit)
	out := gen.PairPage{Items: []gen.PairView{}}
	err = s.readGlobal(ctx, func(g store.GlobalTx) error {
		rows, err := g.PairsPage(after, limit+1)
		if err != nil {
			return err
		}
		if len(rows) > limit {
			rows = rows[:limit]
			out.NextCursor = ptr(encodeKey(rows[len(rows)-1].ID.String()))
		}
		for _, r := range rows {
			out.Items = append(out.Items, pairView(r))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return gen.ListPairs200JSONResponse(out), nil
}

// checkPairMembers judges the two nodes of a pair against the rows read under the lock: they differ, they exist, both
// are active (a pending node is in no table and a revoked one is never given an answer to hold), and neither would have
// a second peer.
func checkPairMembers(m *nodeadmin.Membership, self, primary, fallback uuid.UUID) error {
	if primary == fallback {
		return errValidation("fallback_node_id", "same_node")
	}
	for _, f := range []struct {
		field string
		id    uuid.UUID
	}{{"primary_node_id", primary}, {"fallback_node_id", fallback}} {
		found := false
		for _, n := range m.Nodes {
			if n.ID != f.id {
				continue
			}
			found = true
			if n.Status != "active" {
				return errNodeState()
			}
		}
		if !found {
			return errValidation(f.field, "unknown_node")
		}
	}
	if nodeadmin.SecondPeer(m.Pairs, self, primary, fallback) {
		return httpx.New(http.StatusConflict, httpx.CodeSecondPeer)
	}
	return nil
}

// CreatePair is POST /pairs. The change that makes the first pair also makes it the global pair, because a table with a
// pair and no global pair is not valid (SC 8a.4).
func (s *Server) CreatePair(ctx context.Context, req gen.CreatePairRequestObject) (gen.CreatePairResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	makeGlobal := req.Body.MakeGlobal != nil && *req.Body.MakeGlobal
	var out gen.PairView
	err = s.global(ctx, func(g store.GlobalTx) error {
		if _, err := g.AdminJobsSupersede(jobPairChange); err != nil {
			return err
		}
		if err := g.NodePairsLock(); err != nil {
			return err
		}
		m, err := membership(g)
		if err != nil {
			return err
		}
		if err := checkPairMembers(m, uuid.Nil, req.Body.PrimaryNodeId, req.Body.FallbackNodeId); err != nil {
			return err
		}
		if m.Global == uuid.Nil && !makeGlobal {
			return httpx.New(http.StatusUnprocessableEntity, httpx.CodeGlobalPairNeeded)
		}
		id, err := g.PairInsert(req.Body.PrimaryNodeId, req.Body.FallbackNodeId)
		if err != nil {
			return err
		}
		if makeGlobal {
			if err := g.GlobalPairSet(id); err != nil {
				return err
			}
		}
		after, err := membership(g)
		if err != nil {
			return err
		}
		if err := judge(after, uuid.Nil); err != nil {
			return err
		}
		if err := s.queuePairChange(g, p.AdminID); err != nil {
			return err
		}
		if _, err := audit.Admin(g, s.now(), p.AdminID, httpx.ClientIPFrom(g.Context()), audit.PairCreate{Pair: id, MakeGlobal: makeGlobal}); err != nil {
			return err
		}
		row, _, err := g.PairGet(id)
		out = pairView(row)
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.CreatePair201JSONResponse(out), nil
}

// UpdatePair is PUT /pairs/{id}: new members, and with make_global the switch of the global pair to this one.
func (s *Server) UpdatePair(ctx context.Context, req gen.UpdatePairRequestObject) (gen.UpdatePairResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	makeGlobal := req.Body.MakeGlobal != nil && *req.Body.MakeGlobal
	var out gen.PairView
	err = s.global(ctx, func(g store.GlobalTx) error {
		if _, err := g.AdminJobsSupersede(jobPairChange); err != nil {
			return err
		}
		if err := g.NodePairsLock(); err != nil {
			return err
		}
		ok, err := g.PairLock(req.Id)
		if err != nil {
			return err
		}
		if !ok {
			return httpx.NotFound()
		}
		m, err := membership(g)
		if err != nil {
			return err
		}
		if err := checkPairMembers(m, req.Id, req.Body.PrimaryNodeId, req.Body.FallbackNodeId); err != nil {
			return err
		}
		if err := g.PairUpdate(req.Id, req.Body.PrimaryNodeId, req.Body.FallbackNodeId); err != nil {
			return err
		}
		if makeGlobal {
			if err := g.GlobalPairSet(req.Id); err != nil {
				return err
			}
		}
		after, err := membership(g)
		if err != nil {
			return err
		}
		if err := judge(after, uuid.Nil); err != nil {
			return err
		}
		if err := s.queuePairChange(g, p.AdminID); err != nil {
			return err
		}
		if _, err := audit.Admin(g, s.now(), p.AdminID, httpx.ClientIPFrom(g.Context()), audit.PairUpdate{Pair: req.Id, MakeGlobal: makeGlobal}); err != nil {
			return err
		}
		row, _, err := g.PairGet(req.Id)
		out = pairView(row)
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.UpdatePair200JSONResponse(out), nil
}

// DeletePair is DELETE /pairs/{id}: dissolving a pair that no Endpoint uses, the step of the replacement order that
// frees a node when none is free (SC 8a.9). In v1 an Endpoint uses a pair only as the global pair (D30), which the
// foreign key of public_settings also refuses.
func (s *Server) DeletePair(ctx context.Context, req gen.DeletePairRequestObject) (gen.DeletePairResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	err = s.global(ctx, func(g store.GlobalTx) error {
		if _, err := g.AdminJobsSupersede(jobPairChange); err != nil {
			return err
		}
		if err := g.NodePairsLock(); err != nil {
			return err
		}
		ok, err := g.PairLock(req.Id)
		if err != nil {
			return err
		}
		if !ok {
			return httpx.NotFound()
		}
		row, _, err := g.PairGet(req.Id)
		if err != nil {
			return err
		}
		if row.IsGlobal {
			return httpx.New(http.StatusConflict, httpx.CodePairInUse)
		}
		if err := g.PairDelete(req.Id); err != nil {
			return err
		}
		after, err := membership(g)
		if err != nil {
			return err
		}
		if err := judge(after, uuid.Nil); err != nil {
			return err
		}
		if err := s.queuePairChange(g, p.AdminID); err != nil {
			return err
		}
		_, err = audit.Admin(g, s.now(), p.AdminID, httpx.ClientIPFrom(g.Context()), audit.PairDelete{Pair: req.Id})
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.DeletePair204Response{}, nil
}

// PutGlobalPair is PUT /settings/global-pair. The pair is the one every Endpoint without an override uses (D30), so the
// switch is a pair change for the worker's notice (T-023).
func (s *Server) PutGlobalPair(ctx context.Context, req gen.PutGlobalPairRequestObject) (gen.PutGlobalPairResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	err = s.global(ctx, func(g store.GlobalTx) error {
		pre, ok, err := g.PairGet(req.Body.PairId)
		if err != nil {
			return err
		}
		if !ok {
			return httpx.NotFound()
		}
		if pre.IsGlobal {
			return nil // no change, so no job and no audit row
		}
		if _, err := g.AdminJobsSupersede(jobPairChange); err != nil {
			return err
		}
		if err := g.NodePairsLock(); err != nil {
			return err
		}
		if ok, err := g.PairLock(req.Body.PairId); err != nil {
			return err
		} else if !ok {
			return httpx.NotFound()
		}
		if err := g.GlobalPairSet(req.Body.PairId); err != nil {
			return err
		}
		after, err := membership(g)
		if err != nil {
			return err
		}
		if err := judge(after, uuid.Nil); err != nil {
			return err
		}
		if err := s.queuePairChange(g, p.AdminID); err != nil {
			return err
		}
		_, err = audit.Admin(g, s.now(), p.AdminID, httpx.ClientIPFrom(g.Context()), audit.GlobalPairSet{Pair: req.Body.PairId})
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.PutGlobalPair200JSONResponse{PairId: req.Body.PairId}, nil
}
