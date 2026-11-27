package hubtel

import (
	"context"
	"crypto/sha256"
	"net/netip"
	"sync"

	"github.com/google/uuid"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	"github.com/Kup1ng/CtrlZ-Shared/identity"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hublimit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// outMsg is one message an outside party can cause: exactly one field is set.
type wakeCh chan struct{}

type outMsg struct {
	learn *hubv1.LearnedIP
	proof *hubv1.ProofObservation
}

type nodeQ struct {
	node uuid.UUID
	q    []outMsg
}

// outside is L10 (5.7): a queue of OutsideQueue messages per node, worked at OutsideRate a second per node at most, on the
// outside pool, which a flood of these messages can fill without touching any other pool.
type outside struct {
	t      *Telemetry
	rate   *hublimit.Keyed // per node, before anything is queued
	learn  *hublimit.Keyed // per Endpoint: LearnPerMinute
	mu     sync.Mutex
	queues map[uuid.UUID]*nodeQ
	order  []uuid.UUID // nodes with something queued, in the order they began
	wake   wakeCh
}

func newOutside(t *Telemetry) *outside {
	return &outside{
		t:      t,
		rate:   hublimit.NewKeyed(OutsideRate, OutsideRate, t.cfg.Now),
		learn:  hublimit.NewKeyed(float64(LearnPerMinute)/60, LearnPerMinute, t.cfg.Now),
		queues: make(map[uuid.UUID]*nodeQ),
		wake:   make(wakeCh, 4),
	}
}

// offer queues a message of a node, or drops and counts it. It runs on the reader of the Control stream.
func (o *outside) offer(node uuid.UUID, m outMsg) {
	if !o.rate.Allow(node.String()) {
		o.t.dropOutsideRate.add()
		return
	}
	o.mu.Lock()
	nq := o.queues[node]
	if nq == nil {
		nq = &nodeQ{node: node}
		o.queues[node] = nq
	}
	if len(nq.q) >= OutsideQueue {
		o.mu.Unlock()
		o.t.dropOutsideFull.add()
		return
	}
	if len(nq.q) == 0 {
		o.order = append(o.order, node)
	}
	nq.q = append(nq.q, m)
	o.mu.Unlock()
	select {
	case o.wake <- struct{}{}:
	default:
	}
}

// take returns the next message, serving the nodes in turn so one node's backlog does not starve another's.
func (o *outside) take() (uuid.UUID, outMsg, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for len(o.order) > 0 {
		n := o.order[0]
		o.order = o.order[1:]
		nq := o.queues[n]
		if nq == nil || len(nq.q) == 0 {
			continue
		}
		m := nq.q[0]
		nq.q = nq.q[1:]
		if len(nq.q) > 0 {
			o.order = append(o.order, n)
		} else {
			delete(o.queues, n)
		}
		return n, m, true
	}
	return uuid.Nil, outMsg{}, false
}

func (o *outside) worker(ctx context.Context) {
	for {
		for {
			n, m, ok := o.take()
			if !ok {
				break
			}
			o.handle(ctx, n, m)
			if ctx.Err() != nil {
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-o.wake:
		}
	}
}

// Drain works every queued message on the caller's goroutine; tests use it instead of the workers.
func (t *Telemetry) Drain(ctx context.Context) {
	for {
		n, m, ok := t.out.take()
		if !ok {
			return
		}
		t.out.handle(ctx, n, m)
	}
}

func (o *outside) handle(ctx context.Context, node uuid.UUID, m outMsg) {
	if o.t.cfg.Outside == nil {
		return
	}
	wctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	switch {
	case m.learn != nil:
		o.handleLearn(wctx, node, m.learn)
	case m.proof != nil:
		o.handleProof(wctx, node, m.proof)
	}
}

func (o *outside) handleLearn(ctx context.Context, node uuid.UUID, l *hubv1.LearnedIP) {
	t := o.t
	// A learned address is a DoH one: encrypted DNS over TCP port 853 or QUIC proves nothing about a device behind a shared
	// address, and the node never sends them (7.6); one that arrives is dropped (a hub that took `dot` is a mutant).
	if l.Protocol != commonv1.Protocol_PROTOCOL_DOH && l.Protocol != commonv1.Protocol_PROTOCOL_DOH3 {
		t.dropLearnProto.add()
		return
	}
	ep, err := uuid.FromBytes(l.EndpointId)
	src, ok := netip.AddrFromSlice(l.SourceIp)
	if err != nil || !ok {
		t.dropLearnProto.add()
		return
	}
	now := t.cfg.Now()
	if t.cfg.Directory == nil || !t.cfg.Directory.Allowed(ep, node, now) {
		t.dropPair.add()
		return
	}
	if !o.learn.Allow(ep.String()) {
		t.dropLearnRate.add()
		return
	}
	tenants, err := t.cfg.Outside.HubEndpointTenants(ctx, []uuid.UUID{ep})
	tn, found := tenants[ep]
	if err != nil || !found {
		t.dropNoTenant.add()
		return
	}
	out, err := t.cfg.Outside.HubLearnIP(ctx, tn, store.HubLearn{Endpoint: ep, Source: src, Node: node})
	if err != nil {
		return
	}
	switch out {
	case store.LearnWritten, store.LearnRefreshed:
		t.wroteLearned.add()
	case store.LearnOverCap:
		t.dropLearnCap.add()
	}
}

// protocolName is the text of observed_protocol.
func protocolName(p commonv1.Protocol) string {
	switch p {
	case commonv1.Protocol_PROTOCOL_UDP:
		return "udp"
	case commonv1.Protocol_PROTOCOL_TCP:
		return "tcp"
	case commonv1.Protocol_PROTOCOL_DOH:
		return "doh"
	case commonv1.Protocol_PROTOCOL_DOH3:
		return "doh3"
	case commonv1.Protocol_PROTOCOL_DOT:
		return "dot"
	case commonv1.Protocol_PROTOCOL_DOQ:
		return "doq"
	}
	return ""
}

func (o *outside) handleProof(ctx context.Context, node uuid.UUID, p *hubv1.ProofObservation) {
	t := o.t
	src, ok := netip.AddrFromSlice(p.SourceIp)
	name := protocolName(p.Protocol)
	if !ok || name == "" || len(t.cfg.ProofKey) == 0 {
		t.dropProofInvalid.add()
		return
	}
	src = src.Unmap()
	tn, ch, claim, found, err := t.cfg.Outside.HubProofLookup(ctx, p.Label)
	if err != nil {
		return
	}
	if !found {
		t.dropProofInvalid.add()
		return
	}
	code := sha256.Sum256([]byte(identity.ProofCode(t.cfg.ProofKey, p.Label, src)))
	now := t.cfg.Now()
	out, err := t.cfg.Outside.HubProofObserve(ctx, tn, store.HubProof{
		Challenge: ch, Claim: claim, Source: src, Protocol: name, RIDHash: p.RidHash, CodeHash: code[:], Node: node,
	}, func(ep uuid.UUID) bool { return t.cfg.Directory != nil && t.cfg.Directory.Allowed(ep, node, now) })
	if err != nil {
		return
	}
	switch out {
	case store.ProofWritten:
		t.wroteProof.add()
	case store.ProofDenied:
		t.dropPair.add()
	default:
		t.dropProofOld.add()
	}
}
