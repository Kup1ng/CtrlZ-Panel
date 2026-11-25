package hub

import (
	"crypto/tls"
	"net/netip"
	"sync"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubtrust"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// maxSeen bounds the learned sources. There is one per node and a hub has a handful of nodes, so the
// bound is a guard and never the working set.
const maxSeen = 4096

// addrSet is the set of source addresses that belong to nodes (5.1): the addresses the database lists
// for non-revoked nodes and enrolments (replaced every 60 s), and, per node, the source of its last
// admitted connection. A node that is revoked or removed leaves the set at the next pass, so a host
// that once was a node does not keep a place in the reserved handshake slots.
type addrSet struct {
	mu   sync.RWMutex
	db   map[netip.Addr]struct{}
	seen map[uuid.UUID]netip.Addr
}

func newAddrSet() *addrSet {
	return &addrSet{db: map[netip.Addr]struct{}{}, seen: map[uuid.UUID]netip.Addr{}}
}

func (s *addrSet) replace(l store.HubAddrs) {
	m := make(map[netip.Addr]struct{}, len(l.Addrs))
	for _, a := range l.Addrs {
		m[a.Unmap()] = struct{}{}
	}
	live := make(map[uuid.UUID]struct{}, len(l.Nodes))
	for _, n := range l.Nodes {
		live[n] = struct{}{}
	}
	s.mu.Lock()
	s.db = m
	for n := range s.seen {
		if _, ok := live[n]; !ok {
			delete(s.seen, n)
		}
	}
	s.mu.Unlock()
}

func (s *addrSet) add(node uuid.UUID, a netip.Addr) {
	a = a.Unmap()
	if !a.IsValid() {
		return
	}
	s.mu.Lock()
	if _, known := s.seen[node]; known || len(s.seen) < maxSeen {
		s.seen[node] = a
	}
	s.mu.Unlock()
}

func (s *addrSet) has(a netip.Addr) bool {
	a = a.Unmap()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.db[a]; ok {
		return true
	}
	for _, v := range s.seen {
		if v == a {
			return true
		}
	}
	return false
}

// hubTLS is the TLS template of the listener: the hub leaf. The listener adds the rest.
func hubTLS(l *hubtrust.Leaf) *tls.Config {
	return &tls.Config{GetCertificate: l.GetCertificate}
}
