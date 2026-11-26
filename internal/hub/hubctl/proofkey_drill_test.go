package hubctl_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubctl"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubnet"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// reopen is the same node (id, key, certificate) on a new stream, as after the hub restarted.
func reopen(n *node) *node {
	ctx, cancel := context.WithCancel(hubnet.WithIdentity(context.Background(), hubnet.IdentityFrom(n.ctx)))
	return &node{id: n.id, key: n.key, peer: &peer{ctx: ctx, cancel: cancel, in: make(chan *hubv1.NodeMessage, 16), out: make(chan *hubv1.HubMessage, 64)}}
}

// configOf reads the stream until a NodeConfig comes and returns it; the test fails when none comes within the wait.
func configOf(t *testing.T, n *node) *hubv1.NodeConfig {
	t.Helper()
	for {
		select {
		case m := <-n.out:
			if c := m.GetNodeConfig(); c != nil {
				return c
			}
		case <-time.After(wait):
			t.Fatal("no NodeConfig came on the stream")
			return nil
		}
	}
}

// T-343, the proof_key recovery drill (spec 11.5, SC 8a.9 compromise step 4): the admin revokes a node, replaces the proof_key
// secret and restarts the hub. Every open stream ends with the restart; the nodes that are active come back to the restarted
// hub and each is given a NodeConfig that carries the new key and a version above the one it reported, never the old key; the
// revoked node, whose host is still up and reconnects with its valid certificate, is given no NodeConfig at all (G2), so it
// never holds the new key, and its stream ends. The key is the only secret in the message, so it is compared as bytes and
// never printed.
func TestProofKeyRotationAcrossAHubRestartReachesEveryActiveNodeAndNoRevokedOne(t *testing.T) {
	oldKey, newKey := bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32)
	hub1 := newWorld(t, free{}, func(c *hubctl.Config) { c.Config.ProofKey = oldKey })
	a, b, revoked := newNode(t), newNode(t), newNode(t)
	for _, n := range []*node{a, b, revoked} {
		hub1.active(n)
	}
	hub1.roll.SetOrder([]uuid.UUID{a.id, b.id, revoked.id})
	done := map[*node]<-chan error{}
	for _, n := range []*node{a, b, revoked} {
		done[n] = hub1.open(n)
		n.in <- heartbeat(0)
	}
	reported := map[uuid.UUID]uint64{}
	for _, n := range []*node{a, b, revoked} {
		c := configOf(t, n)
		if !bytes.Equal(c.ProofKey, oldKey) {
			t.Fatal("before the rotation the node did not get the old key")
		}
		reported[n.id] = c.Version
		n.in <- heartbeat(c.Version) // the node applied it
	}

	// Step 1: the admin revokes. Step 4: the secret is replaced and the hub restarted, which ends every stream.
	hub1.st.mu.Lock()
	hub1.st.reads[revoked.id] = store.HubConfigRead{Found: true, Status: "revoked", SPKI: revoked.spki()}
	hub1.st.mu.Unlock()
	for _, n := range []*node{a, b, revoked} {
		n.cancel()
		select {
		case <-done[n]:
		case <-time.After(wait):
			t.Fatal("a stream outlived the hub's restart")
		}
	}

	hub2 := newWorld(t, free{}, func(c *hubctl.Config) {
		c.Config.ProofKey = newKey
		c.Store = hub1.st // the same database
	})
	hub2.roll.SetOrder([]uuid.UUID{a.id, b.id})

	for _, n := range []*node{a, b} {
		again := reopen(n)
		hub2.open(again)
		again.in <- heartbeat(reported[n.id])
		c := configOf(t, again) // fails the test when the restarted hub gives an active node no NodeConfig
		if !bytes.Equal(c.ProofKey, newKey) || bytes.Equal(c.ProofKey, oldKey) {
			t.Fatal("an active node did not get the new proof_key")
		}
		if c.Version <= reported[n.id] {
			t.Fatalf("the new config has version %d, not above the %d the node holds, so the node would refuse it", c.Version, reported[n.id])
		}
	}

	// The revoked node's host is still on and its certificate still verifies: it reconnects, and gets nothing.
	again := reopen(revoked)
	ended := hub2.open(again)
	again.in <- heartbeat(reported[revoked.id])
	for {
		select {
		case m := <-again.out:
			if m.GetNodeConfig() != nil || m.GetCertBundle() != nil {
				t.Fatalf("a revoked node was sent a %T after the rotation", m.Body)
			}
		case <-ended:
			return
		case <-time.After(wait):
			t.Fatal("the revoked node's stream did not end")
		}
	}
}
