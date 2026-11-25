// Package hub is the node-facing service of the panel (p4-nodes 2, 4, 5): the one listener on the node
// port with its two gRPC servers (Enrollment with no client certificate, NodeHub with one), the install
// files, the hub's certificates and the checks of every node certificate.
//
// This package only assembles. The parts have their own packages so each can be tested alone and read
// for its one rule: hubpki (what a certificate may say), hublimit (how much one source may ask),
// hubnet (the listener and the root handler), hubenroll (Enroll and Poll), hubnodes (the check of a
// node certificate and RenewCert), hubinstall (GET /install/*) and hubtrust (the hub's own leaf and
// the CA rows).
//
// What is not here yet: the Control stream and the transfer, head and telemetry RPCs (5.2 to 5.6). The
// NodeHub server answers Unimplemented for them through the Next field of Deps; when they are built
// they are passed there and inherit the checks that already guard every method.
package hub

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"google.golang.org/grpc"

	enrollv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/enroll/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubenroll"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubinstall"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubnet"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubnodes"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubpki"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubtrust"
	"github.com/Kup1ng/CtrlZ-Panel/internal/safego"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

type unit string

const (
	unitTrust unit = "hub_trust"
	unitAddrs unit = "hub_addrs"
)

func (u unit) Valid() bool { return u == unitTrust || u == unitAddrs }

// Stores are the hub's database handles, one per pool of p4-nodes 5.7. A component is given the store
// of the pool its work belongs to and no other, so which pool a query runs on is a fact of the wiring
// that a test reads (N12) and not of each statement.
type Stores struct {
	// L3 is the check at open of every NodeHub RPC and nothing else (2 connections).
	L3 hubnodes.NodeReader
	// Control: later checks of open streams, the NodeConfig and CertBundle builds, RenewCert and the
	// prev_cert_serial clear, the node_ca and zone_ca rows, the node address set (2 connections).
	Control ControlStore
	// Telemetry carries every alerts insert of the hub (2 connections).
	Telemetry hubtrust.Alerter
	// Enrollment: Enroll, Poll and the bundle token check, with a statement timeout of 2 s (1 connection).
	Enrollment EnrollmentStore
}

// ControlStore is what the control pool is asked.
type ControlStore interface {
	hubnodes.Renewer
	hubnodes.PrevClearer
	hubtrust.Rows
	HubNodeAddrs(ctx context.Context) (store.HubAddrs, error)
}

// EnrollmentStore is what the enrollment pool is asked.
type EnrollmentStore interface {
	hubenroll.Store
	hubinstall.TokenChecker
}

// Deps is everything Build needs. Files are read by the caller, so a test builds a hub without a disk.
type Deps struct {
	Stores Stores
	Now    func() time.Time
	Log    *slog.Logger

	NodeCAKeyPEM []byte
	NodeCAPEM    []byte
	HubKeyPEM    []byte
	ZoneKeyPEM   []byte
	// HubHost is CTRLZ_HUB_HOST: the names and addresses of the hub leaf, comma separated.
	HubHost string
	// PublicDir is the volume hub_tls.spki is written to; empty writes nothing (tests).
	PublicDir  string
	BundlesDir string
	// DenyRootKeys are the key ids a production root must not hold; empty in lab builds and dev.
	DenyRootKeys []string
	// Next is the NodeHub server for every method but RenewCert (5.2 to 5.6); nil leaves them Unimplemented.
	Next hubv1.NodeHubServer
}

// Hub is a built hub, not yet listening.
type Hub struct {
	deps    Deps
	CA      *hubpki.NodeCA
	CAs     *hubtrust.CAs
	Leaf    *hubtrust.Leaf
	Streams *hubnodes.Registry

	root     *hubnet.Root
	checker  *hubnodes.Checker
	recheck  *hubnodes.Rechecker
	nodeAddr *addrSet
}

// Build reads the keys, issues the hub leaf, stores the CA rows and wires the servers. It fails
// closed: a CA certificate that does not carry its key, a host list that is not names, a database that
// cannot be written, all stop the start, so a hub that runs has its trust in place.
func Build(ctx context.Context, d Deps) (*Hub, error) {
	if d.Now == nil {
		d.Now = appclock.Now
	}
	ca, err := hubpki.LoadNodeCA(d.NodeCAKeyPEM, d.NodeCAPEM, d.Now())
	if err != nil {
		return nil, fmt.Errorf("node CA: %w", err)
	}
	hubKey, err := hubpki.ParseKey(d.HubKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("hub TLS key: %w", err)
	}
	zoneKey, err := hubpki.ParseKey(d.ZoneKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("zone CA key: %w", err)
	}
	leaf, err := hubtrust.NewLeaf(ca, hubKey, d.HubHost, d.Now)
	if err != nil {
		return nil, fmt.Errorf("hub leaf: %w", err)
	}
	if d.PublicDir != "" {
		pin, err := leaf.Pin()
		if err != nil {
			return nil, err
		}
		if err := hubtrust.WritePin(d.PublicDir, pin); err != nil {
			return nil, fmt.Errorf("pin file: %w", err)
		}
	}
	cas := &hubtrust.CAs{Node: ca, ZoneKey: zoneKey, Rows: d.Stores.Control, Alerts: d.Stores.Telemetry, Now: d.Now, Log: d.Log}
	if err := cas.EnsureNodeRow(ctx); err != nil {
		return nil, err
	}
	if err := cas.EnsureZone(ctx); err != nil {
		return nil, err
	}

	h := &Hub{deps: d, CA: ca, CAs: cas, Leaf: leaf, Streams: hubnodes.NewRegistry(), nodeAddr: newAddrSet()}
	if addrs, err := d.Stores.Control.HubNodeAddrs(ctx); err == nil {
		h.nodeAddr.replace(addrs)
	}

	h.checker = &hubnodes.Checker{Open: d.Stores.L3, Clear: d.Stores.Control, Log: d.Log, Seen: h.nodeAddr.add}
	h.recheck = &hubnodes.Rechecker{Reg: h.Streams, Nodes: d.Stores.Control, Log: d.Log}

	enrollSrv := grpc.NewServer(grpc.MaxRecvMsgSize(hubnet.EnrollBodyBytes), grpc.UnaryInterceptor(hubnodes.EnrollmentGuard()))
	enrollv1.RegisterEnrollmentServer(enrollSrv, &hubenroll.Service{Store: d.Stores.Enrollment, CA: ca, Now: d.Now})
	nodeSrv := grpc.NewServer(grpc.UnaryInterceptor(h.checker.Unary()), grpc.StreamInterceptor(h.checker.Stream(h.Streams)))
	hubv1.RegisterNodeHubServer(nodeSrv, hubnodes.NewService(d.Next, ca, d.Stores.Control, d.Now))

	h.root = &hubnet.Root{
		Now:        d.Now,
		Enrollment: enrollSrv,
		NodeHub:    nodeSrv,
		Install: hubinstall.New(hubinstall.Config{
			BundlesDir: d.BundlesDir, NodeCAPEM: ca.PEM(), Tokens: d.Stores.Enrollment, Now: d.Now, Log: d.Log, DenyRootKeys: d.DenyRootKeys,
		}),
		NodeCheck: func(ctx context.Context, method string) (hubnet.Identity, error) {
			return h.checker.CheckOpen(ctx, method)
		},
		Limits: hubnet.NewRootLimits(d.Now),
		Log:    d.Log,
	}
	return h, nil
}

// Handler is the root handler of the port, for tests that serve it themselves.
func (h *Hub) Handler() http.Handler { return h.root }

// Recheck judges every open stream against its node row once, as the 60-second loop does, and says how
// many it ended. Tests and the revocation path of 5.5 call it; nothing else needs to.
func (h *Hub) Recheck(ctx context.Context) int { return h.recheck.Pass(ctx) }

// Serve listens on ln (already bound, plain TCP) and serves until ctx ends. The maintenance loops run
// beside it: the 60-second recheck of open streams, the daily reissue checks of the CAs and the leaf, and
// the refresh of the node address set.
func (h *Hub) Serve(ctx context.Context, ln net.Listener) error {
	conns, hs, noCert, nodeConns := hubnet.NewLimits(h.deps.Now)
	tl, err := hubnet.NewListener(ln, hubnet.ListenerConfig{
		TLS: hubTLS(h.Leaf), CA: h.CA, Now: h.deps.Now, NodeAddr: h.nodeAddr.has,
		Conns: conns, Handshakes: hs, NoCert: noCert, NodeConns: nodeConns, Log: h.deps.Log,
	})
	if err != nil {
		return err
	}
	srv := hubnet.NewServer(h.root, nil, h.deps.Log)
	mctx, stop := context.WithCancel(ctx)
	defer stop()
	var wg sync.WaitGroup
	for _, loop := range []struct {
		u  unit
		fn func(context.Context)
	}{
		{unitTrust, h.recheck.Run}, {unitTrust, h.maintainTrust}, {unitAddrs, h.refreshAddrs},
	} {
		wg.Add(1)
		safego.Go(h.deps.Log, loop.u, func() { defer wg.Done(); loop.fn(mctx) })
	}
	errc := make(chan error, 1)
	safego.Go(h.deps.Log, unitTrust, func() {
		// A panic of the serve loop is a listener nobody serves: say so and stop, so Compose restarts the hub.
		var err error
		if safego.Run(h.deps.Log, unitTrust, func() { err = srv.Serve(tl) }) {
			err = errors.New("hub: the serve loop stopped by a panic")
		}
		errc <- err
	})
	var serr error
	select {
	case serr = <-errc:
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
	_ = srv.Close()
	stop()
	wg.Wait()
	if errors.Is(serr, http.ErrServerClosed) {
		serr = nil
	}
	return serr
}

// maintainTrust reissues the hub leaf when a third of its life is left and re-checks the CA rows daily.
func (h *Hub) maintainTrust(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	last := h.deps.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.trustPass(ctx, &last)
		}
	}
}

func (h *Hub) trustPass(ctx context.Context, last *time.Time) {
	defer safego.Keep(h.deps.Log, unitTrust)
	if _, err := h.Leaf.Renew(); err != nil && h.deps.Log != nil {
		h.deps.Log.Error("hub leaf renewal failed")
	}
	if now := h.deps.Now(); now.Sub(*last) >= 24*time.Hour {
		*last = now
		if err := h.CAs.EnsureZone(ctx); err != nil && h.deps.Log != nil {
			h.deps.Log.Error("zone CA check failed")
		}
	}
}

func (h *Hub) refreshAddrs(ctx context.Context) {
	t := time.NewTicker(hubnodes.RecheckEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.addrPass(ctx)
		}
	}
}

func (h *Hub) addrPass(ctx context.Context) {
	defer safego.Keep(h.deps.Log, unitAddrs)
	rctx, cancel := context.WithTimeout(ctx, hubnodes.OpenTimeout)
	defer cancel()
	if addrs, err := h.deps.Stores.Control.HubNodeAddrs(rctx); err == nil {
		h.nodeAddr.replace(addrs)
	}
}
