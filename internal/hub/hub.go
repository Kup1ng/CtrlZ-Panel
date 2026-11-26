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
// Beside them: hubctl (the Control stream, 5.2), hubxfer (GetHead, FetchEntries, FetchBlob, GetSnapshot and
// FetchBundle), hubroll (how far each node may read, 6.4), hubsign (the policy key) and hubtel (what nodes report, 5.3 and 5.4:
// Heartbeat fields, quarantine, activity, learned addresses, proof observations, free counters). Build wires them as the
// NodeHub server unless Deps.Next gives another; hubtel needs Stores.Tel and Stores.Outside and takes its pair rule from
// Deps.Directory. What is not here yet: the revocations, the log view that is the Directory (5.5) and the failover
// evaluator (5.6); their seams are Deps.Directory, Deps.Evaluator and Hub.Roll, and UploadLogs answers Unimplemented
// until P5. Every method inherits the checks that already guard it.
package hub

import (
	"context"
	"crypto/x509"
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
	"github.com/Kup1ng/CtrlZ-Panel/internal/compiler"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubctl"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubenroll"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubfail"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubinstall"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubnet"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubnodes"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubpki"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubprobe"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubrev"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubroll"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubtel"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubtrust"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubview"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubxfer"
	"github.com/Kup1ng/CtrlZ-Panel/internal/safego"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

type unit string

const (
	unitTrust unit = "hub_trust"
	unitAddrs unit = "hub_addrs"
	unitCtl   unit = "hub_control"
)

func (u unit) Valid() bool { return u == unitTrust || u == unitAddrs || u == unitCtl }

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
	// Stream is the same control pool as Control, seen as what the Control stream reads: NodeConfig rows, the log poll, the rollout
	// order and the free DNS switch (5.2, 5.5). Nil only where a test replaces the NodeHub server.
	Stream StreamStore
	// Transfer: the config_log and snapshot reads of GetHead, FetchEntries and GetSnapshot (2 connections). Blobs and bundles are
	// files and take no connection.
	Transfer hubxfer.Log
	// Lease: the hub-decider renewal (1 connection).
	Lease hubctl.LeaseStore
	// Tel is the telemetry pool: Heartbeat fields, quarantine rows, activity, free counters and alerts (2 connections). Outside is the
	// pool for what an outside party can cause, LearnedIP and ProofObservation (2 connections). Nil in tests that replace the NodeHub
	// server; then no telemetry is taken and the uploads answer Unimplemented.
	Tel     hubtel.TelemetryStore
	Outside hubtel.OutsideStore
	// View reads the log for the hub's log view (5.5) on the control pool; Eval is the failover loop's own pool, L4 (5.6, 1 connection, a statement timeout of
	// 1 s). Nil in tests that replace the NodeHub server; then there is no log view, no revocation and no failover, and the hub decides on
	// the lease and the heartbeats alone, as it did before 5.5.
	View hubview.Store
	Eval hubfail.Store
	// Wildcards reads the uploaded wildcard rows on the control pool (the CertBundle builds' pool, 5.7). Nil serves none.
	Wildcards hubctl.WildcardRows
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
	PublicDir string
	// NTSDir is the directory the panel host's chrony reads its NTS leaf from (deploy/chrony/nts, 7.10); empty writes nothing.
	NTSDir     string
	BundlesDir string
	// DenyRootKeys are the key ids a production root must not hold; empty in lab builds and dev.
	DenyRootKeys []string
	// Next, when set, is the NodeHub server for every method but RenewCert and replaces the one Build makes (tests). Left nil,
	// Build wires the Control stream and the transfer RPCs; the uploads (5.3, 5.4) stay Unimplemented until they are built.
	Next hubv1.NodeHubServer

	// PolicyKeyPEM signs heads (3.3); ProofKey goes to nodes in NodeConfig; ArtifactsDir is the read-only volume of blobs and snapshots.
	PolicyKeyPEM []byte
	ProofKey     []byte
	ArtifactsDir string
	// Release is the release point of L12; nil is the head of the log, which holds until the evaluator of 5.6 provides one.
	Release hubroll.Release
	// Evaluator, Wildcards and Intake are the seams of 5.3 to 5.6 and the uploaded wildcard; nil is quiet.
	Evaluator hubctl.Evaluator
	Wildcards hubctl.Wildcards
	Intake    hubctl.Intake
	// WildcardKeyPEM is the hub's wildcard_intake_key (X25519, PKCS #8 PEM), the only key that opens the private key of an
	// uploaded wildcard (3.3). With it and Stores.Wildcards, and no Wildcards of the caller's own, Build serves the uploaded
	// rows (4.3); without them every zone is private-CA.
	WildcardKeyPEM []byte
	// WildcardRoots replaces the embedded public roots an uploaded chain must verify to. Only tests set it.
	WildcardRoots *x509.CertPool
	// Directory is the log view of 5.5 as the pair rule needs it; nil means no report that needs a pair is accepted.
	Directory hubtel.Directory
}

// Hub is a built hub, not yet listening.
type Hub struct {
	deps    Deps
	CA      *hubpki.NodeCA
	CAs     *hubtrust.CAs
	Leaf    *hubtrust.Leaf
	nts     *hubtrust.NTS
	Streams *hubnodes.Registry
	// Roll is the rollout state: how far each node may read.
	Roll *hubroll.Roll

	root     *hubnet.Root
	checker  *hubnodes.Checker
	recheck  *hubnodes.Rechecker
	nodeAddr *addrSet

	// The log view, the failover loop, the prober and the revocation keeper (5.5, 5.6): nil together when Stores.View or Stores.Eval is nil.
	view     *hubview.View
	fail     *hubfail.Loop
	prober   *hubprobe.Prober
	keeper   *hubrev.Keeper
	trackers *hubctl.Trackers
	arts     *compiler.DirArtifacts
	ctl      *hubctl.Server
	feed     *hubctl.Feed
	tel      *hubtel.Telemetry
	lease    *hubctl.Lease
	zones    zoneCache
	// publicRoots joins the zone CA in the probes' pool while uploaded wildcards are served: a node then presents a public chain.
	publicRoots *x509.CertPool
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

	h := &Hub{deps: d, CA: ca, CAs: cas, Leaf: leaf, Streams: hubnodes.NewRegistry(), nodeAddr: newAddrSet(), Roll: hubroll.New(hubroll.Config{Release: d.Release})}
	if d.NTSDir != "" {
		h.nts = &hubtrust.NTS{CA: ca, Dir: d.NTSDir, Hosts: d.HubHost, Now: d.Now, Alerts: d.Stores.Telemetry}
		// A leaf that cannot be written is the chrony service's problem, not the node port's: the nodes keep their own clocks
		// meanwhile, so the hub starts and the next pass of the trust loop tries again.
		h.ntsPass(ctx)
	}
	if addrs, err := d.Stores.Control.HubNodeAddrs(ctx); err == nil {
		h.nodeAddr.replace(addrs)
	}

	h.checker = &hubnodes.Checker{Open: d.Stores.L3, Clear: d.Stores.Control, Log: d.Log, Seen: h.nodeAddr.add, Reg: h.Streams, Now: d.Now}
	h.recheck = &hubnodes.Rechecker{Reg: h.Streams, Nodes: d.Stores.Control, Log: d.Log, Now: d.Now}

	enrollSrv := grpc.NewServer(grpc.MaxRecvMsgSize(hubnet.EnrollBodyBytes), grpc.ChainUnaryInterceptor(hubnodes.RecoverUnary(d.Log), hubnodes.EnrollmentGuard()), grpc.ChainStreamInterceptor(hubnodes.RecoverStream(d.Log)))
	enrollv1.RegisterEnrollmentServer(enrollSrv, &hubenroll.Service{Store: d.Stores.Enrollment, CA: ca, Now: d.Now})
	install := hubinstall.New(hubinstall.Config{
		BundlesDir: d.BundlesDir, NodeCAPEM: ca.PEM(), Tokens: d.Stores.Enrollment, Now: d.Now, Log: d.Log, DenyRootKeys: d.DenyRootKeys,
	})
	next := d.Next
	if next == nil {
		if next, err = h.nodeHub(install); err != nil {
			return nil, err
		}
	}
	nodeSrv := grpc.NewServer(grpc.ChainUnaryInterceptor(hubnodes.RecoverUnary(d.Log), h.checker.Unary()), grpc.ChainStreamInterceptor(hubnodes.RecoverStream(d.Log), h.checker.Stream(h.Streams)))
	hubv1.RegisterNodeHubServer(nodeSrv, hubnodes.NewService(next, ca, d.Stores.Control, d.Now))

	h.root = &hubnet.Root{
		Now:        d.Now,
		Enrollment: enrollSrv,
		NodeHub:    nodeSrv,
		Install:    install,
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
// beside it: the 60-second recheck of open streams, the minute check of the zone CA and the leaf, and
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
	// The rollout starts from the head the hub finds now: nothing is served from a log the hub has not read (L12).
	// The log view is read before the feed, so the head the feed starts from is one the view has applied (5.5).
	if h.view != nil {
		if err := h.view.Load(ctx, h.deps.Stores.View, h.arts); err != nil {
			return fmt.Errorf("hub: the log view cannot be read at start: %w", err)
		}
	}
	if h.feed != nil {
		if err := h.feed.Start(ctx); err != nil {
			return fmt.Errorf("hub: the log cannot be read at start: %w", err)
		}
	}
	srv := hubnet.NewServer(h.root, nil, h.deps.Log)
	mctx, stop := context.WithCancel(ctx)
	defer stop()
	var wg sync.WaitGroup
	loops := []struct {
		u  unit
		fn func(context.Context)
	}{
		{unitTrust, h.recheck.Run}, {unitTrust, h.maintainTrust}, {unitAddrs, h.refreshAddrs},
	}
	if h.feed != nil {
		loops = append(loops, struct {
			u  unit
			fn func(context.Context)
		}{unitCtl, h.lease.Run}, struct {
			u  unit
			fn func(context.Context)
		}{unitCtl, h.feed.Run})
	}
	if h.tel != nil {
		loops = append(loops, struct {
			u  unit
			fn func(context.Context)
		}{unitCtl, h.tel.Run})
	}
	if h.fail != nil {
		loops = append(loops, struct {
			u  unit
			fn func(context.Context)
		}{unitCtl, h.fail.Run}, struct {
			u  unit
			fn func(context.Context)
		}{unitCtl, h.prober.Run}, struct {
			u  unit
			fn func(context.Context)
		}{unitCtl, h.keepRevocations})
	}
	for _, loop := range loops {
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

// TrustEvery is how often the hub looks at its leaf and the zone CA. The check of the zone CA reads two
// rows and writes only when the zones, the key or the age call for a new certificate, so it runs every
// minute: a domain change must give the zone CA its new zone at once, since a zone the CA does not list
// cannot be given a certificate (4.3, 9.4), and waiting for a daily pass would leave private-CA users
// without one for up to a day.
const TrustEvery = time.Minute

// maintainTrust reissues the hub leaf when a third of its life is left and keeps the zone CA matched to
// the live zones.
func (h *Hub) maintainTrust(ctx context.Context) {
	t := time.NewTicker(TrustEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.trustPass(ctx)
		}
	}
}

func (h *Hub) trustPass(ctx context.Context) {
	defer safego.Keep(h.deps.Log, unitTrust)
	if _, err := h.Leaf.Renew(); err != nil && h.deps.Log != nil {
		h.deps.Log.Error("hub leaf renewal failed")
	}
	if err := h.CAs.EnsureZone(ctx); err != nil && h.deps.Log != nil {
		h.deps.Log.Error("zone CA check failed")
	}
	h.ntsPass(ctx)
}

// TrustPass runs one pass of that loop; tests call it instead of waiting for the ticker.
func (h *Hub) TrustPass(ctx context.Context) { h.trustPass(ctx) }

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

// StreamStore is what the Control stream and its feed read on the control pool.
type StreamStore interface {
	hubctl.ControlStore
	hubctl.FeedStore
}

// ntsPass keeps the NTS leaf of the panel host's chrony current (7.10). It logs the fact and never the cause's detail beyond
// the error class, because the error may name a path under the secrets directory.
func (h *Hub) ntsPass(ctx context.Context) {
	if h.nts == nil {
		return
	}
	if _, err := h.nts.Ensure(ctx); err != nil && h.deps.Log != nil {
		h.deps.Log.Error("NTS leaf pass failed")
	}
}
