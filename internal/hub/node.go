package hub

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"google.golang.org/grpc"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	telemetryv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/telemetry/v1"

	"github.com/Kup1ng/CtrlZ-Panel/internal/certcheck"
	"github.com/Kup1ng/CtrlZ-Panel/internal/compiler"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubctl"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubinstall"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubsign"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubtel"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubxfer"
	"github.com/Kup1ng/CtrlZ-Panel/internal/intakeseal"
)

// nodeHub is the NodeHub server of the hub for every method but RenewCert: the Control stream (hubctl) and the transfer
// RPCs (hubxfer). It forwards by name and embeds nothing, because two embedded servers that both define Control would make
// the method ambiguous and leave the type without it. The uploads of 5.3 and 5.4 are the Unimplemented ones until built.
type nodeHub struct {
	hubv1.UnimplementedNodeHubServer
	ctl  *hubctl.Server
	xfer *hubxfer.Service
	// tel is the intake of 5.3 and 5.4; nil where the telemetry stores are not given (tests), and the uploads then answer Unimplemented.
	tel *hubtel.Telemetry
}

func (n *nodeHub) Control(s grpc.BidiStreamingServer[hubv1.NodeMessage, hubv1.HubMessage]) error {
	return n.ctl.Control(s)
}

func (n *nodeHub) GetHead(c context.Context, r *hubv1.GetHeadRequest) (*signv1.Envelope, error) {
	return n.xfer.GetHead(c, r)
}

func (n *nodeHub) FetchEntries(r *hubv1.FetchEntriesRequest, s grpc.ServerStreamingServer[hubv1.StoredEntry]) error {
	return n.xfer.FetchEntries(r, s)
}

func (n *nodeHub) FetchBlob(r *hubv1.FetchBlobRequest, s grpc.ServerStreamingServer[hubv1.BlobChunk]) error {
	return n.xfer.FetchBlob(r, s)
}

func (n *nodeHub) GetSnapshot(r *hubv1.GetSnapshotRequest, s grpc.ServerStreamingServer[hubv1.BlobChunk]) error {
	return n.xfer.GetSnapshot(r, s)
}

func (n *nodeHub) FetchBundle(r *hubv1.FetchBundleRequest, s grpc.ServerStreamingServer[hubv1.BlobChunk]) error {
	return n.xfer.FetchBundle(r, s)
}

func (n *nodeHub) ReportActivity(s grpc.BidiStreamingServer[telemetryv1.ActivityBatch, telemetryv1.Ack]) error {
	if n.tel == nil {
		return n.UnimplementedNodeHubServer.ReportActivity(s)
	}
	return n.tel.ReportActivity(s)
}

func (n *nodeHub) UploadCounters(s grpc.BidiStreamingServer[telemetryv1.CountersBatch, telemetryv1.Ack]) error {
	if n.tel == nil {
		return n.UnimplementedNodeHubServer.UploadCounters(s)
	}
	return n.tel.UploadCounters(s)
}

func (n *nodeHub) UploadLogs(s grpc.BidiStreamingServer[telemetryv1.LogBatch, telemetryv1.Ack]) error {
	if n.tel == nil {
		return n.UnimplementedNodeHubServer.UploadLogs(s)
	}
	return n.tel.UploadLogs(s)
}

// nodeHub builds the Control stream, the transfer service and what they stand on. It fails closed: a policy key that does not
// parse, a proof key too short for the validator, an artifacts directory that cannot be opened, all stop the start, so a hub that
// runs signs and serves.
func (h *Hub) nodeHub(install *hubinstall.Handler) (hubv1.NodeHubServer, error) {
	d := h.deps
	if d.Stores.Stream == nil || d.Stores.Transfer == nil || d.Stores.Lease == nil {
		return nil, errors.New("hub: the control, transfer and lease stores are not given")
	}
	signer, err := hubsign.Parse(d.PolicyKeyPEM)
	if err != nil {
		return nil, err
	}
	if len(d.ProofKey) < 16 {
		return nil, errors.New("hub: the proof key is missing or shorter than 16 bytes")
	}
	arts, err := compiler.NewDirArtifacts(d.ArtifactsDir)
	if err != nil {
		return nil, err
	}
	h.lease = hubctl.NewLease(d.Stores.Lease, uuid.NewString(), d.Now, d.Log)
	tr := hubctl.NewTrackers(d.Now)
	h.trackers, h.arts = tr, arts
	intake := d.Intake
	wild := d.Wildcards
	if wild == nil && d.Stores.Wildcards != nil && len(d.WildcardKeyPEM) > 0 {
		if err := intakeseal.CheckPrivateKey(d.WildcardKeyPEM); err != nil {
			return nil, errors.New("hub: the wildcard intake key is not an X25519 private key in PEM")
		}
		h.publicRoots = d.WildcardRoots
		if h.publicRoots == nil {
			h.publicRoots = certcheck.EmbeddedRoots()
		}
		wild = hubctl.NewUploadedWildcards(d.Stores.Wildcards, d.WildcardKeyPEM, d.Now).WithRoots(h.publicRoots)
	}
	dir, eval := h.logView(d, signer)
	if d.Stores.Tel != nil {
		h.tel = hubtel.New(hubtel.Config{
			Trackers: tr, Store: d.Stores.Tel, Outside: d.Stores.Outside, Directory: dir, ProofKey: d.ProofKey, Now: d.Now, Log: d.Log,
		})
		if intake == nil {
			intake = h.tel
		}
	}
	h.feed = &hubctl.Feed{St: d.Stores.Stream, Roll: h.Roll, Log: d.Log}
	decider := &hubctl.LeaseDecider{Lease: h.lease, Trackers: tr, Eval: eval, Streams: func() int { return h.ctl.Streams() }}
	h.ctl = hubctl.New(hubctl.Config{
		Roll: h.Roll, Store: d.Stores.Stream, Decider: decider, Trackers: tr, Free: h.feed, Intake: intake, Now: d.Now, Log: d.Log,
		Certs:     hubctl.NewCerts(h.CAs, wild, d.Now),
		Config:    &hubctl.ConfigBuilder{ProofKey: d.ProofKey, Now: d.Now},
		Accepting: h.accepting, Opened: h.opened, HeadSent: h.headSent,
	})
	h.wireFailover(d)
	h.feed.OnFreeOff = h.ctl.FreeOff
	xfer := hubxfer.New(hubxfer.Service{Log: d.Stores.Transfer, Bounds: h.Roll, Files: arts, Bundles: install, Signer: signer, Deciding: h.lease.Held, Now: d.Now, Logger: d.Log})
	return &nodeHub{ctl: h.ctl, xfer: xfer, tel: h.tel}, nil
}
