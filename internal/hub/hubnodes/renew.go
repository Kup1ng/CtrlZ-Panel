package hubnodes

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hublimit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubnet"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubpki"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// MaxCSR bounds a CSR before it is parsed.
const MaxCSR = 4096

// Renewer writes a renewal (control pool).
type Renewer interface {
	NodeReader
	HubRenewCert(ctx context.Context, node uuid.UUID, nodeSPKI []byte, presented, serial string, notBefore, notAfter time.Time) error
}

// Service is the NodeHub server: RenewCert here, everything else delegated to Next (the seam of 5.2 to
// 5.6). The interceptors of Checker have already judged the caller when a method of Service runs.
type Service struct {
	hubv1.NodeHubServer
	CA    *hubpki.NodeCA
	Store Renewer
	Now   func() time.Time
	// limit is the renewals one node may ask for: a node has no reason to renew more than a few times an
	// hour, and every renewal is a signature, an UPDATE and a node_certs row that nothing sweeps (4.3).
	limit *hublimit.Keyed
}

// Renewal limits. A node renews once in about 20 days (a third of 30), and again after a lost response
// or a restart in the middle of it; RenewBurst leaves room for those, RenewPerHour is the steady rate.
// RenewMinLifeLeft is the share of its life a certificate must have spent before it is renewed: the agent
// asks at two thirds, so a certificate with more than half of its life left is not one a healthy node
// presents.
const (
	RenewBurst       = 6
	RenewPerHour     = 6
	RenewMinLifeLeft = 2 // a certificate with more than 1/RenewMinLifeLeft of its life left is refused
)

// NewService builds the server. next may be nil, which leaves every method but RenewCert
// Unimplemented.
func NewService(next hubv1.NodeHubServer, ca *hubpki.NodeCA, st Renewer, now func() time.Time) *Service {
	if next == nil {
		next = hubv1.UnimplementedNodeHubServer{}
	}
	if now == nil {
		now = appclock.Now
	}
	return &Service{NodeHubServer: next, CA: ca, Store: st, Now: now, limit: hublimit.NewKeyed(RenewPerHour/3600.0, RenewBurst, now)}
}

// RenewCert renews the certificate of the enrolled key and of no other (SC 12, 4.3). The hub reads
// only the public key out of the CSR, refuses one whose key is not the row's, moves cert_serial to
// prev_cert_serial and writes the new serial. The response carries the new certificate and the CA chain.
func (s *Service) RenewCert(ctx context.Context, req *hubv1.RenewCertRequest) (*hubv1.RenewCertResponse, error) {
	id := hubnet.IdentityFrom(ctx)
	if !id.Node || id.Cert == nil {
		return nil, errDenied()
	}
	der := req.GetCsrDer()
	if len(der) == 0 || len(der) > MaxCSR {
		return nil, status.Error(codes.InvalidArgument, "bad request")
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "bad request")
	}
	// The key type is judged before the signature is checked, as in hubenroll.csrKey (W3-r4-4).
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() || csr.CheckSignature() != nil {
		return nil, status.Error(codes.InvalidArgument, "bad request")
	}
	spki, err := hubpki.SPKISHA256(pub)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "bad request")
	}
	// Only the key the node enrolled with: the CSR's key must be the certificate's own, which the check
	// at open tied to the row. A new key is a new enrolment (SC 12).
	if !bytes.Equal(spki, hubpki.CertSPKISHA256(id.Cert)) {
		return nil, status.Error(codes.PermissionDenied, "not the enrolled key")
	}
	now := s.Now()
	// A fresh certificate has nothing to renew. The presented certificate decides, so a node whose
	// response was lost (it still holds the older certificate, which is by then old) is never refused,
	// and an attacker with a young certificate gets no row.
	if life := id.Cert.NotAfter.Sub(id.Cert.NotBefore); id.Cert.NotAfter.Sub(now) > life/RenewMinLifeLeft {
		return nil, status.Error(codes.ResourceExhausted, "too early")
	}
	if !s.limit.Allow(id.NodeID.String()) {
		return nil, status.Error(codes.ResourceExhausted, "rate limited")
	}
	iss, err := s.CA.IssueClient(pub, id.NodeID, now)
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}
	err = s.Store.HubRenewCert(ctx, id.NodeID, spki, hubpki.SerialText(id.Cert), iss.Serial, iss.NotBefore, iss.NotAfter)
	switch {
	case err == nil:
	case errors.Is(err, store.ErrNodeGone):
		// Revoked, or the serial moved, between the check at open and the write: nothing was written.
		return nil, errDenied()
	default:
		return nil, errDown()
	}
	return &hubv1.RenewCertResponse{CertDer: iss.DER, CaChainDer: [][]byte{s.CA.CertDER()}}, nil
}
