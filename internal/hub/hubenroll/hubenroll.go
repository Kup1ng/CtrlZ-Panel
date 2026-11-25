// Package hubenroll is the Enrollment service of the hub (p4-nodes 4.2 steps 3 and 6; SC 12): Enroll
// writes the frozen record of a host that holds a live token, and Poll hands that host its certificate
// once the admin has confirmed its fingerprint and approved the node.
//
// What the service trusts. Nothing the caller says is believed past its format. The token is a bearer
// secret that is used once; the key is whatever the CSR carries, proven by the CSR's own signature; the
// addresses and the hostname are what the host reports and what the admin compares with its console
// (R19). The certificate is built from the key alone: the node id and the lifetime are the hub's.
package hubenroll

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"net/netip"
	"regexp"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Kup1ng/CtrlZ-Shared/enrollproof"
	enrollv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/enroll/v1"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubnet"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubpki"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubtoken"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Bounds of the record (3.2 item 3).
const (
	MaxCSR      = 4096
	MaxHostname = 253
	MaxFreeText = 256
)

var hostnameRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

// Store is what the service needs of the database, on the enrollment pool (5.7).
type Store interface {
	HubEnroll(ctx context.Context, in store.HubEnrollIn) (uuid.UUID, string, error)
	HubEnrollmentLoad(ctx context.Context, id uuid.UUID) (store.HubEnrollment, bool, error)
	HubIssueCert(ctx context.Context, enrollment, node uuid.UUID, nodeSPKI []byte, serial string, notBefore, notAfter time.Time, certDER []byte) (bool, error)
}

// Service implements enrollv1.EnrollmentServer.
type Service struct {
	enrollv1.UnimplementedEnrollmentServer
	Store Store
	CA    *hubpki.NodeCA
	Now   func() time.Time
}

// The answers are built at the call and not kept in variables: a status error is a value that carries its own
// state, and the module keeps no package-level mutable state.
func errBad() error     { return status.Error(codes.InvalidArgument, "bad request") }
func errRefused() error { return status.Error(codes.PermissionDenied, "refused") }
func errDown() error    { return status.Error(codes.Unavailable, "try again") }

func printable(s string) bool {
	if s == "" || len(s) > MaxFreeText {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// addr reads an address field: empty is none (when optional), else 4 or 16 bytes that are a unicast,
// specified address.
func addr(b []byte, optional bool) (netip.Addr, error) {
	if len(b) == 0 {
		if optional {
			return netip.Addr{}, nil
		}
		return netip.Addr{}, errBad()
	}
	a, ok := netip.AddrFromSlice(b)
	if !ok {
		return netip.Addr{}, errBad()
	}
	a = a.Unmap()
	if a.IsUnspecified() || a.IsMulticast() {
		return netip.Addr{}, errBad()
	}
	return a, nil
}

// csrKey parses a CSR, checks its signature (proof of possession of the key) and returns the key. Only
// ECDSA P-256 is a node key.
func csrKey(der []byte) (*ecdsa.PublicKey, error) {
	if len(der) == 0 || len(der) > MaxCSR {
		return nil, errBad()
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || csr.CheckSignature() != nil {
		return nil, errBad()
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errBad()
	}
	return pub, nil
}

// Enroll writes the record of a first Enroll with a live token (4.2 step 3). The format is checked
// before any database read; then one statement refuses a used, expired or unknown token and a source
// outside the token's bound address, with one answer for all of them.
func (s *Service) Enroll(ctx context.Context, req *enrollv1.EnrollRequest) (*enrollv1.EnrollResponse, error) {
	hash, ok := hubtoken.Parse(req.GetToken())
	if !ok {
		return nil, errBad()
	}
	pub, err := csrKey(req.GetCsrDer())
	if err != nil {
		return nil, err
	}
	spki, err := hubpki.SPKISHA256(pub)
	if err != nil {
		return nil, errBad()
	}
	host := req.GetHostname()
	if len(host) > MaxHostname || !hostnameRE.MatchString(host) {
		return nil, errBad()
	}
	if !printable(req.GetOsRelease()) || !printable(req.GetNodeVersion()) {
		return nil, errBad()
	}
	in := store.HubEnrollIn{TokenHash: hash, CSR: req.GetCsrDer(), SPKI: spki, Hostname: host, OSRelease: req.GetOsRelease(), NodeVersion: req.GetNodeVersion()}
	if in.DNSBind, err = addr(req.GetDnsBindIp(), false); err != nil {
		return nil, err
	}
	if in.DNSAdv, err = addr(req.GetDnsAdvertisedIp(), false); err != nil {
		return nil, err
	}
	if in.ProxyBind, err = addr(req.GetProxyBindIp(), true); err != nil {
		return nil, err
	}
	if in.ProxyAdv, err = addr(req.GetProxyAdvertisedIp(), true); err != nil {
		return nil, err
	}
	if in.From = hubnet.IdentityFrom(ctx).Source; !in.From.IsValid() {
		return nil, errDown()
	}
	id, fp, err := s.Store.HubEnroll(ctx, in)
	switch {
	case err == nil:
	case errors.Is(err, store.ErrEnrollRefused):
		return nil, errRefused()
	default:
		return nil, errDown()
	}
	return &enrollv1.EnrollResponse{EnrollmentId: id[:], KeyFingerprint: fp}, nil
}

func rejected() *enrollv1.PollResponse {
	return &enrollv1.PollResponse{State: enrollv1.EnrollState_ENROLL_STATE_REJECTED}
}

func pending() *enrollv1.PollResponse {
	return &enrollv1.PollResponse{State: enrollv1.EnrollState_ENROLL_STATE_PENDING}
}

// Poll answers the enrolling host (4.2 step 6). The proof of possession is checked against the key
// of the record before anything else is read from it, so a leaked enrolment id gives nothing. The
// first Poll after the node row turns active issues the certificate; later ones return it and change
// nothing, so a replayed Poll cannot move cert_serial.
func (s *Service) Poll(ctx context.Context, req *enrollv1.PollRequest) (*enrollv1.PollResponse, error) {
	idb := req.GetEnrollmentId()
	if len(idb) != enrollproof.IDLen || len(req.GetProofSig()) == 0 || len(req.GetProofSig()) > enrollproof.MaxSigLen {
		return nil, errBad()
	}
	id, err := uuid.FromBytes(idb)
	if err != nil {
		return nil, errBad()
	}
	e, found, err := s.Store.HubEnrollmentLoad(ctx, id)
	if err != nil {
		return nil, errDown()
	}
	// An unknown id, and one that has no record yet (a token that was never used), are answered like a
	// finished enrolment: rejected, which tells a prober nothing it could not guess.
	if !found || len(e.CSR) == 0 {
		return rejected(), nil
	}
	pub, err := csrKey(e.CSR)
	if err != nil {
		return rejected(), nil
	}
	if want, err := hubpki.SPKISHA256(pub); err != nil || string(want) != string(e.SPKI) {
		return rejected(), nil
	}
	if !enrollproof.Verify(pub, idb, req.GetProofSig()) {
		return nil, errRefused()
	}
	switch e.State {
	case "pending_approval":
		return pending(), nil
	case "approved":
	default: // issued, rejected, expired
		return rejected(), nil
	}
	switch e.NodeStatus {
	case "", "pending":
		return pending(), nil
	case "active":
	default: // revoked
		return rejected(), nil
	}
	// The row the admin made must carry the key this host proved: the fingerprint it confirmed.
	if string(e.NodeSPKI) != string(e.SPKI) || e.NodeID == uuid.Nil {
		return rejected(), nil
	}
	if len(e.CertDER) == 0 {
		now := s.Now()
		iss, err := s.CA.IssueClient(pub, e.NodeID, now)
		if err != nil {
			return nil, status.Error(codes.Internal, "internal error")
		}
		issued, err := s.Store.HubIssueCert(ctx, id, e.NodeID, e.SPKI, iss.Serial, iss.NotBefore, iss.NotAfter, iss.DER)
		switch {
		case err == nil:
		case errors.Is(err, store.ErrNodeGone):
			return rejected(), nil
		default:
			return nil, errDown()
		}
		if issued {
			e.CertDER = iss.DER
		} else {
			// Another Poll won: return what it stored, not what this one signed.
			e2, found, err := s.Store.HubEnrollmentLoad(ctx, id)
			if err != nil {
				return nil, errDown()
			}
			if !found || len(e2.CertDER) == 0 {
				return pending(), nil
			}
			e.CertDER = e2.CertDER
		}
	}
	return &enrollv1.PollResponse{
		State:         enrollv1.EnrollState_ENROLL_STATE_APPROVED,
		NodeId:        e.NodeID[:],
		ClientCertDer: e.CertDER,
		CaChainDer:    [][]byte{s.CA.CertDER()},
	}, nil
}
