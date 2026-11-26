package adminapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/adminapi/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/certcheck"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/intakeseal"
	"github.com/Kup1ng/CtrlZ-Panel/internal/nodeadmin"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The certificate routes (p4-nodes 4.3, 9.2). An upload is checked in full before anything is stored. The private key is
// parsed, compared with the leaf, written as PKCS #8 and sealed to the intake public key of its kind in one step, and the
// plaintext is never kept: not in the row, not in the audit row, not in an error, not in the answer. The admin holds no
// private half of an intake key, so it cannot read back what it stored.

// certError maps a refusal of certcheck to its code and the field that failed.
func certError(err error) error {
	field := "chain_pem"
	var code string
	switch {
	case errors.Is(err, certcheck.ErrKeyMismatch):
		code, field = httpx.CodeCertKeyMismatch, "key_pem"
	case errors.Is(err, certcheck.ErrNotPublic):
		code = httpx.CodeCertNotPublic
	case errors.Is(err, certcheck.ErrExpiring):
		code = httpx.CodeCertExpiring
	case errors.Is(err, certcheck.ErrInvalid):
		code = httpx.CodeCertInvalid
	default:
		return err
	}
	return httpx.New(http.StatusUnprocessableEntity, code).WithFields(httpx.FieldError{Name: field, Code: "refused"})
}

// scopeFor is what a certificate of a kind must cover now: the live zones for a wildcard, the host for panel and admin.
func (s *Server) scopeFor(kind certcheck.Kind, d store.DomainSettings, now time.Time) certcheck.Scope {
	if kind == certcheck.Wildcard {
		st := nodeadmin.DomainState{DNSZone: d.DNSZone, PrevDNSZone: d.PrevDNSZone, TransitionUntil: d.TransitionUntil}
		return certcheck.Scope{Zones: st.LiveZones(now)}
	}
	return certcheck.Scope{Host: s.hostForChoice(kind, d)}
}

// UploadCertificate is POST /certificates.
func (s *Server) UploadCertificate(ctx context.Context, req gen.UploadCertificateRequestObject) (gen.UploadCertificateResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	if s.d.Intake == nil {
		return nil, httpx.Unavailable()
	}
	kind := certcheck.Kind(req.Body.Kind)
	purpose, pub := intakeseal.Web, s.d.Intake.Web
	if kind == certcheck.Wildcard {
		purpose, pub = intakeseal.Wildcard, s.d.Intake.Wildcard
	}
	if !kind.Valid() {
		return nil, errValidation("kind", "invalid")
	}
	// The key is read before the database is asked for anything, so a body that is not a key costs no transaction.
	keyPublic, keyPKCS8, err := certcheck.ParseKey([]byte(req.Body.KeyPem))
	if err != nil {
		return nil, httpx.New(http.StatusUnprocessableEntity, httpx.CodeCertInvalid).WithFields(httpx.FieldError{Name: "key_pem", Code: "refused"})
	}
	// What the certificate must cover comes from the settings, read in a transaction of its own: the chain is verified
	// against the embedded roots outside any transaction, which keeps a connection free of that work.
	now := s.now()
	var settings store.DomainSettings
	if err := s.readGlobal(ctx, func(g store.GlobalTx) (err error) {
		settings, err = g.DomainGet()
		return err
	}); err != nil {
		return nil, err
	}
	res, err := certcheck.Check([]byte(req.Body.ChainPem), kind, s.scopeFor(kind, settings, now), now,
		certcheck.Options{KeyPublic: keyPublic, MinLife: certcheck.MinUploadLife, Roots: s.d.certRoots})
	if err != nil {
		return nil, certError(err)
	}
	sealed, err := intakeseal.Seal(pub, purpose, keyPKCS8)
	if err != nil {
		return nil, err // a broken intake key is the deployment's fault; the text names no key
	}
	var out gen.CertificateCreated
	err = s.global(ctx, func(g store.GlobalTx) error {
		id, err := g.CertInsertUploaded(string(kind), res.ChainPEM, sealed, res.NotBefore.UTC(), res.NotAfter.UTC(), res.Names)
		if err != nil {
			return err
		}
		if _, err := audit.Admin(g, s.now(), p.AdminID, httpx.ClientIPFrom(g.Context()), audit.CertificateUpload{Certificate: id, Kind: audit.CertKind(kind), Names: len(res.Names)}); err != nil {
			return err
		}
		out = gen.CertificateCreated{Id: id, Names: res.Names, NotAfter: res.NotAfter.UTC()}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return gen.UploadCertificate201JSONResponse(out), nil
}

// RetireCertificate is POST /certificates/{id}:retire.
func (s *Server) RetireCertificate(ctx context.Context, req gen.RetireCertificateRequestObject) (gen.RetireCertificateResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	err = s.global(ctx, func(g store.GlobalTx) error {
		ok, err := g.CertRetire(req.Id)
		if err != nil {
			return err
		}
		if !ok {
			return httpx.NotFound()
		}
		_, err = audit.Admin(g, s.now(), p.AdminID, httpx.ClientIPFrom(g.Context()), audit.CertificateRetire{Certificate: req.Id})
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.RetireCertificate204Response{}, nil
}

func certView(c store.CertRow) gen.CertificateView {
	names := c.Names
	if names == nil {
		names = []string{}
	}
	return gen.CertificateView{Id: c.ID, Kind: gen.CertificateViewKind(c.Kind), Source: gen.CertificateViewSource(c.Source), State: gen.CertificateViewState(c.State),
		Names: names, NotBefore: c.NotBefore.UTC(), NotAfter: c.NotAfter.UTC(), CreatedAt: c.CreatedAt.UTC()}
}

// ListCertificates is GET /certificates.
func (s *Server) ListCertificates(ctx context.Context, req gen.ListCertificatesRequestObject) (gen.ListCertificatesResponseObject, error) {
	before, err := uuidCursor(req.Params.Cursor)
	if err != nil {
		return nil, err
	}
	limit := pageLimit(req.Params.Limit)
	out := gen.CertificatePage{Items: []gen.CertificateView{}}
	err = s.readGlobal(ctx, func(g store.GlobalTx) error {
		rows, err := g.CertsPage(before, limit+1)
		if err != nil {
			return err
		}
		if len(rows) > limit {
			rows = rows[:limit]
			out.NextCursor = ptr(encodeKey(rows[len(rows)-1].ID.String()))
		}
		for _, r := range rows {
			out.Items = append(out.Items, certView(r))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return gen.ListCertificates200JSONResponse(out), nil
}
