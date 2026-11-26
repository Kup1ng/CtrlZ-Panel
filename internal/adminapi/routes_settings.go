package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/Kup1ng/CtrlZ-Panel/internal/adminapi/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

func validMode(m gen.RegistrationMode) bool {
	switch m {
	case "closed", "invite", "open":
		return true
	}
	return false
}

func registrationSettings(r store.Registration) gen.RegistrationSettings {
	return gen.RegistrationSettings{Mode: gen.RegistrationMode(r.Mode), OpenGraceDays: r.OpenGraceDays, TakeoverIdleDays: r.TakeoverIdleDays}
}

// GetRegistration is GET /settings/registration.
func (s *Server) GetRegistration(ctx context.Context, _ gen.GetRegistrationRequestObject) (gen.GetRegistrationResponseObject, error) {
	var r store.Registration
	err := s.readGlobal(ctx, func(g store.GlobalTx) (err error) {
		r, err = g.RegistrationGet()
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.GetRegistration200JSONResponse(registrationSettings(r)), nil
}

// GetRegistrationImpact is GET /settings/registration/impact (spec 11.4). Only a
// move to open touches claims; any other target counts nothing.
func (s *Server) GetRegistrationImpact(ctx context.Context, req gen.GetRegistrationImpactRequestObject) (gen.GetRegistrationImpactResponseObject, error) {
	if !validMode(req.Params.To) {
		return nil, errValidation("to", "invalid")
	}
	var im store.RegistrationImpact
	if req.Params.To == "open" {
		if err := s.readGlobal(ctx, func(g store.GlobalTx) (err error) {
			im, err = g.RegistrationImpact()
			return err
		}); err != nil {
			return nil, err
		}
	}
	return gen.GetRegistrationImpact200JSONResponse{Graced: im.Graced, SuspendedAtOnce: im.SuspendedAtOnce}, nil
}

// PutRegistration is PUT /settings/registration (spec 11.4): the mode change,
// its admin job and its audit row in one transaction.
func (s *Server) PutRegistration(ctx context.Context, req gen.PutRegistrationRequestObject) (gen.PutRegistrationResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	b := *req.Body
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	if !validMode(b.Mode) {
		return nil, errValidation("mode", "invalid")
	}
	if b.OpenGraceDays != nil && (*b.OpenGraceDays < 1 || *b.OpenGraceDays > 365) {
		return nil, errValidation("open_grace_days", "out_of_range")
	}
	var out store.Registration
	ip := httpx.ClientIPFrom(ctx)
	err = s.global(ctx, func(g store.GlobalTx) error {
		// 0. A change of mode ends a transition job that the worker never finished, so a stopped
		// worker cannot make closing registration a 409 (round 5, admin-r5-2). It comes before the
		// settings row is locked because admin_jobs ranks first (rule lock-order), and the mode
		// is read without a lock to decide whether this is a change at all: a request that only
		// repeats the mode must not end a job that is still doing its work. If another admin
		// changes the mode between this read and the lock below, the job they queued is active
		// and the insert answers 409: two changes at the same moment, one of them retries.
		pre, err := g.RegistrationGet()
		if err != nil {
			return err
		}
		s.d.betweenReadAndLock()
		if string(b.Mode) != pre.Mode {
			if _, err := g.AdminJobsSupersede("registration_transition"); err != nil {
				return err
			}
		}
		// 1. The row lock orders two admins changing the mode at once.
		cur, err := g.RegistrationLock()
		if err != nil {
			return err
		}
		// The read above decided whether to end a job and carried no lock. If the mode moved before
		// the lock was taken, that decision was about a state that is gone, and it may have ended the
		// job another admin queued with the change that moved it (a statement under Read Committed
		// sees what has committed since the read). Going on would find the mode already equal to the
		// target, return without queueing a replacement and leave the transition never run
		// (round 7, admin-r7-2). The transaction is rolled back, which gives the ended job back, and
		// the second of two changes at the same moment retries.
		if cur.Mode != pre.Mode {
			return store.ErrConflict
		}
		out = cur
		grace := cur.OpenGraceDays
		if b.OpenGraceDays != nil {
			grace = *b.OpenGraceDays
		}
		if string(b.Mode) == cur.Mode {
			// Same mode: only the grace may differ.
			if grace == cur.OpenGraceDays {
				return nil
			}
			if err := g.RegistrationGraceSet(grace); err != nil {
				return err
			}
			out.OpenGraceDays = grace
			_, err := audit.Admin(g, s.now(), p.AdminID, ip, audit.RegistrationModeChange{From: audit.RegModeOf(cur.Mode), To: audit.RegModeOf(cur.Mode), GraceDays: grace})
			return err
		}
		// 2 to 4. Update, queue the transition (P3 does the work, 11.2), audit.
		var im store.RegistrationImpact
		if b.Mode == "open" {
			if im, err = g.RegistrationImpact(); err != nil {
				return err
			}
		}
		if err := g.RegistrationSet(string(b.Mode), b.OpenGraceDays); err != nil {
			return err
		}
		out.Mode, out.OpenGraceDays = string(b.Mode), grace
		params, err := json.Marshal(map[string]any{"from": cur.Mode, "to": string(b.Mode), "grace_days": grace})
		if err != nil {
			return err
		}
		if _, err := g.AdminJobInsert("registration_transition", params, p.AdminID); err != nil {
			return err
		}
		_, err = audit.Admin(g, s.now(), p.AdminID, ip, audit.RegistrationModeChange{
			From: audit.RegModeOf(cur.Mode), To: audit.RegModeOf(string(b.Mode)), Graced: im.Graced, SuspendedAtOnce: im.SuspendedAtOnce, GraceDays: grace,
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.PutRegistration200JSONResponse(registrationSettings(out)), nil
}

// ---------------------------------------------------------------------------
// Passkey configuration (spec 7.2, 7.4)

func webauthnConfig(c store.WebauthnConfig) gen.WebauthnConfig {
	out := gen.WebauthnConfig{AllowedOrigins: c.AllowedOrigins, Enabled: c.Enabled}
	if out.AllowedOrigins == nil {
		out.AllowedOrigins = []string{}
	}
	if c.RPID != "" {
		out.RpId = ptr(c.RPID)
	}
	return out
}

// hostnameRE is the shape of an RP ID: lower-case DNS labels. It rejects a scheme,
// a port, a path and a trailing dot, which the browser would not match anyway.
var hostnameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// checkRPID applies the rules of 7.2 to an RP ID: the panel host or a
// dot-boundary suffix of it, and never a public suffix, so a typo cannot make
// every credential stale. golang.org/x/net/publicsuffix embeds its list, so the
// check needs no network. "panel.localhost" passes; "localhost", "co.ir" and a
// bare TLD do not.
func checkRPID(rp, host string) *httpx.Error {
	rp = strings.ToLower(rp)
	switch {
	case len(rp) == 0 || len(rp) > 253 || !hostnameRE.MatchString(rp):
		return errValidation("rp_id", "invalid")
	case rp != host && !strings.HasSuffix(host, "."+rp):
		return errValidation("rp_id", "not_panel_host")
	}
	if suffix, _ := publicsuffix.PublicSuffix(rp); suffix == rp {
		return errValidation("rp_id", "public_suffix")
	}
	return nil
}

// GetWebauthn is GET /settings/webauthn.
func (s *Server) GetWebauthn(ctx context.Context, _ gen.GetWebauthnRequestObject) (gen.GetWebauthnResponseObject, error) {
	var c store.WebauthnConfig
	err := s.readGlobal(ctx, func(g store.GlobalTx) (err error) {
		c, err = g.WebauthnConfigGet()
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.GetWebauthn200JSONResponse(webauthnConfig(c)), nil
}

// GetWebauthnImpact is GET /settings/webauthn/impact (spec 7.4 step 1).
func (s *Server) GetWebauthnImpact(ctx context.Context, req gen.GetWebauthnImpactRequestObject) (gen.GetWebauthnImpactResponseObject, error) {
	rp := strings.ToLower(strings.TrimSpace(req.Params.RpId))
	if rp == "" || len(rp) > 253 || !hostnameRE.MatchString(rp) {
		return nil, errValidation("rp_id", "invalid")
	}
	var im store.WebauthnImpact
	err := s.readGlobal(ctx, func(g store.GlobalTx) (err error) {
		im, err = g.WebauthnImpact(rp)
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.GetWebauthnImpact200JSONResponse{Credentials: im.Credentials, Users: im.Users, EnforcedUsers: im.EnforcedUsers}, nil
}

// PutWebauthn is PUT /settings/webauthn (spec 7.2, 7.4 step 2). The body carries
// no origins: the server writes https://<effective panel host>, so a caller
// cannot widen the origin check.
func (s *Server) PutWebauthn(ctx context.Context, req gen.PutWebauthnRequestObject) (gen.PutWebauthnResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	rp := strings.ToLower(strings.TrimSpace(req.Body.RpId))
	enabled := req.Body.Enabled
	var out store.WebauthnConfig
	err = s.global(ctx, func(g store.GlobalTx) error {
		host, err := s.panelHost(g)
		if err != nil {
			return err
		}
		// Production turns Passkey on only over a public certificate that is served now (p4-nodes 10.5, T-105).
		if enabled && s.d.Env == EnvProduction {
			if err := s.requirePublicPanelCert(g); err != nil {
				return err
			}
		}
		// The RP ID is a domain: a host with a port (a dev panel on :8443) is compared by its
		// name, while the origin below keeps the port.
		if e := checkRPID(rp, httpx.HostName(host)); e != nil {
			return e
		}
		// A change of RP ID ends an RP job the worker never finished (round 5, admin-r5-2; see
		// PutRegistration). The job is a function of the target RP ID, so the newer one replaces it.
		pre, err := g.WebauthnConfigGet()
		if err != nil {
			return err
		}
		s.d.betweenReadAndLock()
		if pre.RPID != rp {
			if _, err := g.AdminJobsSupersede("webauthn_rp_change"); err != nil {
				return err
			}
		}
		cur, err := g.WebauthnConfigLock()
		if err != nil {
			return err
		}
		// Same as PutRegistration: a decision to end the job that the lock does not confirm is
		// rolled back with the transaction (round 7, admin-r7-2).
		if cur.RPID != pre.RPID {
			return store.ErrConflict
		}
		im, err := g.WebauthnImpact(rp)

		if err != nil {
			return err
		}
		out = store.WebauthnConfig{RPID: rp, AllowedOrigins: []string{"https://" + host}, Enabled: enabled}
		if err := g.WebauthnConfigSet(out); err != nil {
			return err
		}
		// Credentials of another RP ID go stale in the worker (7.4 step 4). A change
		// of the switch alone queues nothing.
		if cur.RPID != rp {
			params, err := json.Marshal(map[string]string{"rp_id": rp})
			if err != nil {
				return err
			}
			if _, err := g.AdminJobInsert("webauthn_rp_change", params, p.AdminID); err != nil {
				return err
			}
		}
		_, err = audit.Admin(g, s.now(), p.AdminID, httpx.ClientIPFrom(g.Context()), audit.WebauthnConfigChange{
			FromRP: audit.HostOf(cur.RPID), ToRP: audit.HostOf(rp), FromEnabled: cur.Enabled, ToEnabled: enabled,
			Credentials: im.Credentials, Users: im.Users,
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.PutWebauthn200JSONResponse(webauthnConfig(out)), nil
}

// requirePublicPanelCert is the production guard of Passkey (p4-nodes 10.5, AUTH 7.2): enabled=true is accepted when no domain
// change waits to be applied and the panel certificate in force is an active uploaded row whose chain verified to the public
// roots and covers the host the panel is served on, else cert_not_public. "Nothing waits" is domainView's apply_pending, which
// already says that the row the choice rule picks now (it re-checks chain, names, dates and roots on each call) is the row the
// last apply served and that no requested host differs from the served one. What is left to test is that an apply happened at
// all: a panel with no applied host or no applied certificate is served by the private CA of a first install, and a Passkey
// bound to its name would not survive the move to the real domain.
func (s *Server) requirePublicPanelCert(g store.GlobalTx) error {
	refused := httpx.New(http.StatusUnprocessableEntity, httpx.CodeCertNotPublic).WithFields(httpx.FieldError{Name: "enabled", Code: "refused"})
	d, err := g.DomainGet()
	if err != nil {
		return err
	}
	if d.AppliedPanelHost == "" || d.AppliedPanelCertID == nil {
		return refused
	}
	v, err := s.domainView(g, d, s.now())
	if err != nil {
		return err
	}
	if v.ApplyPending {
		return refused
	}
	return nil
}
