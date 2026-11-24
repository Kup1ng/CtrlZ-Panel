package api

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/api/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/proof"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/throttle"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/profiles"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Lock and unlock (docs/specs/p2-profiles.md 7, Full). The lock password is the profile's own, chosen when the lock is
// set, and it is secret.String from decode on. Neither route writes an outbox row or bumps the version: the lock is not
// compiled. A lock needs a live reauth, because it outlives the session that set it and only its password lifts it.

// lockState tells what a profile is, in one read, before any hash: 404 for a profile that is not the tenant's, and
// whether it is locked.
func (s *Server) lockState(ctx context.Context, tenant, id uuid.UUID) (locked bool, err error) {
	err = s.readTenant(ctx, tenant, func(tx store.Tx) error {
		l, found, err := tx.ProfileLocked(id)
		if err != nil {
			return err
		}
		if !found {
			return httpx.NotFound()
		}
		locked = l
		return nil
	})
	return locked, err
}

// LockProfile is POST /profiles/{id}/lock.
func (s *Server) LockProfile(ctx context.Context, req gen.LockProfileRequestObject) (gen.LockProfileResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	// The bound comes first, before any charge, read, hash or verify: a violation is a 422 that spends nothing.
	pw, perr := profiles.NormalizeLockPassword(secret.New(req.Body.Password))
	if perr != nil {
		return nil, profileError(perr)
	}
	message := str(req.Body.Message)
	if merr := profiles.CheckLockMessage(message); merr != nil {
		return nil, profileError(merr)
	}
	id := uuid.UUID(req.Id)
	who := throttle.Who{Tenant: pr.TenantID, Profile: id}
	if err := s.throttle.Charge(ctx, throttle.ProfileLockTenant, who); err != nil {
		return nil, apiError(err)
	}
	locked, err := s.lockState(ctx, pr.TenantID, id)
	if err != nil {
		return nil, err
	}
	if locked {
		return nil, httpx.New(http.StatusConflict, httpx.CodeConflict)
	}
	hash, err := s.hasher.Hash(ctx, pw)
	if err != nil {
		if proof.Busy(err) {
			_ = s.throttle.Refund(context.WithoutCancel(ctx), throttle.ProfileLockTenant, who)
		}
		return nil, apiError(err)
	}
	ip := httpx.ClientIPFrom(ctx)
	err = s.writeTx(ctx, pr.TenantID, func(tx store.Tx) error {
		won, err := tx.ProfileLock(id, hash, message, pr.UserID)
		if err != nil {
			return err
		}
		if !won.Yes() {
			// Already locked by a lock that came between, or not the tenant's.
			if _, found, err := tx.ProfileLocked(id); err != nil {
				return err
			} else if !found {
				return httpx.NotFound()
			}
			return httpx.New(http.StatusConflict, httpx.CodeConflict)
		}
		return audit.Tenant(tx, pr.UserID, ip, audit.ProfileLock{ProfileID: id})
	})
	if err != nil {
		return nil, err
	}
	return gen.LockProfile204Response{}, nil
}

// UnlockProfile is POST /profiles/{id}/unlock.
func (s *Server) UnlockProfile(ctx context.Context, req gen.UnlockProfileRequestObject) (gen.UnlockProfileResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	pw, perr := profiles.NormalizeLockPassword(secret.New(req.Body.Password))
	if perr != nil {
		return nil, profileError(perr)
	}
	id := uuid.UUID(req.Id)
	who := throttle.Who{Tenant: pr.TenantID, Profile: id}
	// The tenant-wide budget first, then the one of this profile (keyed with the session's own tenant, so another tenant's
	// attempts at this id land in its own bucket): both count before any hash is verified.
	if err := s.throttle.Charge(ctx, throttle.ProfileLockTenant, who); err != nil {
		return nil, apiError(err)
	}
	if err := s.throttle.Charge(ctx, throttle.ProfileUnlock, who); err != nil {
		_ = s.throttle.Refund(context.WithoutCancel(ctx), throttle.ProfileLockTenant, who)
		return nil, apiError(err)
	}
	var stored secret.String
	var notLocked bool
	err = s.readTenant(ctx, pr.TenantID, func(tx store.Tx) error {
		l, found, err := tx.ProfileLocked(id)
		if err != nil {
			return err
		}
		if !found {
			return httpx.NotFound()
		}
		if !l {
			notLocked = true // nothing to unlock; audited below, outside this read
			return nil
		}
		h, ok, err := tx.ProfileLockHash(id)
		if err != nil {
			return err
		}
		if !ok {
			notLocked = true
			return nil
		}
		stored = h
		return nil
	})
	if err != nil {
		return nil, err
	}
	ip := httpx.ClientIPFrom(ctx)
	// An error returned inside writeTx rolls its audit row back, so a 409 that must leave a row is answered after the
	// row is committed (spec 7.2: every attempt on an existing profile of the tenant is audited).
	auditFailed := func() error {
		return s.writeTx(ctx, pr.TenantID, func(tx store.Tx) error {
			return audit.Tenant(tx, pr.UserID, ip, audit.ProfileUnlockFailed{ProfileID: id})
		})
	}
	if notLocked {
		if err := auditFailed(); err != nil {
			return nil, err
		}
		return nil, httpx.New(http.StatusConflict, httpx.CodeConflict)
	}
	ok, err := s.verifyStored(ctx, pw, stored)
	if err != nil {
		if proof.Busy(err) {
			bg := context.WithoutCancel(ctx)
			_ = s.throttle.Refund(bg, throttle.ProfileUnlock, who)
			_ = s.throttle.Refund(bg, throttle.ProfileLockTenant, who)
		}
		return nil, apiError(err)
	}
	if !ok {
		// Every attempt on an existing profile of the tenant is audited, bounded by the two scopes.
		if err := auditFailed(); err != nil {
			return nil, err
		}
		return nil, errInvalidCredentials()
	}
	var relocked bool
	err = s.writeTx(ctx, pr.TenantID, func(tx store.Tx) error {
		won, err := tx.ProfileUnlock(id, stored)
		if err != nil {
			return err
		}
		if !won.Yes() {
			// A relock came between the read and the clear: the hash that was verified is no longer the lock. The attempt
			// is recorded, and the 409 is answered after the commit.
			relocked = true
			return audit.Tenant(tx, pr.UserID, ip, audit.ProfileUnlockFailed{ProfileID: id})
		}
		return audit.Tenant(tx, pr.UserID, ip, audit.ProfileUnlock{ProfileID: id})
	})
	if err != nil {
		return nil, err
	}
	if relocked {
		return nil, httpx.New(http.StatusConflict, httpx.CodeConflict)
	}
	_ = s.throttle.Clear(ctx, throttle.ProfileUnlock, who) // a convenience after commit, not a gate
	return gen.UnlockProfile204Response{}, nil
}
