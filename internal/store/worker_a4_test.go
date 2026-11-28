package store_test

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The store methods work package A4 added for the SMS worker and the job runner.

func TestWorkerGatewaysListsRoutedCredentialedAndNoopGateways(t *testing.T) {
	f := newFixture(t)
	super := f.superConn(t)
	worker := f.db.Store(f.ctx, t, store.RoleWorker)
	for _, sql := range []string{
		`DELETE FROM ctrlz.sms_gateways`,
		// Routed, without credentials.
		`INSERT INTO ctrlz.sms_gateways (provider, role) VALUES ('sms_ir', 'primary')`,
		// Not routed, with credentials: a test send may pin it.
		`INSERT INTO ctrlz.sms_gateways (provider, role, credentials_ct) VALUES ('melipayamak', 'disabled', '\x01')`,
		// Not routed, no credentials, and needing none.
		`INSERT INTO ctrlz.sms_gateways (provider, role) VALUES ('noop', 'disabled')`,
	} {
		if _, err := super.Exec(f.ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	f.global(t, worker, func(g store.GlobalTx) {
		gws, err := g.WorkerGateways()
		if err != nil || len(gws) != 3 {
			t.Fatalf("%+v %v", gws, err)
		}
	})

	// A gateway that is neither routed, credentialed nor noop stays out.
	if _, err := super.Exec(f.ctx, `DELETE FROM ctrlz.sms_gateways WHERE provider <> 'sms_ir'`); err != nil {
		t.Fatal(err)
	}
	if _, err := super.Exec(f.ctx, `UPDATE ctrlz.sms_gateways SET role = 'disabled'`); err != nil {
		t.Fatal(err)
	}
	f.global(t, worker, func(g store.GlobalTx) {
		if gws, err := g.WorkerGateways(); err != nil || len(gws) != 0 {
			t.Errorf("a disabled gateway with no credentials was listed: %+v %v", gws, err)
		}
	})
}

func TestWorkerProviderTemplatesAndOutboxRetryLater(t *testing.T) {
	f := newFixture(t)
	super := f.superConn(t)
	worker := f.db.Store(f.ctx, t, store.RoleWorker)
	// The seed maps (otp, fa) on its noop gateway.
	f.global(t, worker, func(g store.GlobalTx) {
		tpls, err := g.WorkerProviderTemplates()
		if err != nil || len(tpls) != 1 || tpls[0].Key != "otp" || tpls[0].Locale != "fa" || tpls[0].ProviderTemplateID != "123456" ||
			len(tpls[0].ParamNames) != 1 || tpls[0].ParamNames[0] != "CODE" {
			t.Fatalf("%+v %v", tpls, err)
		}
	})

	var id uuid.UUID
	if err := super.QueryRow(f.ctx, `SELECT id FROM ctrlz.sms_outbox LIMIT 1`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	f.global(t, worker, func(g store.GlobalTx) {
		if err := g.OutboxRetryLater(id, 90*time.Second); err != nil {
			t.Fatal(err)
		}
	})
	var left float64
	if err := super.QueryRow(f.ctx, `SELECT extract(epoch FROM claimed_until - now()) FROM ctrlz.sms_outbox WHERE id = $1`, id).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left < 80 || left > 91 {
		t.Errorf("held back for %v seconds, want about 90", left)
	}
	// Held back, the message is not claimed; after the time it is, with attempts
	// counted again.
	f.global(t, worker, func(g store.GlobalTx) {
		if got, _ := g.OutboxClaim(5); len(got) != 0 {
			t.Errorf("a held-back message was claimed: %+v", got)
		}
	})
	// A finished message is not held back by a late retry.
	if _, err := super.Exec(f.ctx, `UPDATE ctrlz.sms_outbox SET state = 'sent', claimed_until = NULL WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	f.global(t, worker, func(g store.GlobalTx) { _ = g.OutboxRetryLater(id, time.Hour) })
	var untouched bool
	if err := super.QueryRow(f.ctx, `SELECT claimed_until IS NULL FROM ctrlz.sms_outbox WHERE id = $1`, id).Scan(&untouched); err != nil || !untouched {
		t.Error("a sent message was given a claim")
	}
}

// UnprovenClaims counts the caller's tenant only: the seed gives each tenant one
// active claim with no proof, and each count is 1.
func TestUnprovenClaimsCountsOneTenant(t *testing.T) {
	f := newFixture(t)
	super := f.superConn(t)
	worker := f.db.Store(f.ctx, t, store.RoleWorker)
	count := func(tenant uuid.UUID) (n int) {
		f.inTenant(t, worker, tenant, func(tx store.Tx) {
			var err error
			if n, err = tx.UnprovenClaims(); err != nil {
				t.Fatal(err)
			}
		})
		return n
	}
	if count(f.A.Tenant) != 1 || count(f.B.Tenant) != 1 {
		t.Fatalf("A %d, B %d", count(f.A.Tenant), count(f.B.Tenant))
	}
	// Proving A's claim changes A's count and not B's.
	if _, err := super.Exec(f.ctx, `UPDATE ctrlz.ip_claims SET proven_at = now() WHERE tenant_id = $1`, f.A.Tenant); err != nil {
		t.Fatal(err)
	}
	if count(f.A.Tenant) != 0 || count(f.B.Tenant) != 1 {
		t.Errorf("after proving A's claim: A %d, B %d", count(f.A.Tenant), count(f.B.Tenant))
	}
	// A suspended claim is not "active".
	if _, err := super.Exec(f.ctx, `UPDATE ctrlz.ip_claims SET state = 'suspended' WHERE tenant_id = $1`, f.B.Tenant); err != nil {
		t.Fatal(err)
	}
	if count(f.B.Tenant) != 0 {
		t.Error("a suspended claim counted")
	}
}

func TestRegisterUserWithNoPasswordStoresNull(t *testing.T) {
	f := newFixture(t)
	super := f.superConn(t)
	tenant := f.db.Store(f.ctx, t, store.RoleTenant)
	if _, err := super.Exec(f.ctx, `UPDATE ctrlz.system_settings SET registration_mode = 'open'`); err != nil {
		t.Fatal(err)
	}
	// An OTP consumed in the last ten minutes for this phone proves it (the
	// database checks): plant it as the superuser, as the function expects it.
	var otp uuid.UUID
	if err := super.QueryRow(f.ctx, `INSERT INTO ctrlz.otp_challenges (phone_e164, purpose, code_hash, expires_at, consumed_at, ip)
	  VALUES ('+989125550001', 'signup', '\x01', now() + interval '5 minutes', now(), '198.51.100.9') RETURNING id`).Scan(&otp); err != nil {
		t.Fatal(err)
	}
	reg, ok, err := tenant.Auth().RegisterUser(f.ctx, "+989125550001", "", "fa", uuid.Nil, otp)
	if err != nil || !ok {
		t.Fatalf("%+v %v %v", reg, ok, err)
	}
	var isNull bool
	if err := super.QueryRow(f.ctx, `SELECT password_hash IS NULL FROM ctrlz.users WHERE id = $1`, reg.UserID).Scan(&isNull); err != nil || !isNull {
		t.Errorf("password_hash is not NULL for an OTP-only account: %v %v", isNull, err)
	}
	f.inTenant(t, tenant, reg.TenantID, func(tx store.Tx) {
		has, found, err := tx.UserFlags(reg.UserID)
		if err != nil || !found || has {
			t.Errorf("auth_user_flags says the account has a password: %v %v %v", has, found, err)
		}
	})
}
