package phonechange_test

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/marker"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/otp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/phonechange"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/token"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

var cluster *testpg.Cluster

func TestMain(m *testing.M) {
	os.Exit(testpg.RunMain(m, func(c *testpg.Cluster) { cluster = c }))
}

var ip = netip.MustParseAddr("198.51.100.7")

const code = "012345"

type rig struct {
	t      *testing.T
	env    *authtest.Env
	tenant *store.Store
	mgr    *session.Manager
	svc    *phonechange.Service
	// session is the one the seed gave tenant A: id and cookie value.
	sessionID uuid.UUID
}

func newRig(t *testing.T) *rig {
	t.Helper()
	env := authtest.New(t, cluster)
	env.ResetSMS(t)
	ring, err := keyring.NewEphemeral(keyring.DomainAuthMAC, keyring.DomainOTPDelivery)
	if err != nil {
		t.Fatal(err)
	}
	wring, _ := keyring.NewEphemeral(keyring.DomainSMSCred)
	env.AddGateway(t, wring, authtest.Gateway{Provider: "noop", Role: "primary"})
	tenant := env.Tenant(t)
	cfg := func(ctx context.Context) (store.PublicConfig, error) { return tenant.Auth().PublicConfig(ctx) }
	o, err := otp.New(tenant.Auth(), ring, cfg, otp.WithCodeSource(func() (secret.String, error) { return secret.New(code), nil }))
	if err != nil {
		t.Fatal(err)
	}
	mgr := session.NewManager(tenant, session.DefaultPolicy(), nil)
	r := &rig{t: t, env: env, tenant: tenant, mgr: mgr, svc: &phonechange.Service{DB: tenant, OTP: o, Markers: marker.New(ring, nil), Sessions: mgr, Config: cfg}}
	r.sessionID = uuid.MustParse("00000000-0000-7000-8000-000000010001")
	return r
}

func (r *rig) count(sql string, args ...any) int {
	r.t.Helper()
	var n int
	if err := r.env.DB.Scan(r.env.Ctx, sql, args, &n); err != nil {
		r.t.Fatal(err)
	}
	return n
}

func (r *rig) start(newPhone string) (phonechange.Started, error) {
	return r.svc.Start(r.env.Ctx, phonechange.StartInput{Tenant: r.env.A.Tenant, User: r.env.A.User, NewPhone: newPhone, Locale: "fa", IP: ip})
}

func (r *rig) confirm(id uuid.UUID, oldCode, newCode string) (phonechange.Confirmed, error) {
	return r.svc.Confirm(r.env.Ctx, phonechange.ConfirmInput{
		Tenant: r.env.A.Tenant, User: r.env.A.User, Session: r.sessionID, RequestID: id, OldCode: oldCode, NewCode: newCode, IP: ip,
	})
}

func (r *rig) phoneOf(user uuid.UUID) string {
	var p string
	r.env.Scan(r.t, `SELECT phone_e164 FROM ctrlz.users WHERE id = $1`, []any{user}, &p)
	return p
}

const free = "+989127770001"

func TestChangeWithBothNumbers(t *testing.T) {
	r := newRig(t)
	a, b := r.env.A, r.env.B

	// Other state of A that must end: a second session with a refresh token, an
	// open mfa ticket. State of B that must not move.
	var second session.Issued
	if err := r.tenant.WithTenant(r.env.Ctx, a.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
		second, err = r.mgr.Create(tx, session.NewSession{User: a.User, Remember: true, Method: "password", IP: ip})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	r.env.Exec(t, `UPDATE ctrlz.webauthn_config SET rp_id = 'example.test', allowed_origins = '{https://example.test}', enabled = true`)
	oldPhoneB := r.phoneOf(b.User)

	st, err := r.start(free)
	if err != nil {
		t.Fatal(err)
	}
	if st.ExpiresIn != 5*time.Minute || st.ResendAfter != 60*time.Second || st.OldChallenge == st.NewChallenge || st.RequestID == uuid.Nil {
		t.Fatalf("%+v", st)
	}
	// Two challenges: phone_old to the current number, phone_new to the new one.
	if r.count(`SELECT count(*) FROM ctrlz.otp_challenges WHERE id = $1 AND purpose = 'phone_old' AND phone_e164 = $2 AND delivery_ct IS NOT NULL`, st.OldChallenge, a.Phone) != 1 ||
		r.count(`SELECT count(*) FROM ctrlz.otp_challenges WHERE id = $1 AND purpose = 'phone_new' AND phone_e164 = $2 AND delivery_ct IS NOT NULL`, st.NewChallenge, free) != 1 {
		t.Error("the two challenges are not as specified")
	}
	if r.phoneOf(a.User) != a.Phone {
		t.Error("the number changed before the codes were checked")
	}

	done, err := r.confirm(st.RequestID, code, code)
	if err != nil {
		t.Fatal(err)
	}
	if r.phoneOf(a.User) != free {
		t.Fatalf("phone is %s", r.phoneOf(a.User))
	}
	if r.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND phone_verified_at IS NOT NULL`, a.User) != 1 {
		t.Error("the new number is not marked verified")
	}
	// 3.7: the current session rotated, the others ended with their refresh tokens.
	if done.Ended != 1 || done.Issued.Session.IsZero() || done.Issued.SessionID != r.sessionID {
		t.Errorf("confirmed: %+v", done)
	}
	if _, ok, _ := r.tenant.Auth().SessionByHash(r.env.Ctx, []byte("session-token-1")); ok {
		t.Error("the old session cookie still works")
	}
	if info, ok, _ := r.tenant.Auth().SessionByHash(r.env.Ctx, token.HashString(done.Issued.Session.Reveal())); !ok || info.UserID != a.User || info.RevokedAt != nil {
		t.Error("the new session cookie does not work")
	}
	if info, ok, _ := r.tenant.Auth().SessionByHash(r.env.Ctx, token.HashString(second.Session.Reveal())); !ok || info.RevokedAt == nil {
		t.Error("the other session was not ended")
	}
	if r.count(`SELECT count(*) FROM ctrlz.refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL`, a.User) != 0 {
		t.Error("a refresh token survived")
	}
	if r.count(`SELECT count(*) FROM ctrlz.api_tokens WHERE user_id = $1 AND revoked_at IS NULL`, a.User) != 0 {
		t.Error("an API token survived")
	}
	// Audit: masked numbers only. Notice for the user.
	if r.count(`SELECT count(*) FROM ctrlz.tenant_audit_log WHERE tenant_id = $1 AND action = 'phone.change'
	  AND params ->> 'old_masked' <> $2 AND params ->> 'new_masked' <> $3 AND params::text NOT LIKE '%' || $4 || '%'`,
		a.Tenant, a.Phone, free, free[4:]) != 1 {
		t.Error("audit row missing, or it holds a full number")
	}
	if r.count(`SELECT count(*) FROM ctrlz.notifications WHERE tenant_id = $1 AND kind = 'phone_changed'`, a.Tenant) != 1 {
		t.Error("no phone_changed notification")
	}
	// A recovery event with a live passkey and no Enforce marks it for review (7.7).
	if r.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND passkey_review_at IS NOT NULL`, a.User) != 1 ||
		r.count(`SELECT count(*) FROM ctrlz.notifications WHERE tenant_id = $1 AND kind = 'passkey_review'`, a.Tenant) != 1 {
		t.Error("the passkey review was not requested")
	}

	// B did not move.
	if r.phoneOf(b.User) != oldPhoneB || r.count(`SELECT count(*) FROM ctrlz.sessions WHERE tenant_id = $1 AND revoked_at IS NULL`, b.Tenant) != 1 ||
		r.count(`SELECT count(*) FROM ctrlz.notifications WHERE tenant_id = $1 AND kind IN ('phone_changed', 'passkey_review')`, b.Tenant) != 0 ||
		r.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND passkey_review_at IS NOT NULL`, b.User) != 0 {
		t.Error("tenant B changed")
	}

	// The request is used up.
	if _, err := r.confirm(st.RequestID, code, code); err == nil {
		t.Error("a finished request was confirmed twice")
	}
}

func TestPasskeyReviewIsSkippedWhileEnforceIsInForce(t *testing.T) {
	r := newRig(t)
	a := r.env.A
	r.env.Exec(t, `UPDATE ctrlz.webauthn_config SET rp_id = 'example.test', allowed_origins = '{https://example.test}', enabled = true`)
	r.env.Exec(t, `UPDATE ctrlz.users SET enforce_passkey = true WHERE id = $1`, a.User)
	st, err := r.start(free)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.confirm(st.RequestID, code, code); err != nil {
		t.Fatal(err)
	}
	if r.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND passkey_review_at IS NULL`, a.User) != 1 {
		t.Error("review was set while Enforce is in force: that would lock the owner out (7.7)")
	}
}

func TestNoReviewWithoutALivePasskey(t *testing.T) {
	r := newRig(t)
	st, _ := r.start(free) // passkeys are off in this database
	if _, err := r.confirm(st.RequestID, code, code); err != nil {
		t.Fatal(err)
	}
	if r.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND passkey_review_at IS NULL`, r.env.A.User) != 1 {
		t.Error("review set with no live passkey")
	}
}

func TestATypoInOneCodeLetsTheUserRetry(t *testing.T) {
	r := newRig(t)
	st, err := r.start(free)
	if err != nil {
		t.Fatal(err)
	}
	// The new code is mistyped. The old code was consumed by the first try.
	_, err = r.confirm(st.RequestID, code, "999999")
	var ce *phonechange.CodeError
	if !errors.As(err, &ce) || ce.Field != "new_code" || !errors.Is(err, otp.ErrInvalid) {
		t.Fatalf("typo: %v", err)
	}
	if r.phoneOf(r.env.A.User) != r.env.A.Phone {
		t.Fatal("changed on a bad code")
	}
	// The retry works, and the already consumed old code still counts.
	if _, err := r.confirm(st.RequestID, code, code); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if r.phoneOf(r.env.A.User) != free {
		t.Error("not changed after the retry")
	}
}

func TestWrongOldCodeNamesTheOldField(t *testing.T) {
	r := newRig(t)
	st, _ := r.start(free)
	_, err := r.confirm(st.RequestID, "999999", code)
	var ce *phonechange.CodeError
	if !errors.As(err, &ce) || ce.Field != "old_code" {
		t.Fatalf("%v", err)
	}
	// The new code was not tried, so it is not spent.
	if r.count(`SELECT attempts FROM ctrlz.otp_challenges WHERE id = $1`, st.NewChallenge) != 0 {
		t.Error("the new code was spent by a wrong old code")
	}
}

func TestSameNumberIsRefused(t *testing.T) {
	r := newRig(t)
	if _, err := r.start(r.env.A.Phone); !errors.Is(err, phonechange.ErrSamePhone) {
		t.Errorf("%v", err)
	}
	if r.count(`SELECT count(*) FROM ctrlz.otp_challenges`) != 0 {
		t.Error("a refused request spent a challenge")
	}
}

func TestNewNumberTakenByTheTimeOfConfirm(t *testing.T) {
	r := newRig(t)
	st, err := r.start(free)
	if err != nil {
		t.Fatal(err)
	}
	// Someone registers that number between the request and the confirm.
	r.env.Exec(t, `INSERT INTO ctrlz.tenants (id) VALUES ('00000000-0000-7000-8000-0000000000aa')`)
	r.env.Exec(t, `INSERT INTO ctrlz.users (tenant_id, id, phone_e164) VALUES ('00000000-0000-7000-8000-0000000000aa', '00000000-0000-7000-8000-0000000000ab', $1)`, free)
	_, err = r.confirm(st.RequestID, code, code)
	if !errors.Is(err, phonechange.ErrPhoneUnavailable) {
		t.Fatalf("%v", err)
	}
	if r.phoneOf(r.env.A.User) != r.env.A.Phone {
		t.Error("the number changed to one that belongs to someone else")
	}
	// The failed confirm left the session alone.
	if _, ok, _ := r.tenant.Auth().SessionByHash(r.env.Ctx, []byte("session-token-1")); !ok {
		t.Error("a refused change rotated the session")
	}
}

func TestRequestingAnumberOfSomeoneElseGivesADecoy(t *testing.T) {
	r := newRig(t)
	// B's number: the request succeeds and looks the same, but no message goes to B.
	st, err := r.start(r.env.B.Phone)
	if err != nil {
		t.Fatal(err)
	}
	if st.NewChallenge == uuid.Nil || r.count(`SELECT count(*) FROM ctrlz.otp_challenges WHERE id = $1 AND delivery_ct IS NULL`, st.NewChallenge) != 1 {
		t.Error("a message was queued for a number that belongs to someone else")
	}
	// Nobody can finish it: B's number is taken, and the decoy has no code.
	for i := 0; i < 3; i++ {
		_, _ = r.confirm(st.RequestID, code, "999999")
	}
	if r.phoneOf(r.env.A.User) != r.env.A.Phone || r.phoneOf(r.env.B.User) != r.env.B.Phone {
		t.Error("a number moved")
	}
}

func TestAnotherTenantCannotConfirm(t *testing.T) {
	r := newRig(t)
	st, err := r.start(free)
	if err != nil {
		t.Fatal(err)
	}
	b := r.env.B
	// B's session on A's request id: 404 and nothing changes.
	_, err = r.svc.Confirm(r.env.Ctx, phonechange.ConfirmInput{
		Tenant: b.Tenant, User: b.User, Session: uuid.MustParse("00000000-0000-7000-8000-000000020001"), RequestID: st.RequestID,
		OldCode: code, NewCode: code, IP: ip,
	})
	if !errors.Is(err, phonechange.ErrNotFound) {
		t.Fatalf("B on A's request: %v", err)
	}
	// A's tenant with B's user id: same.
	_, err = r.svc.Confirm(r.env.Ctx, phonechange.ConfirmInput{
		Tenant: r.env.A.Tenant, User: b.User, Session: r.sessionID, RequestID: st.RequestID, OldCode: code, NewCode: code, IP: ip,
	})
	if !errors.Is(err, phonechange.ErrNotFound) {
		t.Fatalf("A's tenant, B's user: %v", err)
	}
	if r.phoneOf(r.env.A.User) != r.env.A.Phone || r.phoneOf(b.User) != b.Phone {
		t.Error("a number moved")
	}
	// Neither challenge was spent by the foreign attempts.
	if r.count(`SELECT count(*) FROM ctrlz.otp_challenges WHERE id IN ($1, $2) AND (attempts <> 0 OR consumed_at IS NOT NULL)`, st.OldChallenge, st.NewChallenge) != 0 {
		t.Error("a foreign attempt spent the codes")
	}
	// Start for a user of another tenant is not found either.
	_, err = r.svc.Start(r.env.Ctx, phonechange.StartInput{Tenant: r.env.A.Tenant, User: b.User, NewPhone: "+989127770009", Locale: "fa", IP: ip})
	if !errors.Is(err, phonechange.ErrNotFound) {
		t.Errorf("Start for another tenant's user: %v", err)
	}
}

func TestExpiredCodes(t *testing.T) {
	r := newRig(t)
	st, _ := r.start(free)
	r.env.Exec(t, `UPDATE ctrlz.otp_challenges SET expires_at = now() - interval '1 second'`)
	_, err := r.confirm(st.RequestID, code, code)
	var ce *phonechange.CodeError
	if !errors.As(err, &ce) || !errors.Is(err, otp.ErrExpired) {
		t.Errorf("%v", err)
	}
	if r.phoneOf(r.env.A.User) != r.env.A.Phone {
		t.Error("changed with expired codes")
	}
}

func TestStartRefusalsSpendNothingOnTheOldNumber(t *testing.T) {
	r := newRig(t)
	// The new number's caps are used up: 429, and the old number's challenge is
	// never issued (the new one is asked first, 5.6 step 3).
	r.env.Exec(t, `UPDATE ctrlz.system_settings SET otp_cap_phone = 1`)
	if _, err := r.start(free); err != nil {
		t.Fatal(err)
	}
	r.env.Exec(t, `DELETE FROM ctrlz.phone_change_requests`)
	r.env.Exec(t, `UPDATE ctrlz.otp_challenges SET created_at = created_at - interval '2 minutes'`)
	oldBefore := r.count(`SELECT count(*) FROM ctrlz.otp_challenges WHERE purpose = 'phone_old'`)
	_, err := r.start(free)
	if !errors.Is(err, otp.ErrLimited) {
		t.Fatalf("%v", err)
	}
	if r.count(`SELECT count(*) FROM ctrlz.otp_challenges WHERE purpose = 'phone_old'`) != oldBefore {
		t.Error("a code was issued to the old number although the new one was refused")
	}
	// No gateway: 503 before anything is spent.
	r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET breaker_open_until = now() + interval '1 minute'`)
	if _, err := r.start("+989127770002"); !errors.Is(err, otp.ErrSMSUnavailable) {
		t.Errorf("no gateway: %v", err)
	}
}
