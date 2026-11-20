package otp_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/marker"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/otp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/credgen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

var cluster *testpg.Cluster

func TestMain(m *testing.M) {
	os.Exit(testpg.RunMain(m, func(c *testpg.Cluster) { cluster = c }))
}

var ip = netip.MustParseAddr("198.51.100.7")

type rig struct {
	t       *testing.T
	env     *authtest.Env
	ring    *keyring.Ring
	tenant  *store.Store
	svc     *otp.Service
	now     time.Time
	markers *marker.Service
}

// newRig plants one available gateway and builds a service over a fixed code.
func newRig(t *testing.T, code string) *rig {
	t.Helper()
	env := authtest.New(t, cluster)
	env.ResetSMS(t)
	ring, err := keyring.NewEphemeral(keyring.DomainAuthMAC, keyring.DomainOTPDelivery)
	if err != nil {
		t.Fatal(err)
	}
	wring, _ := keyring.NewEphemeral(keyring.DomainSMSCred)
	env.AddGateway(t, wring, authtest.Gateway{Provider: "noop", Role: "primary"})
	r := &rig{t: t, env: env, ring: ring, tenant: env.Tenant(t), now: time.Now()}
	r.markers = marker.New(ring, func() time.Time { return r.now })
	opts := []otp.Option{otp.WithClock(func() time.Time { return r.now })}
	if code != "" {
		opts = append(opts, otp.WithCodeSource(func() (secret.String, error) { return secret.New(code), nil }))
	}
	r.svc, err = otp.New(r.tenant.Auth(), ring, func(ctx context.Context) (store.PublicConfig, error) {
		return r.tenant.Auth().PublicConfig(ctx)
	}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *rig) req(phone string, p otp.Purpose) (otp.Challenge, error) {
	return r.svc.Request(r.env.Ctx, otp.Request{Phone: phone, Purpose: p, Locale: "fa", IP: ip})
}

func (r *rig) mustReq(phone string, p otp.Purpose) otp.Challenge {
	r.t.Helper()
	ch, err := r.req(phone, p)
	if err != nil {
		r.t.Fatalf("request %s %s: %v", phone, p, err)
	}
	return ch
}

// row reads what the issue stored.
type row struct {
	Purpose  string
	Sealed   bool
	CodeHash []byte
	Trusted  bool
	Attempts int
}

func (r *rig) row(id uuid.UUID) row {
	r.t.Helper()
	var x row
	var ct []byte
	if err := r.env.DB.Scan(r.env.Ctx, `SELECT purpose, delivery_ct, code_hash, trusted, attempts FROM ctrlz.otp_challenges WHERE id = $1`,
		[]any{id}, &x.Purpose, &ct, &x.CodeHash, &x.Trusted, &x.Attempts); err != nil {
		r.t.Fatal(err)
	}
	x.Sealed = ct != nil
	return x
}

func (r *rig) delivery(id uuid.UUID, phone, purpose string) sms.OTPDelivery {
	r.t.Helper()
	var ct []byte
	if err := r.env.DB.Scan(r.env.Ctx, `SELECT delivery_ct FROM ctrlz.otp_challenges WHERE id = $1`, []any{id}, &ct); err != nil {
		r.t.Fatal(err)
	}
	d, err := sms.OpenOTP(r.ring, phone, purpose, ct)
	if err != nil {
		r.t.Fatal(err)
	}
	return d
}

func (r *rig) counter(scope, key string) int {
	r.t.Helper()
	var n int
	if err := r.env.DB.Scan(r.env.Ctx, `SELECT COALESCE((SELECT count FROM ctrlz.sms_counters
	  WHERE day = (now() AT TIME ZONE 'Asia/Tehran')::date AND scope = $1 AND key = $2), 0)`, []any{scope, key}, &n); err != nil {
		r.t.Fatal(err)
	}
	return n
}

// pastCooldown moves every challenge back so the next request is outside the 60 s.
func (r *rig) pastCooldown() {
	r.env.Exec(r.t, `UPDATE ctrlz.otp_challenges SET created_at = created_at - interval '2 minutes'`)
}

func TestKnownAndUnknownPhoneLookTheSame(t *testing.T) {
	r := newRig(t, "")
	known, unknown := r.env.A.Phone, "+989129990000"
	a, b := r.mustReq(known, otp.Login), r.mustReq(unknown, otp.Login)

	// The 202 body: the same lifetimes, an id of the same kind.
	if a.ExpiresIn != b.ExpiresIn || a.ResendAfter != b.ResendAfter || a.ExpiresIn != 5*time.Minute || a.ResendAfter != 60*time.Second {
		t.Errorf("bodies differ: %+v %+v", a, b)
	}
	if a.ID == uuid.Nil || b.ID == uuid.Nil || a.ID.Version() != b.ID.Version() {
		t.Errorf("ids: %v %v", a.ID, b.ID)
	}
	// The row: the known phone has a payload for the worker, the decoy none.
	ra, rb := r.row(a.ID), r.row(b.ID)
	if !ra.Sealed || rb.Sealed {
		t.Errorf("sealed: known %v, decoy %v", ra.Sealed, rb.Sealed)
	}
	if len(ra.CodeHash) != len(rb.CodeHash) || len(ra.CodeHash) != 32 {
		t.Errorf("hash lengths %d %d", len(ra.CodeHash), len(rb.CodeHash))
	}
	// Counters: the decoy counts on the phone and the network, like a real
	// request, and not on the global counter, which counts messages.
	if r.counter("phone", known) != 1 || r.counter("phone", unknown) != 1 {
		t.Error("the phone counter differs between known and unknown")
	}
	if r.counter("global", "all") != 1 {
		t.Errorf("global counter %d: only the real message counts", r.counter("global", "all"))
	}
	// The cooldown is the same.
	for _, p := range []string{known, unknown} {
		if _, err := r.req(p, otp.Login); !errors.Is(err, otp.ErrLimited) {
			t.Errorf("a second request for %s inside the cooldown: %v", p, err)
		}
	}
}

func TestSealedPayloadOpensWithTheOTPDeliveryKey(t *testing.T) {
	r := newRig(t, "")
	phone := r.env.A.Phone
	ch := r.mustReq(phone, otp.Login)
	d := r.delivery(ch.ID, phone, "login")
	if d.Template != "otp" || d.Locale != "fa" || len(d.Code.Reveal()) != 6 {
		t.Fatalf("payload: %+v", d)
	}
	// That code is the one the database holds a hash of.
	if err := r.svc.Check(r.env.Ctx, ch.ID, phone, otp.Login, d.Code.Reveal()); err != nil {
		t.Errorf("the sealed code does not verify: %v", err)
	}
	// The stored hash is a keyed MAC: not the SHA-256 of the text, and different
	// under another key, so a leaked row cannot be reversed by a table of 10^6 codes.
	other := r.another(d.Code.Reveal())
	plain := sha256.Sum256([]byte("ctrlz-otp-v1\x00" + phone + "\x00login\x00" + d.Code.Reveal()))
	ra := r.row(ch.ID)
	if string(ra.CodeHash) == string(plain[:]) {
		t.Error("the stored hash is an unkeyed SHA-256")
	}
	r.pastCooldown()
	chOther, err := other.Request(r.env.Ctx, otp.Request{Phone: phone, Purpose: otp.Login, Locale: "fa", IP: ip})
	if err != nil {
		t.Fatal(err)
	}
	if string(r.row(chOther.ID).CodeHash) == string(ra.CodeHash) {
		t.Error("two keys produced one hash")
	}
}

func TestVerifyOutcomes(t *testing.T) {
	r := newRig(t, "012345")
	phone := r.env.A.Phone

	ch := r.mustReq(phone, otp.Login)
	// Wrong phone, wrong purpose: a free invalid that spends no try.
	if o, _ := r.svc.Verify(r.env.Ctx, ch.ID, r.env.B.Phone, otp.Login, "012345"); o != otp.Invalid {
		t.Errorf("another phone: %v", o)
	}
	if o, _ := r.svc.Verify(r.env.Ctx, ch.ID, phone, otp.Reset, "012345"); o != otp.Invalid {
		t.Errorf("another purpose: %v", o)
	}
	if r.row(ch.ID).Attempts != 0 {
		t.Error("a mismatch spent a try")
	}
	// Wrong code, then right, then reuse.
	if o, _ := r.svc.Verify(r.env.Ctx, ch.ID, phone, otp.Login, "000000"); o != otp.Invalid {
		t.Errorf("wrong code: %v", o)
	}
	if o, err := r.svc.Verify(r.env.Ctx, ch.ID, phone, otp.Login, "012345"); err != nil || o != otp.OK {
		t.Errorf("right code: %v %v", o, err)
	}
	if o, _ := r.svc.Verify(r.env.Ctx, ch.ID, phone, otp.Login, "012345"); o != otp.Consumed {
		t.Errorf("reuse: %v", o)
	}
	// The mapping of 5.4.
	for o, want := range map[otp.Outcome]error{otp.OK: nil, otp.Invalid: otp.ErrInvalid, otp.Expired: otp.ErrExpired,
		otp.Consumed: otp.ErrExpired, otp.Locked: otp.ErrLocked, otp.Outcome("surprise"): otp.ErrInvalid} {
		if got := o.Err(); !errors.Is(got, want) && got != want {
			t.Errorf("%s maps to %v, want %v", o, got, want)
		}
	}

	// Five tries, then locked, even for the right code.
	r.pastCooldown()
	ch2 := r.mustReq(phone, otp.Login)
	for i := 0; i < 5; i++ {
		if o, _ := r.svc.Verify(r.env.Ctx, ch2.ID, phone, otp.Login, "999999"); o != otp.Invalid {
			t.Fatalf("try %d: %v", i, o)
		}
	}
	if o, _ := r.svc.Verify(r.env.Ctx, ch2.ID, phone, otp.Login, "012345"); o != otp.Locked {
		t.Errorf("after five tries: %v", o)
	}

	// Expiry.
	r.pastCooldown()
	ch3 := r.mustReq(phone, otp.Login)
	r.env.Exec(t, `UPDATE ctrlz.otp_challenges SET expires_at = now() - interval '1 second' WHERE id = $1`, ch3.ID)
	if o, _ := r.svc.Verify(r.env.Ctx, ch3.ID, phone, otp.Login, "012345"); o != otp.Expired {
		t.Errorf("expired: %v", o)
	}
}

func TestADecoyBehavesLikeARealChallengeUnderGuessing(t *testing.T) {
	r := newRig(t, "")
	known, unknown := r.env.A.Phone, "+989129990000"
	a, b := r.mustReq(known, otp.Login), r.mustReq(unknown, otp.Login)
	seq := func(id uuid.UUID, phone string) string {
		var out []string
		for i := 0; i < 7; i++ {
			o, err := r.svc.Verify(r.env.Ctx, id, phone, otp.Login, fmt.Sprintf("%06d", 100000+i))
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, string(o))
		}
		return strings.Join(out, ",")
	}
	sa, sb := seq(a.ID, known), seq(b.ID, unknown)
	if sa != sb || sa != "invalid,invalid,invalid,invalid,invalid,locked,locked" {
		t.Errorf("known: %s\nunknown: %s", sa, sb)
	}
}

func TestSuspendedTenantGetsADecoy(t *testing.T) {
	r := newRig(t, "")
	r.env.Exec(t, `UPDATE ctrlz.tenants SET status = 'suspended' WHERE id = $1`, r.env.A.Tenant)
	ch := r.mustReq(r.env.A.Phone, otp.Login)
	if r.row(ch.ID).Sealed {
		t.Error("a suspended tenant's login request was sent a code")
	}
	r.env.Exec(t, `UPDATE ctrlz.tenants SET status = 'deleting' WHERE id = $1`, r.env.A.Tenant)
	r.pastCooldown()
	if r.row(r.mustReq(r.env.A.Phone, otp.Reset).ID).Sealed {
		t.Error("a deleting tenant's reset request was sent a code")
	}
}

func TestResetUsesItsOwnTemplate(t *testing.T) {
	r := newRig(t, "")
	ch := r.mustReq(r.env.A.Phone, otp.Reset)
	if d := r.delivery(ch.ID, r.env.A.Phone, "reset"); d.Template != "otp_reset" {
		t.Errorf("template %s", d.Template)
	}
}

func TestSignupAndInvite(t *testing.T) {
	r := newRig(t, "")
	// Closed: refused, and no counter moved. The mode is public anyway.
	if _, err := r.req("+989128880000", otp.Signup); !errors.Is(err, otp.ErrRegistrationClosed) {
		t.Fatalf("closed mode: %v", err)
	}
	if r.counter("phone", "+989128880000") != 0 {
		t.Error("a refused signup spent a cap")
	}
	// An invite works in every mode.
	inv := r.mustReq("+989128880001", otp.Invite)
	if d := r.delivery(inv.ID, "+989128880001", "invite"); d.Template != "otp" || d.Code.IsZero() {
		t.Errorf("invite for a new number: %+v", d)
	}

	r.env.Exec(t, `UPDATE ctrlz.system_settings SET registration_mode = 'open'`)
	free, taken := "+989128880002", r.env.A.Phone
	fa, ta := r.mustReq(free, otp.Signup), r.mustReq(taken, otp.Signup)
	// A free number gets a code. A taken one gets a message that says so, with no
	// code, and the requester learns nothing: the answers are the same.
	if d := r.delivery(fa.ID, free, "signup"); d.Template != "otp" || len(d.Code.Reveal()) != 6 {
		t.Errorf("free: %+v", d)
	}
	if d := r.delivery(ta.ID, taken, "signup"); d.Template != "account_exists" || !d.Code.IsZero() {
		t.Errorf("taken: %+v", d)
	}
	if fa.ExpiresIn != ta.ExpiresIn || fa.ResendAfter != ta.ResendAfter {
		t.Error("the answers differ")
	}
	// Both are real messages and count globally.
	if r.counter("global", "all") != 3 {
		t.Errorf("global %d, want 3 (invite, free, taken)", r.counter("global", "all"))
	}
	// Nobody can ever consume the challenge of a taken number.
	for i := 0; i < 5; i++ {
		_, _ = r.svc.Verify(r.env.Ctx, ta.ID, taken, otp.Signup, fmt.Sprintf("%06d", i))
	}
	// An invite for a taken number is account_exists too.
	r.pastCooldown()
	ti := r.mustReq(taken, otp.Invite)
	if r.delivery(ti.ID, taken, "invite").Template != "account_exists" {
		t.Error("invite for a taken number")
	}
}

func TestUnavailableGatewayRefusesBeforeAnyCap(t *testing.T) {
	r := newRig(t, "")
	r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET breaker_open_until = now() + interval '1 minute'`)
	for _, p := range []string{r.env.A.Phone, "+989129990000"} {
		if _, err := r.req(p, otp.Login); !errors.Is(err, otp.ErrSMSUnavailable) {
			t.Errorf("%s: %v", p, err)
		}
	}
	if _, err := r.svc.RequestForSession(r.env.Ctx, otp.ForReauth, r.env.A.Phone, "fa", ip); !errors.Is(err, otp.ErrSMSUnavailable) {
		t.Errorf("reauth: %v", err)
	}
	if _, err := r.svc.RequestForSession(r.env.Ctx, otp.ForPhoneOld, r.env.A.Phone, "fa", ip); !errors.Is(err, otp.ErrSMSUnavailable) {
		t.Errorf("phone old: %v", err)
	}
	if _, err := r.svc.RequestNewPhone(r.env.Ctx, "+989127770000", "fa", ip); !errors.Is(err, otp.ErrSMSUnavailable) {
		t.Errorf("phone new: %v", err)
	}
	var n int
	_ = r.env.DB.Scan(r.env.Ctx, `SELECT (SELECT count(*) FROM ctrlz.sms_counters) + (SELECT count(*) FROM ctrlz.otp_challenges)`, nil, &n)
	if n != 0 {
		t.Errorf("refused requests left %d rows", n)
	}
}

func TestInfrastructureErrorsAreNotLimits(t *testing.T) {
	r := newRig(t, "")
	boom := errors.New("config down")
	svc, err := otp.New(r.tenant.Auth(), r.ring, func(context.Context) (store.PublicConfig, error) { return store.PublicConfig{}, boom })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Request(r.env.Ctx, otp.Request{Phone: r.env.A.Phone, Purpose: otp.Login, Locale: "fa", IP: ip}); !errors.Is(err, boom) {
		t.Errorf("%v", err)
	}
	if _, err := r.svc.Request(r.env.Ctx, otp.Request{Phone: r.env.A.Phone, Purpose: otp.PhoneNew, Locale: "fa", IP: ip}); !errors.Is(err, otp.ErrBadPurpose) {
		t.Errorf("a purpose that needs a session: %v", err)
	}
	// Without an address there is no bucket to count on, and the issue is refused.
	if _, err := r.svc.Request(r.env.Ctx, otp.Request{Phone: r.env.A.Phone, Purpose: otp.Login, Locale: "fa"}); !errors.Is(err, otp.ErrLimited) {
		t.Errorf("no client address: %v", err)
	}
}

func TestCapsAreTheSameForKnownAndUnknown(t *testing.T) {
	r := newRig(t, "")
	// Three per phone and network a day (D31). The fourth is refused for both.
	for _, p := range []string{r.env.A.Phone, "+989129990000"} {
		for i := 0; i < 3; i++ {
			r.mustReq(p, otp.Login)
			r.pastCooldown()
		}
		if _, err := r.req(p, otp.Login); !errors.Is(err, otp.ErrLimited) {
			t.Errorf("%s: the fourth request: %v", p, err)
		}
	}
}

func TestKnownDeviceBreakerAndTrustedKey(t *testing.T) {
	r := newRig(t, "")
	owner := r.env.A.User
	phone := r.env.A.Phone
	// 10 messages a day, soft breaker at 50%. Five have been sent.
	r.env.Exec(t, `UPDATE ctrlz.system_settings SET otp_cap_global = 10, otp_soft_pct = 50`)
	r.env.Exec(t, testpg.PlantCounters(`INSERT INTO ctrlz.sms_counters (day, scope, key, count) VALUES ((now() AT TIME ZONE 'Asia/Tehran')::date, 'global', 'all', 5)`))

	// An unknown device is refused; a known one passes (5.5).
	if _, err := r.req(phone, otp.Login); !errors.Is(err, otp.ErrLimited) {
		t.Fatalf("an unknown device past the soft breaker: %v", err)
	}
	cookie, err := r.markers.Issue(marker.User, r.stamp(owner))
	if err != nil {
		t.Fatal(err)
	}
	dev := r.markers.Open(marker.User, cookie.Value)
	if dev.Zero() {
		t.Fatal("a marker just issued did not open")
	}
	ch, err := r.svc.Request(r.env.Ctx, otp.Request{Phone: phone, Purpose: otp.Login, Locale: "fa", IP: ip, Device: dev})
	if err != nil {
		t.Fatalf("a known device was refused: %v", err)
	}
	if !r.row(ch.ID).Trusted {
		t.Error("the row does not say it was trusted")
	}
	// A trusted request counts on its own key and leaves the shared ones alone.
	if r.counter("phone", phone+"|trusted") != 1 || r.counter("phone", phone) != 0 || r.counter("phone_net", phone+"|198.51.100.0/24") != 0 {
		t.Error("counters of a trusted request")
	}

	// The marker is bound to the credentials the account had when it was issued
	// (tenant-r4-5): after the owner changes the password, an intruder's old marker
	// is an unknown device again, and the owner's fresh one is known.
	r.pastCooldown()
	r.env.Exec(t, `UPDATE ctrlz.users SET password_changed_at = now() WHERE id = $1`, owner)
	if _, err := r.svc.Request(r.env.Ctx, otp.Request{Phone: phone, Purpose: otp.Login, Locale: "fa", IP: ip, Device: dev}); !errors.Is(err, otp.ErrLimited) {
		t.Errorf("a marker from before the password change was still known: %v", err)
	}
	fresh, _ := r.markers.Issue(marker.User, r.stamp(owner))
	if _, err := r.svc.Request(r.env.Ctx, otp.Request{Phone: phone, Purpose: otp.Login, Locale: "fa", IP: ip, Device: r.markers.Open(marker.User, fresh.Value)}); err != nil {
		t.Errorf("a marker issued after the password change was refused: %v", err)
	}

	// The cookie of one account is worth nothing on another's phone: the same
	// device asking for B's number counts as unknown.
	if _, err := r.svc.Request(r.env.Ctx, otp.Request{Phone: r.env.B.Phone, Purpose: otp.Login, Locale: "fa", IP: ip, Device: dev}); !errors.Is(err, otp.ErrLimited) {
		t.Errorf("A's device cookie opened B's phone past the breaker: %v", err)
	}
	// A decoy never counts as trusted, even with a cookie.
	if _, err := r.svc.Request(r.env.Ctx, otp.Request{Phone: "+989129990000", Purpose: otp.Login, Locale: "fa", IP: ip, Device: dev}); !errors.Is(err, otp.ErrLimited) {
		t.Errorf("a cookie opened a decoy past the breaker: %v", err)
	}
}

func TestAStrangerCannotSpendTheOwnersCap(t *testing.T) {
	r := newRig(t, "")
	phone := r.env.A.Phone
	r.env.Exec(t, `UPDATE ctrlz.system_settings SET otp_cap_phone = 1`)
	// A stranger takes the shared phone allowance.
	r.mustReq(phone, otp.Login)
	r.pastCooldown()
	if _, err := r.req(phone, otp.Login); !errors.Is(err, otp.ErrLimited) {
		t.Fatalf("the stranger's second request: %v", err)
	}
	// The owner's browser carries the device marker and still gets a code.
	cookie, _ := r.markers.Issue(marker.User, r.stamp(r.env.A.User))
	ch, err := r.svc.Request(r.env.Ctx, otp.Request{Phone: phone, Purpose: otp.Login, Locale: "fa", IP: ip, Device: r.markers.Open(marker.User, cookie.Value)})
	if err != nil || !r.row(ch.ID).Sealed {
		t.Errorf("the owner on a known device: %v", err)
	}
}

func TestSessionBoundRequests(t *testing.T) {
	r := newRig(t, "")
	phone := r.env.A.Phone

	re, err := r.svc.RequestForSession(r.env.Ctx, otp.ForReauth, phone, "en", ip)
	if err != nil {
		t.Fatal(err)
	}
	if x := r.row(re.ID); x.Purpose != "login" || !x.Sealed || !x.Trusted {
		t.Errorf("reauth row: %+v", x)
	}
	if d := r.delivery(re.ID, phone, "login"); d.Template != "otp" || d.Locale != "en" {
		t.Errorf("reauth payload: %+v", d)
	}

	old, err := r.svc.RequestForSession(r.env.Ctx, otp.ForPhoneOld, phone, "fa", ip)
	if err != nil {
		t.Fatal(err)
	}
	if x := r.row(old.ID); x.Purpose != "phone_old" || !x.Sealed {
		t.Errorf("phone_old row: %+v", x)
	}
	if d := r.delivery(old.ID, phone, "phone_old"); d.Template != "otp_phone" {
		t.Errorf("phone_old payload: %+v", d)
	}
	if _, err := r.svc.RequestForSession(r.env.Ctx, otp.SessionPurpose(99), phone, "fa", ip); !errors.Is(err, otp.ErrBadPurpose) {
		t.Errorf("unknown kind: %v", err)
	}

	// The new number: a free one gets a real message, one that belongs to someone
	// else gets a decoy, so no SMS reaches a third party and the answers match.
	free, err := r.svc.RequestNewPhone(r.env.Ctx, "+989127770000", "fa", ip)
	if err != nil {
		t.Fatal(err)
	}
	taken, err := r.svc.RequestNewPhone(r.env.Ctx, r.env.B.Phone, "fa", ip)
	if err != nil {
		t.Fatal(err)
	}
	if !r.row(free.ID).Sealed || r.row(taken.ID).Sealed {
		t.Errorf("phone_new: free sealed %v, taken sealed %v", r.row(free.ID).Sealed, r.row(taken.ID).Sealed)
	}
	if x := r.row(free.ID); x.Purpose != "phone_new" || x.Trusted {
		t.Errorf("phone_new row: %+v", x)
	}
	if free.ExpiresIn != taken.ExpiresIn || free.ResendAfter != taken.ResendAfter {
		t.Error("the answers differ")
	}
}

func TestCodeTypedWithOtherDigitsAndSeparators(t *testing.T) {
	r := newRig(t, "012345")
	phone := r.env.A.Phone
	ch := r.mustReq(phone, otp.Login)
	// Persian digits, a hyphen, a zero-width non-joiner and a space.
	typed := "۰۱۲" + "-" + string(rune(0x200c)) + "۳ ۴۵"
	if err := r.svc.Check(r.env.Ctx, ch.ID, phone, otp.Login, typed); err != nil {
		t.Errorf("%q: %v", typed, err)
	}
	if otp.NormalizeCode("٠١٢ ３４５") != "012345" {
		t.Error("Arabic-Indic and fullwidth digits")
	}
	// A malformed code is hashed like any other and fails there: it costs a try.
	r.pastCooldown()
	ch2 := r.mustReq(phone, otp.Login)
	for _, bad := range []string{"", "12345", "1234567", "abcdef", strings.Repeat("9", 500)} {
		if err := r.svc.Check(r.env.Ctx, ch2.ID, phone, otp.Login, bad); !errors.Is(err, otp.ErrInvalid) && !errors.Is(err, otp.ErrLocked) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if r.row(ch2.ID).Attempts != 5 {
		t.Errorf("attempts %d, want 5: a malformed code must spend a try", r.row(ch2.ID).Attempts)
	}
}

func TestNewCode(t *testing.T) {
	seenZero := false
	counts := [10]int{}
	for i := 0; i < 4000; i++ {
		c, err := otp.NewCode()
		if err != nil {
			t.Fatal(err)
		}
		s := c.Reveal()
		if len(s) != 6 {
			t.Fatalf("length %d: %q", len(s), s)
		}
		for _, d := range s {
			if d < '0' || d > '9' {
				t.Fatalf("not a digit: %q", s)
			}
			counts[d-'0']++
		}
		if s[0] == '0' {
			seenZero = true
		}
	}
	if !seenZero {
		t.Error("no code began with 0 in 4000: leading zeros are lost")
	}
	for d, n := range counts { // 24000 digits, expected 2400 each
		if n < 2100 || n > 2700 {
			t.Errorf("digit %d appeared %d times of 24000", d, n)
		}
	}
	if c, _ := otp.NewCode(); fmt.Sprint(c) != secret.Redacted {
		t.Error("a code prints in clear")
	}
}

// stamp is the credentials of a seeded user, read the way the login reads them.
func (r *rig) stamp(user uuid.UUID) credgen.Stamp {
	r.t.Helper()
	st := credgen.Stamp{Subject: user}
	r.env.Scan(r.t, `SELECT tenant_id, credential_gen FROM ctrlz.users WHERE id = $1`, []any{user}, &st.Tenant, &st.Gen)
	return st
}

func TestNewRequiresItsKeyDomains(t *testing.T) {
	ring, _ := keyring.NewEphemeral(keyring.DomainAuthMAC)
	if _, err := otp.New(store.AuthLookups{}, ring, nil); err == nil {
		t.Error("a service without the otp_delivery key was built")
	}
}

// TestCrossTenant: the same machinery for two tenants does not mix them up.
func TestCrossTenant(t *testing.T) {
	r := newRig(t, "012345")
	a, b := r.env.A.Phone, r.env.B.Phone
	cha, chb := r.mustReq(a, otp.Login), r.mustReq(b, otp.Login)
	// A's challenge does not verify under B's phone, and the reverse, even with
	// the right code.
	if o, _ := r.svc.Verify(r.env.Ctx, cha.ID, b, otp.Login, "012345"); o != otp.Invalid {
		t.Errorf("A's challenge under B's phone: %v", o)
	}
	if o, _ := r.svc.Verify(r.env.Ctx, chb.ID, a, otp.Login, "012345"); o != otp.Invalid {
		t.Errorf("B's challenge under A's phone: %v", o)
	}
	// Each payload opens for its own phone only.
	if d := r.delivery(cha.ID, a, "login"); d.Template != "otp" {
		t.Error("A's payload")
	}
	var ct []byte
	_ = r.env.DB.Scan(r.env.Ctx, `SELECT delivery_ct FROM ctrlz.otp_challenges WHERE id = $1`, []any{cha.ID}, &ct)
	if _, err := sms.OpenOTP(r.ring, b, "login", ct); err == nil {
		t.Error("A's sealed code opened under B's phone")
	}
	// Both users are untouched by the requests.
	for _, u := range []struct {
		tenant, user uuid.UUID
	}{{r.env.A.Tenant, r.env.A.User}, {r.env.B.Tenant, r.env.B.User}} {
		err := r.tenant.WithTenant(r.env.Ctx, u.tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) error {
			got, ok, err := tx.User(u.user)
			if err != nil || !ok || got.LastLoginAt != nil || got.PhoneVerifiedAt != nil {
				t.Errorf("user %v changed by an OTP request: %+v %v", u.user, got, err)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// another builds a second service over the same database with its own keys, as a
// second installation would have.
func (r *rig) another(code string) *otp.Service {
	r.t.Helper()
	ring, err := keyring.NewEphemeral(keyring.DomainAuthMAC, keyring.DomainOTPDelivery)
	if err != nil {
		r.t.Fatal(err)
	}
	svc, err := otp.New(r.tenant.Auth(), ring, func(ctx context.Context) (store.PublicConfig, error) {
		return r.tenant.Auth().PublicConfig(ctx)
	}, otp.WithCodeSource(func() (secret.String, error) { return secret.New(code), nil }))
	if err != nil {
		r.t.Fatal(err)
	}
	return svc
}

// TestGlobalCapHoldsWithParallelCallers is the "Global cost burn" row of 18.5:
// the daily cap is a hard limit even when many callers ask at once, because the
// check and the increment are one statement in auth_otp_issue. Each caller has
// its own phone and its own network, so no other cap can be the one that stops
// them.
func TestGlobalCapHoldsWithParallelCallers(t *testing.T) {
	r := newRig(t, "")
	const cap = 12
	r.env.Exec(t, `UPDATE ctrlz.system_settings SET registration_mode = 'open', otp_cap_global = $1, otp_soft_pct = 100`, cap)

	const callers = 48
	var wg sync.WaitGroup
	var ok, limited, other atomic.Int32
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := r.svc.Request(r.env.Ctx, otp.Request{
				Phone: fmt.Sprintf("+98912777%04d", i), Purpose: otp.Signup, Locale: "fa",
				IP: netip.MustParseAddr(fmt.Sprintf("198.51.%d.7", 100+i)),
			})
			switch {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, otp.ErrLimited):
				limited.Add(1)
			default:
				other.Add(1)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if other.Load() != 0 {
		t.Fatalf("%d requests failed for another reason than the cap", other.Load())
	}
	if ok.Load() != cap || limited.Load() != callers-cap {
		t.Fatalf("%d accepted and %d refused, want %d and %d", ok.Load(), limited.Load(), cap, callers-cap)
	}
	if got := r.counter("global", "all"); got != cap {
		t.Fatalf("the global counter is %d, want %d", got, cap)
	}
	var sealed int
	r.env.Scan(t, `SELECT count(*) FROM ctrlz.otp_challenges WHERE phone_e164 LIKE '+98912777%' AND delivery_ct IS NOT NULL`, nil, &sealed)
	if sealed != cap {
		t.Fatalf("%d messages are queued for the worker, want %d", sealed, cap)
	}
}
