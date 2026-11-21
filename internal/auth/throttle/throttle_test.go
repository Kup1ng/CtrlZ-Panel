package throttle_test

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/throttle"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/totp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/reqledger"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

var cluster *testpg.Cluster

func TestMain(m *testing.M) {
	os.Exit(testpg.RunMain(m, func(c *testpg.Cluster) { cluster = c }))
}

// recorder is a fake pair of store functions that counts per key.
type recorder struct {
	counts  map[string]int
	hits    []string // "scope"
	resets  []string
	refunds []string
}

func newRecorder() *recorder { return &recorder{counts: map[string]int{}} }

func (r *recorder) hit(_ context.Context, scope string, key []byte, max int, _ time.Duration) (store.ThrottleResult, error) {
	r.hits = append(r.hits, scope)
	k := scope + "|" + string(key)
	r.counts[k]++
	if r.counts[k] > max {
		return store.ThrottleResult{Allowed: false, RetryAfter: 7 * time.Second}, nil
	}
	return store.ThrottleResult{Allowed: true, Epoch: 7}, nil
}

func (r *recorder) reset(_ context.Context, scope string, key []byte) error {
	r.resets = append(r.resets, scope)
	delete(r.counts, scope+"|"+string(key))
	return nil
}

func fakeMAC(parts ...[]byte) []byte { return bytes.Join(parts, []byte{0}) }

func TestPoliciesMatchTable45(t *testing.T) {
	want := map[throttle.Scope]throttle.Policy{
		throttle.LoginPhoneNet:    {Max: 5, Window: 15 * time.Minute, ResetOnSuccess: true},
		throttle.LoginPhone:       {Max: 20, Window: time.Hour, ResetOnSuccess: true},
		throttle.LoginNet:         {Max: 50, Window: 15 * time.Minute},
		throttle.LoginNet48:       {Max: 200, Window: 15 * time.Minute},
		throttle.TOTPUser:         {Max: 5, Window: 15 * time.Minute, ResetOnSuccess: true},
		throttle.ReauthSession:    {Max: 5, Window: 15 * time.Minute, ResetOnSuccess: true},
		throttle.TOTPSession:      {Max: 5, Window: 15 * time.Minute, ResetOnSuccess: true},
		throttle.ResetPasskeyUser: {Max: 5, Window: 15 * time.Minute, ResetOnSuccess: true},
		throttle.OTPVerifyNet:     {Max: 30, Window: 15 * time.Minute},
		throttle.InviteNet:        {Max: 10, Window: 15 * time.Minute},
		throttle.AdminLogin:       {Max: 5, Window: 15 * time.Minute, ResetOnSuccess: true},
		throttle.AdminLoginUser:   {Max: 30, Window: 15 * time.Minute, ResetOnSuccess: true},
		throttle.AdminLoginNet:    {Max: 20, Window: 15 * time.Minute},
		throttle.InviteUse:        {Max: 30, Window: 15 * time.Minute},
		throttle.AdminLoginMarker: {Max: 10, Window: 15 * time.Minute, ResetOnSuccess: true},
		throttle.LoginMarker:      {Max: 10, Window: 15 * time.Minute, ResetOnSuccess: true},
		throttle.AdminReauth:      {Max: 5, Window: 15 * time.Minute, ResetOnSuccess: true},
		throttle.AdminTOTP:        {Max: 5, Window: 15 * time.Minute, ResetOnSuccess: true},
		throttle.AdminTOTPSession: {Max: 5, Window: 15 * time.Minute, ResetOnSuccess: true},
	}
	for sc, w := range want {
		if got, ok := throttle.PolicyOf(sc); !ok || got != w {
			t.Errorf("%s = %+v, want %+v", sc, got, w)
		}
	}
	if _, ok := throttle.PolicyOf("nope"); ok {
		t.Error("unknown scope")
	}
}

func TestLoginHitsCountFourScopesAndNeverTheRawPhone(t *testing.T) {
	r := newRecorder()
	s := throttle.New(r.hit, r.reset, fakeMAC)
	ip := netip.MustParseAddr("2001:db8:1:2::9")
	if err := s.LoginHits(reqledger.With(context.Background()), "+989121234567", ip); err != nil {
		t.Fatal(err)
	}
	if strings.Join(r.hits, ",") != "login_phone_net,login_phone,login_net,login_net48" {
		t.Fatalf("scopes hit: %v", r.hits)
	}
	r = newRecorder()
	s = throttle.New(r.hit, r.reset, fakeMAC)
	_ = s.LoginHits(reqledger.With(context.Background()), "+989121234567", netip.MustParseAddr("203.0.113.9"))
	if strings.Join(r.hits, ",") != "login_phone_net,login_phone,login_net" {
		t.Fatalf("IPv4 must not touch the /48 scope: %v", r.hits)
	}
}

func TestLoginHitStopsAtTheFirstRefusalAndReportsRetryAfter(t *testing.T) {
	r := newRecorder()
	s := throttle.New(r.hit, r.reset, fakeMAC)
	ip := netip.MustParseAddr("203.0.113.9")
	var err error
	for i := 0; i < 6; i++ {
		err = s.LoginHits(reqledger.With(context.Background()), "+989121234567", ip)
	}
	var tm *throttle.TooManyError
	if !errors.Is(err, throttle.ErrTooMany) || !errors.As(err, &tm) || tm.RetryAfter != 7*time.Second {
		t.Fatalf("6th attempt: %v", err)
	}
	// The refused sixth hit did not count on the wider scopes.
	if r.counts["login_phone|"+"login_phone\x00+989121234567"] != 5 {
		t.Fatalf("login_phone counted %d, want 5", r.counts["login_phone|login_phone\x00+989121234567"])
	}
	// Another phone from the same network starts its own phone counters.
	if err := s.LoginHits(reqledger.With(context.Background()), "+989351112233", ip); err != nil {
		t.Fatalf("another phone: %v", err)
	}
}

func TestSuccessResetsOnlyTheResettingScopes(t *testing.T) {
	r := newRecorder()
	s := withRefund(r)
	ip := netip.MustParseAddr("203.0.113.9")
	_ = s.LoginHits(reqledger.With(context.Background()), "+989121234567", ip)
	if err := s.LoginSuccess(reqledger.With(context.Background()), "+989121234567", ip, ""); err != nil {
		t.Fatal(err)
	}
	if strings.Join(r.resets, ",") != "login_phone_net,login_phone" {
		t.Fatalf("resets: %v", r.resets)
	}
	// Asking to reset a network scope is refused: it must not be clearable.
	if err := s.Clear(reqledger.With(context.Background()), throttle.LoginNet, throttle.Who{IP: ip}); err == nil {
		t.Fatal("login_net does not reset on success")
	}
}

func TestSameValueUnderTwoScopesHasTwoKeys(t *testing.T) {
	var keys [][]byte
	hit := func(_ context.Context, _ string, key []byte, _ int, _ time.Duration) (store.ThrottleResult, error) {
		keys = append(keys, key)
		return store.ThrottleResult{Allowed: true}, nil
	}
	s := throttle.New(hit, nil, fakeMAC)
	w := throttle.Who{IP: netip.MustParseAddr("203.0.113.9")}
	_ = s.Charge(reqledger.With(context.Background()), throttle.LoginNet, w)
	_ = s.Charge(reqledger.With(context.Background()), throttle.OTPVerifyNet, w)
	if bytes.Equal(keys[0], keys[1]) {
		t.Fatal("the scope must be part of the key")
	}
}

func TestAdminLoginKeysIncludeTheNetworkOnlyInTheFirstScope(t *testing.T) {
	r := newRecorder()
	s := throttle.New(r.hit, r.reset, fakeMAC)
	for _, ip := range []string{"203.0.113.9", "198.51.100.4"} {
		_, _ = s.AdminLoginHits(reqledger.With(context.Background()), "Root ", netip.MustParseAddr(ip), "")
	}
	// admin_login splits by network, admin_login_user does not: two networks
	// guessing at one username share the second counter.
	if r.counts["admin_login_user|admin_login_user\x00root"] != 2 {
		t.Fatalf("admin_login_user counts: %v", r.counts)
	}
	n := 0
	for k := range r.counts {
		if strings.HasPrefix(k, "admin_login|") {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("admin_login has %d keys, want one per network", n)
	}
}

// TestCountedGuardIsAValidGuard: the guard of a check inside a transaction allows every
// hit once the attempt was counted (Charge, before the transaction), spends on the
// caller's connection, and resets nothing (Clear runs after the commit). It holds no
// Service, so it has nothing to count with: that is how a check inside a transaction
// cannot ask the pool for a second connection (rule one-connection-per-request).
func TestCountedGuardIsAValidGuard(t *testing.T) {
	r := newRecorder()
	s := throttle.New(r.hit, r.reset, fakeMAC)
	who := throttle.Who{Admin: uuid.New()}
	charged, err := s.ChargeProof(reqledger.With(context.Background()), throttle.AdminTOTP, who)
	if err != nil {
		t.Fatal(err)
	}
	spent := int64(0)
	g := throttle.Counted(charged, throttle.AdminTOTP, who, func(_ context.Context, step int64) (bool, error) {
		if step <= spent {
			return false, nil
		}
		spent = step
		return true, nil
	})
	var _ totp.Guard = g
	ctx := reqledger.With(context.Background())
	for i := 0; i < 20; i++ {
		if ok, _, err := g.Hit(ctx); err != nil || !ok {
			t.Fatalf("hit %d: %v %v", i, ok, err)
		}
	}
	if fresh, _ := g.Spend(ctx, 10); !fresh {
		t.Fatal("first spend")
	}
	if fresh, _ := g.Spend(ctx, 10); fresh {
		t.Fatal("a spent step must not be fresh")
	}
	if err := g.Reset(ctx); err != nil {
		t.Fatal(err)
	}
}

// TestCountedGuardRefusesACheckThatWasNotCharged is the abuse test of round 5
// (primitives-r5-1, -10): a check reached with no charge, with the charge of another
// scope or with the charge of another account never gets as far as the comparison, so a
// route that forgot to count cannot be used to guess a code without limit. The proof is a
// type only the service makes, so the zero value and a foreign one are the only things a
// forgetful route can hold.
func TestCountedGuardRefusesACheckThatWasNotCharged(t *testing.T) {
	r := newRecorder()
	s := throttle.New(r.hit, r.reset, fakeMAC)
	ctx := reqledger.With(context.Background())
	admin, other := throttle.Who{Admin: uuid.New()}, throttle.Who{Admin: uuid.New()}
	mine, err := s.ChargeProof(ctx, throttle.AdminTOTP, admin)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		proof throttle.Charged
		sc    throttle.Scope
		who   throttle.Who
	}{
		"no charge":        {throttle.Charged{}, throttle.AdminTOTP, admin},
		"another account":  {mine, throttle.AdminTOTP, other},
		"another scope":    {mine, throttle.AdminReauth, admin},
		"the right charge": {mine, throttle.AdminTOTP, admin},
	} {
		spends := 0
		g := throttle.Counted(c.proof, c.sc, c.who, func(context.Context, int64) (bool, error) {
			spends++
			return true, nil
		})
		seed := secret.NewBytes([]byte("12345678901234567890"))
		err := totp.CheckAt(ctx, g, seed, secret.New("287082"), time.Unix(59, 0))
		if name == "the right charge" {
			if err != nil || spends != 1 {
				t.Errorf("%s: err %v, spends %d", name, err, spends)
			}
			continue
		}
		if !errors.Is(err, throttle.ErrNotCharged) || spends != 0 {
			t.Errorf("%s: err %v, spends %d; a check that was not counted must stop before it spends", name, err, spends)
		}
	}
}

// ---------------------------------------------------------------------------
// Against the real functions

func ring(t *testing.T) *keyring.Ring {
	t.Helper()
	r, err := keyring.NewEphemeral(keyring.DomainAuthMAC, keyring.DomainAdminMAC)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestLoginThrottleInPostgres(t *testing.T) {
	env := authtest.New(t, cluster)
	st := env.Tenant(t)
	s := throttle.NewUser(st.Auth(), ring(t))
	ctx := reqledger.With(context.Background())
	ip := netip.MustParseAddr("203.0.113.9")

	for i := 0; i < 5; i++ {
		if err := s.LoginHits(ctx, env.A.Phone, ip); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	var tm *throttle.TooManyError
	if err := s.LoginHits(ctx, env.A.Phone, ip); !errors.As(err, &tm) || tm.RetryAfter <= 0 {
		t.Fatalf("6th attempt: %v", err)
	}
	// Another phone is unaffected: the guesser is stopped, the neighbour is not.
	if err := s.LoginHits(ctx, env.B.Phone, ip); err != nil {
		t.Fatalf("other phone: %v", err)
	}
	// Success clears the phone and network pair.
	if err := s.LoginSuccess(ctx, env.A.Phone, ip, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.LoginHits(ctx, env.A.Phone, ip); err != nil {
		t.Fatalf("after success: %v", err)
	}
}

func TestAdminScopesAreNotReachableFromTheTenantService(t *testing.T) {
	env := authtest.New(t, cluster)
	st := env.Tenant(t)
	// A user-service throttle pointed at an admin scope: the database refuses.
	s := throttle.NewUser(st.Auth(), ring(t))
	if err := s.Charge(reqledger.With(context.Background()), throttle.AdminLogin, throttle.Who{Username: "root", IP: netip.MustParseAddr("203.0.113.9")}); err == nil {
		t.Fatal("ctrlz_tenant must not be able to hit an admin scope")
	}
	// And the admin pair works for them.
	adm := throttle.NewAdmin(env.Admin(t).Admin(), ring(t))
	if _, err := adm.AdminLoginHits(reqledger.With(context.Background()), "root", netip.MustParseAddr("203.0.113.9"), ""); err != nil {
		t.Fatalf("admin hits: %v", err)
	}
	// While the admin service cannot reach a user scope.
	if err := adm.Charge(reqledger.With(context.Background()), throttle.LoginNet, throttle.Who{IP: netip.MustParseAddr("203.0.113.9")}); err == nil {
		t.Fatal("ctrlz_admin must not be able to hit a user scope")
	}
}

// TestAdminKnownDeviceChargesOnlyItsMarker: review round 1 (admin-r1-13), made a rule
// by budget-keying. A request that carries a marker that holds for the account counts
// on the marker's own scope and on none of the three that strangers can fill: not the
// username (which locked the owner out from many networks), and not the network ones
// (which a stranger on the owner's carrier NAT shares).
func TestAdminKnownDeviceChargesOnlyItsMarker(t *testing.T) {
	r := newRecorder()
	s := throttle.New(r.hit, r.reset, fakeMAC)
	for i := 0; i < 3; i++ {
		_, _ = s.AdminLoginHits(reqledger.With(context.Background()), "root", netip.MustParseAddr("203.0.113.9"), "m1")
	}
	var other, marker int
	for k, v := range r.counts {
		if strings.HasPrefix(k, "admin_login|admin_login_marker") {
			marker += v // stored under the database scope admin_login, with a key of its own
		} else {
			other += v
		}
	}
	if marker != 3 || other != 0 {
		t.Fatalf("marker scope %d, every other scope %d, want 3 and 0 (counts %v)", marker, other, r.counts)
	}
}

// throttleRow reads the one row of a scope as the superuser. The tests below
// use one key per scope, so the scope alone finds it.
func throttleRow(t *testing.T, env *authtest.Env, scope string) (count int, ageSeconds float64) {
	t.Helper()
	env.Scan(t, `SELECT count, extract(epoch FROM now() - window_start) FROM ctrlz.auth_throttle WHERE scope = $1`,
		[]any{scope}, &count, &ageSeconds)
	return count, ageSeconds
}

// TestThrottleWindowSaturationAndReset is primitives-r1-5: the SQL window logic
// that spec 4.5 and 18.5 lean on, with time moved by editing window_start.
func TestThrottleWindowSaturationAndReset(t *testing.T) {
	env := authtest.New(t, cluster)
	user := throttle.NewUser(env.Tenant(t).Auth(), ring(t))
	adm := throttle.NewAdmin(env.Admin(t).Admin(), ring(t))
	ctx := reqledger.With(context.Background())

	for _, tc := range []struct {
		name  string
		svc   *throttle.Service
		scope throttle.Scope
	}{
		{"user pair", user, throttle.LoginPhoneNet},
		{"admin pair", adm, throttle.AdminLogin},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pol, _ := throttle.PolicyOf(tc.scope)
			sc := string(tc.scope)
			who := throttle.Who{Phone: "k", Username: "k", IP: netip.MustParseAddr("203.0.113.9")}
			hit := func() error { return tc.svc.Charge(ctx, tc.scope, who) }

			for i := 0; i < pol.Max; i++ {
				if err := hit(); err != nil {
					t.Fatalf("hit %d: %v", i+1, err)
				}
			}
			// Refused, with the time that is left in the window.
			var tm *throttle.TooManyError
			if err := hit(); !errors.As(err, &tm) {
				t.Fatalf("hit %d: %v", pol.Max+1, err)
			}
			if tm.RetryAfter < pol.Window-5*time.Second || tm.RetryAfter > pol.Window {
				t.Errorf("RetryAfter %v, want about the whole window %v", tm.RetryAfter, pol.Window)
			}
			// Saturation: a flood does not grow the counter past max (a refused hit leaves the line as it
			// found it, primitives-r7-7: past max the refund of an earlier attempt would not free the line), so the
			// integer cannot overflow and the row cannot be inflated.
			for i := 0; i < 20; i++ {
				_ = hit()
			}
			if n, _ := throttleRow(t, env, sc); n != pol.Max {
				t.Errorf("count after a flood is %d, want %d", n, pol.Max)
			}

			// Ten minutes into a 15 minute window: still refused, five minutes left.
			env.Exec(t, `UPDATE ctrlz.auth_throttle SET window_start = now() - interval '10 minutes' WHERE scope = $1`, sc)
			if err := hit(); !errors.As(err, &tm) {
				t.Fatalf("inside the window: %v", err)
			}
			if want := pol.Window - 10*time.Minute; tm.RetryAfter < want-5*time.Second || tm.RetryAfter > want+5*time.Second {
				t.Errorf("RetryAfter %v, want about %v", tm.RetryAfter, want)
			}

			// Past the window: the next hit starts a fresh count of 1, with a
			// new window_start, and the whole budget is back.
			env.Exec(t, `UPDATE ctrlz.auth_throttle SET window_start = now() - interval '16 minutes' WHERE scope = $1`, sc)
			if err := hit(); err != nil {
				t.Fatalf("after the window: %v", err)
			}
			n, age := throttleRow(t, env, sc)
			if n != 1 || age > 5 {
				t.Errorf("after the window: count %d, window age %.0fs, want 1 and a new window", n, age)
			}
			for i := 1; i < pol.Max; i++ {
				if err := hit(); err != nil {
					t.Fatalf("fresh window, hit %d: %v", i+1, err)
				}
			}
			if err := hit(); !errors.As(err, &tm) {
				t.Fatalf("fresh window must refuse hit %d: %v", pol.Max+1, err)
			}

			// Reset (a success) sets the count to 0 and keeps window_start:
			// reset is only a zeroed counter inside the window it was counted in.
			env.Exec(t, `UPDATE ctrlz.auth_throttle SET window_start = now() - interval '3 minutes' WHERE scope = $1`, sc)
			if err := tc.svc.Clear(ctx, tc.scope, who); err != nil {
				t.Fatal(err)
			}
			n, age = throttleRow(t, env, sc)
			if n != 0 || age < 170 || age > 200 {
				t.Errorf("after reset: count %d, window age %.0fs, want 0 and about 180", n, age)
			}
			if err := hit(); err != nil {
				t.Fatalf("after reset: %v", err)
			}
		})
	}
}

// Every entry point keyed on the source network refuses a zero address and
// touches no counter, so callers without an address never share one MACed key
// (review round 4, primitives-r4-1).
func TestEveryNetworkKeyedEntryPointRefusesTheZeroAddress(t *testing.T) {
	var none netip.Addr
	ctx := reqledger.With(context.Background())
	cases := map[string]func(s *throttle.Service) error{
		"LoginHits":            func(s *throttle.Service) error { return s.LoginHits(ctx, "+989121234567", none) },
		"LoginHitsMalformed":   func(s *throttle.Service) error { return s.LoginHitsMalformed(ctx, none) },
		"LoginSuccess":         func(s *throttle.Service) error { return s.LoginSuccess(ctx, "+989121234567", none, "") },
		"OTPVerifyHit":         func(s *throttle.Service) error { return s.OTPVerifyHit(ctx, none) },
		"OTPVerifyRefund":      func(s *throttle.Service) error { return s.OTPVerifyRefund(ctx, none) },
		"LoginRefund":          func(s *throttle.Service) error { return s.LoginRefund(ctx, "+989121234567", none, "") },
		"LoginRefundMalformed": func(s *throttle.Service) error { return s.LoginRefundMalformed(ctx, none) },
		"InviteHit":            func(s *throttle.Service) error { return s.InviteHit(ctx, none, uuid.Nil) },
		"InviteHitLive":        func(s *throttle.Service) error { return s.InviteHit(ctx, none, uuid.New()) },
		"AdminLoginHits": func(s *throttle.Service) error {
			_, err := s.AdminLoginHits(ctx, "root", none, "")
			return err
		},
		"AdminLoginSuccess": func(s *throttle.Service) error { return s.AdminLoginSuccess(ctx, "root", none, "") },
	}
	for name, call := range cases {
		r := newRecorder()
		s := throttle.New(r.hit, r.reset, fakeMAC)
		if err := call(s); err == nil || errors.Is(err, throttle.ErrTooMany) {
			t.Errorf("%s with the zero address: err = %v, want a no-address error", name, err)
		}
		if len(r.hits) != 0 || len(r.resets) != 0 {
			t.Errorf("%s with the zero address touched a counter: hits %v resets %v", name, r.hits, r.resets)
		}
	}
	// An address does count, so the test cannot pass by every call failing.
	r := newRecorder()
	s := throttle.New(r.hit, r.reset, fakeMAC)
	if err := s.OTPVerifyHit(ctx, netip.MustParseAddr("203.0.113.9")); err != nil || len(r.hits) != 1 {
		t.Fatalf("a real address: err %v hits %v", err, r.hits)
	}
}

func (r *recorder) giveBack(_ context.Context, scope string, key []byte, _ time.Duration, _ int64) error {
	r.refunds = append(r.refunds, scope)
	if k := scope + "|" + string(key); r.counts[k] > 0 {
		r.counts[k]--
	}
	return nil
}

// withRefund is a service on the recorder that also gives back.
func withRefund(r *recorder) *throttle.Service {
	return throttle.New(r.hit, r.reset, fakeMAC).WithRefund(r.giveBack)
}

// TestLoginSuccessGivesTheNetworkAttemptBack is tenant-r5-3. A network scope counts failed
// guesses, not sign-ins: a success clears the pair that resets and gives its own attempt back on
// the two that do not.
func TestLoginSuccessGivesTheNetworkAttemptBack(t *testing.T) {
	r := newRecorder()
	s := withRefund(r)
	ip := netip.MustParseAddr("2001:db8:1:2::9")
	ctx := reqledger.With(context.Background())
	if err := s.LoginHits(ctx, "+989121234567", ip); err != nil {
		t.Fatal(err)
	}
	if err := s.LoginSuccess(ctx, "+989121234567", ip, ""); err != nil {
		t.Fatal(err)
	}
	if strings.Join(r.refunds, ",") != "login_net,login_net48" {
		t.Fatalf("refunds %v, want the two network scopes only", r.refunds)
	}
	// Fifty-one sign-ins from one address group, each right: none is refused.
	r = newRecorder()
	s = withRefund(r)
	v4 := netip.MustParseAddr("203.0.113.9")
	for i := 0; i < 51; i++ {
		phone := "+98912" + strings.Repeat("1", 4) + string(rune('0'+i/10)) + string(rune('0'+i%10)) + "1"
		if err := s.LoginHits(ctx, phone, v4); err != nil {
			t.Fatalf("sign-in %d refused: %v", i+1, err)
		}
		if err := s.LoginSuccess(ctx, phone, v4, ""); err != nil {
			t.Fatal(err)
		}
	}
	// Failed guesses still fill the scope: fifty are allowed and the fifty-first is not.
	r = newRecorder()
	s = withRefund(r)
	var err error
	allowed := 0
	for i := 0; i < 60; i++ {
		phone := "+98935" + string(rune('0'+i/10)) + string(rune('0'+i%10)) + "112233"
		if err = s.LoginHits(ctx, phone, v4); err != nil {
			break
		}
		allowed++
	}
	if !errors.Is(err, throttle.ErrTooMany) || allowed != 50 {
		t.Fatalf("%d failed guesses allowed (%v), want 50", allowed, err)
	}
}

// TestAMarkerThatHoldsTakesThePlaceOfLoginPhoneOnly is tenant-r5-9, at the unit level.
func TestAMarkerThatHoldsTakesThePlaceOfLoginPhoneOnly(t *testing.T) {
	r := newRecorder()
	s := withRefund(r)
	ctx := reqledger.With(context.Background())
	if err := s.LoginHitsFor(ctx, "+989121234567", netip.MustParseAddr("203.0.113.9"), "m-1"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(r.hits, ",") != "login_phone_net,login_phone,login_net" {
		// login_marker is stored under the name login_phone, the key tells the two apart.
		t.Fatalf("scopes hit: %v", r.hits)
	}
	if err := s.LoginRefund(ctx, "+989121234567", netip.MustParseAddr("203.0.113.9"), "m-1"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(r.refunds, ",") != "login_phone_net,login_phone,login_net" {
		t.Fatalf("refunds %v", r.refunds)
	}
	for k, n := range r.counts {
		if n != 0 {
			t.Errorf("%q still counts %d after the refund", k, n)
		}
	}
}

// TestOTPVerifyRefundGivesOneBack: the check of a right code is not a guess.
func TestOTPVerifyRefundGivesOneBack(t *testing.T) {
	r := newRecorder()
	s := withRefund(r)
	ip := netip.MustParseAddr("203.0.113.9")
	ctx := reqledger.With(context.Background())
	_ = s.OTPVerifyHit(ctx, ip)
	if err := s.OTPVerifyRefund(ctx, ip); err != nil || strings.Join(r.refunds, ",") != "otp_verify_net" {
		t.Fatalf("refund: %v %v", err, r.refunds)
	}
	if err := throttle.New(r.hit, r.reset, fakeMAC).OTPVerifyRefund(ctx, ip); err == nil {
		t.Fatal("a service with no refund must say so, not skip it")
	}
}

// TestRefundInPostgres is tenant-r5-1 on the real function: it gives back inside the window, never
// goes below zero, and cannot reach a counter the tenant service has no business with.
func TestRefundInPostgres(t *testing.T) {
	env := authtest.New(t, cluster)
	st := env.Tenant(t)
	s := throttle.NewUser(st.Auth(), ring(t))
	ctx := reqledger.With(context.Background())
	ip := netip.MustParseAddr("203.0.113.9")
	for i := 0; i < 4; i++ {
		if err := s.LoginHits(ctx, env.A.Phone, ip); err != nil {
			t.Fatal(err)
		}
	}
	// Four busy answers, each given back, leave the budget whole: the five tries still all work.
	for i := 0; i < 4; i++ {
		if err := s.LoginRefund(ctx, env.A.Phone, ip, ""); err != nil {
			t.Fatal(err)
		}
	}
	// A refund with nothing counted does not make a credit.
	for i := 0; i < 3; i++ {
		if err := s.LoginRefund(ctx, env.A.Phone, ip, ""); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 5; i++ {
		if err := s.LoginHits(ctx, env.A.Phone, ip); err != nil {
			t.Fatalf("attempt %d after the refunds: %v", i+1, err)
		}
	}
	if err := s.LoginHits(ctx, env.A.Phone, ip); !errors.Is(err, throttle.ErrTooMany) {
		t.Fatalf("a sixth attempt: %v, want a refusal (a refund must never be a credit)", err)
	}
}

// TestAdminRefundInPostgres is primitives-r6-9 on the real function: the admin login can give back
// an attempt its verify never looked at, only inside the window it was counted in, and never as a
// credit.
func TestAdminRefundInPostgres(t *testing.T) {
	env := authtest.New(t, cluster)
	adm := throttle.NewAdmin(env.Admin(t).Admin(), ring(t))
	ctx := reqledger.With(context.Background())
	ip := netip.MustParseAddr("203.0.113.9")
	w := throttle.Who{IP: ip, Username: "root"}
	pol, _ := throttle.PolicyOf(throttle.AdminLoginUser)
	for i := 0; i < pol.Max-1; i++ {
		if err := adm.Charge(ctx, throttle.AdminLoginUser, w); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < pol.Max+5; i++ { // more refunds than charges: no credit
		if err := adm.Refund(ctx, throttle.AdminLoginUser, w); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < pol.Max; i++ {
		if err := adm.Charge(ctx, throttle.AdminLoginUser, w); err != nil {
			t.Fatalf("attempt %d after the refunds: %v", i+1, err)
		}
	}
	if err := adm.Charge(ctx, throttle.AdminLoginUser, w); !errors.Is(err, throttle.ErrTooMany) {
		t.Fatalf("attempt %d: %v, want a refusal", pol.Max+1, err)
	}
}

// TestRefundNeedsTheBookOfTheRequest: a refund on a context with no request book does not guess
// the window; it fails and the attempt stays counted (primitives-r6-2).
func TestRefundNeedsTheBookOfTheRequest(t *testing.T) {
	r := newRecorder()
	s := withRefund(r)
	ip := netip.MustParseAddr("203.0.113.9")
	if err := s.OTPVerifyHit(reqledger.With(context.Background()), ip); err != nil {
		t.Fatal(err)
	}
	if err := s.OTPVerifyRefund(context.Background(), ip); err == nil {
		t.Fatal("a refund with no request book was made")
	}
	if len(r.refunds) != 0 {
		t.Fatalf("refunds %v", r.refunds)
	}
	// Another request's book does not hold this request's charge: nothing is given back.
	other := reqledger.With(context.Background())
	if err := s.OTPVerifyRefund(other, ip); err != nil || len(r.refunds) != 0 {
		t.Fatalf("a refund of a charge this request never made: err %v, refunds %v", err, r.refunds)
	}
}
