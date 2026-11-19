package throttle_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/throttle"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/budget"
	"github.com/Kup1ng/CtrlZ-Panel/internal/reqledger"
)

// ceilingCase is one scope that counts guesses at a second factor, with whom it is keyed on.
type ceilingCase struct {
	name  string
	admin bool
	scope throttle.Scope
	who   func() throttle.Who
}

// ceilingCases is every scope of the registry that declares a long ceiling, with a Who that holds exactly the
// parts its key is made of. It is read from the registry and not listed by hand (round 9, primitives-r9-3): the
// ceiling is applied for every caller by Service.Charge, Refund, Clear and Unlock, so its enforcement is run over
// every scope that declares one, and a scope added tomorrow is walked, cleared and unlocked the day it is declared.
func ceilingCases(t testing.TB) []ceilingCase {
	t.Helper()
	var out []ceilingCase
	for _, b := range budget.All() {
		if b.Layer != budget.Throttle || b.CeilingMax < 1 {
			continue
		}
		out = append(out, ceilingCase{
			name: string(b.Service) + " " + b.Name, admin: b.Service == budget.Admin, scope: throttle.Scope(b.Name),
			who: func() throttle.Who {
				var w throttle.Who
				for _, p := range b.Parts {
					switch p {
					case budget.PartUser:
						w.User = uuid.New()
					case budget.PartAdmin:
						w.Admin = uuid.New()
					case budget.PartUserSession, budget.PartAdminSession:
						w.Session = uuid.New()
					case budget.PartMarker:
						w.Marker = uuid.NewString()
					default:
						t.Fatalf("%s: a ceiling over the part %q: the test does not know how to build a subject for it", b.Name, p)
					}
				}
				// A member of a ceiling group also carries the account, as the handler's Who does, so that a
				// success on it can end the ceilings of the group.
				if b.CeilingGroup != "" && w.User == uuid.Nil && w.Admin == uuid.Nil {
					w.User = uuid.New()
				}
				return w
			},
		})
	}
	if len(out) < 7 {
		t.Fatalf("%d scopes declare a ceiling, want at least the seven of round 9: the filter found nothing to prove", len(out))
	}
	return out
}

func ceilingService(t *testing.T, env *authtest.Env, admin bool) *throttle.Service {
	t.Helper()
	if admin {
		return throttle.NewAdmin(env.Admin(t).Admin(), ring(t))
	}
	return throttle.NewUser(env.Tenant(t).Auth(), ring(t))
}

// TestTheLongCeilingBoundsGuessesAcrossManyWindows is primitives-r8-4 on the real database function. The
// 15 minute window refills 96 times a day, so a guesser who spent exactly five tries per window had 480
// a day for as long as he cared to, a 41% chance of a hit within a year at three matching codes in a
// million. Here the clock is driven across a whole day (window_start moved back by the length of each
// window, the way TestThrottleWindowSaturationAndReset does) and the number of tries one subject gets in
// that day must be the ceiling and not 480, for every scope that counts a code, on both services. A
// second subject, the account of another tenant or the other admin, keeps its own whole budget.
func TestTheLongCeilingBoundsGuessesAcrossManyWindows(t *testing.T) {
	for _, tc := range ceilingCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			env := authtest.New(t, cluster)
			svc := ceilingService(t, env, tc.admin)
			b, _ := budget.FindScope(string(tc.scope))
			if b.CeilingMax < 1 || b.CeilingWindow < 24*time.Hour {
				t.Fatalf("%s declares no daily ceiling: %+v", tc.scope, b)
			}
			var hook []throttle.Scope
			svc = svc.WithCeilingHook(func(sc throttle.Scope) { hook = append(hook, sc) })
			ctx := reqledger.With(context.Background())
			victim, bystander := tc.who(), tc.who()

			// Day one: six tries in every 16 minutes, the most the short window allows (five) plus one it refuses.
			allowed := 0
			for elapsed := time.Duration(0); elapsed < 24*time.Hour; elapsed += 16 * time.Minute {
				for i := 0; i < 6; i++ {
					switch err := svc.Charge(ctx, tc.scope, victim); {
					case err == nil:
						allowed++
					case !errors.Is(err, throttle.ErrTooMany):
						t.Fatal(err)
					}
				}
				env.Exec(t, `UPDATE ctrlz.auth_throttle SET window_start = window_start - interval '16 minutes'`)
			}
			if allowed != b.CeilingMax {
				t.Fatalf("%d tries in a day, want exactly the ceiling %d (the short window alone would give 480)", allowed, b.CeilingMax)
			}
			if len(hook) == 0 || hook[0] != tc.scope {
				t.Errorf("the ceiling hook was told %v, want %s", hook, tc.scope)
			}
			// The refusal is the same error as the short window's and says how long is left, a day at most.
			env.Exec(t, `UPDATE ctrlz.auth_throttle SET window_start = window_start + interval '16 minutes'`)
			var tm *throttle.TooManyError
			if err := svc.Charge(ctx, tc.scope, victim); !errors.As(err, &tm) || tm.RetryAfter <= 0 || tm.RetryAfter > 24*time.Hour {
				t.Errorf("a charge on a full ceiling: %v", err)
			}
			// Another subject has its whole budget: the ceiling is a count of the subject and not of the scope.
			for i := 0; i < b.Max; i++ {
				if err := svc.Charge(ctx, tc.scope, bystander); err != nil {
					t.Fatalf("the other subject's try %d: %v", i+1, err)
				}
			}
			// The day is over: the ceiling restarts, and only then.
			env.Exec(t, `UPDATE ctrlz.auth_throttle SET window_start = window_start - interval '25 hours'`)
			if err := svc.Charge(ctx, tc.scope, victim); err != nil {
				t.Fatalf("after the day: %v", err)
			}
		})
	}
}

// TestASuccessEndsTheCeilingAndAnUnlockDoesToo: what the ceiling counts is the run of tries since the last
// success, so an owner who signs in with the right code is not walked toward it by their own sign-ins; and
// the console's `unlock` clears it for an admin (round 8, primitives-r8-4).
func TestASuccessEndsTheCeilingAndAnUnlockDoesToo(t *testing.T) {
	for _, tc := range ceilingCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			env := authtest.New(t, cluster)
			svc := ceilingService(t, env, tc.admin)
			b, _ := budget.FindScope(string(tc.scope))
			ctx := reqledger.With(context.Background())
			w := tc.who()
			fill := func() {
				t.Helper()
				// As many full short windows as the ceiling holds, and one more.
				for win := 0; win <= b.CeilingMax/b.Max; win++ {
					for i := 0; i < b.Max; i++ {
						_ = svc.Charge(ctx, tc.scope, w)
					}
					env.Exec(t, `UPDATE ctrlz.auth_throttle SET window_start = window_start - interval '16 minutes'`)
				}
				env.Exec(t, `UPDATE ctrlz.auth_throttle SET window_start = window_start + interval '16 minutes'`)
			}
			fill()
			if err := svc.Charge(ctx, tc.scope, w); !errors.Is(err, throttle.ErrTooMany) {
				t.Fatalf("the ceiling is not full: %v", err)
			}
			if err := svc.Clear(ctx, tc.scope, w); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < b.Max; i++ {
				if err := svc.Charge(ctx, tc.scope, w); err != nil {
					t.Fatalf("after a success, try %d: %v", i+1, err)
				}
			}
			if tc.admin && !b.Unlock {
				t.Fatalf("%s has a long ceiling and the console's unlock does not clear it: an admin locked out by it would have no way back", tc.scope)
			}
			if b.Unlock {
				fill()
				admin := w.Admin
				if admin == uuid.Nil {
					admin = uuid.New() // unlock names the admin even when the scope under test is keyed on a session
				}
				if err := svc.Unlock(ctx, throttle.Who{Username: "root", Admin: admin, IP: netip.MustParseAddr("203.0.113.9")}); err != nil {
					t.Fatal(err)
				}
				if err := svc.Charge(ctx, tc.scope, w); err != nil {
					t.Fatalf("after unlock: %v", err)
				}
			}
		})
	}
}

// TestTheCeilingIsGivenBackWithTheTryItBelongsTo: a try the server was too busy to look at is given back
// (tenant-r5-1) and must not stay spent on the ceiling either, and the ceiling key is not the short
// window's key. A try the short window refused is not a guess and costs the ceiling nothing.
func TestTheCeilingIsGivenBackWithTheTryItBelongsTo(t *testing.T) {
	r := newRecorder()
	s := withRefund(r)
	ctx := reqledger.With(context.Background())
	w := throttle.Who{User: uuid.New()}
	if err := s.Charge(ctx, throttle.TOTPUser, w); err != nil {
		t.Fatal(err)
	}
	if len(r.hits) != 2 || r.hits[0] != "totp_user" || r.hits[1] != "totp_user" {
		t.Fatalf("hits %v, want the short window and the ceiling, both stored under totp_user", r.hits)
	}
	if len(r.counts) != 2 {
		t.Fatalf("the two counts share a key: %v", r.counts)
	}
	if err := s.Refund(ctx, throttle.TOTPUser, w); err != nil {
		t.Fatal(err)
	}
	if len(r.refunds) != 2 {
		t.Fatalf("refunds %v, want both counts given back", r.refunds)
	}
	for k, n := range r.counts {
		if n != 0 {
			t.Errorf("%q still holds %d after the refund", k, n)
		}
	}
	// Six tries: five pairs, then the short window's refusal alone.
	r = newRecorder()
	s = withRefund(r)
	for i := 0; i < 6; i++ {
		_ = s.Charge(ctx, throttle.TOTPUser, w)
	}
	if len(r.hits) != 11 {
		t.Errorf("%d hits, want 11 (five pairs, then one refused hit on the short window and none on the ceiling)", len(r.hits))
	}
}

// fillCeiling spends the whole ceiling of a scope for a subject, window after window, the way a patient guesser
// does, and leaves the clock where the last window is still open.
func fillCeiling(t *testing.T, env *authtest.Env, svc *throttle.Service, ctx context.Context, sc throttle.Scope, w throttle.Who) {
	t.Helper()
	b, _ := budget.FindScope(string(sc))
	for win := 0; win <= b.CeilingMax/b.Max; win++ {
		for i := 0; i < b.Max; i++ {
			_ = svc.Charge(ctx, sc, w)
		}
		env.Exec(t, `UPDATE ctrlz.auth_throttle SET window_start = window_start - interval '16 minutes'`)
	}
	env.Exec(t, `UPDATE ctrlz.auth_throttle SET window_start = window_start + interval '16 minutes'`)
}

// TestACeilingGroupIsSplitByWhatProvedTheFirstStepAndEndedByAnySuccess is primitives-r9-4 on the real database
// function. The tenant's second-factor ceiling used to be one count keyed on the account, so whoever held only the
// SMS (a SIM swap, the reset ticket) filled it with twenty requests and the owner's password login was refused for a
// day, recovery codes included. Now (1) filling the ceiling of one member of the group refuses that member and no
// other, for the same account; (2) a success on ANY member, the recovery code's included, ends the ceilings of the
// others (the owner's own way out, the console has no tenant unlock), but not their 15 minute windows; (3) another
// account's ceilings are never touched. The group is read from the registry.
func TestACeilingGroupIsSplitByWhatProvedTheFirstStepAndEndedByAnySuccess(t *testing.T) {
	groups := map[string][]budget.Bucket{}
	for _, b := range budget.All() {
		if b.Layer == budget.Throttle && b.CeilingGroup != "" {
			groups[b.CeilingGroup] = append(groups[b.CeilingGroup], b)
		}
	}
	if len(groups) == 0 {
		t.Fatal("no ceiling group in the registry: the split of round 9 is gone")
	}
	for name, members := range groups {
		withCeiling := 0
		for _, m := range members {
			if m.CeilingMax > 0 {
				withCeiling++
			}
		}
		if withCeiling < 3 {
			t.Fatalf("group %s has %d scopes with a ceiling, want the password ticket, the SMS ticket and the marker", name, withCeiling)
		}
		for _, victim := range members {
			if victim.CeilingMax < 1 {
				continue
			}
			t.Run(name+"/"+victim.Name, func(t *testing.T) {
				env := authtest.New(t, cluster)
				svc := ceilingService(t, env, victim.Service == budget.Admin)
				ctx := reqledger.With(context.Background())
				user, other := uuid.New(), uuid.New()
				// One browser per account: a marker id belongs to the account it was sealed for.
				markers := map[uuid.UUID]string{user: uuid.NewString(), other: uuid.NewString()}
				whoOf := func(m budget.Bucket, u uuid.UUID) throttle.Who {
					w := throttle.Who{User: u}
					if m.Parts[0] == budget.PartMarker {
						w.Marker = markers[u]
					}
					return w
				}
				// A stranger who holds one proof fills that member's ceiling.
				fillCeiling(t, env, svc, ctx, throttle.Scope(victim.Name), whoOf(victim, user))
				if err := svc.Charge(ctx, throttle.Scope(victim.Name), whoOf(victim, user)); !errors.Is(err, throttle.ErrTooMany) {
					t.Fatalf("the ceiling of %s is not full: %v", victim.Name, err)
				}
				for _, m := range members {
					if m.Name == victim.Name {
						continue
					}
					// Every other member of the group, for the SAME account, still serves its first try.
					if err := svc.Charge(ctx, throttle.Scope(m.Name), whoOf(m, user)); err != nil {
						t.Errorf("filling the ceiling of %s refused %s for the same account: %v", victim.Name, m.Name, err)
					}
				}
				// Another account's counters are its own.
				if err := svc.Charge(ctx, throttle.Scope(victim.Name), whoOf(victim, other)); err != nil {
					t.Errorf("another account met the ceiling of %s: %v", victim.Name, err)
				}
				// A success on any other member ends the run for the account: the full ceiling serves again. The
				// exception is the ceiling of a marker, which belongs to one browser and which a request without that
				// marker cannot name: it is ended by a success of the same browser (the generic success test above),
				// and a success elsewhere must not reach it (it stays full, by design).
				for _, m := range members {
					if m.Name == victim.Name {
						continue
					}
					if victim.Parts[0] == budget.PartMarker {
						fillCeiling(t, env, svc, ctx, throttle.Scope(victim.Name), whoOf(victim, user))
						if err := svc.Clear(ctx, throttle.Scope(m.Name), whoOf(m, user)); err != nil && !errors.Is(err, throttle.ErrTooMany) {
							t.Fatalf("clear %s: %v", m.Name, err)
						}
						env.Exec(t, `UPDATE ctrlz.auth_throttle SET window_start = window_start - interval '16 minutes'`)
						if m.Parts[0] != budget.PartMarker {
							if err := svc.Charge(ctx, throttle.Scope(victim.Name), whoOf(victim, user)); !errors.Is(err, throttle.ErrTooMany) {
								t.Errorf("a success on %s, which carries no marker, reached the ceiling of one browser: %v", m.Name, err)
							}
						}
						continue
					}
					fillCeiling(t, env, svc, ctx, throttle.Scope(victim.Name), whoOf(victim, user))
					if err := svc.Clear(ctx, throttle.Scope(m.Name), whoOf(m, user)); err != nil {
						t.Fatalf("clear %s: %v", m.Name, err)
					}
					env.Exec(t, `UPDATE ctrlz.auth_throttle SET window_start = window_start - interval '16 minutes'`) // the short windows have run out
					if err := svc.Charge(ctx, throttle.Scope(victim.Name), whoOf(victim, user)); err != nil {
						t.Errorf("a success on %s did not end the ceiling of %s: %v", m.Name, victim.Name, err)
					}
				}
			})
		}
	}
}
