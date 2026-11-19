package admincli_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/admincli"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/totp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// TestDeclareLostAfterTotalLossReusingTheKeyNumber covers admin-r4-3. After a
// loss of the root and the domain file the host regenerates both, and the new
// kek_user_totp is key 1 again. The old seeds still name key 1, the ring holds a
// key 1, and nothing opens them. The tool must clear them. It decides per seed, not per
// number (admin-r13-3): a seed that opens is kept, the ones that do not are cleared.
func TestDeclareLostAfterTotalLossReusingTheKeyNumber(t *testing.T) {
	r := newRig(t)
	oldRoot, newRoot := make([]byte, 32), make([]byte, 32)
	oldRoot[0], newRoot[0] = 1, 2
	lost, _ := keyring.FromRoot(secret.NewBytes(oldRoot), map[string][]uint16{keyring.DomainUserTOTP: {1}})
	regenerated, _ := keyring.FromRoot(secret.NewBytes(newRoot), map[string][]uint16{keyring.DomainUserTOTP: {1}})
	seed := secret.NewBytes(bytes.Repeat([]byte{3}, 20))
	type acct struct{ tenant, user uuid.UUID }
	a, b := acct{r.env.A.Tenant, r.env.A.User}, acct{r.env.B.Tenant, r.env.B.User}
	put := func(ring *keyring.Ring, x acct) {
		t.Helper()
		c, err := ring.Seal(keyring.DomainUserTOTP, totp.UserAAD(x.tenant, x.user), seed.Reveal())
		if err != nil {
			t.Fatal(err)
		}
		r.env.Exec(t, `UPDATE ctrlz.users SET totp_secret_ct = $3, totp_enabled_at = now() WHERE tenant_id = $1 AND id = $2`, x.tenant, x.user, c)
	}
	worker := r.env.Keytool(t)
	env := r.cliEnv(&r.out, &r.errb)
	env.OpenRekey = func(context.Context) (*admincli.RekeyTools, error) {
		return &admincli.RekeyTools{Store: worker, Keys: regenerated}, nil
	}
	declare := func() int {
		r.out.Reset()
		r.errb.Reset()
		return admincli.RunDeclareLost(r.env.Ctx, []string{"user_totp", "--key-number", "1", "--yes"}, env)
	}

	// Tenant A's seed is readable under the regenerated key 1 (it was enrolled
	// after the recovery), tenant B's is under the lost one. The number is the same,
	// so it decides nothing (admin-r13-3, which replaced the refusal of admin-r4-3):
	// B's seed does not open and is cleared, A's opens and is left alone, and the run
	// succeeds. Before round 13 it refused here for good, and no command could clear B.
	put(regenerated, a)
	put(lost, b)
	if code := declare(); code != 0 || !strings.Contains(r.out.String(), "1 users") || !strings.Contains(r.out.String(), "1 seeds that name key 1 open") {
		t.Fatalf("with a readable seed under the number: %d %q %q", code, r.out.String(), r.errb.String())
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND totp_secret_ct IS NOT NULL AND totp_enabled_at IS NOT NULL`, a.user); n != 1 {
		t.Fatal("the seed that opens was cleared")
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND totp_secret_ct IS NULL AND totp_enabled_at IS NULL`, b.user); n != 1 {
		t.Fatal("the seed that does not open was kept")
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.notifications WHERE kind = 'totp_lost' AND tenant_id = $1`, a.tenant); n != 0 {
		t.Fatalf("tenant A, whose seed opens, got %d notices", n)
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.notifications WHERE kind = 'totp_lost' AND tenant_id = $1`, b.tenant); n != 1 {
		t.Fatalf("tenant B got %d notices, want one", n)
	}

	// A second run finds nothing more to clear and does not write another notice.
	if code := declare(); code != 0 || !strings.Contains(r.out.String(), "0 users") {
		t.Fatalf("the second run: %d %q", code, r.out.String())
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.notifications WHERE kind = 'totp_lost'`); n != 1 {
		t.Fatalf("%d notices after the second run, want 1", n)
	}

	// Both under the lost key: none opens, so both are cleared, with their notices.
	put(lost, a)
	if code := declare(); code != 0 || !strings.Contains(r.out.String(), "1 users") {
		t.Fatalf("declare-lost with key 1 in the ring but unreadable seeds: %d %q %q", code, r.out.String(), r.errb.String())
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.users WHERE totp_enabled_at IS NOT NULL OR totp_secret_ct IS NOT NULL`); n != 0 {
		t.Fatalf("%d users still have TOTP set", n)
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.notifications WHERE kind = 'totp_lost'`); n != 2 {
		t.Fatalf("%d notices, want one per tenant", n)
	}
}

// TestDeclareLostClearsTheSeedsThatDoNotOpen is admin-r13-3 as the operator meets it: after the total
// loss of 8.5 the stack runs on regenerated keys, one user enrols under the new key 1 before
// declare-lost is run, and the old seeds, which also say key 1, must still be clearable. The same
// tenant holds two old seeds and the new one; the other tenant holds an old seed of its own.
func TestDeclareLostClearsTheSeedsThatDoNotOpen(t *testing.T) {
	r := newRig(t)
	oldRoot, newRoot := make([]byte, 32), make([]byte, 32)
	oldRoot[0], newRoot[0] = 1, 2
	lost, _ := keyring.FromRoot(secret.NewBytes(oldRoot), map[string][]uint16{keyring.DomainUserTOTP: {1}})
	regenerated, _ := keyring.FromRoot(secret.NewBytes(newRoot), map[string][]uint16{keyring.DomainUserTOTP: {1}})
	seed := secret.NewBytes(bytes.Repeat([]byte{3}, 20))
	seal := func(ring *keyring.Ring, tenant, user uuid.UUID) []byte {
		c, err := ring.Seal(keyring.DomainUserTOTP, totp.UserAAD(tenant, user), seed.Reveal())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	// A second user of tenant A, made by the test, so that tenant A holds a lost seed and the new one.
	second := uuid.New()
	// v1 allows one owner per tenant (D32 keeps members open); the index is dropped in this test database
	// only, to give one tenant a second seed.
	r.env.Exec(t, `DROP INDEX ctrlz.users_one_owner_uq`)
	r.env.Exec(t, `INSERT INTO ctrlz.users (tenant_id, id, phone_e164, password_hash) VALUES ($1, $2, '+989129990000', 'argon2id$member')`, r.env.A.Tenant, second)
	type row struct {
		tenant, user uuid.UUID
		ring         *keyring.Ring
	}
	rows := []row{{r.env.A.Tenant, r.env.A.User, lost}, {r.env.A.Tenant, second, regenerated}, {r.env.B.Tenant, r.env.B.User, lost}}
	sealed := map[uuid.UUID][]byte{}
	for _, x := range rows {
		c := seal(x.ring, x.tenant, x.user)
		sealed[x.user] = c
		r.env.Exec(t, `UPDATE ctrlz.users SET totp_secret_ct = $3, totp_enabled_at = now() WHERE tenant_id = $1 AND id = $2`, x.tenant, x.user, c)
	}
	worker := r.env.Keytool(t)
	env := r.cliEnv(&r.out, &r.errb)
	env.OpenRekey = func(context.Context) (*admincli.RekeyTools, error) {
		return &admincli.RekeyTools{Store: worker, Keys: regenerated}, nil
	}
	if code := admincli.RunDeclareLost(r.env.Ctx, []string{"user_totp", "--key-number", "1", "--yes"}, env); code != 0 {
		t.Fatalf("declare-lost: %d %q", code, r.errb.String())
	}
	for _, x := range rows {
		var ct []byte
		r.env.Scan(t, `SELECT totp_secret_ct FROM ctrlz.users WHERE id = $1`, []any{x.user}, &ct)
		if opens := x.ring == regenerated; opens != bytes.Equal(ct, sealed[x.user]) || (!opens && ct != nil) {
			t.Errorf("user %s: kept=%v, want kept=%v", x.user, ct != nil, opens)
		}
	}
}

// TestMACKeyToolsWarnAboutDeviceMarkers covers admin-r4-7. admin_mac and
// auth_mac also seal the known-device markers that live in browsers for 90 and
// 365 days, so "wait an hour after a rotation" was wrong for them: removing the
// old line after an hour makes every admin browser count on admin_login_user like
// a stranger's. Both tools say how long the old line has to stay.
func TestMACKeyToolsWarnAboutDeviceMarkers(t *testing.T) {
	r := newRig(t)
	for _, domain := range []string{"admin_mac", "auth_mac", "otp_delivery"} {
		for _, args := range [][]string{{"keys", "status", domain}, {"rekey", domain}} {
			r.out.Reset()
			r.errb.Reset()
			if code := r.run(args...); code != 0 {
				t.Fatalf("%v: %d %q", args, code, r.errb.String())
			}
			out := r.out.String()
			// Rendered from keyring.Uses (rule spec-fact-drift): every use, its life and what
			// removal costs, nothing written by hand in the command.
			for _, u := range keyring.UsesOf(domain) {
				for _, want := range []string{u.What, keyring.LifeText(u.Life), u.IfRemoved} {
					if !strings.Contains(out, want) {
						t.Fatalf("%v: output lacks %q: %q", args, want, out)
					}
				}
			}
			if strings.Contains(out, "wait that long") || strings.Contains(out, "rows live 1 hour") {
				t.Fatalf("%v: output still carries the old hand-written wait: %q", args, out)
			}
			if domain == "admin_mac" && !strings.Contains(out, "markers") {
				t.Fatalf("%v: no word about the device markers: %q", args, out)
			}
		}
	}
}
