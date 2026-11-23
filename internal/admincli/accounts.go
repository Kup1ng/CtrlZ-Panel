package admincli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/adminname"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/adminnotice"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/throttle"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// cliVia is the params.via of the audit rows these commands write (13.2).
const cliVia = audit.ViaCLI

// maxBootstrapRetries bounds the Serializable retry of bootstrap. A conflict
// means a parallel bootstrap won; the second attempt then sees its row and
// refuses, so a handful of tries is plenty.
const maxBootstrapRetries = 5

// validUsername is the rule of 10.1 step 1, and it is the login schema's rule: both ask
// internal/adminname, because a name the CLI took and the schema refused made an account nobody
// could sign in to, and bootstrap runs only once (round 6, admin-r6-2).
func validUsername(u string) bool { return adminname.Valid(u) }

// runBootstrap is `ctrlz-admin bootstrap` (10.1): the first admin, and only if
// no admin exists. Two parallel runs cannot both win, because the insert is
// conditional and runs at Serializable.
func runBootstrap(ctx context.Context, env Env, args []string) error {
	fs := newFlags(env, "bootstrap")
	username := fs.String("username", "", "the new admin's username")
	outFile := fs.String("out-file", "", "the new file (mode 0600) that receives the one-time password; required")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return usageErr("bootstrap takes no arguments besides its flags")
	}
	// The output rule first: nothing changes if the password could not be written.
	out, err := prepareOutput(env, *outFile)
	if err != nil {
		return err
	}
	name := strings.TrimSpace(*username)
	if name == "" {
		if name, err = prompt(env, "username: "); err != nil {
			out.abandon()
			return err
		}
	}
	if !validUsername(name) {
		out.abandon()
		return usageErr("the username must be 1 to 64 characters with no spaces or control characters")
	}
	err = withTools(ctx, env, func(t *Tools) error {
		pw, err := password.NewOneTime()
		if err != nil {
			return err
		}
		// The cheap one-time hash: 120 bits need no slow hash, and it takes no slot of the
		// Argon2 gate, so the first login does not queue behind strangers (admin-r3-11).
		hash, err := t.Hasher.HashOneTime(pw)
		if err != nil {
			return err
		}
		now := env.Now()
		var id uuid.UUID
		for try := 0; ; try++ {
			var ok bool
			err = t.Store.WithGlobal(ctx, store.TxOpts{Isolation: store.Serializable}, func(g store.GlobalTx) error {
				var err error
				id, ok, err = g.AdminBootstrap(name, hash)
				if err != nil || !ok {
					return err
				}
				// admin_id is NULL: the CLI has no session, and the new admin is the
				// target (10.1 step 4).
				_, err = audit.Admin(g, now, uuid.Nil, netip.Addr{}, audit.AdminBootstrap{Admin: id, Via: cliVia})
				return err
			})
			if errors.Is(err, store.ErrRetry) && try < maxBootstrapRetries {
				continue
			}
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("an admin already exists")
			}
			break
		}
		return out.write("one-time password", pw)
	})
	if err != nil {
		out.abandon()
		return err
	}
	out.announce(env.Stdout)
	fmt.Fprintln(env.Stderr, "admin created; it must change the password and enrol TOTP at first login")
	return nil
}

// runReset is `reset-password` and, with totp, `reset-totp` (10.1). Both give a
// new one-time password valid for 24 hours, end every session of that admin and
// clear its login throttle; reset-totp also forgets the authenticator. The old
// password stops working in both, so enrolling a new authenticator needs a
// secret that came from the server console: otherwise whoever phished the
// password could enrol their own.
func runReset(ctx context.Context, env Env, args []string, totpToo bool) error {
	name := "reset-password"
	if totpToo {
		name = "reset-totp"
	}
	fs := newFlags(env, name)
	user := fs.String("user", "", "the admin's username")
	outFile := fs.String("out-file", "", "the new file (mode 0600) that receives the one-time password; required")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if *user == "" || len(pos) != 0 {
		return usageErr("%s needs --user", name)
	}
	out, err := prepareOutput(env, *outFile)
	if err != nil {
		return err
	}
	err = withTools(ctx, env, func(t *Tools) error {
		var admin store.AdminUser
		var found bool
		if err := t.Store.WithGlobal(ctx, store.TxOpts{ReadOnly: true}, func(g store.GlobalTx) (err error) {
			admin, found, err = g.AdminUserByName(*user)
			return err
		}); err != nil {
			return err
		}
		if !found {
			return errors.New("no such admin")
		}
		pw, err := password.NewOneTime()
		if err != nil {
			return err
		}
		// The cheap one-time hash: 120 bits need no slow hash, and it takes no slot of the
		// Argon2 gate, so the first login does not queue behind strangers (admin-r3-11).
		hash, err := t.Hasher.HashOneTime(pw)
		if err != nil {
			return err
		}
		now := env.Now()
		kind, ev := adminnotice.PasswordReset, audit.AdminEvent(audit.AdminPasswordResetCLI{Admin: admin.ID, Via: cliVia})
		if totpToo {
			kind, ev = adminnotice.TOTPReset, audit.AdminTOTPResetCLI{Admin: admin.ID, Via: cliVia}
		}
		err = t.Store.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error {
			cur, ok, err := g.AdminUserLockByID(admin.ID)
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("no such admin")
			}
			// One definer function: a new one-time password, 24 hours, and with reset-totp the
			// authenticator forgotten in the same statement (rule one-time-state).
			if ok, err := g.AdminReset(admin.ID, hash, totpToo); err != nil || !ok {
				return errors.Join(err, errors.New("no such admin"))
			}
			if _, err := g.AdminSessionsRevokeOthers(admin.ID, uuid.Nil); err != nil {
				return err
			}
			notice, err := adminnotice.Append(cur.PendingNotice, adminnotice.Notice{Kind: kind, At: now})
			if err != nil {
				return err
			}
			if err := g.AdminNoticeSet(admin.ID, notice); err != nil {
				return err
			}
			_, err = audit.Admin(g, now, uuid.Nil, netip.Addr{}, ev)
			return err
		})
		if err != nil {
			return err
		}
		// The one-time password goes to the file first (admin-r10-2). From the commit above the
		// old password is dead and the sessions are revoked, so until this write the new one
		// exists only in this process; a kill, an OOM stop of the 128 MiB admin container or a
		// Valkey or audit step that stalls to lock_timeout in the clear below must not be able to
		// lose it. The clear needs no password and its warnings go to stderr either way.
		if err := out.write("one-time password", pw); err != nil {
			return err
		}
		// The throttle lives on other connections and outside the transaction (the
		// tool holds one connection). A failure here leaves a locked-out admin a
		// reason to run `unlock`; it never undoes the reset. The clear is a state change of its
		// own, so it has its row whatever it did, and each store is reported apart (rule
		// console-state-change-is-audited, round 8, admin-r8-7): a Valkey that was down is not a
		// reason to run unlock, a database scope that was not cleared is.
		clearAndAudit(ctx, env, t, admin).warnAfterReset(env.Stderr)
		return nil
	})
	if err != nil {
		out.abandon()
		return err
	}
	out.announce(env.Stdout)
	return nil
}

// clearAdminThrottle clears every scope an admin could be locked out by. It does
// not list them: throttle.Service.Unlock walks the registry of internal/budget, so
// a scope that is declared is cleared, and the unlock test fails for one that is
// not (rule budget-keying). Scopes keyed on a network or a marker cannot be listed
// from the console and go as a whole (10.1); the others are cleared by the exact
// key of the admin. The admin's TOTP attempts are a registered scope and always go: an unlock
// that left the second factor locked would print "unlocked" and lie.
//
// The two stores are reported apart (round 7, admin-r7-3 and -7). The database scopes are the
// lock-out; the Valkey buckets are request speed bumps that refill within a minute and, for the login,
// no longer refuse the console password (admin-r7-1). A Valkey that is down used to fail the whole
// command after the database scopes were already cleared, so the operator retried a command that had
// done its work and the audit row of what it did was never written.
func clearAdminThrottle(ctx context.Context, t *Tools, a store.AdminUser) (db, valkey error) {
	db = throttle.NewAdmin(t.Store.Admin(), t.Keys).Unlock(ctx, throttle.Who{Username: a.Username, Admin: a.ID})
	// The speed bumps of the admin login are in Valkey too (class admin-login, keyed on the network
	// and on the device marker). A neighbour on the owner's carrier address group can spend them,
	// and the console had no way to clear them (round 6, admin-r6-7). A Valkey that is not
	// reachable holds nothing to clear, and the limiter then runs on its in-process buckets, so
	// that is an error to report and not to hide.
	if t.ClearRateLimits != nil {
		valkey = t.ClearRateLimits(ctx)
	}
	return db, valkey
}

// clearResult is what clearing an admin's throttle did in each store, apart.
type clearResult struct {
	db, valkey, audit error
}

// clearAndAudit clears the admin's throttle and writes admin.unlock_cli after it, whatever the clear
// did. The scopes are cleared one by one, so a command that failed half way has still changed what
// locks an admin out, and a console clear that leaves no trace is the hole the audit chain exists to
// close (rule console-state-change-is-audited; admin-r7-3, -7 and, for the two resets, admin-r8-7).
// The row says which store was cleared, with two booleans and no error text. Every command of
// ctrlz-admin that clears the throttle goes through here, so none can report two stores as one or
// skip its row on a partial failure.
func clearAndAudit(ctx context.Context, env Env, t *Tools, admin store.AdminUser) clearResult {
	res := clearResult{}
	res.db, res.valkey = clearAdminThrottle(ctx, t, admin)
	res.audit = t.Store.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		_, err := audit.Admin(g, env.Now(), uuid.Nil, netip.Addr{}, audit.AdminUnlockCLI{
			Admin: admin.ID, Via: cliVia, DatabaseCleared: res.db == nil, ValkeyCleared: res.valkey == nil,
		})
		return err
	})
	return res
}

// warnAfterReset prints one warning per store that failed, after a reset that has already
// committed and must not be undone or turned into a failure (its one-time password is still to be
// written). The Valkey buckets refill within a minute and, for the login, no longer refuse the
// console password, so only the database scopes send the operator to `unlock`. No error text is printed.
func (c clearResult) warnAfterReset(w io.Writer) {
	if c.db != nil {
		fmt.Fprintln(w, "warning: the login throttle in the database could not be cleared; run unlock")
	}
	if c.valkey != nil {
		fmt.Fprintln(w, "warning: the request speed limits in Valkey could not be cleared; they refill within a minute")
	}
	if c.audit != nil {
		fmt.Fprintln(w, "warning: the throttle clear could not be recorded in the audit log")
	}
}

// runUnlock is `ctrlz-admin unlock --user X` (10.1): it clears a locked-out
// admin's login keys and writes admin.unlock_cli.
func runUnlock(ctx context.Context, env Env, args []string) error {
	fs := newFlags(env, "unlock")
	user := fs.String("user", "", "the admin's username")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if *user == "" || len(pos) != 0 {
		return usageErr("unlock needs --user")
	}
	return withTools(ctx, env, func(t *Tools) error {
		var admin store.AdminUser
		var found bool
		if err := t.Store.WithGlobal(ctx, store.TxOpts{ReadOnly: true}, func(g store.GlobalTx) (err error) {
			admin, found, err = g.AdminUserByName(*user)
			return err
		}); err != nil {
			return err
		}
		if !found {
			return errors.New("no such admin")
		}
		res := clearAndAudit(ctx, env, t, admin)
		if res.audit != nil {
			return res.audit
		}
		dbErr, valkeyErr := res.db, res.valkey
		if dbErr != nil {
			// The lock-out itself is not cleared (or not all of it): that is a failed unlock.
			return errors.New("the login throttle could not be cleared")
		}
		if valkeyErr != nil {
			// The database part, which is what locks the admin out, is done and audited. The Valkey
			// buckets are a per-minute speed bump that refill on their own, so this is a warning and not
			// a second failure that would make the operator run an unlock that already worked.
			fmt.Fprintln(env.Stderr, "warning: the request speed limits in Valkey could not be cleared; they refill within a minute")
			fmt.Fprintln(env.Stdout, "unlocked in the database")
			return nil
		}
		fmt.Fprintln(env.Stdout, "unlocked")
		return nil
	})
}
