package admincli

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/totp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// pageSize is how many tenants a per-tenant command takes at a time.
const pageSize = 200

// runKeysAdmin is `ctrlz-admin keys <status|declare-lost|derive>`.
func runKeysAdmin(ctx context.Context, env Env, args []string) error {
	if len(args) == 0 {
		return usageErr("keys needs status, declare-lost or derive")
	}
	switch args[0] {
	case "status":
		return runKeysStatus(ctx, env, args[1:])
	case "declare-lost":
		return runDeclareLost(ctx, env, args[1:])
	case "derive":
		return deriveKeys(env, args[1:])
	}
	return usageErr("unknown keys command %q", args[0])
}

// domainArg reads the one positional domain and checks it is a defined one.
func domainArg(pos []string, what string) (string, error) {
	if len(pos) != 1 {
		return "", usageErr("%s needs one domain", what)
	}
	if !keyring.ValidDomain(pos[0]) {
		return "", usageErr("unknown domain %q", pos[0])
	}
	return pos[0], nil
}

// keyCounts tallies sealed values by the key number in their header, and for each
// number how many of them the container's keys really open. A header number says
// which key the value claims; only opening proves it (review round 5, rule
// key-identity): after a total loss the host's key 1 is a new key and values that
// name 1 open under none of it. unknown is the number of values whose header could
// not be read.
type keyCounts struct {
	byKey   map[uint16]*keyCount
	unknown int
}

type keyCount struct{ total, open int }

func (k *keyCounts) add(ct []byte, opens bool) {
	n, ok := keyring.KeyNumber(ct)
	if !ok {
		k.unknown++
		return
	}
	if k.byKey == nil {
		k.byKey = map[uint16]*keyCount{}
	}
	c := k.byKey[n]
	if c == nil {
		c = &keyCount{}
		k.byKey[n] = c
	}
	c.total++
	if opens {
		c.open++
	}
}

func (k *keyCounts) String() string {
	if len(k.byKey) == 0 && k.unknown == 0 {
		return "no rows"
	}
	var nums []int
	for n := range k.byKey {
		nums = append(nums, int(n))
	}
	sort.Ints(nums)
	var parts []string
	for _, n := range nums {
		c := k.byKey[uint16(n)]
		if c.open == c.total {
			parts = append(parts, fmt.Sprintf("key %d: %d (all open)", n, c.total))
		} else {
			parts = append(parts, fmt.Sprintf("key %d: %d (%d open, %d not readable)", n, c.total, c.open, c.total-c.open))
		}
	}
	if k.unknown > 0 {
		parts = append(parts, fmt.Sprintf("unreadable header: %d", k.unknown))
	}
	return strings.Join(parts, ", ")
}

func numbersText(r *keyring.Ring, domain string) string {
	if r == nil || !r.Has(domain) {
		return "not loaded in this container"
	}
	var parts []string
	for _, n := range r.Numbers(domain) {
		parts = append(parts, fmt.Sprint(n))
	}
	newest, _ := r.Newest(domain)
	return fmt.Sprintf("loaded %s, newest %d", strings.Join(parts, ","), newest)
}

// runKeysStatus is `keys status <domain>` (8.4 step 4): how many stored values
// sit under each key number, for the columns the admin can read. It prints key
// numbers and counts, never a key.
func runKeysStatus(ctx context.Context, env Env, args []string) error {
	fs := newFlags(env, "keys status")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	domain, err := domainArg(pos, "keys status")
	if err != nil {
		return err
	}
	return withTools(ctx, env, func(t *Tools) error {
		fmt.Fprintf(env.Stdout, "domain %s: %s\n", domain, numbersText(t.Keys, domain))
		switch domain {
		case keyring.DomainAdminTOTP:
			var c keyCounts
			if err := t.Store.WithGlobal(ctx, store.TxOpts{ReadOnly: true}, func(g store.GlobalTx) error {
				rows, err := g.AdminTOTPSecrets()
				for _, r := range rows {
					c.add(r.CT, opensWith(t.Keys.Open(domain, totp.AdminAAD(r.Admin), r.CT)))
				}
				return err
			}); err != nil {
				return err
			}
			fmt.Fprintf(env.Stdout, "  admin_users.totp_secret_ct: %s\n", c.String())
		case keyring.DomainSMSCred:
			var c keyCounts
			if err := t.Store.WithGlobal(ctx, store.TxOpts{ReadOnly: true}, func(g store.GlobalTx) error {
				rows, err := g.SMSCredentialsSealed()
				for _, r := range rows {
					c.add(r.CT, opensWith(sms.OpenCredentials(t.Keys, r.ID, r.Provider, r.CT)))
				}
				return err
			}); err != nil {
				return err
			}
			fmt.Fprintf(env.Stdout, "  sms_gateways.credentials_ct: %s\n", c.String())
			fmt.Fprintln(env.Stdout, "  (the count includes sms_gateways.credentials_pending_ct, credentials a PUT saved and the console has not confirmed)")
			fmt.Fprintln(env.Stdout, "  sms_outbox.params_ct: not readable by the admin role; a pending row ends within 1 hour")
		case keyring.DomainUserTOTP:
			fmt.Fprintln(env.Stdout, "  users.totp_secret_ct: not readable by the admin role; the rekey tool prints its own counts")
		case keyring.DomainDOHToken, keyring.DomainCertWrap:
			fmt.Fprintln(env.Stdout, "  reserved for a later phase")
		case keyring.DomainAdminMAC, keyring.DomainAuthMAC, keyring.DomainOTPDelivery:
			fmt.Fprintln(env.Stdout, "  no stored ciphertext column to re-encrypt")
			for _, l := range removalLines(domain) {
				fmt.Fprintln(env.Stdout, "  "+l)
			}
		}
		return nil
	})
}

// runDeclareLost is `keys declare-lost <domain>` (8.5): the key for a domain is
// gone with its root, so what it protected cannot be opened. It records the
// operator's declaration, after proving what it can: for sms_cred it opens the
// credentials that name the number and refuses while one opens. The admin does not
// hold user_totp, so for that domain the record is all it can do.
//
// Clearing the sealed user_totp seeds is not done here (review round 3, db-r3-1,
// db-r3-5): that switches off users' second factor, and code running as the admin
// role must not be able to do it for a tenant it picks. It is the tools container's
// `ctrlz declare-lost user_totp`, on the worker role, which holds the user_totp key
// ring and refuses while a seed under the key named still opens.
func runDeclareLost(ctx context.Context, env Env, args []string) error {
	fs := newFlags(env, "keys declare-lost")
	keyNo := fs.Int("key-number", 0, "the number of the lost key (see `keys status`, or the host's key file)")
	yes := fs.Bool("yes", false, "confirm")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	domain, err := domainArg(pos, "keys declare-lost")
	if err != nil {
		return err
	}
	if *keyNo < 1 || *keyNo > 65535 {
		return usageErr("--key-number is required (1 to 65535)")
	}
	switch domain {
	case keyring.DomainDOHToken, keyring.DomainCertWrap:
		return errors.New("this domain is defined in a later phase")
	case keyring.DomainAdminTOTP:
		return errors.New("an admin's authenticator is reset with: ctrlz-admin reset-totp --user X")
	}
	if !*yes {
		return usageErr("this is permanent; add --yes to confirm")
	}
	return withTools(ctx, env, func(t *Tools) error {
		// A key is declared lost when some of what it sealed cannot be opened. The admin holds
		// sms_cred and can read the credentials, so it opens each one that names this number
		// instead of taking the operator's word (review round 5, rule key-identity), and it
		// decides per sealed value, as `ctrlz declare-lost user_totp` does (round 13, admin-r13-3).
		// After a total loss the regenerated kek_sms_cred restarts at number 1, so a credential
		// entered again names 1 and opens beside the old ones that name 1 and do not; "any one
		// opens" refused for ever there, while `rekey` cannot open the old ones either (round 14,
		// admin-r14-2). It refuses only when every credential that names the number opens, the case
		// where nothing is lost and `rekey` is the right tool. user_totp cannot be read by the admin
		// role (the tools container makes the same check there), and the other domains store
		// nothing to open.
		var named, opened int
		if domain == keyring.DomainSMSCred {
			if err := t.Store.WithGlobal(ctx, store.TxOpts{ReadOnly: true}, func(g store.GlobalTx) error {
				rows, err := g.SMSCredentialsSealed()
				for _, r := range rows {
					if n, ok := keyring.KeyNumber(r.CT); ok && int(n) == *keyNo {
						named++
						if opensWith(sms.OpenCredentials(t.Keys, r.ID, r.Provider, r.CT)) {
							opened++
						}
					}
				}
				return err
			}); err != nil {
				return err
			}
			if named > 0 && opened == named {
				return fmt.Errorf("key %d of sms_cred is loaded and all %d gateway credentials under it open, so they are not lost; run `rekey sms_cred` instead", *keyNo, named)
			}
		}
		// The declaration is audited first, before the tools container changes anything:
		// that run clears one tenant at a time, so a row written after it would be missing
		// if it failed part way (13.1). The row records the operator's act, which is
		// true whether or not the clearing finishes.
		if err := t.Store.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error {
			_, err := audit.Admin(g, env.Now(), uuid.Nil, netip.Addr{}, audit.KeyDeclaredLost{Domain: audit.KeyDomainOf(domain), KeyNumber: *keyNo})
			return err
		}); err != nil {
			return err
		}
		switch domain {
		case keyring.DomainUserTOTP:
			fmt.Fprintf(env.Stdout, "declared lost: recorded. Now clear the seeds from the tools container, which holds the user_totp keys:\n  docker compose --profile tools run --rm rekey declare-lost user_totp --key-number %d --yes\n", *keyNo)
		case keyring.DomainSMSCred:
			fmt.Fprintln(env.Stdout, "declared lost: make a new key, then enter the gateway credentials again on the SMS page")
			if opened > 0 {
				fmt.Fprintf(env.Stdout, "%d of the %d gateway credentials under key %d still open and need nothing; `rekey sms_cred` moves them to the newest key\n", opened, named, *keyNo)
			}
		default:
			fmt.Fprintln(env.Stdout, "declared lost: make a new key; nothing stored needs repair")
		}
		return nil
	})
}

// runRekeyAdmin is `ctrlz-admin rekey <domain>` for the domains the admin
// service holds (8.4 step 3). Each value is opened under whichever key it was
// sealed with and sealed again under the newest, compared against the old
// ciphertext in the UPDATE so a value changed in the meantime is not overwritten.
func runRekeyAdmin(ctx context.Context, env Env, args []string) error {
	fs := newFlags(env, "rekey")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	domain, err := domainArg(pos, "rekey")
	if err != nil {
		return err
	}
	switch domain {
	case keyring.DomainAdminTOTP, keyring.DomainSMSCred:
	case keyring.DomainUserTOTP:
		return errors.New("user_totp is re-encrypted by the one-shot tool: docker compose --profile tools run --rm rekey rekey user_totp")
	default:
		// The remaining domains are in keyring.Uses: nothing is stored to rewrite, and
		// what the operator waits for is rendered from the registry (spec 8.4).
		fmt.Fprintln(env.Stdout, "nothing to re-encrypt for this domain")
		for _, l := range removalLines(domain) {
			fmt.Fprintln(env.Stdout, l)
		}
		return nil
	}
	return withTools(ctx, env, func(t *Tools) error {
		newest, ok := t.Keys.Newest(domain)
		if !ok {
			return errors.New("this domain's key is not loaded in this container")
		}
		var res rekeyResult
		err := t.Store.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error {
			switch domain {
			case keyring.DomainAdminTOTP:
				rows, err := g.AdminTOTPSecrets()
				if err != nil {
					return err
				}
				for _, r := range rows {
					res.visit(newest, r.CT,
						func() (secret.Bytes, error) { return t.Keys.Open(domain, totp.AdminAAD(r.Admin), r.CT) },
						func(plain secret.Bytes) ([]byte, error) {
							return t.Keys.Seal(domain, totp.AdminAAD(r.Admin), plain.Reveal())
						},
						func(next []byte) (bool, error) { return g.AdminTOTPReplace(r.Admin, r.CT, next) })
				}
			case keyring.DomainSMSCred:
				rows, err := g.SMSCredentialsSealed()
				if err != nil {
					return err
				}
				for _, r := range rows {
					res.visit(newest, r.CT,
						func() (secret.Bytes, error) { return sms.OpenCredentials(t.Keys, r.ID, r.Provider, r.CT) },
						func(plain secret.Bytes) ([]byte, error) { return sms.SealCredentials(t.Keys, r.ID, r.Provider, plain) },
						func(next []byte) (bool, error) {
							if r.Pending {
								return g.SMSPendingCredentialsReplace(r.ID, r.CT, next)
							}
							return g.SMSCredentialsReplace(r.ID, r.CT, next)
						})
				}
			}
			if res.err != nil {
				return res.err
			}
			// The row is in the transaction of the rewrite, so it exists exactly when the rewritten values
			// were committed, and it is written whatever the other values did: a value that could not be
			// opened ends the command with exit 1 after the rest were kept, and a change of stored
			// ciphertext with no row is the hole the audit chain exists to close (round 9, admin-r9-5;
			// rule console-state-change-is-audited). A run that rewrote nothing changed nothing and writes
			// nothing. Counts only. (The re-seal does not move credential_gen, so this row is also the only
			// trace that a rekey ran.)
			if res.rewritten > 0 {
				if _, err := audit.Admin(g, env.Now(), uuid.Nil, netip.Addr{}, audit.KeyRekeyed{
					Domain: audit.KeyDomainOf(domain), KeyNumber: int(newest),
					Rewritten: res.rewritten, Changed: res.changed, Failed: res.failed,
				}); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		res.print(env, domain, newest)
		if res.failed > 0 {
			return errors.New("some values could not be re-encrypted; they are still readable under their old key, so keep it in the key file")
		}
		return nil
	})
}

// rekeyResult counts what a rekey did. A value that cannot be opened is counted,
// never described: the error from keyring.Open is one value with no detail.
type rekeyResult struct {
	rewritten, current, changed, failed int
	err                                 error
}

// visit re-encrypts one value unless it is under the newest key already. Both
// answers come from opening the value, never from the number in its header: a
// value that names the newest number but does not open (the host regenerated its
// keys after a total loss, and key 1 is a new key) is counted as unreadable and
// is not "already current" (review round 5, rule key-identity).
func (r *rekeyResult) visit(newest uint16, ct []byte, open func() (secret.Bytes, error), seal func(secret.Bytes) ([]byte, error), replace func([]byte) (bool, error)) {
	if r.err != nil {
		return
	}
	plain, err := open()
	if err != nil {
		r.failed++
		return
	}
	defer plain.Wipe()
	// The value opened, and Open uses the key its header names, so that number is
	// the key that sealed it.
	if n, ok := keyring.KeyNumber(ct); ok && n == newest {
		r.current++
		return
	}
	next, err := seal(plain)
	if err != nil {
		r.failed++
		return
	}
	ok, err := replace(next)
	switch {
	case err != nil:
		r.err = err
	case ok:
		r.rewritten++
	default:
		r.changed++
	}
}

func (r rekeyResult) print(env Env, domain string, newest uint16) {
	fmt.Fprintf(env.Stdout, "rekey %s to key %d: %d rewritten, %d already current, %d changed meanwhile, %d could not be opened\n",
		domain, newest, r.rewritten, r.current, r.changed, r.failed)
	// Re-encrypting a seed in force changes totp_secret_ct and not the second factor, so it does
	// not move the credential generation (migration 0029, db-r6-4): no marker or sign-in in flight
	// ends, and a rekey needs no quiet period. Round 5 (admin-r5-3) had the trigger treat it as a
	// new seed and this tool say so; the trigger now reads totp_enabled_at, the column that says
	// which factor is in force.
}

// RunRekey is the one-shot `ctrlz rekey user_totp` (8.4 step 3): the container
// on the worker's database role that is the only place the role meets the
// user_totp key. It pages the tenants and re-encrypts one tenant at a time, so no
// transaction is long.
func RunRekey(ctx context.Context, args []string, env Env) int {
	env = env.withDefaults()
	return finish(env, runRekeyUser(ctx, env, args))
}

func runRekeyUser(ctx context.Context, env Env, args []string) error {
	fs := newFlags(env, "rekey")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	domain, err := domainArg(pos, "rekey")
	if err != nil {
		return err
	}
	if domain != keyring.DomainUserTOTP {
		return usageErr("this tool re-encrypts user_totp only; the other domains are rekeyed by ctrlz-admin")
	}
	t, err := env.OpenRekey(ctx)
	if err != nil {
		return err
	}
	if t.Close != nil {
		defer t.Close()
	}
	newest, ok := t.Keys.Newest(domain)
	if !ok {
		return errors.New("the user_totp key is not loaded")
	}
	var res rekeyResult
	var after uuid.UUID
	for {
		var ids []uuid.UUID
		if err := t.Store.WithGlobal(ctx, store.TxOpts{ReadOnly: true}, func(g store.GlobalTx) (err error) {
			ids, err = g.TenantIDs(after, pageSize)
			return err
		}); err != nil {
			return err
		}
		for _, id := range ids {
			err := t.Store.WithTenant(ctx, id, store.TxOpts{}, func(tx store.Tx) error {
				rows, err := tx.TOTPSecrets()
				if err != nil {
					return err
				}
				before := res
				for _, r := range rows {
					aad := totp.UserAAD(id, r.User)
					res.visit(newest, r.CT,
						func() (secret.Bytes, error) { return t.Keys.Open(domain, aad, r.CT) },
						func(plain secret.Bytes) ([]byte, error) { return t.Keys.Seal(domain, aad, plain.Reveal()) },
						func(next []byte) (bool, error) { return tx.TOTPSecretReplace(r.User, r.CT, next) })
				}
				if res.err != nil {
					return res.err
				}
				// The row of the admin chain is in the transaction of the rewrite, the same rule as the admin
				// side (round 9, admin-r9-5): it exists exactly when the rewritten seeds were committed, and
				// it is written whatever the other seeds of the tenant did. Counts only; a tenant that
				// rewrote nothing changed nothing and writes nothing (admin-r18-6).
				if n := res.rewritten - before.rewritten; n > 0 {
					return tx.KeytoolAuditRekeyed(int(newest), n, res.changed-before.changed, res.failed-before.failed)
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		if len(ids) < pageSize {
			break
		}
		after = ids[len(ids)-1]
	}
	res.print(env, domain, newest)
	if res.failed > 0 {
		return errors.New("some seeds could not be re-encrypted; keep the old key in the key file")
	}
	return nil
}

// runAuditNote is `ctrlz-admin audit-note <action>`: the audit row for a
// rotation or a loss, which happens partly on the host (8.4 step 5).
func runAuditNote(ctx context.Context, env Env, args []string) error {
	fs := newFlags(env, "audit-note")
	domain := fs.String("domain", "", "the key domain")
	keyNo := fs.Int("key-number", 0, "the key number that was added or lost")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageErr("audit-note needs key.rotated or key.declared_lost")
	}
	if !keyring.ValidDomain(*domain) {
		return usageErr("--domain must be a key domain")
	}
	if *keyNo < 1 || *keyNo > 65535 {
		return usageErr("--key-number is required (1 to 65535)")
	}
	var ev audit.AdminEvent
	switch pos[0] {
	case "key.rotated":
		ev = audit.KeyRotated{Domain: audit.KeyDomainOf(*domain), KeyNumber: *keyNo}
	case "key.declared_lost":
		ev = audit.KeyDeclaredLost{Domain: audit.KeyDomainOf(*domain), KeyNumber: *keyNo}
	default:
		return usageErr("audit-note takes key.rotated or key.declared_lost")
	}
	return withTools(ctx, env, func(t *Tools) error {
		return t.Store.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error {
			_, err := audit.Admin(g, env.Now(), uuid.Nil, netip.Addr{}, ev)
			return err
		})
	})
}

// runAudit is `ctrlz-admin audit verify` (13.1): recompute the hash chain from
// the first row, in pages, and report the first row whose link or hash is wrong.
func runAudit(ctx context.Context, env Env, args []string) error {
	if len(args) != 1 || args[0] != "verify" {
		return usageErr("audit takes: verify")
	}
	return withTools(ctx, env, func(t *Tools) error {
		var prev []byte
		var last int64
		total := 0
		for {
			var rows []store.AuditRow
			if err := t.Store.WithGlobal(ctx, store.TxOpts{ReadOnly: true}, func(g store.GlobalTx) (err error) {
				rows, err = g.AuditChain(last, 500)
				return err
			}); err != nil {
				return err
			}
			if len(rows) == 0 {
				break
			}
			var err error
			if prev, err = audit.VerifyChain(prev, rows); err != nil {
				return err
			}
			total += len(rows)
			last = rows[len(rows)-1].ID
		}
		fmt.Fprintf(env.Stdout, "audit chain ok: %d rows, last id %d\n", total, last)
		return nil
	})
}

// RunDeclareLost is `ctrlz declare-lost user_totp --key-number N --yes`, the
// second half of `ctrlz-admin keys declare-lost` (8.5; review round 3, db-r3-1 and
// db-r3-5). It runs on the key tool role in the tools container because it switches
// off users' second factor, and the admin role must not be able to do that for a
// tenant it picks. The container holds the user_totp key ring, which gives the
// tool the one check the database cannot make: whether a seed opens.
//
// It decides per seed, never per key number (round 13, admin-r13-3). A seed that names key N and
// does not open with the ring is lost and is cleared. A seed that names N and opens is left alone
// and counted: after a total loss the regenerated key reuses the number, so a seed enrolled after
// the recovery names N and is not lost, and refusing the whole number for it (the rule of round 4)
// left the old seeds with no command that could clear them. The database function clears a row only
// while it still holds the ciphertext the tool read, and writes the tenant's notice and audit row
// itself.
// tenant's notice and audit row itself.
func RunDeclareLost(ctx context.Context, args []string, env Env) int {
	env = env.withDefaults()
	return finish(env, runDeclareLostUser(ctx, env, args))
}

func runDeclareLostUser(ctx context.Context, env Env, args []string) error {
	fs := newFlags(env, "declare-lost")
	keyNo := fs.Int("key-number", 0, "the number of the lost key (see `keys status`, or the host's key file)")
	yes := fs.Bool("yes", false, "confirm")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	domain, err := domainArg(pos, "declare-lost")
	if err != nil {
		return err
	}
	if domain != keyring.DomainUserTOTP {
		return usageErr("this tool clears user_totp seeds only; the other domains are declared lost with ctrlz-admin keys declare-lost")
	}
	if *keyNo < 1 || *keyNo > 65535 {
		return usageErr("--key-number is required (1 to 65535)")
	}
	if !*yes {
		return usageErr("this is permanent; add --yes to confirm")
	}
	t, err := env.OpenRekey(ctx)
	if err != nil {
		return err
	}
	if t.Close != nil {
		defer t.Close()
	}
	// The proof first (admin-r18-7, D64 keys-declare-lost-proof). Declaring a key lost switches off the
	// second factor of every user whose seed it sealed, so before anything is written the tool asks the
	// key ring it holds: when every seed that names this number opens, nothing is lost and the command
	// refuses (the same rule as sms_cred, round 14); when none names it there is nothing to clear. The
	// per-seed decision below is the proof for each row, and stays: after a total loss the regenerated
	// key reuses the number, so a seed that opens beside one that does not is the normal case (round 13,
	// admin-r13-3), and "refuse while one row opens" would leave the old seeds with no command.
	named, opened := 0, 0
	var scanned uuid.UUID
	for {
		var ids []uuid.UUID
		if err := t.Store.WithGlobal(ctx, store.TxOpts{ReadOnly: true}, func(g store.GlobalTx) (err error) {
			ids, err = g.TenantIDs(scanned, pageSize)
			return err
		}); err != nil {
			return err
		}
		for _, id := range ids {
			if err := t.Store.WithTenant(ctx, id, store.TxOpts{ReadOnly: true}, func(tx store.Tx) error {
				rows, err := tx.TOTPSecrets()
				for _, r := range rows {
					if n, ok := keyring.KeyNumber(r.CT); ok && int(n) == *keyNo {
						named++
						if opensWith(t.Keys.Open(keyring.DomainUserTOTP, totp.UserAAD(id, r.User), r.CT)) {
							opened++
						}
					}
				}
				return err
			}); err != nil {
				return err
			}
		}
		if len(ids) < pageSize {
			break
		}
		scanned = ids[len(ids)-1]
	}
	if named == 0 {
		fmt.Fprintf(env.Stdout, "no stored seed names key %d: nothing to clear and nothing recorded\n", *keyNo)
		return nil
	}
	if opened == named {
		return fmt.Errorf("key %d of user_totp is loaded and all %d seeds under it open, so they are not lost; run the rekey tool instead", *keyNo, named)
	}
	cleared, kept := 0, 0
	var after uuid.UUID
	for {
		var ids []uuid.UUID
		if err := t.Store.WithGlobal(ctx, store.TxOpts{ReadOnly: true}, func(g store.GlobalTx) (err error) {
			ids, err = g.TenantIDs(after, pageSize)
			return err
		}); err != nil {
			return err
		}
		for _, id := range ids {
			// One tenant per transaction: the function writes the tenant's notice and
			// audit row in the same statement as the change, so each tenant is whole.
			if err := t.Store.WithTenant(ctx, id, store.TxOpts{}, func(tx store.Tx) error {
				rows, err := tx.TOTPSecrets()
				if err != nil {
					return err
				}
				var lost []store.TOTPSecret
				for _, r := range rows {
					if n, ok := keyring.KeyNumber(r.CT); !ok || int(n) != *keyNo {
						continue
					}
					seed, err := t.Keys.Open(keyring.DomainUserTOTP, totp.UserAAD(id, r.User), r.CT)
					if err == nil {
						// It opens, so it is not lost: a key made after a total loss reuses the
						// number (8.5) and seeds enrolled under it are the new ones.
						seed.Wipe()
						kept++
						continue
					}
					lost = append(lost, r)
				}
				n, err := tx.TOTPDeclareLost(*keyNo, lost)
				cleared += n
				if err != nil || n == 0 {
					return err
				}
				// The row of the admin chain, in the transaction of the clear (admin-r18-7): one per tenant
				// whose seeds were cleared, like the tenant's own notice and audit row.
				return tx.KeytoolAuditDeclaredLost(*keyNo)
			}); err != nil {
				return err
			}
		}
		if len(ids) < pageSize {
			break
		}
		after = ids[len(ids)-1]
	}
	fmt.Fprintf(env.Stdout, "declared lost: %d users now have no authenticator and must enrol again\n", cleared)
	if kept > 0 {
		fmt.Fprintf(env.Stdout, "%d seeds that name key %d open with the key ring and were left alone\n", kept, *keyNo)
	}
	return nil
}

// removalLines says what removing an old key line of a domain costs, one line per
// use in keyring.Uses, longest life first, and the one time to wait for. Every number
// and phrase comes from the registry that the table of spec 8.2 is checked against
// (rule spec-fact-drift); the text used to be written by hand here and said "wait an
// hour", true of the throttle rows and not of the markers that live in browsers
// (review round 4, admin-r4-7), then went stale again for otp_delivery.
func removalLines(domain string) []string {
	uses := keyring.UsesOf(domain)
	if len(uses) == 0 {
		return nil
	}
	lines := make([]string, 0, len(uses)+1)
	for _, u := range uses {
		lines = append(lines, fmt.Sprintf("%s last up to %s; if the old line is removed first: %s", u.What, keyring.LifeText(u.Life), u.IfRemoved))
	}
	lines = append(lines, fmt.Sprintf("keep the old line for %s after the new one is in use, or accept the effects above", keyring.LifeText(keyring.LongestLife(domain))))
	return lines
}

// opensWith turns the result of an Open into the one bit the callers keep, and
// wipes the plaintext at once: the tools prove a value opens, they never look at it.
func opensWith(plain secret.Bytes, err error) bool {
	if err != nil {
		return false
	}
	plain.Wipe()
	return true
}
