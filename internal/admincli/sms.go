package admincli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"strings"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/adminnotice"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// runSMS is `ctrlz-admin sms <pending|confirm|discard>` (admin-r18-1, D64 sms-gateway-takeover, spec 10.8).
//
// Credentials that PUT /sms/gateways/{provider} saves are pending: they carry no code. This is the one
// place that makes them the active credentials, and it needs the server console, which is the owner's
// (D12), not an admin session: a session that was taken, with one fresh authenticator code, can stage
// credentials of its own and cannot make a single tenant's login code travel to them. The command is
// also the one place the operator reads what is pending, by provider and hint and never the credentials.
func runSMS(ctx context.Context, env Env, args []string) error {
	if len(args) == 0 {
		return usageErr("sms takes: pending, confirm <provider> --hint H --fingerprint F, or discard <provider>")
	}
	switch args[0] {
	case "pending":
		return runSMSPending(ctx, env, args[1:])
	case "confirm":
		return runSMSConfirm(ctx, env, args[1:])
	case "discard":
		return runSMSDiscard(ctx, env, args[1:])
	}
	return usageErr("sms takes: pending, confirm <provider> --hint H --fingerprint F, or discard <provider>")
}

func runSMSPending(ctx context.Context, env Env, args []string) error {
	fs := newFlags(env, "sms pending")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return usageErr("sms pending takes no arguments")
	}
	return withTools(ctx, env, func(t *Tools) error {
		var rows []store.SMSPendingGateway
		staged := map[string]stagedRow{}
		if err := t.Store.WithGlobal(ctx, store.TxOpts{ReadOnly: true}, func(g store.GlobalTx) (err error) {
			if rows, err = g.SMSPendingGateways(); err != nil {
				return err
			}
			for _, r := range rows {
				staged[r.Provider], err = stagedBy(g, r.ID)
				if err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}
		if len(rows) == 0 {
			fmt.Fprintln(env.Stdout, "no gateway credentials wait for a confirmation")
			return nil
		}
		for _, r := range rows {
			// The address is written here and not by stagedBy: a function that returned the text of an
			// address would make every caller a source of the network cut lint's key flow.
			when, ip := "(no audit row of the staging)", ""
			if sr := staged[r.Provider]; sr.found {
				ip = "an unknown address"
				if sr.ip != nil {
					ip = sr.ip.String()
				}
				when = fmt.Sprintf("at %s by %s from %s", sr.at, sr.who, ip)
			}
			replaces := "first credentials of this gateway"
			if r.HasActive {
				replaces = "replace the active credentials"
			}
			// No ready-made confirm line (admin-r20-3): the hint is chosen by whoever staged the pair, so a
			// line built from it would invite a blind confirmation of a thief's pair. The fingerprint is
			// what the PUT that staged the pair returned, and it is not printed here.
			fmt.Fprintf(env.Stdout, "%s: hint %q, %s\n  staged %s\n"+
				"  your own PUT staged this: ctrlz-admin sms confirm %s --hint %q --fingerprint <the fingerprint that PUT returned>\n"+
				"  you did not stage it, or your PUT was refused with pending_exists: ctrlz-admin sms discard %s   (a new PUT is refused while this waits)\n",
				r.Provider, r.Hint, replaces, when, r.Provider, r.Hint, r.Provider)
		}
		return nil
	})
}

// stagedBy says when, by which admin and from which address the pair that waits was saved, from the
// audit row of the PUT (admin-r20-3). A pair cannot be replaced while it waits, so the newest row of
// the gateway that names the field credentials is the one that staged it; the console reads it to let the
// owner tell their own PUT from a stolen session's. Rows of the cost, of a confirmation and of a discard
// name other fields and are skipped.
func stagedBy(g store.GlobalTx, gateway uuid.UUID) (stagedRow, error) {
	target := audit.SMSGatewayChange{Gateway: gateway}.Target()
	// Page back until a staging row or the start of the log. A fixed window let a stolen session bury
	// the row of its own pair under cost-only PUTs, each of which writes an sms.gateway_change row of
	// its own (admin-r21-4).
	const page = 200
	var before int64
	for {
		rows, err := g.AuditPage(before, "sms.gateway_change", page)
		if err != nil {
			return stagedRow{}, err
		}
		if row, ok, err := stagingRow(g, target, rows); err != nil || ok {
			return row, err
		}
		if len(rows) < page {
			return stagedRow{}, nil
		}
		before = rows[len(rows)-1].ID
	}
}

// stagingRow picks, from rows (newest first), the newest that names the gateway and the field
// credentials.
func stagingRow(g store.GlobalTx, target string, rows []store.AuditRow) (stagedRow, bool, error) {
	for _, r := range rows {
		if r.Target != target {
			continue
		}
		var p struct {
			Fields []string `json:"fields"`
		}
		if json.Unmarshal(r.Params, &p) != nil {
			continue
		}
		staging := false
		for _, f := range p.Fields {
			staging = staging || f == string(audit.FieldCredentials)
		}
		if !staging {
			continue
		}
		who := "an unknown admin"
		if r.AdminID != nil {
			who = "admin " + r.AdminID.String()
			if a, ok, err := g.AdminUserByID(*r.AdminID); err != nil {
				return stagedRow{}, false, err
			} else if ok {
				who = fmt.Sprintf("admin %q", a.Username)
			}
		}
		return stagedRow{found: true, at: r.At.UTC().Format("2006-01-02 15:04:05 UTC"), who: who, ip: r.IP}, true, nil
	}
	return stagedRow{}, false, nil
}

// stagedRow is the audit row that staged a pair, as parts. found is false when the log holds no
// staging row of the gateway.
type stagedRow struct {
	found bool
	at    string
	who   string
	ip    *netip.Addr
}

// providerCLI is a provider whose credentials can be confirmed. noop has none.
func providerCLI(p string) bool { return p == "sms_ir" || p == "melipayamak" }

func runSMSConfirm(ctx context.Context, env Env, args []string) error {
	fs := newFlags(env, "sms confirm")
	hint := fs.String("hint", "", "the hint `sms pending` shows for these credentials (required, so a different PUT is not confirmed by mistake)")
	fingerprint := fs.String("fingerprint", "", "the fingerprint the PUT that staged these credentials returned (required: only the session that staged the pair holds it)")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	hintGiven := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "hint" {
			hintGiven = true
		}
	})
	if len(pos) != 1 || !providerCLI(pos[0]) {
		return usageErr("sms confirm takes a provider (sms_ir or melipayamak), --hint and --fingerprint")
	}
	if !hintGiven {
		return usageErr("sms confirm needs --hint, the hint `sms pending` shows")
	}
	fp := strings.ToLower(strings.TrimSpace(*fingerprint))
	if fp == "" {
		return usageErr("sms confirm needs --fingerprint, the one the PUT that staged these credentials returned; if you did not stage them, discard them")
	}
	provider := pos[0]
	return withTools(ctx, env, func(t *Tools) error {
		return t.Store.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error {
			// The banner of 10.7 goes to every enabled admin here, the moment the credentials that carry
			// the codes change, and not only when a PUT staged them (admin-r19-5). The admin rows come
			// first, then the gateway, then the audit row: the one lock order of internal/lockrank. A
			// confirmation that finds nothing returns an error below, which rolls this append back.
			if _, err := g.AdminNoticeAppendAll(adminnotice.Notice{Kind: adminnotice.SMSGatewayChanged, At: env.Now()}); err != nil {
				return err
			}
			// A pair that the ring cannot open would be activated into a gateway that every sender judges
			// unusable, so a pair sealed under a key that was lost is refused here, and the operator is sent to
			// discard it (admin-r20-4). The console holds sms_cred; the text names no value.
			sealed, err := g.SMSCredentialsSealed()
			if err != nil {
				return err
			}
			for _, r := range sealed {
				if r.Pending && r.Provider == provider && !opensWith(sms.OpenCredentials(t.Keys, r.ID, r.Provider, r.CT)) {
					return errors.New("the pending credentials do not open with the key ring of this container (a key was lost or replaced): run `ctrlz-admin sms discard` for this provider and enter the credentials again")
				}
			}
			id, ok, err := g.SMSGatewayConfirmCredentials(provider, *hint, fp)
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("nothing to confirm: the provider has no pending credentials, or the hint or the fingerprint is not theirs (run `sms pending`; a rekey of sms_cred changes the fingerprint of a pair that waits, so discard it and enter it again)")
			}
			// The row names the field, never a value (13.2), and is written in the transaction
			// of the change: the activation cannot commit without it.
			_, err = audit.Admin(g, env.Now(), uuid.Nil, netip.Addr{},
				audit.SMSGatewayChange{Gateway: id, Fields: []audit.Field{audit.FieldCredentialsConfirmed}})
			return err
		})
	})
}

// runSMSDiscard drops the pending credentials of a provider without activating them (db-r19-2). A PUT
// refuses while a pair waits, so that a later PUT cannot take the place of the one the owner is about to
// confirm; this is how the owner frees the gateway, for the pair they no longer want or one they did not
// stage. It is the console's act like the confirmation, and its row names the field and never a value.
func runSMSDiscard(ctx context.Context, env Env, args []string) error {
	fs := newFlags(env, "sms discard")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 || !providerCLI(pos[0]) {
		return usageErr("sms discard takes a provider (sms_ir or melipayamak)")
	}
	provider := pos[0]
	return withTools(ctx, env, func(t *Tools) error {
		return t.Store.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error {
			id, ok, err := g.SMSGatewayDiscardPending(provider, nil)
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("nothing to discard: the provider has no pending credentials")
			}
			_, err = audit.Admin(g, env.Now(), uuid.Nil, netip.Addr{},
				audit.SMSGatewayChange{Gateway: id, Fields: []audit.Field{audit.FieldCredentialsDiscarded}})
			return err
		})
	})
}
