package admincli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/adminnotice"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
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
		return usageErr("sms takes: pending, confirm <provider> --hint H, or discard <provider>")
	}
	switch args[0] {
	case "pending":
		return runSMSPending(ctx, env, args[1:])
	case "confirm":
		return runSMSConfirm(ctx, env, args[1:])
	case "discard":
		return runSMSDiscard(ctx, env, args[1:])
	}
	return usageErr("sms takes: pending, confirm <provider> --hint H, or discard <provider>")
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
		if err := t.Store.WithGlobal(ctx, store.TxOpts{ReadOnly: true}, func(g store.GlobalTx) (err error) {
			rows, err = g.SMSPendingGateways()
			return err
		}); err != nil {
			return err
		}
		if len(rows) == 0 {
			fmt.Fprintln(env.Stdout, "no gateway credentials wait for a confirmation")
			return nil
		}
		for _, r := range rows {
			replaces := "first credentials of this gateway"
			if r.HasActive {
				replaces = "replace the active credentials"
			}
			fmt.Fprintf(env.Stdout, "%s: hint %q, %s\n  ctrlz-admin sms confirm %s --hint %q\n  ctrlz-admin sms discard %s   (a new PUT is refused while this waits)\n",
				r.Provider, r.Hint, replaces, r.Provider, r.Hint, r.Provider)
		}
		return nil
	})
}

// providerCLI is a provider whose credentials can be confirmed. noop has none.
func providerCLI(p string) bool { return p == "sms_ir" || p == "melipayamak" }

func runSMSConfirm(ctx context.Context, env Env, args []string) error {
	fs := newFlags(env, "sms confirm")
	hint := fs.String("hint", "", "the hint `sms pending` shows for these credentials (required, so a different PUT is not confirmed by mistake)")
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
		return usageErr("sms confirm takes a provider (sms_ir or melipayamak) and --hint")
	}
	if !hintGiven {
		return usageErr("sms confirm needs --hint, the hint `sms pending` shows")
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
			id, ok, err := g.SMSGatewayConfirmCredentials(provider, *hint)
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("nothing to confirm: the provider has no pending credentials, or the hint is not theirs (run `sms pending`)")
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
			id, ok, err := g.SMSGatewayDiscardPending(provider)
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
