package smssend_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"strconv"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/classify"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/senders"
	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/smssend"
)

// Review round 15, SMS area (sms-r15-1, sms-r15-4). A routed gateway the router passes over
// locally, because no sender can be built for it, has a known outcome: nothing can be sent. Round
// 14 kept the login page from offering a code for a held gateway; this class is the rest of it.
// Only the breaker timestamp reached auth_public_config, the only thing that opens that breaker
// without a user's send runs once at worker start, so 60 s later the flag read true again, the next
// user was told 202, and the row ended unsent with the caps spent, at every pause for as long as
// the key stayed wrong.
//
// The test is generated from the code table, not listed: every code of codes.go whose scope is
// the whole gateway (the codes a gateway with no sender can have, which is what ProblemAttempt
// reports) is put on both routed gateways with every pause lapsed, and sms_available must read
// false. A Problem code added tomorrow is in the list tomorrow.

// gatewayProblemCodes reads codes.go for the codes classified as the whole gateway being unusable.
func gatewayProblemCodes(t *testing.T) []sms.Code {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "../../sms/codes.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []sms.Code
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			if id, ok := vs.Type.(*ast.Ident); !ok || id.Name != "Code" {
				continue
			}
			for _, v := range vs.Values {
				lit, ok := v.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				s, _ := strconv.Unquote(lit.Value)
				c := sms.Code(s)
				if scope, ok := classify.Of(c, sms.Config); ok && scope == classify.Gateway {
					out = append(out, c)
				}
			}
		}
	}
	if len(out) < 5 {
		t.Fatalf("only %d gateway-scope codes read from codes.go; the test is not looking at the table", len(out))
	}
	return out
}

func (r *rig) newSource(env senders.Env, ring *keyring.Ring) *smssend.Source {
	r.t.Helper()
	return smssend.NewSource(r.worker, ring, env, slog.New(slog.NewJSONHandler(r.logs, nil)))
}

func (r *rig) available() bool {
	r.t.Helper()
	cfg, err := r.tenant.Auth().PublicConfig(r.env.Ctx)
	if err != nil {
		r.t.Fatal(err)
	}
	return cfg.SMSAvailable
}

// pausesLapsed makes every breaker the state a pause that has just ended leaves: three failures,
// open_until in the past. It is the moment the flag read true again before the fix.
func (r *rig) pausesLapsed() {
	r.env.Exec(r.t, `UPDATE ctrlz.sms_gateways SET consecutive_failures = 3, breaker_open_until = now() - interval '1 second'`)
}

func TestEveryGatewayProblemKeepsSMSUnavailableAfterTheBreakerPauseLapses(t *testing.T) {
	for _, code := range gatewayProblemCodes(t) {
		t.Run(string(code), func(t *testing.T) {
			r := newRig(t)
			ctx := r.env.Ctx
			if !r.available() {
				t.Fatal("two working routed gateways read as unavailable")
			}
			bad := r.newSource(senders.Env{Name: "test"}, r.ring)
			bad.Build = func(string, secret.Bytes) (sms.Sender, error) { return nil, &senders.ErrUnusable{Problem: code} }
			r.pausesLapsed()
			if _, err := bad.Load(ctx); err != nil {
				t.Fatal(err)
			}
			if r.available() {
				t.Fatalf("both routed gateways are unusable (%s) and sms_available is true with every pause lapsed", code)
			}
			// A later load changes nothing, and a lapse again does not either: the judgement is
			// written once against the credentials, not once per breaker step.
			if _, err := bad.Load(ctx); err != nil {
				t.Fatal(err)
			}
			r.pausesLapsed()
			if r.available() {
				t.Fatalf("a second lapsed pause made unusable (%s) gateways available again", code)
			}
			// A worker that can build them (a key that opens again, a restart outside production)
			// takes the judgement back, with the breakers still lapsed.
			good := r.newSource(senders.Env{Name: "test"}, r.ring)
			good.Build = r.build
			if _, err := good.Load(ctx); err != nil {
				t.Fatal(err)
			}
			if !r.available() {
				t.Fatalf("the judgement (%s) was not taken back when a build worked", code)
			}
		})
	}
}

// The three ways a gateway has no sender that need no stubbed build: credentials no key opens,
// none stored, and a noop row in production. Each is the real path of Source, with the real
// factory where the case is about it.
func TestUnusableGatewaysFromTheRealPaths(t *testing.T) {
	t.Run("credentials no key opens", func(t *testing.T) {
		r := newRig(t)
		// The worker's ring is not the one that sealed them.
		wrong, err := keyring.NewEphemeral(keyring.DomainOTPDelivery, keyring.DomainSMSCred)
		if err != nil {
			t.Fatal(err)
		}
		src := r.newSource(senders.Env{Name: "test"}, wrong)
		src.Build = r.build
		r.pausesLapsed()
		if _, err := src.Load(r.env.Ctx); err != nil {
			t.Fatal(err)
		}
		if r.available() {
			t.Fatal("credentials that no key opens, and the login page offers a code")
		}
		r.pausesLapsed()
		if r.available() {
			t.Fatal("a lapsed pause made them available again")
		}
	})
	t.Run("no credentials needs no worker", func(t *testing.T) {
		r := newRig(t)
		r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET credentials_ct = NULL`)
		// Nothing has loaded: the database knows this one by itself.
		if r.available() {
			t.Fatal("two routed gateways with no credentials read as available")
		}
	})
	t.Run("noop in production", func(t *testing.T) {
		r := newRig(t)
		// One noop row exists at most (unique by provider), so it is the only routed gateway.
		r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET role = 'disabled' WHERE id = $1`, r.fbID)
		r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET provider = 'noop', credentials_ct = NULL WHERE id = $1`, r.priID)
		if !r.available() {
			t.Fatal("the database alone cannot know the environment; a noop row reads as available until the worker judges it")
		}
		prod := r.newSource(senders.Env{Name: "production", NoopFile: r.noopFile}, r.ring)
		r.pausesLapsed()
		if _, err := prod.Load(r.env.Ctx); err != nil {
			t.Fatal(err)
		}
		if r.available() {
			t.Fatal("noop gateways in production read as available")
		}
		r.pausesLapsed()
		if r.available() {
			t.Fatal("a lapsed pause made noop gateways in production available")
		}
		dev := r.newSource(senders.Env{Name: "dev", NoopFile: r.noopFile}, r.ring)
		if _, err := dev.Load(r.env.Ctx); err != nil {
			t.Fatal(err)
		}
		if !r.available() {
			t.Fatal("a worker outside production did not take the judgement back")
		}
	})
}
