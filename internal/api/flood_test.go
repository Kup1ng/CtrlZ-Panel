package api

import (
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/pwstrength"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest/flood"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest/oracle"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
)

// The behavioural half of rule proof-before-work (P1 auth review round 5, spec 4.3, 4.4,
// 5.6, 7.5, 18.5; internal/lint TestProofBeforeWorkRule is the source half).
//
// For every operation of api/openapi.yaml that needs no session, in both registration
// modes, a request whose proof is made up (an unknown ticket, a challenge nobody issued, an
// invite nobody made, a sealed-ticket-sized value no key signed) and whose password, where
// the schema has one, is 100 runes. Such a request may not take a scoring slot, run Argon2
// beyond the one first-factor verify the operation declares, or add a row to auth_tickets.
// The bodies are generated from the OpenAPI schema (internal/authtest/flood), so a route
// added to the document is covered the day it is added, and one the generator cannot
// build fails the test.

// floodArgon2 is the declared first-factor verify of an operation: a password login
// verifies once, against the dummy for a phone it does not know (4.5).
func floodArgon2(op string) uint64 {
	if op == "loginPassword" {
		return 1
	}
	return 0
}

func TestFloodOfMadeUpProofsCostsNothing(t *testing.T) {
	f := newFrig(t, frigOpts{passkey: true})
	strong, anon := pwstrength.NewWithLimit(2, 100*time.Millisecond), pwstrength.NewWithLimit(2, 100*time.Millisecond)
	f.deps.Strength, f.deps.StrengthUnauthenticated = strong, anon
	f.setLimiter(f.deps.Limiter)
	seq := 0
	next := func() int { seq++; return seq }

	ops := oracle.NoneOperations(t, ratelimit.Tenant)
	fired := 0
	for _, mode := range []string{"closed", "open"} {
		f.env.Exec(t, `UPDATE ctrlz.system_settings SET registration_mode = $1`, mode)
		f.ck.add(31 * time.Second) // the public configuration is cached for 30 s
		for _, op := range ops {
			reqs, err := flood.Requests(api.Tenant(), op, next)
			if err != nil {
				t.Fatalf("%s: %v", op.ID, err)
			}
			if len(reqs) == 0 {
				t.Fatalf("%s: the generator built no request", op.ID)
			}
			for _, r := range reqs {
				rows := f.count(`SELECT count(*) FROM ctrlz.auth_tickets`)
				runs, scored := f.hasher.Runs(), strong.Scorings()+anon.Scorings()
				raw, err := oracle.Fire(f.h, host, f.freshIP(), r.Request)
				if err != nil {
					t.Fatal(err)
				}
				fired++
				name := mode + "/" + r.Name
				// 405, 413 and 415 mean the request never reached its handler. 404 is left alone:
				// invite_invalid is the application's own answer.
				switch raw.Status {
				case 405, 413, 415:
					t.Errorf("%s: status %d: the generated request did not reach its handler (%.80s)", name, raw.Status, raw.Body)
				}
				if got := f.hasher.Runs() - runs; got > floodArgon2(op.ID) {
					t.Errorf("%s: %d Argon2 runs for a made-up proof, the operation declares %d", name, got, floodArgon2(op.ID))
				}
				if got := strong.Scorings() + anon.Scorings() - scored; got != 0 {
					t.Errorf("%s: %d scorings for a made-up proof", name, got)
				}
				if got := f.count(`SELECT count(*) FROM ctrlz.auth_tickets`) - rows; got != 0 {
					t.Errorf("%s: %d auth_tickets rows written before any proof", name, got)
				}
			}
		}
	}
	if fired < 2*len(ops) {
		t.Errorf("only %d requests fired for %d operations", fired, len(ops))
	}
}
