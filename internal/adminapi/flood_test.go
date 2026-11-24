package adminapi

import (
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest/flood"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest/oracle"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
)

// TestFloodOfMadeUpProofsCostsNothing is the admin half of rule proof-before-work (P1 auth
// review round 5, spec 10.2, 18.5; the tenant half is internal/api flood_test.go). The one
// operation that needs no session is the admin login: a made-up username with a 100-rune
// password may run Argon2 once, the first-factor verify it declares (against the dummy), and
// may not write an auth_tickets row, which the admin service never uses. The body comes
// from the OpenAPI schema, so a second none operation is covered the day it is added.
func TestFloodOfMadeUpProofsCostsNothing(t *testing.T) {
	w := newAdminWorld(t)
	seq := 0
	next := func() int { seq++; return seq }
	ops := oracle.NoneOperations(t, ratelimit.Admin)
	fired := 0
	for _, op := range ops {
		reqs, err := flood.Requests(api.Admin(), op, next)
		if err != nil {
			t.Fatalf("%s: %v", op.ID, err)
		}
		if len(reqs) == 0 {
			t.Fatalf("%s: the generator built no request", op.ID)
		}
		for _, r := range reqs {
			w.reset()
			rows := w.r.count(t, `SELECT count(*) FROM ctrlz.auth_tickets`)
			before := w.meters()
			raw, err := oracle.Fire(w.h, adminHost, freshIP(), r.Request)
			if err != nil {
				t.Fatal(err)
			}
			fired++
			switch raw.Status {
			case 404, 405, 413, 415:
				t.Errorf("%s: status %d: the generated request did not reach its handler", r.Name, raw.Status)
			}
			if got := w.meters().Sub(before).Argon2; got > 1 {
				t.Errorf("%s: %d Argon2 runs for a made-up proof, the first-factor verify is one", r.Name, got)
			}
			if got := w.r.count(t, `SELECT count(*) FROM ctrlz.auth_tickets`) - rows; got != 0 {
				t.Errorf("%s: %d auth_tickets rows written before any proof", r.Name, got)
			}
		}
	}
	if fired < len(ops) {
		t.Errorf("only %d requests fired for %d operations", fired, len(ops))
	}
}
