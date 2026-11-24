package proof_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/proof"
)

// TestRefundIsForABusyServerAndNothingElse is tenant-r5-1. A charge comes before the work on
// purpose, so a flood cannot reach Argon2; but an attempt the server turned away for want of
// capacity looked at nothing, and it must not stay spent. The refund runs for ErrBusy (the
// Argon2 gate and the scoring gate both answer it) and for no other ending: a wrong answer
// is the caller's own and a failure of the database is not a reason to hand tries back.
func TestRefundIsForABusyServerAndNothingElse(t *testing.T) {
	boom := errors.New("boom")
	cases := []struct {
		name   string
		work   error
		refund bool
	}{
		{"busy", password.ErrBusy, true},
		{"busy wrapped", fmt.Errorf("scoring: %w", password.ErrBusy), true},
		{"another error", boom, false},
		{"success", nil, false},
	}
	for _, c := range cases {
		refunds := 0
		_, err := proof.Run(context.Background(), proof.Spec[int]{
			Kind:   proof.Password,
			Charge: func(context.Context) error { return nil },
			Refund: func(context.Context) { refunds++ },
			Work:   func(context.Context, proof.Proved) (int, error) { return 0, c.work },
		})
		if !errors.Is(err, c.work) || (refunds == 1) != c.refund || refunds > 1 {
			t.Errorf("%s: err %v, %d refunds, want a refund: %v", c.name, err, refunds, c.refund)
		}
	}
}

// TestRefundOutlivesAGoneClient: a client that gave up on the 503 must still get its tries back.
func TestRefundOutlivesAGoneClient(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var live bool
	_, _ = proof.Run(ctx, proof.Spec[int]{
		Kind:   proof.Password,
		Charge: func(context.Context) error { return nil },
		Refund: func(c context.Context) { live = c.Err() == nil },
		Work: func(context.Context, proof.Proved) (int, error) {
			cancel()
			return 0, password.ErrBusy
		},
	})
	if !live {
		t.Fatal("the refund ran on a cancelled context")
	}
}

// TestAChargeNeedsARefund: a Spec with a Charge and no Refund is malformed (there is no reason to give instead,
// primitives-r6-9).
func TestAChargeNeedsARefund(t *testing.T) {
	_, err := proof.Run(context.Background(), proof.Spec[int]{
		Kind:   proof.Password,
		Charge: func(context.Context) error { return nil },
		Work:   func(context.Context, proof.Proved) (int, error) { t.Error("Work ran"); return 0, nil },
	})
	if !errors.Is(err, proof.ErrSpec) {
		t.Fatalf("err = %v, want ErrSpec", err)
	}
}

func TestRunKeepsTheOrderAndStopsAtTheFirstError(t *testing.T) {
	var seen []string
	step := func(name string, err error) func(context.Context) error {
		return func(context.Context) error { seen = append(seen, name); return err }
	}
	spec := func(shape, charge, check error) proof.Spec[int] {
		return proof.Spec[int]{
			Kind: proof.Ticket, Shape: step("shape", shape), Charge: step("charge", charge), Check: step("check", check),
			Refund: func(context.Context) {},
			Work: func(_ context.Context, p proof.Proved) (int, error) {
				seen = append(seen, "work")
				if p.Kind() != proof.Ticket {
					t.Errorf("Proved.Kind = %v", p.Kind())
				}
				return 7, nil
			},
		}
	}
	boom := errors.New("boom")
	cases := []struct {
		name string
		s    proof.Spec[int]
		want []string
		err  error
		out  int
	}{
		{"all pass", spec(nil, nil, nil), []string{"shape", "charge", "check", "work"}, nil, 7},
		{"shape refuses", spec(boom, nil, nil), []string{"shape"}, boom, 0},
		{"charge refuses", spec(nil, boom, nil), []string{"shape", "charge"}, boom, 0},
		{"check refuses", spec(nil, nil, boom), []string{"shape", "charge", "check"}, boom, 0},
	}
	for _, c := range cases {
		seen = nil
		out, err := proof.Run(context.Background(), c.s)
		if !errors.Is(err, c.err) || out != c.out || !slices.Equal(seen, c.want) {
			t.Errorf("%s: out %d err %v steps %v, want %d %v %v", c.name, out, err, seen, c.out, c.err, c.want)
		}
	}
}

func TestRunRefusesAMalformedSpec(t *testing.T) {
	work := func(context.Context, proof.Proved) (int, error) {
		t.Error("Work ran for a malformed spec")
		return 0, nil
	}
	check := func(context.Context) error { return nil }
	for name, s := range map[string]proof.Spec[int]{
		"no kind":             {Check: check, Work: work},
		"no work":             {Kind: proof.Ticket, Check: check},
		"a ticket, no check":  {Kind: proof.Ticket, Work: work},
		"a code, no check":    {Kind: proof.OneTimeCode, Work: work},
		"a sealed, no check":  {Kind: proof.Sealed, Work: work},
		"an invite, no check": {Kind: proof.Invite, Work: work},
	} {
		if _, err := proof.Run(context.Background(), s); !errors.Is(err, proof.ErrSpec) {
			t.Errorf("%s: err = %v, want ErrSpec", name, err)
		}
	}
}

func TestAFirstFactorPasswordNeedsNoCheck(t *testing.T) {
	ran := false
	_, err := proof.Run(context.Background(), proof.Spec[int]{Kind: proof.Password, Work: func(context.Context, proof.Proved) (int, error) { ran = true; return 0, nil }})
	if err != nil || !ran {
		t.Fatalf("err %v ran %v", err, ran)
	}
}

func TestRunStopsWhenTheRequestIsGone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	_, err := proof.Run(ctx, proof.Spec[int]{
		Kind:  proof.Ticket,
		Check: func(context.Context) error { cancel(); return nil },
		Work: func(context.Context, proof.Proved) (int, error) {
			t.Error("Work ran after the request was cancelled")
			return 0, nil
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

// TestOnlyAProofThatWasLookedAtTakesTheGateLane is tenant-r6-1 and -7: Work of every kind of
// proof that has a Check runs in the priority lane of the Argon2 gate (a reset whose code is right
// is not a stranger), and Work of a first-factor password does not (it is the stranger until its
// caller shows a device marker). The kinds are listed, so a new Kind has to choose.
func TestOnlyAProofThatWasLookedAtTakesTheGateLane(t *testing.T) {
	lane := map[proof.Kind]bool{proof.Password: false, proof.OneTimeCode: true, proof.Ticket: true, proof.Invite: true, proof.Sealed: true}
	for kind, want := range lane {
		var got bool
		spec := proof.Spec[int]{
			Kind:  kind,
			Check: func(context.Context) error { return nil },
			Work:  func(ctx context.Context, _ proof.Proved) (int, error) { got = password.IsProved(ctx); return 0, nil },
		}
		if _, err := proof.Run(context.Background(), spec); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("kind %d: Work ran with the lane = %v, want %v", kind, got, want)
		}
	}
	// And the request that comes in unproved is not changed by it: the Check step sees no mark.
	var checked bool
	_, _ = proof.Run(context.Background(), proof.Spec[int]{
		Kind: proof.Ticket, Check: func(ctx context.Context) error { checked = password.IsProved(ctx); return nil },
		Work: func(context.Context, proof.Proved) (int, error) { return 0, nil },
	})
	if checked {
		t.Error("the Check step ran in the lane: a proof that is still being looked at is a stranger")
	}
}
