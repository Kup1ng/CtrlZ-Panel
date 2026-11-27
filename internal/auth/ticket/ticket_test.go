package ticket_test

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/ticket"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/credgen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

var cluster *testpg.Cluster

func TestMain(m *testing.M) {
	os.Exit(testpg.RunMain(m, func(c *testpg.Cluster) { cluster = c }))
}

func TestTicketLifecycle(t *testing.T) {
	env := authtest.New(t, cluster)
	svc := ticket.New(env.Tenant(t).Auth())
	ctx := context.Background()

	in := ticket.Issue{Kind: store.TicketMFA, Tenant: env.A.Tenant, User: env.A.User, RememberMe: true, FirstFactor: "password", Cred: credgen.Stamp{Tenant: env.A.Tenant, Subject: env.A.User, Gen: 7}}
	iss, err := svc.Put(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if iss.ExpiresIn <= 0 || iss.Token.IsZero() {
		t.Fatalf("issued %+v", iss)
	}

	// A ticket is of one kind.
	if _, ok, _ := svc.Peek(ctx, iss.Token.Reveal(), store.TicketReset); ok {
		t.Fatal("a mfa ticket must not peek as reset")
	}
	got, ok, err := svc.Peek(ctx, iss.Token.Reveal(), store.TicketMFA)
	if err != nil || !ok || got.Tenant != env.A.Tenant || got.User != env.A.User || !got.RememberMe || got.FirstFactor != "password" {
		t.Fatalf("peek: %+v %v %v", got, ok, err)
	}
	if got.Cred != in.Cred {
		t.Fatalf("the ticket came back with stamp %+v, made with %+v", got.Cred, in.Cred)
	}
	if _, ok, err := svc.Take(ctx, iss.Token.Reveal(), store.TicketMFA); err != nil || !ok {
		t.Fatalf("take: %v %v", ok, err)
	}
	if _, ok, _ := svc.Take(ctx, iss.Token.Reveal(), store.TicketMFA); ok {
		t.Fatal("a ticket is single use")
	}
	if _, ok, _ := svc.Peek(ctx, iss.Token.Reveal(), store.TicketMFA); ok {
		t.Fatal("a used ticket cannot be peeked")
	}
}

func TestPeekIsLimitedToFiveReads(t *testing.T) {
	env := authtest.New(t, cluster)
	svc := ticket.New(env.Tenant(t).Auth())
	ctx := context.Background()
	iss, err := svc.Put(ctx, ticket.Issue{Kind: store.TicketReset, Tenant: env.A.Tenant, User: env.A.User})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for i := 0; i < 8; i++ {
		if _, ok, _ := svc.Peek(ctx, iss.Token.Reveal(), store.TicketReset); ok {
			n++
		}
	}
	if n != 5 {
		t.Fatalf("%d peeks succeeded, want 5", n)
	}
}

func TestJunkTokensNeverReachTheDatabase(t *testing.T) {
	// A service over a closed pool would error on any call; junk must return
	// "not found" before getting that far.
	env := authtest.New(t, cluster)
	st := env.Tenant(t)
	svc := ticket.New(st.Auth())
	st.Close()
	for _, junk := range []string{"", "x", "short-token", string(make([]byte, 100))} {
		if _, ok, err := svc.Peek(context.Background(), junk, store.TicketMFA); ok || err != nil {
			t.Errorf("Peek(%q) = %v, %v", junk, ok, err)
		}
		if _, ok, err := svc.Take(context.Background(), junk, store.TicketMFA); ok || err != nil {
			t.Errorf("Take(%q) = %v, %v", junk, ok, err)
		}
	}
}

func TestParallelTakeGivesExactlyOne(t *testing.T) {
	env := authtest.New(t, cluster)
	svc := ticket.New(env.Tenant(t).Auth())
	ctx := context.Background()
	for round := 0; round < 5; round++ {
		iss, err := svc.Put(ctx, ticket.Issue{Kind: store.TicketMFA, Tenant: env.A.Tenant, User: env.A.User, Cred: credgen.Stamp{Tenant: env.A.Tenant, Subject: env.A.User, Gen: 7}})
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var won atomic.Int32
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, ok, _ := svc.Take(ctx, iss.Token.Reveal(), store.TicketMFA); ok {
					won.Add(1)
				}
			}()
		}
		wg.Wait()
		if won.Load() != 1 {
			t.Fatalf("round %d: %d takers won, want 1", round, won.Load())
		}
	}
}

func TestPayloadRoundTripAndSubjectlessTicket(t *testing.T) {
	env := authtest.New(t, cluster)
	svc := ticket.New(env.Tenant(t).Auth())
	ctx := context.Background()
	iss, err := svc.Put(ctx, ticket.Issue{Kind: store.TicketPasskeyLogin, Payload: []byte(`{"webauthn":"session"}`)})
	if err != nil {
		t.Fatal(err)
	}
	got, ok, err := svc.Take(ctx, iss.Token.Reveal(), store.TicketPasskeyLogin)
	if err != nil || !ok || string(got.Payload) != `{"webauthn":"session"}` || got.Tenant.String() != "00000000-0000-0000-0000-000000000000" {
		t.Fatalf("take: %+v %v %v", got, ok, err)
	}
}

// TestMFATicketNeedsTheGeneration: an mfa ticket is worth what the credentials were when
// it was made, so one made without the generation (or with the stamp of someone else)
// could never be refused and is not made (rule credential-generation).
func TestMFATicketNeedsTheGeneration(t *testing.T) {
	env := authtest.New(t, cluster)
	svc := ticket.New(env.Tenant(t).Auth())
	ctx := context.Background()
	if _, err := svc.Put(ctx, ticket.Issue{Kind: store.TicketMFA, Tenant: env.A.Tenant, User: env.A.User}); err == nil {
		t.Error("an mfa ticket without a generation was made")
	}
	other := credgen.Stamp{Tenant: env.B.Tenant, Subject: env.B.User, Gen: 1}
	if _, err := svc.Put(ctx, ticket.Issue{Kind: store.TicketMFA, Tenant: env.A.Tenant, User: env.A.User, Cred: other}); err == nil {
		t.Error("an mfa ticket of tenant A was made with tenant B's stamp")
	}
	// The other kinds carry none, and come back with none.
	iss, err := svc.Put(ctx, ticket.Issue{Kind: store.TicketReset, Tenant: env.A.Tenant, User: env.A.User})
	if err != nil {
		t.Fatal(err)
	}
	got, ok, err := svc.Peek(ctx, iss.Token.Reveal(), store.TicketReset)
	if err != nil || !ok || !got.Cred.Zero() {
		t.Errorf("a reset ticket: %+v %v %v", got, ok, err)
	}
}
