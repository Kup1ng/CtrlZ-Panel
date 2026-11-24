package ticket

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/token"
	"github.com/Kup1ng/CtrlZ-Panel/internal/credgen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// A ticket carries a tag the pipeline checks with no I/O (tenant-r19-1, D64 nat-proof-tag). These tests need no database: the
// token is made and screened by the service alone.

func taggedService(t *testing.T, now *time.Time) *Service {
	t.Helper()
	ring, err := keyring.NewEphemeral(keyring.DomainAuthMAC)
	if err != nil {
		t.Fatal(err)
	}
	return New(store.AuthLookups{}).WithSealing(ring, func() time.Time { return *now })
}

func TestATicketNamesItsAccountAndRunsOutInProcess(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	s := taggedService(t, &now)
	user := uuid.New()
	n, iss, err := s.newTicket(Issue{Kind: store.TicketMFA, User: user, Cred: credgen.Stamp{Subject: user, Gen: 1}})
	if err != nil {
		t.Fatal(err)
	}
	id, subject, ok := s.Screen(iss.Token.Reveal())
	if !ok || subject != "u:"+user.String() || id == "" || id == subject {
		t.Fatalf("a fresh ticket screens as %q %q %v", id, subject, ok)
	}
	if string(n.TokenHash) != string(token.HashString(iss.Token.Reveal())) {
		t.Fatal("the stored hash is not the hash of the text the client holds")
	}
	now = now.Add(TTL(store.TicketMFA) + time.Second)
	if _, _, ok := s.Screen(iss.Token.Reveal()); ok {
		t.Fatal("a ticket past its life still screens: dead tickets would buy database reads")
	}
}

func TestATaggedServiceRefusesAPlainTokenAndJunk(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	s := taggedService(t, &now)
	plain, err := token.New()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{plain.Reveal(), "", "x", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} {
		if _, _, ok := s.Screen(v); ok {
			t.Fatalf("%q screens as a ticket", v)
		}
	}
	// And it is refused by Peek, Take and TakeTx before any read: the service has no store at all, so a database call would panic.
	if _, ok, err := s.Peek(context.Background(), plain.Reveal(), store.TicketReset); ok || err != nil {
		t.Fatalf("Peek of a plain token = %v %v", ok, err)
	}
	if _, ok, err := s.Take(context.Background(), plain.Reveal(), store.TicketReset); ok || err != nil {
		t.Fatalf("Take of a plain token = %v %v", ok, err)
	}
}

func TestATicketCannotBeAnotherKindOfValue(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	s := taggedService(t, &now)
	_, iss, err := s.newTicket(Issue{Kind: store.TicketReset, User: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.tags.Open('r', iss.Token.Reveal()); ok {
		t.Fatal("a ticket opens as a refresh token")
	}
}
