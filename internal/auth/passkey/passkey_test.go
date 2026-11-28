package passkey

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/passkey/passkeytest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

const (
	rpID   = "panel.localhost"
	origin = "https://panel.localhost"
)

func enabledConfig(c store.PublicConfig) func(context.Context) (store.PublicConfig, error) {
	return func(context.Context) (store.PublicConfig, error) { return c, nil }
}

func localConfig() store.PublicConfig {
	return store.PublicConfig{PasskeyEnabled: true, RPID: rpID, AllowedOrigins: []string{origin}}
}

// noDial makes the default transport fail on any dial and counts the attempts.
// Spec 7.1: the full ceremony must run with no network.
func noDial(t *testing.T) *atomic.Int32 {
	t.Helper()
	var dials atomic.Int32
	old := http.DefaultTransport
	http.DefaultTransport = &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("test: network is forbidden")
	}}
	t.Cleanup(func() { http.DefaultTransport = old })
	return &dials
}

// register runs a registration with the authenticator and returns the stored form.
func register(t *testing.T, in Instance, u *User, a *passkeytest.Authenticator) store.Credential {
	t.Helper()
	b, err := in.BeginRegistration(u)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Session) > 3000 {
		t.Fatalf("session data is %d bytes; a ticket payload holds 4096 and a login adds credential ids", len(b.Session))
	}
	body, err := a.Create(b.Options)
	if err != nil {
		t.Fatal(err)
	}
	r, err := in.FinishRegistration(u, b.Session, body)
	if err != nil {
		t.Fatalf("registration refused: %v", err)
	}
	c := r.Credential
	c.UserID = uuid.UUID(u.id)
	return c
}

func TestFullCeremonyNeedsNoNetwork(t *testing.T) {
	dials := noDial(t)
	p := NewProvider(enabledConfig(localConfig()))
	in, err := p.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	uid := uuid.New()
	a := passkeytest.New(origin, rpID)
	cred := register(t, in, NewUser(uid, "+989121234567", nil), a)
	if cred.RPID != rpID || len(cred.PublicKey) == 0 || cred.AttestationType != "none" {
		t.Fatalf("stored credential is incomplete: %+v", cred)
	}

	// Login for a known user.
	u := NewUser(uid, "+989121234567", []store.Credential{cred})
	b, err := in.BeginLogin(u)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := a.Get(b.Options)
	got, err := in.FinishLogin(u, b.Session, body)
	if err != nil || got.SignCount != 1 {
		t.Fatalf("known-user login: %v %+v", err, got)
	}

	// Discoverable login: the resolver sees the credential id and the user handle.
	d, err := in.BeginDiscoverable()
	if err != nil {
		t.Fatal(err)
	}
	body, _ = a.Get(d.Options)
	resolved, asserted, err := in.FinishDiscoverable(func(raw, handle []byte) (*User, error) {
		if string(handle) != string(uid[:]) {
			return nil, errors.New("handle")
		}
		return NewUser(uid, "", []store.Credential{cred}), nil
	}, d.Session, body)
	if err != nil || resolved == nil || asserted.SignCount != 2 {
		t.Fatalf("discoverable login: %v %+v", err, asserted)
	}
	if dials.Load() != 0 {
		t.Fatalf("the ceremony dialled the network %d times", dials.Load())
	}
}

func TestLoginRefusals(t *testing.T) {
	p := NewProvider(enabledConfig(localConfig()))
	in, _ := p.Get(context.Background())
	uid := uuid.New()
	a := passkeytest.New(origin, rpID)
	cred := register(t, in, NewUser(uid, "", nil), a)
	u := NewUser(uid, "", []store.Credential{cred})

	try := func(name string, mutate func(*passkeytest.Authenticator)) {
		t.Helper()
		b, err := in.BeginLogin(u)
		if err != nil {
			t.Fatal(err)
		}
		clone := *a
		mutate(&clone)
		body, _ := clone.Get(b.Options)
		if _, err := in.FinishLogin(u, b.Session, body); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: got %v, want ErrInvalid", name, err)
		}
	}
	try("user verification off", func(x *passkeytest.Authenticator) { x.UV = false })
	try("another origin", func(x *passkeytest.Authenticator) { x.Origin = "https://evil.example" })
	try("another relying party", func(x *passkeytest.Authenticator) { x.RPID = "evil.example" })
	try("backup eligibility changed", func(x *passkeytest.Authenticator) { x.BackupEligible = true })

	// Another user's passkey on this user's ceremony.
	other := passkeytest.New(origin, rpID)
	b, _ := in.BeginLogin(u)
	other.UserHandle = uid[:]
	body, _ := other.Get(b.Options)
	if _, err := in.FinishLogin(u, b.Session, body); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a credential the user does not own: %v", err)
	}

	// A challenge cannot be replayed on another session.
	b1, _ := in.BeginLogin(u)
	b2, _ := in.BeginLogin(u)
	body, _ = a.Get(b1.Options)
	if _, err := in.FinishLogin(u, b2.Session, body); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an assertion for another challenge: %v", err)
	}
	if _, err := in.FinishLogin(u, []byte("{"), body); !errors.Is(err, ErrInvalid) {
		t.Fatalf("broken session data: %v", err)
	}
}

func TestRegistrationRefusals(t *testing.T) {
	p := NewProvider(enabledConfig(localConfig()))
	in, _ := p.Get(context.Background())
	u := NewUser(uuid.New(), "", nil)
	for name, mutate := range map[string]func(*passkeytest.Authenticator){
		"no user verification": func(x *passkeytest.Authenticator) { x.UV = false },
		"another origin":       func(x *passkeytest.Authenticator) { x.Origin = "https://evil.example" },
		"another rp":           func(x *passkeytest.Authenticator) { x.RPID = "evil.example" },
	} {
		a := passkeytest.New(origin, rpID)
		mutate(a)
		b, _ := in.BeginRegistration(u)
		body, _ := a.Create(b.Options)
		if _, err := in.FinishRegistration(u, b.Session, body); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: got %v", name, err)
		}
	}
}

func TestProviderFollowsTheConfiguration(t *testing.T) {
	cfg := localConfig()
	p := NewProvider(func(context.Context) (store.PublicConfig, error) { return cfg, nil })
	ctx := context.Background()
	first, err := p.Get(ctx)
	if err != nil || first.RPID != rpID {
		t.Fatal(err)
	}
	again, _ := p.Get(ctx)
	if first.wa != again.wa {
		t.Fatal("an unchanged configuration rebuilt the relying party")
	}
	cfg.RPID, cfg.AllowedOrigins = "other.localhost", []string{"https://other.localhost"}
	changed, _ := p.Get(ctx)
	if changed.RPID != "other.localhost" || changed.wa == first.wa {
		t.Fatal("a changed RP ID did not rebuild the relying party")
	}
	for name, c := range map[string]store.PublicConfig{
		"disabled":   {PasskeyEnabled: false, RPID: rpID, AllowedOrigins: []string{origin}},
		"no rp id":   {PasskeyEnabled: true, AllowedOrigins: []string{origin}},
		"no origins": {PasskeyEnabled: true, RPID: rpID},
	} {
		if _, err := NewProvider(enabledConfig(c)).Get(ctx); !errors.Is(err, ErrDisabled) {
			t.Fatalf("%s: got %v, want ErrDisabled", name, err)
		}
	}
	boom := errors.New("db down")
	if _, err := NewProvider(func(context.Context) (store.PublicConfig, error) { return store.PublicConfig{}, boom }).Get(ctx); !errors.Is(err, boom) {
		t.Fatalf("a configuration error must pass through, got %v", err)
	}
}

func TestLiveSkipsStaleAndOtherRP(t *testing.T) {
	stale := store.Credential{RPID: rpID}
	ts := timeNow()
	stale.StaleAt = &ts
	got := Live([]store.Credential{{RPID: rpID}, stale, {RPID: "old.example"}}, rpID)
	if len(got) != 1 {
		t.Fatalf("live = %d, want 1", len(got))
	}
}

func TestUserHandleIsTheIDAndNameIsMasked(t *testing.T) {
	id := uuid.New()
	u := NewUser(id, "+989121234567", nil)
	if string(u.WebAuthnID()) != string(id[:]) || len(u.WebAuthnID()) != 16 {
		t.Fatal("the user handle must be the 16 bytes of the user id")
	}
	if u.WebAuthnName() == "+989121234567" || u.WebAuthnName() == "" {
		t.Fatalf("the authenticator label must be masked, got %q", u.WebAuthnName())
	}
}
