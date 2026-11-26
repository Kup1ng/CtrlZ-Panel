package apitoken_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/apitoken"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/bearer"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// fake is the table of tokens a Lookup reads: by the SHA-256 of the value.
type fake struct {
	rows  map[string]store.TokenInfo
	asked int
	err   error
}

func (f *fake) TokenByHash(_ context.Context, hash []byte) (store.TokenInfo, bool, error) {
	f.asked++
	if f.err != nil {
		return store.TokenInfo{}, false, f.err
	}
	r, ok := f.rows[string(hash)]
	return r, ok, nil
}

func signer(t *testing.T, now func() time.Time) *bearer.Signer {
	t.Helper()
	ring, err := keyring.NewEphemeral(keyring.DomainAuthMAC)
	if err != nil {
		t.Fatal(err)
	}
	s, err := bearer.New(ring, now)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestValueAndShown(t *testing.T) {
	if v, ok := apitoken.Value("ctz_abc"); !ok || v != "abc" {
		t.Errorf("Value = %q %v", v, ok)
	}
	for _, bad := range []string{"", "abc", "CTZ_abc", " ctz_abc", "ctz"} {
		if _, ok := apitoken.Value(bad); ok {
			t.Errorf("%q is no token", bad)
		}
	}
	if apitoken.Shown("x") != "ctz_x" {
		t.Error("Shown")
	}
}

func TestParseAllowed(t *testing.T) {
	good := map[string]string{"203.0.113.7": "203.0.113.7/32", "203.0.113.0/24": "203.0.113.0/24", "2001:db8::/32": "2001:db8::/32", "2001:db8::1": "2001:db8::1/128"}
	for in, want := range good {
		p, ok := apitoken.ParseAllowed(in)
		if !ok || p.String() != want {
			t.Errorf("%q = %v %v, want %s", in, p, ok, want)
		}
	}
	for _, in := range []string{"", "x", "203.0.113.7/24", "::ffff:203.0.113.7", "::ffff:203.0.113.0/120", "fe80::1%eth0", "203.0.113.0/33", "1.2.3.4/", " 1.2.3.4"} {
		if _, ok := apitoken.ParseAllowed(in); ok {
			t.Errorf("%q was accepted", in)
		}
	}
}

func TestScreenAndLookupGates(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	clock := now
	sg := signer(t, func() time.Time { return clock })
	tenant, user, id := uuid.New(), uuid.New(), uuid.New()
	value, err := sg.Mint(bearer.APIToken, id, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cred := apitoken.Shown(value.Reveal())
	row := store.TokenInfo{TenantID: tenant, UserID: user, TokenID: id, Kind: "write", TenantStatus: "active"}
	db := &fake{rows: map[string]store.TokenInfo{string(bearer.Hash(value.Reveal())): row}}
	r := apitoken.Resolver{Signer: sg, Auth: db}

	// Screen: the id of the row, no I/O; junk, a value of another kind and a value past its expiry are refused.
	if got, ok := r.Screen(cred); !ok || got != id {
		t.Fatalf("Screen = %v %v", got, ok)
	}
	share, _ := sg.Mint(bearer.ShareLink, id, now.Add(time.Hour))
	for name, c := range map[string]string{"no prefix": value.Reveal(), "junk": "ctz_junk", "a share value": apitoken.Shown(share.Reveal()), "empty": ""} {
		if _, ok := r.Screen(c); ok {
			t.Errorf("%s screened", name)
		}
	}
	if db.asked != 0 {
		t.Fatalf("Screen asked the database %d times", db.asked)
	}
	clock = now.Add(2 * time.Hour)
	if _, ok := r.Screen(cred); ok {
		t.Error("an expired value screened")
	}
	clock = now

	client := netip.MustParseAddr("203.0.113.9")
	info, out, err := r.Lookup(context.Background(), cred, client, true)
	if err != nil || !out.Live || out.Dead || info.TenantID != tenant || info.UserID != user || info.TokenID != id || info.Kind != "write" {
		t.Fatalf("a live write token: %+v %+v %v", info, out, err)
	}

	cases := []struct {
		name   string
		edit   func(*store.TokenInfo)
		writes bool
		client netip.Addr
		want   error
		live   bool
		dead   bool
	}{
		{"not found", nil, true, client, apitoken.ErrInvalid, false, true},
		{"revoked", func(i *store.TokenInfo) { n := now; i.RevokedAt = &n }, false, client, apitoken.ErrInvalid, false, true},
		{"suspended tenant", func(i *store.TokenInfo) { i.TenantStatus = "suspended" }, false, client, apitoken.ErrSuspended, true, false},
		{"deleting tenant", func(i *store.TokenInfo) { i.TenantStatus = "deleting" }, false, client, apitoken.ErrInvalid, true, false},
		{"an unknown status", func(i *store.TokenInfo) { i.TenantStatus = "new" }, false, client, apitoken.ErrInvalid, true, false},
		{"outside allowed_ips", func(i *store.TokenInfo) { i.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")} }, false, client, apitoken.ErrIPNotAllowed, true, false},
		{"no address at all", func(i *store.TokenInfo) { i.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")} }, false, netip.Addr{}, apitoken.ErrIPNotAllowed, true, false},
		{"inside allowed_ips", func(i *store.TokenInfo) { i.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")} }, true, client, nil, true, false},
		{"mapped address inside", func(i *store.TokenInfo) { i.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")} }, true, netip.MustParseAddr("::ffff:203.0.113.9"), nil, true, false},
		{"a read token on a write", func(i *store.TokenInfo) { i.Kind = "read" }, true, client, apitoken.ErrReadOnly, true, false},
		{"a read token on a read", func(i *store.TokenInfo) { i.Kind = "read" }, false, client, nil, true, false},
		{"the status comes before the address", func(i *store.TokenInfo) {
			i.TenantStatus = "suspended"
			i.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
		}, true, client, apitoken.ErrSuspended, true, false},
		{"the address comes before the kind", func(i *store.TokenInfo) {
			i.Kind = "read"
			i.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
		}, true, client, apitoken.ErrIPNotAllowed, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rows := map[string]store.TokenInfo{}
			if c.edit != nil {
				e := row
				c.edit(&e)
				rows[string(bearer.Hash(value.Reveal()))] = e
			}
			rr := apitoken.Resolver{Signer: sg, Auth: &fake{rows: rows}}
			_, o, err := rr.Lookup(context.Background(), cred, c.client, c.writes)
			if !errors.Is(err, c.want) || (c.want == nil && err != nil) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			if o.Live != c.live || o.Dead != c.dead {
				t.Fatalf("outcome %+v, want live %v dead %v", o, c.live, c.dead)
			}
		})
	}

	// A database fault is neither live nor dead and is not one of the refusals.
	boom := errors.New("down")
	_, o, err := apitoken.Resolver{Signer: sg, Auth: &fake{err: boom}}.Lookup(context.Background(), cred, client, false)
	if !errors.Is(err, boom) || o.Live || o.Dead {
		t.Errorf("a fault: %+v %v", o, err)
	}
}
