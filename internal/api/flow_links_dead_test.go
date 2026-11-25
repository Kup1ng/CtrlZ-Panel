package api

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/bearer"
)

// E4 over all three public operations (docs/specs/p3-endpoints.md 7.1, 11.2 E4; p3-D6-r2-7): a value whose tenant is suspended or
// being deleted, whose link has expired, and whose link ends between the lookup of the value and the spend of its use, is the one 404
// of every other refusal, on the share view, on the share's Apple profile and on the download, and none of them spends a use or hands
// out a file. The lookup of each route reads the status of the tenant (info.TenantStatus != "active"): remove it from one route and
// the value of a suspended tenant keeps handing out its resolver id and its DoH token for the life of the link.

// pubOp is one of the three public operations: how to make a live value for it, how to send one, and where its row is.
type pubOp struct {
	name  string
	table string
	ok    int // the status of a live value: the share view and the download answer 200, the share Apple profile creates a download link and answers 201
	mint  func(r *linkRig) string
	call  func(r *linkRig, value string) *resp
}

func pubOps() []pubOp {
	return []pubOp{
		{"share view", "setup_share_tokens", 200,
			func(r *linkRig) string { return valueOf(r.f.t, r.share(map[string]any{}).URL) },
			func(r *linkRig, v string) *resp { return r.open(v) }},
		{"share apple profile", "setup_share_tokens", 201,
			func(r *linkRig) string { return valueOf(r.f.t, r.share(map[string]any{}).URL) },
			func(r *linkRig, v string) *resp {
				return r.f.client().post("/public/share/apple-profile", map[string]any{"link": v, "params": map[string]any{"protocol": "doh"}})
			}},
		{"download", "profile_download_tokens", 200,
			func(r *linkRig) string {
				var dl pLinkURL
				r.apple(map[string]any{"protocol": "doh"}).want(201, "").json(&dl)
				return valueOf(r.f.t, dl.URL)
			},
			func(r *linkRig, v string) *resp { return r.download(v) }},
	}
}

func (r *linkRig) rowOf(op pubOp, value string) uuid.UUID {
	r.f.t.Helper()
	var id uuid.UUID
	r.f.env.Scan(r.f.t, `SELECT id FROM ctrlz.`+op.table+` WHERE token_hash = $1`, []any{bearer.Hash(value)}, &id)
	return id
}

func (r *linkRig) uses(op pubOp, id uuid.UUID) int {
	r.f.t.Helper()
	var n int
	r.f.env.Scan(r.f.t, `SELECT uses FROM ctrlz.`+op.table+` WHERE id = $1`, []any{id}, &n)
	return n
}

func TestPublicRoutesRefuseDeadValuesAlike(t *testing.T) {
	r := newLinkRig(t)
	f := r.f
	var hook func()
	prev := f.srv.ep.Turn
	f.srv.ep.Turn = func(ctx context.Context, tenant uuid.UUID) (func(), error) {
		if h := hook; h != nil {
			hook = nil
			h()
		}
		if prev != nil {
			return prev(ctx, tenant)
		}
		return func() {}, nil
	}
	t.Cleanup(func() { f.srv.ep.Turn = prev })

	for _, op := range pubOps() {
		t.Run(op.name, func(t *testing.T) {
			// The answer to junk is the one every refusal must equal, to the byte but for the request id, with the same headers.
			base := op.call(r, "x")
			base.want(404, "not_found")
			same := func(what string, got *resp) {
				t.Helper()
				got.want(404, "not_found")
				if !bytes.Equal(withoutRequestID(base.Body), withoutRequestID(got.Body)) {
					t.Errorf("%s: body %q differs from %q", what, got.Body, base.Body)
				}
				for _, h := range []string{"Cache-Control", "X-Robots-Tag", "Referrer-Policy", "Content-Type"} {
					if base.H.Get(h) != got.H.Get(h) {
						t.Errorf("%s: header %s %q differs from %q", what, h, got.H.Get(h), base.H.Get(h))
					}
				}
			}
			setStatus := func(s string) {
				f.env.Exec(t, `UPDATE ctrlz.tenants SET status = $2 WHERE id = $1`, f.env.A.Tenant, s)
			}
			step := func() { f.ck.add(3 * time.Second) }

			// A tenant that is suspended or being deleted: the value is live (it works once the tenant is active) and is refused meanwhile,
			// and nothing is spent by the refusal.
			for _, status := range []string{"suspended", "deleting"} {
				v := op.mint(r)
				id := r.rowOf(op, v)
				setStatus(status)
				same(status+" tenant", op.call(r, v))
				step()
				setStatus("active")
				if n := r.uses(op, id); n != 0 {
					t.Errorf("a %s tenant's request spent %d uses", status, n)
				}
				if got := op.call(r, v); got.Code != op.ok {
					t.Errorf("the value of a tenant that is active again answered %d %s, want %d: the refusal above was not its status", got.Code, got.Body, op.ok)
				}
				step()
			}

			// A link whose time is up (the expiry is the application's now, which no longer lies after it).
			v := op.mint(r)
			id := r.rowOf(op, v)
			f.env.Exec(t, `UPDATE ctrlz.`+op.table+` SET expires_at = $2 WHERE id = $1`, id, f.ck.now())
			same("expired", op.call(r, v))
			step()

			// A link that ends between the lookup of its value and the spend of its use: the statement of the spend decides, and says 404.
			late := map[string]func(id uuid.UUID){
				"revoked in flight": func(id uuid.UUID) {
					if op.table == "setup_share_tokens" {
						f.env.Exec(t, `UPDATE ctrlz.setup_share_tokens SET revoked_at = now() WHERE id = $1`, id)
					} else {
						f.env.Exec(t, `DELETE FROM ctrlz.profile_download_tokens WHERE id = $1`, id)
					}
				},
				"used up in flight": func(id uuid.UUID) {
					f.env.Exec(t, `UPDATE ctrlz.`+op.table+` SET uses = max_uses WHERE id = $1`, id)
				},
				"expired in flight": func(id uuid.UUID) {
					f.env.Exec(t, `UPDATE ctrlz.`+op.table+` SET expires_at = $2 WHERE id = $1`, id, f.ck.now())
				},
			}
			for _, name := range []string{"revoked in flight", "used up in flight", "expired in flight"} {
				v := op.mint(r)
				id := r.rowOf(op, v)
				fn := late[name]
				hook = func() { fn(id) }
				same(name, op.call(r, v))
				if hook != nil {
					t.Fatalf("%s: the turn of the route never ran, so the link did not end between the lookup and the spend", name)
				}
				// A refused request spends nothing: the row of a used-up link stays used up, and the download that a revoke deleted is gone.
				if name == "expired in flight" || (name == "revoked in flight" && op.table == "setup_share_tokens") {
					if n := r.uses(op, id); n != 0 {
						t.Errorf("%s: %d uses were spent by a refused request", name, n)
					}
				}
				step()
			}
		})
	}
}
