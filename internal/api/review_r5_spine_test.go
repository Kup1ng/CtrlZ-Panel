package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/passkey/passkeytest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest/boundary"
)

// Tests of the P1 auth review, round 5, area "HTTP spine and tenant API".

// countingBody counts what a handler or middleware reads from it.
type countingBody struct {
	r *bytes.Reader
	n int
}

func (c *countingBody) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// TestSessionRouteWithoutACookieReadsNoBody is tenant-r5-2. A session route has no
// network bucket, so a request with no cookie that could be ours used to pay a body read of up
// to 64 KiB and a schema check before its 401, and was charged to nothing. The cookie is
// looked at first now: no cookie, a cookie with a wrong tag and a cookie past its expiry
// are 401 session_expired and the body is never touched; a cookie that checks reaches the
// schema (a 400 for a body that breaks it), so the check is still done for the session
// whose lookup is yet to come.
func TestSessionRouteWithoutACookieReadsNoBody(t *testing.T) {
	f := newFrig(t, frigOpts{passkey: true})
	big := bytes.Repeat([]byte("a"), 60<<10)
	send := func(ck *http.Cookie) (int, int) {
		cb := &countingBody{r: bytes.NewReader(big)}
		req := httptest.NewRequest("POST", "/api/v1/account/passkeys/finish", cb)
		req.Host = host
		req.Header.Set("X-Forwarded-For", f.freshIP())
		req.Header.Set("User-Agent", "r5-2")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Ctrlz-Ticket", "t")
		if ck != nil {
			req.AddCookie(ck)
		}
		w := httptest.NewRecorder()
		f.h.ServeHTTP(w, req)
		return w.Code, cb.n
	}
	good := boundary.TenantCookie(f.keys, f.ck.now().Add(time.Hour))
	wrongTag := &http.Cookie{Name: good.Name, Value: good.Value[:len(good.Value)-2] + "AA"}
	expired := boundary.TenantCookie(f.keys, f.ck.now().Add(-time.Hour))
	for name, ck := range map[string]*http.Cookie{"no cookie": nil, "wrong tag": wrongTag, "expired": expired} {
		if code, read := send(ck); code != 401 || read != 0 {
			t.Errorf("%s: status %d after reading %d bytes, want 401 and none", name, code, read)
		}
	}
	if code, read := send(good); code != 400 || read == 0 {
		t.Errorf("a cookie that checks: status %d after reading %d bytes, want the schema to refuse the body", code, read)
	}
}

// TestPhoneChangeEndsAPasskeyReauthWindow is tenant-r5-4. A phone change marks the passkeys for
// review and, by 7.7, only a proof that is not a passkey may clear the mark. The rotation of
// the change keeps the reauth window, so a window made by a passkey before the change used to
// carry on and clear the mark at once. The change now ends the window when it sets the mark.
func TestPhoneChangeEndsAPasskeyReauthWindow(t *testing.T) {
	f := newFrig(t, frigOpts{passkey: true})
	A := f.env.A
	const newPhone = "+989128880001"
	key := passkeytest.New(pkOrigin, pkRP)

	setup := f.client()
	setup.mustLogin(A.Phone, pwA)
	setup.reauthPassword(pwA).want(204, "")
	setup.addPasskey(key).want(201, "")

	c := f.client()
	c.mustLogin(A.Phone, pwA)
	c.reauthPasskey(key).want(204, "") // the window comes from a passkey
	b, oldCode, newCode := c.startChange(newPhone)
	c.post("/account/phone/change/"+b.RequestID+"/confirm", map[string]any{"old_code": oldCode, "new_code": newCode}).want(204, "")
	if f.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND passkey_review_at IS NOT NULL`, A.User) != 1 {
		t.Fatal("the phone change did not mark the passkeys for review")
	}
	c.post("/account/passkeys/review", nil).want(403, "reauth_required")
	// A proof that is not a passkey clears it, and the passkey is refused as one while the mark is set.
	c.reauthPassword(pwA).want(204, "")
	c.post("/account/passkeys/review", nil).want(204, "")
}
