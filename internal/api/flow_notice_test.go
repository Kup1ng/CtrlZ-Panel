package api

import (
	"fmt"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/google/uuid"

	apidoc "github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/passkey/passkeytest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/caps"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// noticeItem and noticePage are the parts of Notification and NotificationPage the security notices add (spec 12.3).
type noticeItem struct {
	ID       string  `json:"id"`
	Kind     string  `json:"kind"`
	Security bool    `json:"security"`
	Markable bool    `json:"markable"`
	ReadAt   *string `json:"read_at"`
}

type noticePage struct {
	Items          []noticeItem `json:"items"`
	Next           string       `json:"next_cursor"`
	Unread         int          `json:"unread_count"`
	SecurityItems  []noticeItem `json:"security_items"`
	SecurityUnread int          `json:"security_unread_count"`
}

func (c *client) notices(query string) noticePage {
	c.f.t.Helper()
	var p noticePage
	c.get("/notifications"+query).want(200, "").json(&p)
	return p
}

// noticeID is the id of the newest notice of a kind in a tenant.
func (f *frig) noticeID(tenant uuid.UUID, kind string) string {
	f.t.Helper()
	var id string
	f.env.Scan(f.t, `SELECT id::text FROM ctrlz.notifications WHERE tenant_id = $1 AND kind = $2 ORDER BY created_at DESC, id DESC LIMIT 1`, []any{tenant, kind}, &id)
	return id
}

func (f *frig) unreadNotice(id string) bool {
	f.t.Helper()
	return f.count(`SELECT count(*) FROM ctrlz.notifications WHERE id = $1 AND read_at IS NULL`, id) == 1
}

// addKey registers a new virtual authenticator with a fresh reauth, the way an owner adds a passkey.
func (c *client) addKey(pw string) *resp {
	c.f.t.Helper()
	c.f.ck.add(time.Minute) // the ceremony has its own rate class: a minute on, the bucket is full again
	c.reauthPassword(pw).want(204, "")
	return c.addPasskey(passkeytest.New(pkOrigin, pkRP)).want(201, "")
}

// TestASessionThatExistedCannotMarkASecurityNoticeRead is question 19 (spec 12.3, tenant-r19-3). A thief who holds a
// session and the password adds a passkey and then marks the notice read from the same session, which hid the one sign
// the owner would see. The session that caused the notice, after its rotation and after a refresh, cannot mark it: 409,
// and the notice stays unread. A session made after it can. An ordinary notice is marked from any session, and another
// tenant's notice is not found.
func TestASessionThatExistedCannotMarkASecurityNoticeRead(t *testing.T) {
	f := newFrig(t, frigOpts{passkey: true})
	A, B := f.env.A, f.env.B

	old := f.client()
	old.mustLogin(A.Phone, pwA)
	bOwner := f.client()
	bOwner.mustLogin(B.Phone, pwB)

	old.addKey(pwA)
	n1 := f.noticeID(A.Tenant, "passkey_added")

	t.Run("the session that caused the notice", func(t *testing.T) {
		old.post("/notifications/"+n1+"/read", nil).want(409, "conflict")
		if !f.unreadNotice(n1) {
			t.Fatal("a refused mark changed the notice")
		}
		// The ordinary notice of the seed is marked from the same session.
		var welcome string
		for _, it := range old.notices("").Items {
			if it.Kind == "welcome" {
				welcome = it.ID
			}
		}
		if welcome == "" {
			t.Fatal("the seeded welcome notice is not in the list")
		}
		old.post("/notifications/"+welcome+"/read", nil).want(204, "")
	})

	t.Run("another tenant", func(t *testing.T) {
		// B's session asks for A's notice: it is not B's, whatever B's own sessions may do.
		bOwner.post("/notifications/"+n1+"/read", nil).want(404, "not_found")
		if !f.unreadNotice(n1) {
			t.Fatal("B marked A's notice")
		}
	})

	t.Run("a session made after the notice", func(t *testing.T) {
		newer := f.client()
		newer.mustLogin(A.Phone, pwA)
		if got := newer.notices("").SecurityItems; len(got) != 1 || got[0].ID != n1 || !got[0].Markable {
			t.Fatalf("the newer session sees %+v, want the notice, markable", got)
		}
		newer.post("/notifications/"+n1+"/read", nil).want(204, "")
		if f.unreadNotice(n1) {
			t.Fatal("the newer session's mark did not take")
		}
	})

	t.Run("after a refresh", func(t *testing.T) {
		c := f.client()
		c.loginPassword(A.Phone, pwA, true).want(200, "")
		c.addKey(pwA) // ends the other sessions; this one is rotated
		n2 := f.noticeID(A.Tenant, "passkey_added")
		if n2 == n1 {
			t.Fatal("the second passkey wrote no notice")
		}
		c.post("/notifications/"+n2+"/read", nil).want(409, "conflict")
		// The cookie of the session is gone with the browser: the refresh brings the same session back, and a
		// refresh keeps created_at, so it is still older than the notice.
		c.forget(session.CookieSession)
		c.post("/auth/refresh", nil).want(204, "")
		c.post("/notifications/"+n2+"/read", nil).want(409, "conflict")
		if !f.unreadNotice(n2) {
			t.Fatal("a refresh gave the session the right to mark the notice")
		}
	})
}

// TestSecurityNoticesAreShownApart is spec 12.3 and 14.2: the unread security notices are not in `items` or
// `unread_count`, they are in `security_items` with their own count, the same on every page, each with whether the
// asking session may mark it; a read one is history like any other and is in `items`. Tenant B sees none of A's.
func TestSecurityNoticesAreShownApart(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	a, b := f.client(), f.client()
	a.mustLogin(A.Phone, pwA)
	b.mustLogin(B.Phone, pwB)

	// n1 was made before the session, n2 after it (the database's clock on both sides).
	f.env.Exec(t, `INSERT INTO ctrlz.notifications (tenant_id, kind, severity, created_at) VALUES ($1, 'passkey_added', 'info', now() - interval '1 hour')`, A.Tenant)
	n1 := f.noticeID(A.Tenant, "passkey_added")
	f.env.Exec(t, `INSERT INTO ctrlz.notifications (tenant_id, kind, severity, created_at) VALUES ($1, 'recovery_codes_regenerated', 'info', now() + interval '1 hour')`, A.Tenant)
	n2 := f.noticeID(A.Tenant, "recovery_codes_regenerated")
	for i := 0; i < 2; i++ {
		f.env.Exec(t, `INSERT INTO ctrlz.notifications (tenant_id, kind, severity, created_at) VALUES ($1, 'ordinary', 'info', now() - interval '30 minutes')`, A.Tenant)
	}
	f.env.Exec(t, `INSERT INTO ctrlz.notifications (tenant_id, kind, severity, created_at) VALUES ($1, 'passkey_added', 'info', now() - interval '1 hour')`, B.Tenant)

	p1 := a.notices("?limit=1")
	if len(p1.Items) != 1 || p1.Next == "" || p1.Items[0].Security || !p1.Items[0].Markable {
		t.Fatalf("page 1 = %+v: want one ordinary notice and a next page", p1)
	}
	// The newest first: n2 is in the future of the session, n1 in its past.
	if len(p1.SecurityItems) != 2 || p1.SecurityItems[0].ID != n2 || p1.SecurityItems[1].ID != n1 ||
		p1.SecurityItems[0].Markable || !p1.SecurityItems[1].Markable || !p1.SecurityItems[0].Security || !p1.SecurityItems[1].Security {
		t.Fatalf("security items = %+v, want [%s not markable, %s markable]", p1.SecurityItems, n2, n1)
	}
	// The seed's welcome and the two ordinary ones: the security notices are in neither count.
	if p1.Unread != 3 || p1.SecurityUnread != 2 {
		t.Fatalf("unread %d and security unread %d, want 3 and 2", p1.Unread, p1.SecurityUnread)
	}
	p2 := a.notices("?limit=1&cursor=" + p1.Next)
	if len(p2.SecurityItems) != 2 || p2.SecurityItems[0].ID != n2 || p2.SecurityUnread != 2 || p2.Unread != 3 {
		t.Fatalf("page 2 = %+v: the security notices are the same on every page", p2)
	}
	for _, p := range []noticePage{p1, p2} {
		for _, it := range p.Items {
			if it.Security {
				t.Errorf("an unread security notice is in items: %+v", it)
			}
		}
	}

	// A read one moves to the history.
	a.post("/notifications/"+n1+"/read", nil).want(204, "")
	a.post("/notifications/"+n2+"/read", nil).want(409, "conflict")
	all := a.notices("?limit=100")
	if len(all.SecurityItems) != 1 || all.SecurityItems[0].ID != n2 || all.SecurityUnread != 1 || all.Unread != 3 {
		t.Fatalf("after the mark: %+v", all)
	}
	var seen bool
	for _, it := range all.Items {
		if it.ID == n1 {
			seen = it.Security && it.ReadAt != nil && it.Markable
		}
	}
	if !seen {
		t.Fatalf("the read security notice is not in items as a read, security notice: %+v", all.Items)
	}

	// A security notice that is already read is history: any session may mark it again and nothing changes, so the
	// flag says markable and the endpoint agrees (review dec-c-r1-1). n2 is in the future of this session, so the
	// session could not have marked it while it was unread.
	f.env.Exec(t, `UPDATE ctrlz.notifications SET read_at = now() WHERE id = $1`, n2)
	var again bool
	for _, it := range a.notices("?limit=100").Items {
		if it.ID == n2 {
			again = it.Security && it.ReadAt != nil && it.Markable
		}
	}
	if !again {
		t.Fatal("a read security notice of the future of the session is not listed as markable")
	}
	a.post("/notifications/"+n2+"/read", nil).want(204, "")

	// Tenant B sees its own notice and none of A's.
	pb := b.notices("")
	if len(pb.SecurityItems) != 1 || pb.SecurityUnread != 1 {
		t.Fatalf("B's security items = %+v", pb)
	}
	for _, it := range pb.SecurityItems {
		if it.ID == n1 || it.ID == n2 {
			t.Fatal("B sees A's security notice")
		}
	}
}

// outboxNotices reads the rows of kind notice as the superuser: the template, the locale, the phone, and that no value
// and no gateway were stored.
func (f *frig) outboxNotices(phone string) (n int) {
	f.t.Helper()
	return f.count(`SELECT count(*) FROM ctrlz.sms_outbox WHERE kind = 'notice' AND phone_e164 = $1 AND params_ct IS NULL AND gateway_id IS NULL`, phone)
}

// TestASecurityNoticeQueuesOneSMSToTheAccountPhone is spec 12.3. Each security notice queues one outbox row of kind
// notice to the verified phone of the user who made the change, with the template of its kind and the user's locale,
// no value and the id of the notice, so one notice is one message. A phone that was never verified gets none, a
// refused change queues none, and past caps.MaxNoticeSMS in a day the notice is written and nothing is sent. The
// tenants count on their own.
func TestASecurityNoticeQueuesOneSMSToTheAccountPhone(t *testing.T) {
	f := newFrig(t, frigOpts{passkey: true})
	A, B := f.env.A, f.env.B
	f.env.Exec(t, `DELETE FROM ctrlz.sms_outbox`) // the seed's test row
	f.env.Exec(t, `UPDATE ctrlz.users SET phone_verified_at = now() WHERE id = $1`, A.User)
	f.env.Exec(t, `UPDATE ctrlz.users SET locale = 'en' WHERE id = $1`, B.User) // B's phone is not verified yet

	a, b := f.client(), f.client()
	a.mustLogin(A.Phone, pwA)
	b.mustLogin(B.Phone, pwB)

	// An unverified phone is not told.
	b.addKey(pwB)
	if n := f.count(`SELECT count(*) FROM ctrlz.sms_outbox`); n != 0 {
		t.Fatalf("a phone that was never verified got %d messages", n)
	}
	if f.count(`SELECT count(*) FROM ctrlz.notifications WHERE tenant_id = $1 AND kind = 'passkey_added'`, B.Tenant) != 1 {
		t.Fatal("the notice is not written when the SMS is not queued")
	}

	// The first change of A: one message, as described.
	key := passkeytest.New(pkOrigin, pkRP)
	a.reauthPassword(pwA).want(204, "")
	a.addPasskey(key).want(201, "")
	n1 := f.noticeID(A.Tenant, "passkey_added")
	var id, tmpl, locale, phone, kind string
	f.env.Scan(t, `SELECT id::text, template_key, locale, phone_e164, kind FROM ctrlz.sms_outbox`, nil, &id, &tmpl, &locale, &phone, &kind)
	if id != n1 || tmpl != "notice_passkey" || locale != "fa" || phone != A.Phone || kind != "notice" {
		t.Fatalf("outbox row %s %s %s %s %s, want the notice %s as notice_passkey in fa to %s", id, kind, tmpl, locale, phone, n1, A.Phone)
	}
	if f.outboxNotices(A.Phone) != 1 {
		t.Fatal("the row holds a value or a gateway")
	}

	// A refused change (the same authenticator again) writes no notice and queues nothing.
	a.reauthPassword(pwA).want(204, "")
	a.addPasskey(key).want(401, "passkey_invalid")
	if n := f.count(`SELECT count(*) FROM ctrlz.sms_outbox`); n != 1 {
		t.Fatalf("a refused change left %d messages, want 1", n)
	}
	// The same notice asked twice queues once: the row has the notice's id.
	err := f.st.WithTenant(f.env.Ctx, A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		u, err := uuid.Parse(n1)
		if err != nil {
			return err
		}
		again, err := tx.SecurityNoticeSMS(A.User, u, caps.MaxNoticeSMS)
		if again {
			t.Error("the same notice queued a second message")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	// B's notice is not A's to ask for, and A's user is not B's.
	err = f.st.WithTenant(f.env.Ctx, B.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		u, err := uuid.Parse(n1)
		if err != nil {
			return err
		}
		queued, err := tx.SecurityNoticeSMS(A.User, u, caps.MaxNoticeSMS)
		if queued {
			t.Error("tenant B queued a message for A's notice to A's phone")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM ctrlz.sms_outbox`); n != 1 {
		t.Fatalf("%d messages after the repeated and cross calls, want 1", n)
	}

	// The daily cap: three messages a day for the tenant, for each of the two kinds of change on its own.
	a.addKey(pwA)
	a.addKey(pwA)
	if n := f.outboxNotices(A.Phone); n != caps.MaxNoticeSMS {
		t.Fatalf("%d notice messages after %d changes, want %d", n, caps.MaxNoticeSMS, caps.MaxNoticeSMS)
	}
	a.addKey(pwA)
	if n := f.outboxNotices(A.Phone); n != caps.MaxNoticeSMS {
		t.Fatalf("%d notice messages after a fourth change in a day, want the cap %d", n, caps.MaxNoticeSMS)
	}
	if n := f.count(`SELECT count(*) FROM ctrlz.notifications WHERE tenant_id = $1 AND kind = 'passkey_added'`, A.Tenant); n != 4 {
		t.Fatalf("%d notices, want one for each of the four changes", n)
	}

	// The cap is per kind (review dec-c-r1-6): A's passkey messages are spent, and the notices of replaced recovery
	// codes still have their own three. A holder of the session who spent one kind to silence the other would find
	// the other still sent. The change is made as the route makes it (notice, audit row, then the SMS) because the
	// route needs an authenticator app of its own; the routes' own SMS is checked in the TOTP flow test.
	regenerate := func() (queued bool) {
		err := f.st.WithTenant(f.env.Ctx, A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			if _, ok, err := tx.UserLock(A.User); err != nil || !ok {
				return fmt.Errorf("user lock: %v %v", ok, err)
			}
			notice, err := tx.SecurityNoticeAdd("recovery_codes_regenerated")
			if err != nil {
				return err
			}
			if _, err := tx.DB().Exec(tx.Context(), `INSERT INTO ctrlz.tenant_audit_log (tenant_id, user_id, action) VALUES ($1, $2, 'recovery.regenerate')`, tx.TenantID(), A.User); err != nil {
				return err
			}
			queued, err = tx.SecurityNoticeSMS(A.User, notice, caps.MaxNoticeSMS)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return queued
	}
	for i := 1; i <= caps.MaxNoticeSMS; i++ {
		if !regenerate() {
			t.Fatalf("recovery notice %d of the day was not sent after the passkey messages were spent", i)
		}
	}
	if regenerate() {
		t.Fatal("a fourth recovery notice in a day was sent")
	}
	if n := f.count(`SELECT count(*) FROM ctrlz.sms_outbox WHERE phone_e164 = $1 AND template_key = 'notice_recovery'`, A.Phone); n != caps.MaxNoticeSMS {
		t.Fatalf("%d recovery messages, want %d", n, caps.MaxNoticeSMS)
	}
	if n := f.count(`SELECT count(*) FROM ctrlz.sms_outbox WHERE phone_e164 = $1 AND template_key = 'notice_passkey'`, A.Phone); n != caps.MaxNoticeSMS {
		t.Fatalf("%d passkey messages after the recovery ones, want %d", n, caps.MaxNoticeSMS)
	}

	// Tenant B counts on its own: verified now, its first message goes out in English, though A has spent its day.
	f.env.Exec(t, `UPDATE ctrlz.users SET phone_verified_at = now() WHERE id = $1`, B.User)
	b.addKey(pwB)
	var bTmpl, bLocale string
	f.env.Scan(t, `SELECT template_key, locale FROM ctrlz.sms_outbox WHERE phone_e164 = $1`, []any{B.Phone}, &bTmpl, &bLocale)
	if bTmpl != "notice_passkey" || bLocale != "en" || f.outboxNotices(B.Phone) != 1 {
		t.Fatalf("B's row: %s %s, want notice_passkey in en, once", bTmpl, bLocale)
	}
}

// TestASecurityNoticeWithNoGatewayQueuesNothing is the no-gateway rule of spec 12.3: with no routed gateway the
// change goes through and the notice in the panel stands, and nothing waits in the outbox for a gateway that is not
// there.
func TestASecurityNoticeWithNoGatewayQueuesNothing(t *testing.T) {
	f := newFrig(t, frigOpts{passkey: true})
	A := f.env.A
	f.env.ResetSMS(t) // no gateway: sms_available is false from the first read of the configuration
	f.env.Exec(t, `UPDATE ctrlz.users SET phone_verified_at = now() WHERE id = $1`, A.User)
	a := f.client()
	a.mustLogin(A.Phone, pwA)
	a.addKey(pwA)
	if n := f.count(`SELECT count(*) FROM ctrlz.sms_outbox`); n != 0 {
		t.Fatalf("%d messages queued with no gateway", n)
	}
	n1 := f.noticeID(A.Tenant, "passkey_added")
	if got := a.notices("").SecurityItems; len(got) != 1 || got[0].ID != n1 {
		t.Fatalf("the notice does not stand in the panel: %+v", got)
	}
}

// TestTheSecurityNoticesShownApartAreBoundedAndNoneIsLeftOutOfEveryResponse is review dec-c-r1-2 and dec-c-r1-7. The
// unread security notices shown apart are the newest SecurityNoticeListLimit, and that number is the document's own
// maxItems. A thief can make that many in minutes (a regeneration is ten a minute and the reauth window keeps going),
// so a notice older than the newest fifty must not fall out of every response: it stays in the list, where paging
// reaches it, and in its count, marked as a security notice that this session may mark. Tenant B is untouched.
func TestTheSecurityNoticesShownApartAreBoundedAndNoneIsLeftOutOfEveryResponse(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	doc, err := openapi3.NewLoader().LoadFromData(apidoc.Tenant())
	if err != nil {
		t.Fatal(err)
	}
	if got := doc.Components.Schemas["NotificationPage"].Value.Properties["security_items"].Value.MaxItems; got == nil || *got != uint64(store.SecurityNoticeListLimit) {
		t.Fatalf("the document bounds NotificationPage.security_items at %v and the store at %d: they are one number", got, store.SecurityNoticeListLimit)
	}
	a, b := f.client(), f.client()
	a.mustLogin(A.Phone, pwA)
	b.mustLogin(B.Phone, pwB)

	// The passkey notice is the oldest; 51 notices of regenerated codes come after it, each a minute apart, all
	// before the session of `a` (the database's clock on both sides), so the session may mark every one.
	f.env.Exec(t, `INSERT INTO ctrlz.notifications (tenant_id, kind, severity, created_at) VALUES ($1, 'passkey_added', 'info', now() - interval '2 days')`, A.Tenant)
	oldest := f.noticeID(A.Tenant, "passkey_added")
	f.env.Exec(t, `INSERT INTO ctrlz.notifications (tenant_id, kind, severity, created_at)
		SELECT $1, 'recovery_codes_regenerated', 'info', now() - interval '1 day' + make_interval(mins => g) FROM generate_series(1, $2) g`,
		A.Tenant, store.SecurityNoticeListLimit+1)
	f.env.Exec(t, `INSERT INTO ctrlz.notifications (tenant_id, kind, severity, created_at) VALUES ($1, 'passkey_added', 'info', now() - interval '1 hour')`, B.Tenant)

	total := store.SecurityNoticeListLimit + 2
	p1 := a.notices("?limit=2")
	if len(p1.SecurityItems) != store.SecurityNoticeListLimit {
		t.Fatalf("%d security items, want the bound %d", len(p1.SecurityItems), store.SecurityNoticeListLimit)
	}
	if p1.SecurityUnread != total {
		t.Fatalf("security unread %d, want every one of the %d", p1.SecurityUnread, total)
	}
	for i, it := range p1.SecurityItems {
		if it.ID == oldest {
			t.Fatal("the oldest notice is among the newest fifty")
		}
		if !it.Security || !it.Markable {
			t.Fatalf("security item %d = %+v", i, it)
		}
	}
	// Walk every page of the list: the oldest passkey notice and the one regeneration past the fifty are in it, as
	// unread security notices that the session may mark, and the badge counts them (the welcome notice and the two).
	seen := map[string]noticeItem{}
	cursor := ""
	for pages := 0; ; pages++ {
		if pages > 10 {
			t.Fatal("the list does not end")
		}
		q := "?limit=2"
		if cursor != "" {
			q += "&cursor=" + cursor
		}
		p := a.notices(q)
		if p.Unread != 3 {
			t.Fatalf("unread %d, want the welcome notice and the 2 left out of security_items", p.Unread)
		}
		for _, it := range p.Items {
			seen[it.ID] = it
		}
		if p.Next == "" {
			break
		}
		cursor = p.Next
	}
	it, ok := seen[oldest]
	if !ok || !it.Security || !it.Markable || it.ReadAt != nil {
		t.Fatalf("the oldest passkey notice reaches no page, or reaches it wrong: %+v (found %v)", it, ok)
	}
	var left int
	for _, it := range seen {
		if it.Security {
			left++
		}
	}
	if left != 2 {
		t.Fatalf("%d security notices in the list past the fifty, want 2", left)
	}
	// It can be read from where it is listed, and then it is history.
	a.post("/notifications/"+oldest+"/read", nil).want(204, "")
	after := a.notices("")
	if after.SecurityUnread != total-1 || after.Unread != 2 {
		t.Fatalf("after the mark: security unread %d and unread %d, want %d and 2", after.SecurityUnread, after.Unread, total-1)
	}

	pb := b.notices("")
	if len(pb.SecurityItems) != 1 || pb.SecurityUnread != 1 || pb.Unread != 1 {
		t.Fatalf("B sees %+v, want its own one security notice and its welcome", pb)
	}
}
