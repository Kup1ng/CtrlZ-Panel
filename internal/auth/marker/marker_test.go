package marker_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/marker"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/credgen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
)

type rig struct {
	t    *testing.T
	ring *keyring.Ring
	now  time.Time
	svc  *marker.Service
}

func newRig(t *testing.T) *rig {
	t.Helper()
	ring, err := keyring.NewEphemeral(keyring.DomainAuthMAC, keyring.DomainAdminMAC)
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, ring: ring, now: time.Now()}
	r.svc = marker.New(ring, func() time.Time { return r.now })
	return r
}

func userStamp() credgen.Stamp {
	return credgen.Stamp{Tenant: uuid.New(), Subject: uuid.New(), Gen: 3}
}

// TestRoundTripAndAttributes: both kinds, one implementation, their own cookies.
func TestRoundTripAndAttributes(t *testing.T) {
	r := newRig(t)
	st := userStamp()
	adm := credgen.Stamp{Subject: uuid.New(), Gen: 5}
	for _, k := range []struct {
		name   string
		kind   marker.Kind
		stamp  credgen.Stamp
		cookie string
		maxAge time.Duration
	}{
		{"user", marker.User, st, session.CookieDevice, session.DeviceMaxAge},
		{"admin", marker.Admin, adm, session.CookieAdminDevice, session.AdminDeviceMaxAge},
	} {
		c, err := r.svc.Issue(k.kind, k.stamp)
		if err != nil {
			t.Fatal(err)
		}
		if c.Name != k.cookie || !c.Secure || !c.HttpOnly || c.Path != "/" || c.Domain != "" || c.MaxAge != int(k.maxAge.Seconds()) {
			t.Errorf("%s attributes: %+v", k.name, c)
		}
		if strings.Contains(c.Value, k.stamp.Subject.String()) || strings.Contains(c.Value, "=") {
			t.Errorf("%s: the value leaks the subject or is padded: %q", k.name, c.Value)
		}
		m := r.svc.Open(k.kind, c.Value)
		if m.Zero() || !m.Holds(k.stamp) {
			t.Fatalf("%s: round trip: %+v", k.name, m)
		}
		// Anything but the very stamp it was issued under does not hold: another
		// generation, another subject, another tenant, nothing.
		for name, other := range map[string]credgen.Stamp{
			"generation": {Tenant: k.stamp.Tenant, Subject: k.stamp.Subject, Gen: k.stamp.Gen + 1},
			"subject":    {Tenant: k.stamp.Tenant, Subject: uuid.New(), Gen: k.stamp.Gen},
			"tenant":     {Tenant: uuid.New(), Subject: k.stamp.Subject, Gen: k.stamp.Gen},
			"zero":       {},
		} {
			if m.Holds(other) {
				t.Errorf("%s: a marker holds for another %s", k.name, name)
			}
		}
	}
}

// TestKindsAreSeparate: a user marker is not an admin marker, though one service
// opens both.
func TestKindsAreSeparate(t *testing.T) {
	r := newRig(t)
	st := userStamp()
	u, _ := r.svc.Issue(marker.User, st)
	a, _ := r.svc.Issue(marker.Admin, st)
	if !r.svc.Open(marker.Admin, u.Value).Zero() || !r.svc.Open(marker.User, a.Value).Zero() {
		t.Error("a marker of one kind opened as the other")
	}
}

// TestMarkerIDIsPerMarker: the id a bucket is keyed on is random per marker and never
// the subject, so two markers of one account are two buckets (tenant-r4-5).
func TestMarkerIDIsPerMarker(t *testing.T) {
	r := newRig(t)
	st := userStamp()
	c1, _ := r.svc.Issue(marker.User, st)
	c2, _ := r.svc.Issue(marker.User, st)
	d1, d2 := r.svc.Open(marker.User, c1.Value), r.svc.Open(marker.User, c2.Value)
	if d1.ID == "" || d1.ID == d2.ID || strings.Contains(d1.ID, st.Subject.String()) {
		t.Errorf("marker ids %q and %q", d1.ID, d2.ID)
	}
}

func TestRefusals(t *testing.T) {
	r := newRig(t)
	st := userStamp()
	c, err := r.svc.Issue(marker.User, st)
	if err != nil {
		t.Fatal(err)
	}
	flipped := []byte(c.Value)
	flipped[20] ^= 1
	for _, v := range []string{"", "x", c.Value[:len(c.Value)-3], c.Value + "AA", strings.ToUpper(c.Value), "!!!" + c.Value, strings.Repeat("A", 600), string(flipped)} {
		if got := r.svc.Open(marker.User, v); !got.Zero() {
			t.Errorf("%q accepted", v)
		}
	}
	// Another installation's key.
	other := newRig(t)
	oc, _ := other.svc.Issue(marker.User, st)
	if !r.svc.Open(marker.User, oc.Value).Zero() {
		t.Error("a marker of another key was accepted")
	}
	// A seal under the right key and domain but without the marker's label and context.
	ct, _ := r.ring.Seal(keyring.DomainAuthMAC, keyring.RowContext([]uuid.UUID{st.Subject}, "ctrlz-device-v3"), []byte(`{"t":"`+st.Tenant.String()+`","u":"`+st.Subject.String()+`","m":"x","g":1,"i":1}`))
	if !r.svc.Open(marker.User, string(ct)).Zero() {
		t.Error("an unlabelled seal was accepted")
	}
	// A zero stamp makes no marker.
	if _, err := r.svc.Issue(marker.User, credgen.Stamp{}); err == nil {
		t.Error("a marker was made for no one")
	}
}

// TestLife: good for its cookie's life and not a day longer; a date in the future is
// refused.
func TestLife(t *testing.T) {
	r := newRig(t)
	st := userStamp()
	c, _ := r.svc.Issue(marker.User, st)
	a, _ := r.svc.Issue(marker.Admin, credgen.Stamp{Subject: uuid.New(), Gen: 1})
	r.now = r.now.Add(session.AdminDeviceMaxAge - 24*time.Hour)
	if r.svc.Open(marker.User, c.Value).Zero() || r.svc.Open(marker.Admin, a.Value).Zero() {
		t.Error("refused within its life")
	}
	r.now = r.now.Add(2 * 24 * time.Hour)
	if !r.svc.Open(marker.Admin, a.Value).Zero() {
		t.Error("an admin marker outlived its 90 days")
	}
	if r.svc.Open(marker.User, c.Value).Zero() {
		t.Error("a user marker did not last past 90 days")
	}
	r.now = r.now.Add(session.DeviceMaxAge)
	if !r.svc.Open(marker.User, c.Value).Zero() {
		t.Error("accepted after its year")
	}
	r.now = time.Now().Add(-time.Hour)
	if !r.svc.Open(marker.User, c.Value).Zero() {
		t.Error("accepted a marker dated in the future")
	}
}

// TestRequestProofIsTheMarkerIDOfTheRightCookie: the pipeline's proof hook gives the
// marker's own id for a cookie whose seal checks, and nothing for an absent, forged or
// other-kind cookie, so it can only ever move a request to that browser's own bucket.
func TestRequestProofIsTheMarkerIDOfTheRightCookie(t *testing.T) {
	r := newRig(t)
	st := userStamp()
	c, err := r.svc.Issue(marker.User, st)
	if err != nil {
		t.Fatal(err)
	}
	req := func(cookies ...*http.Cookie) *http.Request {
		q := httptest.NewRequest(http.MethodPost, "/", nil)
		for _, ck := range cookies {
			q.AddCookie(ck)
		}
		return q
	}
	user, admin := r.svc.RequestProof(marker.User), r.svc.RequestProof(marker.Admin)
	id, subject, ok := user(req(c))
	if !ok || id != r.svc.Open(marker.User, c.Value).ID || id == "" {
		t.Fatalf("a valid marker: %q %v", id, ok)
	}
	// The account the seal names comes with it, so the proof-network bucket can be keyed on it
	// (primitives-r6-5).
	if subject != st.Subject.String() {
		t.Errorf("the proof names account %q, want %q", subject, st.Subject)
	}
	if _, _, ok := user(req()); ok {
		t.Error("no cookie is a proof")
	}
	// The last two characters are replaced by two others, never by what they already are: a cookie that happens to end
	// in "AA" (one in 4096) was "damaged" into itself and passed, a flake of this test and not of the marker.
	damage := "AA"
	if strings.HasSuffix(c.Value, damage) {
		damage = "BB"
	}
	if _, _, ok := user(req(&http.Cookie{Name: c.Name, Value: c.Value[:len(c.Value)-2] + damage})); ok {
		t.Error("a damaged marker is a proof")
	}
	if _, _, ok := admin(req(c)); ok {
		t.Error("a tenant marker is an admin proof")
	}
}

// TestMarkerHasOneSpelling: a device marker is a cookie the throttle keys on (its id), so a
// lenient base64 decode, which maps the spare bits of the last character to the same bytes,
// would give one marker several spellings. Every other last character is refused.
func TestMarkerHasOneSpelling(t *testing.T) {
	r := newRig(t)
	c, err := r.svc.Issue(marker.User, userStamp())
	if err != nil {
		t.Fatal(err)
	}
	if r.svc.Open(marker.User, c.Value).Zero() {
		t.Fatal("the marker just issued is refused")
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for _, ch := range alphabet {
		if byte(ch) == c.Value[len(c.Value)-1] {
			continue
		}
		if !r.svc.Open(marker.User, c.Value[:len(c.Value)-1]+string(ch)).Zero() {
			t.Fatalf("last character %q was accepted: a marker has more than one spelling", ch)
		}
	}
}

// TestAMarkerSealedForOneSubjectDoesNotOpenUnderAnother is primitives-r18-4 (D64 marker-seal-context). The
// seal of a marker is bound to the subject it speaks for: the cookie is the subject id followed by the
// sealed payload, and the context of the seal is that id and the kind's version tag. A marker made for
// account A, presented with account B's id in front of it, is refused by the seal itself, and so is the
// same marker with its own id when it is moved to the other kind. The golden bytes of the context are in
// internal/keyring TestContextEncodingIsFrozen.
func TestAMarkerSealedForOneSubjectDoesNotOpenUnderAnother(t *testing.T) {
	r := newRig(t)
	a, b := userStamp(), userStamp()
	ca, err := r.svc.Issue(marker.User, a)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := r.svc.Issue(marker.User, b)
	if err != nil {
		t.Fatal(err)
	}
	if r.svc.Open(marker.User, ca.Value).Zero() || r.svc.Open(marker.User, cb.Value).Zero() {
		t.Fatal("own markers do not open")
	}
	rawA, err := base64.RawURLEncoding.DecodeString(ca.Value)
	if err != nil {
		t.Fatal(err)
	}
	rawB, err := base64.RawURLEncoding.DecodeString(cb.Value)
	if err != nil {
		t.Fatal(err)
	}
	// A's sealed payload behind B's id, and B's behind A's: the id in front is the context, and it is not the one sealed under.
	swapped := append(append([]byte(nil), rawB[:16]...), rawA[16:]...)
	if !r.svc.Open(marker.User, base64.RawURLEncoding.EncodeToString(swapped)).Zero() {
		t.Error("a marker sealed for A opened under B's id")
	}
	if got := rawA[:16]; string(got) != string(a.Subject[:]) {
		t.Errorf("the cookie does not start with the subject id")
	}
	// The same subject on the other kind: another key and another tag.
	adm := credgen.Stamp{Subject: a.Subject, Gen: 1}
	cadm, err := r.svc.Issue(marker.Admin, adm)
	if err != nil {
		t.Fatal(err)
	}
	if !r.svc.Open(marker.User, cadm.Value).Zero() {
		t.Error("an admin marker opened as a user's")
	}
	// A cookie with no sealed part behind the id, or with the id cut, is not a marker.
	for _, v := range []string{base64.RawURLEncoding.EncodeToString(rawA[:16]), base64.RawURLEncoding.EncodeToString(rawA[:10])} {
		if !r.svc.Open(marker.User, v).Zero() {
			t.Errorf("%d bytes opened", len(v))
		}
	}
}
