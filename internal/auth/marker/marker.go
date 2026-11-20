// Package marker is the known-device marker of the tenant login (spec 5.5) and of the
// admin login (spec 10.2): one implementation of what used to be two (P1 auth review
// round 5, rule credential-generation).
//
// A marker is a cookie, set at a successful login, holding {tenant, subject, marker
// id, credential generation, issued at} sealed under the auth_mac or admin_mac key. It
// needs no table: only this installation can make one, and the stamp inside is
// compared with the account found, so a cookie issued to one account is worth nothing
// on another and a stranger who copies it gains nothing they did not already have.
//
// What it buys is narrow, and the same for both kinds: a request with a marker that
// still holds is not counted on the one budget a stranger can spend on the owner's
// behalf (the shared phone cap of the OTP request, the admin_login_user scope of the
// admin login). It never replaces a factor, and the hard caps and per-network caps
// still apply to it.
//
// A marker holds only while the account's credential generation is the one it was
// issued under (internal/credgen), so the browser an intruder used before the owner
// took the account back stops counting the moment a credential changes, by any route
// or none. The marker id is random per marker; anything a browser may spend on its own
// (the passkey begin bucket) is keyed on it, never on the account, so one browser can
// empty its own bucket and nobody else's.
//
// keyring.LabelDevice and keyring.LabelAdminDevice, and the cookie constructors of
// internal/auth/session, are named here and nowhere else (internal/lint).
package marker

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/credgen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
)

// Kind is the tenant marker or the admin marker. The two differ in the key they are
// sealed under, their cookie and their life, and in nothing else. A constant and a
// switch, not a table of values, because a package-level variable is mutable state.
type Kind int

const (
	// User is the marker of the tenant login (cookie __Host-ctrlz_device).
	User Kind = iota + 1
	// Admin is the marker of the admin login (cookie __Host-ctrlz_admin_device).
	Admin
)

// params is what a kind is sealed with.
type params struct {
	domain string
	label  string
	aad    []byte
	maxAge time.Duration
	cookie func(sealed string) *http.Cookie
}

func (k Kind) params() (params, bool) {
	switch k {
	case User:
		return params{keyring.DomainAuthMAC, keyring.LabelDevice, []byte("ctrlz-device-v3"), session.DeviceMaxAge, session.DeviceCookie}, true
	case Admin:
		return params{keyring.DomainAdminMAC, keyring.LabelAdminDevice, []byte("ctrlz-admin-device-v3"), session.AdminDeviceMaxAge, session.AdminDeviceCookie}, true
	}
	return params{}, false
}

// payload is what a marker seals. The subject and the generation are inside, where
// tampering is detected.
type payload struct {
	T uuid.UUID `json:"t"` // tenant, the nil uuid for an admin
	U uuid.UUID `json:"u"` // subject
	M string    `json:"m"` // random marker id
	G int64     `json:"g"` // credential generation
	I int64     `json:"i"` // issued at, unix seconds
}

// Service seals and opens markers.
type Service struct {
	ring *keyring.Ring
	now  func() time.Time
}

// New builds a Service over a key ring that holds the domain of the kinds it will be
// asked about. now may be nil.
func New(ring *keyring.Ring, now func() time.Time) *Service {
	if now == nil {
		now = appclock.Now
	}
	return &Service{ring: ring, now: now}
}

// Issue returns the Set-Cookie for a marker bound to a stamp: the subject and the
// credential generation read from the row in the transaction that opened the session,
// or that changed the credential. Set it after that transaction commits. A zero stamp
// makes no marker.
func (s *Service) Issue(k Kind, st credgen.Stamp) (*http.Cookie, error) {
	p, ok := k.params()
	if !ok || st.Zero() {
		return nil, credgen.ErrStale
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	plain, err := json.Marshal(payload{T: st.Tenant, U: st.Subject, M: hex.EncodeToString(id[:]), G: st.Gen, I: s.now().Unix()})
	if err != nil {
		return nil, err
	}
	ct, err := s.ring.SealLabeled(p.domain, p.label, p.aad, plain)
	if err != nil {
		return nil, err
	}
	return p.cookie(base64.RawURLEncoding.EncodeToString(ct)), nil
}

// Marker is a marker whose seal and age were checked. It still has to be matched with
// the account's current stamp (Holds) before it counts for anything that reads the
// account.
type Marker struct {
	// ID is random per marker. It is never the subject, so a bucket keyed on it
	// belongs to one browser.
	ID    string
	stamp credgen.Stamp
}

// Subject is the account the marker was sealed for, as text. It is the seal's own statement and
// needs no database; a bucket keyed on it belongs to one account (ratelimit.Subject.ProofSubject).
func (m Marker) Subject() string { return m.stamp.Subject.String() }

// Zero reports that there was no valid marker.
func (m Marker) Zero() bool { return m.stamp.Zero() }

// Holds reports whether the marker was issued for the subject of current, under the
// generation current has now.
func (m Marker) Holds(current credgen.Stamp) bool { return m.stamp.Holds(current) }

// Open checks the seal and the age of a marker value. There is no error: every failure
// (absent, damaged, forged, future-dated, too old, sealed for the other kind) is the
// zero Marker, and the request goes on as an unknown one. It needs no database, so a
// request with a forged marker costs a MAC check and nothing else.
func (s *Service) Open(k Kind, value string) Marker {
	kp, ok := k.params()
	if !ok {
		return Marker{}
	}
	if value == "" || len(value) > 512 {
		return Marker{}
	}
	ct, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil {
		return Marker{}
	}
	plain, err := s.ring.OpenLabeled(kp.domain, kp.label, kp.aad, ct)
	if err != nil {
		return Marker{}
	}
	defer plain.Wipe()
	var p payload
	if err := json.Unmarshal(plain.Reveal(), &p); err != nil || p.M == "" {
		return Marker{}
	}
	st := credgen.Stamp{Tenant: p.T, Subject: p.U, Gen: p.G}
	if st.Zero() {
		return Marker{}
	}
	issued, now := time.Unix(p.I, 0), s.now()
	// A marker dated in the future (beyond a little clock skew) or older than the
	// cookie's own lifetime is refused, so a leaked marker does not stay good for ever.
	if issued.After(now.Add(5*time.Minute)) || now.Sub(issued) > kp.maxAge {
		return Marker{}
	}
	return Marker{ID: p.M, stamp: st}
}

// RequestProof is the pipeline's proof hook for a kind (httpx.Pipeline.Proof): the id
// of the marker the request carries when its seal and age check, and false otherwise.
// It needs no database, so it can run before the rate class is charged, and it says
// nothing about the account: a class that takes it charges the marker's own bucket
// instead of the network, and the handler still matches the marker with the account
// before it lets the marker excuse anything that reads the account.
func (s *Service) RequestProof(k Kind) func(*http.Request) (id, subject string, ok bool) {
	name := session.CookieDevice
	if k == Admin {
		name = session.CookieAdminDevice
	}
	return func(r *http.Request) (string, string, bool) {
		c, err := r.Cookie(name)
		if err != nil {
			return "", "", false
		}
		m := s.Open(k, c.Value)
		if m.Zero() {
			return "", "", false
		}
		return m.ID, m.Subject(), true
	}
}
