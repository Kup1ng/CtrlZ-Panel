package hubctl

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/certcheck"
	"github.com/Kup1ng/CtrlZ-Panel/internal/intakeseal"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// WildcardRows is what the hub is asked for the uploaded wildcard certificates: the control pool's store.
type WildcardRows interface {
	HubWildcardRows(ctx context.Context) ([]store.HubWildcardRow, error)
}

// wildcardTTL is how long the choice for a zone is kept. Every node asks about every zone each ConfigEvery, so without it
// each pass of each stream would read the table and verify the chains again. A retired or new upload reaches the nodes at
// most this much later, which the stream's own 5 s rhythm already allows.
const wildcardTTL = 5 * time.Second

// UploadedWildcards is the hub's Wildcards (4.3): of the active uploaded `wildcard` rows it takes the one certcheck.Choose
// picks for a zone, opens its key from the intake seal with the hub's own intake key, checks the key belongs to the leaf, and
// hands both to the bundle builder, which seals the key again for the one node and drops it. The admin never holds the
// private half of the intake key (N8), so this is the only place an uploaded wildcard key is ever readable.
//
// A row that does not open, or whose key is not the leaf's, is an error and not a reason to serve another certificate in
// silence: the stream does not send a bundle for that zone while it lasts, and the node keeps the one it has. The error is
// that zone's alone (Certs.For skips the zone and still builds the others), and it raises one critical alert that names the
// certificate, so an operator who rotated the intake key hears of it before the private-CA leaves of other zones run out.
type UploadedWildcards struct {
	rows   WildcardRows
	key    []byte
	now    func() time.Time
	roots  *x509.CertPool
	alerts Alerter

	mu      sync.Mutex
	memo    map[string]chosen
	alerted map[uuid.UUID]bool // certificates an unusable-wildcard alert stands for, cleared when the row works again
}

// Alerter raises an alert on the telemetry pool (the method hubtrust.Alerter has, so the same value serves).
type Alerter interface {
	HubAlert(ctx context.Context, severity string, kind store.HubAlertKind, params map[string]string) error
}

// WithAlerts sets where the unusable-wildcard alert goes. Without it the error alone is returned.
func (u *UploadedWildcards) WithAlerts(a Alerter) *UploadedWildcards {
	u.alerts = a
	return u
}

// chosen is what Choose said for one zone at one time. The key stays sealed in it.
type chosen struct {
	at       time.Time
	found    bool
	id       uuid.UUID
	chain    []byte
	sealed   []byte
	notAfter time.Time
}

// NewUploadedWildcards builds it. keyPEM is the hub's wildcard_intake_key (PKCS #8 PEM, X25519); it is kept for the life of
// the process, like the hub's other keys.
func NewUploadedWildcards(rows WildcardRows, keyPEM []byte, now func() time.Time) *UploadedWildcards {
	return &UploadedWildcards{rows: rows, key: keyPEM, now: now, roots: certcheck.EmbeddedRoots(), memo: make(map[string]chosen), alerted: make(map[uuid.UUID]bool)}
}

// WithRoots replaces the public roots a chain must verify to. Only tests set it, with a root of their own.
func (u *UploadedWildcards) WithRoots(p *x509.CertPool) *UploadedWildcards {
	u.roots = p
	return u
}

// Covering implements Wildcards.
func (u *UploadedWildcards) Covering(ctx context.Context, zone string) (chainPEM, keyDER []byte, notAfter time.Time, found bool, err error) {
	now := u.now()
	c, err := u.choice(ctx, zone, now)
	if err != nil || !c.found {
		return nil, nil, time.Time{}, false, err
	}
	keyPEM, err := intakeseal.Open(u.key, intakeseal.Wildcard, c.sealed)
	if err != nil {
		return nil, nil, time.Time{}, false, u.unusable(ctx, c.id, zone, "key_does_not_open",
			fmt.Errorf("the key of uploaded certificate %s does not open with the wildcard intake key", c.id))
	}
	pub, pkcs8PEM, err := certcheck.ParseKey(keyPEM)
	clear(keyPEM)
	if err != nil {
		return nil, nil, time.Time{}, false, u.unusable(ctx, c.id, zone, "key_not_a_private_key",
			fmt.Errorf("the key of uploaded certificate %s is not a private key", c.id))
	}
	defer clear(pkcs8PEM)
	// The key is held against the leaf at the time of use too, as domain-apply does, so a row whose sealed key was swapped
	// in the database is never sent to a node as that certificate's key.
	scope := certcheck.Scope{Zones: []string{zone}}
	if _, err := certcheck.Check(c.chain, certcheck.Wildcard, scope, now, certcheck.Options{Roots: u.roots, KeyPublic: pub}); err != nil {
		// The choice may be up to wildcardTTL old, and the chain may have ended inside that time. That is not a key mismatch
		// and must not raise the tampering alert: the zone goes back to the private CA, as Choose does for an ended chain, and
		// the memo is dropped so the next call chooses again. Only a chain that still verifies with a key that is not its own
		// is the mismatch.
		if _, cerr := certcheck.Check(c.chain, certcheck.Wildcard, scope, now, certcheck.Options{Roots: u.roots}); cerr != nil {
			u.mu.Lock()
			delete(u.memo, zone)
			delete(u.alerted, c.id)
			u.mu.Unlock()
			return nil, nil, time.Time{}, false, nil
		}
		return nil, nil, time.Time{}, false, u.unusable(ctx, c.id, zone, "key_not_the_leafs",
			fmt.Errorf("the key of uploaded certificate %s does not belong to it", c.id))
	}
	b, _ := pem.Decode(pkcs8PEM)
	if b == nil {
		return nil, nil, time.Time{}, false, errors.New("hubctl: the uploaded key cannot be encoded")
	}
	u.mu.Lock()
	delete(u.alerted, c.id)
	u.mu.Unlock()
	return c.chain, b.Bytes, c.notAfter, true, nil
}

// unusable raises the one critical alert for a chosen row that cannot be served and returns err. The mark is set before the
// insert, so two nodes' passes at once raise it once, and taken back when the insert fails, so the next pass tries again.
// The params name the certificate, the zone and the reason, never the key.
func (u *UploadedWildcards) unusable(ctx context.Context, id uuid.UUID, zone, reason string, err error) error {
	if u.alerts == nil {
		return err
	}
	u.mu.Lock()
	first := !u.alerted[id]
	u.alerted[id] = true
	u.mu.Unlock()
	if first {
		if aerr := u.alerts.HubAlert(ctx, "critical", store.HubAlertWildcardUnusable,
			map[string]string{"certificate_id": id.String(), "zone": zone, "reason": reason}); aerr != nil {
			u.mu.Lock()
			delete(u.alerted, id)
			u.mu.Unlock()
		}
	}
	return err
}

// choice reads the rows and chooses, or returns the choice of the last few seconds. The lock is never held across the read.
func (u *UploadedWildcards) choice(ctx context.Context, zone string, now time.Time) (chosen, error) {
	u.mu.Lock()
	m, ok := u.memo[zone]
	u.mu.Unlock()
	if ok && now.Sub(m.at) >= 0 && now.Sub(m.at) < wildcardTTL {
		return m, nil
	}
	rows, err := u.rows.HubWildcardRows(ctx)
	if err != nil {
		return chosen{}, fmt.Errorf("uploaded wildcards: %w", err)
	}
	in := make([]certcheck.Row, len(rows))
	sealed := make(map[uuid.UUID][]byte, len(rows))
	for i, r := range rows {
		in[i] = certcheck.Row{ID: r.ID, State: "active", ChainPEM: r.ChainPEM}
		sealed[r.ID] = r.SealedKey
	}
	m = chosen{at: now}
	if row, res, ok := certcheck.Choose(in, certcheck.Wildcard, certcheck.Scope{Zones: []string{zone}}, now, certcheck.Options{Roots: u.roots}); ok {
		m.found, m.id, m.chain, m.sealed, m.notAfter = true, row.ID, []byte(res.ChainPEM), sealed[row.ID], res.NotAfter
	}
	u.mu.Lock()
	u.memo[zone] = m
	for z, o := range u.memo { // a zone that left the live set is forgotten with its sealed key
		if now.Sub(o.at) >= wildcardTTL {
			delete(u.memo, z)
		}
	}
	u.mu.Unlock()
	return m, nil
}
