// Package hubtrust keeps the hub's own certificates: its TLS leaf on the node port, the pin file the
// install command is made from, and the rows of the two private CAs (p4-nodes 3.3, 4.3).
//
// Why a package of its own. Each of these is a thing that must be right at start and must stay right
// without a person: the leaf is reissued over the same key so the SPKI nodes pin never changes, the
// zone CA is replaced only when its key, its zones or its age say so, and a replacement that changes what
// a user installed on a phone raises an alert and a notice instead of happening silently.
package hubtrust

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubpki"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// PlaceholderZone is the one live zone while domain_settings.dns_zone is NULL (4.3, RFC 6761).
const PlaceholderZone = "dns.ctrlz.invalid"

// PinFile is the file the hub writes on the hub_public volume (3.3).
const PinFile = "hub_tls.spki"

// ---------------------------------------------------------------------------------------------------
// The hub's TLS leaf.

// Leaf holds the hub's server certificate and reissues it over the same key.
type Leaf struct {
	ca  *hubpki.NodeCA
	key *ecdsa.PrivateKey
	dns []string
	ips []net.IP
	now func() time.Time

	mu   sync.RWMutex
	cert *tls.Certificate
	life leafLife
}

// leafLife is the validity of the leaf in force, apart from the struct that holds the lock (a mutex with
// a time.Time in one struct reads to the cache lint as a hand-written cache).
type leafLife struct{ nb, na time.Time }

// NewLeaf issues the first leaf: serverAuth only, SANs from the host list, one year, over the key
// that is pinned. A SAN change or a renewal keeps the key, so the pin never moves (3.3).
func NewLeaf(ca *hubpki.NodeCA, key *ecdsa.PrivateKey, hostList string, now func() time.Time) (*Leaf, error) {
	dns, ips, err := hubpki.Names(hostList)
	if err != nil {
		return nil, fmt.Errorf("hub host: %w", err)
	}
	l := &Leaf{ca: ca, key: key, dns: dns, ips: ips, now: now}
	if err := l.reissue(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Leaf) reissue() error {
	now := l.now()
	iss, err := l.ca.IssueServer(&l.key.PublicKey, "ctrlz-hub", l.dns, l.ips, hubpki.ServerLife, now)
	if err != nil {
		return err
	}
	cert := &tls.Certificate{Certificate: [][]byte{iss.DER}, PrivateKey: l.key}
	l.mu.Lock()
	l.cert, l.life = cert, leafLife{iss.NotBefore, iss.NotAfter}
	l.mu.Unlock()
	return nil
}

// Renew reissues the leaf when a third of its life is left, and says whether it did.
func (l *Leaf) Renew() (bool, error) {
	l.mu.RLock()
	left := l.life.na.Sub(l.now())
	life := l.life.na.Sub(l.life.nb)
	l.mu.RUnlock()
	if left > life/3 {
		return false, nil
	}
	return true, l.reissue()
}

// GetCertificate is tls.Config.GetCertificate.
func (l *Leaf) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.cert, nil
}

// Pin is the SHA-256 of the leaf key's SubjectPublicKeyInfo, which nodes and the install command pin.
func (l *Leaf) Pin() ([]byte, error) { return hubpki.SPKISHA256(&l.key.PublicKey) }

// WritePin writes the pin to dir/hub_tls.spki as standard base64 of the 32-byte hash, the form that
// follows `sha256//` in curl's --pinnedpubkey, on one line. It goes by a temporary file and a rename, so
// the admin never reads half of it.
func WritePin(dir string, pin []byte) error {
	if len(pin) != sha256.Size {
		return errors.New("hubtrust: a pin is 32 bytes")
	}
	tmp, err := os.CreateTemp(dir, ".spki-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.WriteString(base64.StdEncoding.EncodeToString(pin) + "\n")
	cerr := tmp.Close()
	if err := errors.Join(werr, cerr, os.Chmod(name, 0o644)); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, filepath.Join(dir, PinFile)); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------
// The rows of the two CAs.

// Rows is what the CA rows need of the database: the control pool.
type Rows interface {
	HubActiveCA(ctx context.Context, kind string) (store.HubCertRow, bool, error)
	HubReplaceCA(ctx context.Context, kind string, old uuid.UUID, chainPEM string, notBefore, notAfter time.Time, names []string, queueJob bool, reinstall string) error
	HubLiveZones(ctx context.Context) (store.HubZones, error)
}

// Alerter raises an alert (telemetry pool).
type Alerter interface {
	HubAlert(ctx context.Context, severity string, kind store.HubAlertKind, params map[string]string) error
}

func certPEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// LiveZones are the zones the hub serves at now (4.3): dns_zone, or the placeholder while none is set,
// and prev_dns_zone until transition_until.
func LiveZones(z store.HubZones, now time.Time) []string {
	zones := []string{PlaceholderZone}
	if z.DNSZone != "" {
		zones = []string{z.DNSZone}
	}
	if z.PrevDNSZone != "" && z.TransitionUntil.After(now) && z.PrevDNSZone != zones[0] {
		zones = append(zones, z.PrevDNSZone)
	}
	slices.Sort(zones)
	return zones
}

// CAs keeps the node CA row and the zone CA and its row.
type CAs struct {
	Node    *hubpki.NodeCA
	ZoneKey *ecdsa.PrivateKey
	Rows    Rows
	Alerts  Alerter
	Now     func() time.Time
	Log     *slog.Logger

	mu   sync.RWMutex
	zone *hubpki.ZoneCA

	// amu guards what the alert path remembers: alerts that could not be inserted and are tried again at
	// the next pass, and whether the invalid-zone alert of the current state was raised.
	amu          sync.Mutex
	pending      []pendingAlert
	invalidAlert bool
}

type pendingAlert struct {
	severity string
	kind     store.HubAlertKind
	params   map[string]string
}

// Zone is the zone CA in force, nil before the first Ensure.
func (c *CAs) Zone() *hubpki.ZoneCA {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.zone
}

// EnsureNodeRow stores the node CA's certificate as the active node_ca row when the stored one is not
// it (the first start, or a new CA after a compromise, which the runbook announces). The private key is
// never a row.
func (c *CAs) EnsureNodeRow(ctx context.Context) error {
	row, found, err := c.Rows.HubActiveCA(ctx, store.CertKindNodeCA)
	if err != nil {
		return fmt.Errorf("node CA row: %w", err)
	}
	want := certPEM(c.Node.CertDER())
	if found && row.ChainPEM == want {
		return nil
	}
	cert := c.Node.Cert()
	return c.Rows.HubReplaceCA(ctx, store.CertKindNodeCA, row.ID, want, cert.NotBefore, cert.NotAfter, nil, false, "")
}

// EnsureZone makes the zone CA row match the live zones and the key, at start and every minute (4.3). It
// reuses the active row while its public key is zone_ca_key's, its names are the live zones and more than
// a third of its life is left. Otherwise it issues a new certificate, retires the old row, raises an
// alert and queues the domain_change job whose notice carries the reinstall line: with the same key the
// subject is the same, with a new key it is new and the notice says to remove the old CA.
func (c *CAs) EnsureZone(ctx context.Context) error {
	c.flushAlerts(ctx)
	zs, err := c.Rows.HubLiveZones(ctx)
	if err != nil {
		return fmt.Errorf("zones: %w", err)
	}
	now := c.Now()
	zones := c.usable(ctx, LiveZones(zs, now))
	row, found, err := c.Rows.HubActiveCA(ctx, store.CertKindZoneCA)
	if err != nil {
		return fmt.Errorf("zone CA row: %w", err)
	}
	if found {
		if blk, _ := pem.Decode([]byte(row.ChainPEM)); blk != nil {
			if cur, err := hubpki.LoadZoneCA(c.ZoneKey, blk.Bytes); err == nil && cur.Reusable(c.ZoneKey, zones, now) {
				c.set(cur)
				return nil
			}
		}
	}
	z, err := hubpki.IssueZoneCA(c.ZoneKey, zones, now)
	if err != nil {
		return fmt.Errorf("zone CA: %w", err)
	}
	reinstall, queue := "same_key", found
	if found && !c.sameKey(row.ChainPEM) {
		reinstall = "new_key"
	}
	cert := z.Cert()
	if found {
		// The alert goes in before the row. It is on the telemetry pool, a different connection from the
		// row's transaction (5.7), so the two cannot be one commit; with the alert first, a crash or a
		// failed insert between the two never leaves a replaced CA that nobody was told about. The price
		// is a second alert when the row write then fails and the next pass tries again. Params are words:
		// the reinstall kind is a closed one.
		c.raise(ctx, "warning", store.HubAlertZoneCAReissued, map[string]string{"reinstall": reinstall})
	}
	if err := c.Rows.HubReplaceCA(ctx, store.CertKindZoneCA, row.ID, certPEM(z.CertDER()), cert.NotBefore, cert.NotAfter, zones, queue, reinstall); err != nil {
		return fmt.Errorf("zone CA row: %w", err)
	}
	c.set(z)
	return nil
}

// usable drops the live zones that fail the rule of domain_invalid. The database CHECK holds less than
// that rule, so a row can name a zone the hub must not sign; leaving that zone out keeps the CA of the
// others (and the whole node port) up instead of stopping the process, and one alert tells the admin.
// With none left the placeholder zone stands, as when no domain is set.
func (c *CAs) usable(ctx context.Context, zones []string) []string {
	out := zones[:0:0]
	for _, z := range zones {
		if hubpki.ValidZone(z) {
			out = append(out, z)
		}
	}
	if len(out) == len(zones) {
		c.amu.Lock()
		c.invalidAlert = false
		c.amu.Unlock()
		return zones
	}
	if len(out) == 0 {
		out = []string{PlaceholderZone}
	}
	c.amu.Lock()
	first := !c.invalidAlert
	c.invalidAlert = true
	c.amu.Unlock()
	if first {
		// The zone is not named: the row is what is wrong, and it may be hostile.
		if c.Log != nil {
			c.Log.Error("a live zone failed the zone rule and is left out of the zone CA")
		}
		c.raise(ctx, "warning", store.HubAlertZoneInvalid, map[string]string{"left_out": fmt.Sprint(len(zones) - len(out))})
	}
	return out
}

// raise inserts an alert and, if that fails, logs it and keeps it for the next pass.
func (c *CAs) raise(ctx context.Context, severity string, kind store.HubAlertKind, params map[string]string) {
	if c.Alerts == nil {
		return
	}
	if err := c.Alerts.HubAlert(ctx, severity, kind, params); err != nil {
		if c.Log != nil {
			c.Log.Error("an alert could not be inserted, it is tried again at the next pass", "kind", string(kind))
		}
		c.amu.Lock()
		if len(c.pending) < 16 {
			c.pending = append(c.pending, pendingAlert{severity, kind, params})
		}
		c.amu.Unlock()
	}
}

func (c *CAs) flushAlerts(ctx context.Context) {
	c.amu.Lock()
	todo := c.pending
	c.pending = nil
	c.amu.Unlock()
	for _, a := range todo {
		c.raise(ctx, a.severity, a.kind, a.params)
	}
}

func (c *CAs) set(z *hubpki.ZoneCA) {
	c.mu.Lock()
	c.zone = z
	c.mu.Unlock()
}

// sameKey says whether the stored zone CA certificate carries the key now in use.
func (c *CAs) sameKey(chainPEM string) bool {
	blk, _ := pem.Decode([]byte(chainPEM))
	if blk == nil {
		return false
	}
	old, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return false
	}
	pub, ok := old.PublicKey.(*ecdsa.PublicKey)
	return ok && pub.Equal(&c.ZoneKey.PublicKey)
}
