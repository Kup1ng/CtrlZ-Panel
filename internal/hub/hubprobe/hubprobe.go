// Package hubprobe is the hub's prober of p4-nodes 5.6 and SC 8a.4: every 5 s it probes every node of the latest membership,
// in a pair or not, with a DoT part and a DoH part that run in parallel, each with a 2 s timeout, both to the node's advertised
// address, and reports each completed round.
//
// What the probes check. Both validate the certificate chain against the configured roots and the exact SNI name, as a client
// would: nothing here sets InsecureSkipVerify or a verifier of its own, so an on-path party without the zone's key cannot
// answer them. They never check which node answers (every node holds the zone's certificate), the recorded risk of a relay in
// SC 8a.9. The DoT part passes only on NOERROR, AA=1, the query id, the question echoed byte for byte and one SOA at the apex
// with the configured MNAME and RNAME. The DoH part passes on HTTP 200 and a body that parses as the /v JSON, whatever `seen`
// says: a query for a guessed label over spoofed Plain UDP would set `seen` (Plan T-046).
//
// The DNS message is built and read by hand: one question and one SOA are all it needs, and a DNS library for that would be a
// new module in the hub for a hundred lines.
package hubprobe

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/safego"
)

// The numbers of SC 8a.4.
const (
	Every   = 5 * time.Second
	Timeout = 2 * time.Second
	// LabelLen is the length of a DoH probe label: 26 characters of [a-z2-7] are 130 bits.
	LabelLen = 26
	maxBody  = 4096
)

type unit string

const unitProbe unit = "hub_probe"

func (u unit) Valid() bool { return u == unitProbe }

// Target is a node to probe: its id and its advertised address (nodes.dns_advertised_ip, the address clients are given).
type Target struct {
	ID   uuid.UUID
	Addr netip.Addr
}

// Result is one completed round of one node. Both parts ran; the round passes when both did.
type Result struct {
	Node     uuid.UUID
	At       time.Time
	DoT, DoH bool
}

// Config is what a Prober needs.
type Config struct {
	// Targets is every node of the hub's latest membership with its address, read at the start of each round.
	Targets func() []Target
	// Zone is the live zone to probe through (it changes with a domain change), "" while none is known.
	Zone func() string
	// Roots is the pool the zone certificate must chain to: the zone CA in private-CA mode. A nil pool is the system's roots,
	// which is public-CA mode.
	Roots func() *x509.CertPool
	// Report receives each completed round. It must not block.
	Report func(Result)

	DoTPort, DoHPort int // 853 and 443

	// Dial replaces the network dial, for tests.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	Now  func() time.Time
	Log  *slog.Logger
	// Timeout and Every replace the SC 8a.4 values, for tests.
	Timeout, Every time.Duration
}

// Prober runs the rounds.
type Prober struct {
	cfg Config
}

// New returns a Prober.
func New(cfg Config) *Prober {
	if cfg.Now == nil {
		cfg.Now = appclock.Now
	}
	if cfg.DoTPort == 0 {
		cfg.DoTPort = 853
	}
	if cfg.DoHPort == 0 {
		cfg.DoHPort = 443
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = Timeout
	}
	if cfg.Every == 0 {
		cfg.Every = Every
	}
	return &Prober{cfg: cfg}
}

// Run probes every Every until ctx ends. A round starts on the tick and does not wait for the one before: each node's probe is
// bounded by the timeout, so a round is over within 2 s whatever the targets do.
func (p *Prober) Run(ctx context.Context) {
	t := time.NewTicker(p.cfg.Every)
	defer t.Stop()
	for {
		p.Round(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Round probes every target once, in parallel, and reports each.
func (p *Prober) Round(ctx context.Context) {
	z := p.cfg.Zone()
	if z == "" {
		// No live zone is known: nothing was probed, so nothing is reported. A failure here would make every node known and
		// down, where 8a.4 has the state stay unknown.
		return
	}
	var wg sync.WaitGroup
	for _, t := range p.cfg.Targets() {
		wg.Add(1)
		safego.Go(p.cfg.Log, unitProbe, func() {
			defer wg.Done()
			dot, doh, _, _ := p.Probe(ctx, t.Addr, z)
			p.cfg.Report(Result{Node: t.ID, At: p.cfg.Now(), DoT: dot, DoH: doh})
		})
	}
	wg.Wait()
}

// Probe is one round against one address: DoT and DoH in parallel.
func (p *Prober) Probe(ctx context.Context, addr netip.Addr, zoneName string) (dotOK, dohOK bool, dotErr, dohErr error) {
	var wg sync.WaitGroup
	wg.Add(2)
	safego.Go(p.cfg.Log, unitProbe, func() { defer wg.Done(); dotErr = p.dot(ctx, addr, zoneName); dotOK = dotErr == nil })
	safego.Go(p.cfg.Log, unitProbe, func() { defer wg.Done(); dohErr = p.doh(ctx, addr, zoneName); dohOK = dohErr == nil })
	wg.Wait()
	return dotOK, dohOK, dotErr, dohErr
}

func (p *Prober) dial(ctx context.Context, addr netip.Addr, port int) (net.Conn, error) {
	ap := net.JoinHostPort(addr.String(), strconv.Itoa(port))
	if p.cfg.Dial != nil {
		return p.cfg.Dial(ctx, "tcp", ap)
	}
	d := net.Dialer{}
	return d.DialContext(ctx, "tcp", ap)
}

func (p *Prober) tlsConfig(name string, protos ...string) *tls.Config {
	var roots *x509.CertPool
	if p.cfg.Roots != nil {
		roots = p.cfg.Roots()
	}
	// ServerName makes crypto/tls check the exact name, and RootCAs nil is the system pool. Nothing here relaxes either check.
	return &tls.Config{ServerName: name, RootCAs: roots, MinVersion: tls.VersionTLS12, NextProtos: protos}
}

func fqdn(z string) string {
	z = strings.ToLower(z)
	if !strings.HasSuffix(z, ".") {
		z += "."
	}
	return z
}

// SOANames are the MNAME and RNAME the zone's SOA carries: the first name server and the hostmaster mailbox, the same strings
// the node's zone answerer builds its SOA from.
func SOANames(zoneName string) (mname, rname string) {
	z := fqdn(zoneName)
	return "ns1." + z, "hostmaster." + z
}

// ---- DoT

func (p *Prober) dot(ctx context.Context, addr netip.Addr, zoneName string) error {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()
	z := fqdn(zoneName)
	raw, err := p.dial(ctx, addr, p.cfg.DoTPort)
	if err != nil {
		return err
	}
	conn := tls.Client(raw, p.tlsConfig("ns1."+strings.TrimSuffix(z, "."), "dot"))
	defer conn.Close()
	// The deadline is the probe's own timeout on the injected clock, not the context's: a context deadline is a machine-clock value.
	_ = conn.SetDeadline(p.cfg.Now().Add(p.cfg.Timeout))
	if err := conn.HandshakeContext(ctx); err != nil {
		return err
	}
	q, err := SOAQuery(z)
	if err != nil {
		return err
	}
	frame := append([]byte{byte(len(q) >> 8), byte(len(q))}, q...)
	if _, err := conn.Write(frame); err != nil {
		return err
	}
	var lenb [2]byte
	if _, err := io.ReadFull(conn, lenb[:]); err != nil {
		return err
	}
	n := int(lenb[0])<<8 | int(lenb[1])
	if n < 12 || n > 4096 {
		return errors.New("probe: bad DoT frame length")
	}
	resp := make([]byte, n)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	return CheckSOA(q, resp, z)
}

// SOAQuery builds the query `<zone> SOA`, class IN, recursion not desired, with a random id.
func SOAQuery(z string) ([]byte, error) {
	var id [2]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	q := make([]byte, 12, 64)
	copy(q, id[:])
	binary.BigEndian.PutUint16(q[4:], 1) // QDCOUNT
	for _, l := range strings.Split(strings.TrimSuffix(z, "."), ".") {
		if l == "" || len(l) > 63 {
			return nil, errors.New("probe: bad zone name")
		}
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0, 0, 6, 0, 1) // root, QTYPE SOA, QCLASS IN
	return q, nil
}

// CheckSOA is the pass rule of the DoT part for a query SOAQuery built and the response bytes: NOERROR, AA=1, the query id, the
// question echoed byte for byte, and one SOA at the zone apex with the configured MNAME and RNAME. The serial is not compared.
func CheckSOA(query, resp []byte, z string) error {
	if len(resp) < 12 || len(query) < 12 {
		return errors.New("probe: short answer")
	}
	flags := binary.BigEndian.Uint16(resp[2:])
	if flags&0x8000 == 0 || flags&0x0400 == 0 || flags&0x000f != 0 {
		return errors.New("probe: not an authoritative NOERROR")
	}
	if resp[0] != query[0] || resp[1] != query[1] {
		return errors.New("probe: wrong ID")
	}
	ql := len(query) - 12
	if len(resp) < 12+ql || string(resp[12:12+ql]) != string(query[12:]) || binary.BigEndian.Uint16(resp[4:]) != 1 {
		return errors.New("probe: question not echoed")
	}
	if binary.BigEndian.Uint16(resp[6:]) != 1 {
		return errors.New("probe: not exactly one answer")
	}
	off := 12 + ql
	owner, off, err := readName(resp, off)
	if err != nil {
		return err
	}
	if !strings.EqualFold(owner, fqdn(z)) {
		return errors.New("probe: the answer is not the apex SOA")
	}
	if len(resp) < off+10 || binary.BigEndian.Uint16(resp[off:]) != 6 || binary.BigEndian.Uint16(resp[off+2:]) != 1 {
		return errors.New("probe: the answer is not an SOA")
	}
	rdlen := int(binary.BigEndian.Uint16(resp[off+8:]))
	off += 10
	if len(resp) < off+rdlen {
		return errors.New("probe: short SOA")
	}
	mname, next, err := readName(resp, off)
	if err != nil {
		return err
	}
	rname, _, err := readName(resp, next)
	if err != nil {
		return err
	}
	wm, wr := SOANames(z)
	if !strings.EqualFold(mname, wm) || !strings.EqualFold(rname, wr) {
		return errors.New("probe: SOA MNAME or RNAME differ")
	}
	return nil
}

// readName reads a possibly compressed name at off and returns it in presentation form with a final dot, and the offset after
// the name's first form (a pointer ends it).
func readName(msg []byte, off int) (string, int, error) {
	var sb strings.Builder
	end, jumped := 0, false
	for hops := 0; hops < 64; hops++ {
		if off >= len(msg) {
			return "", 0, errors.New("probe: name runs past the message")
		}
		c := int(msg[off])
		switch {
		case c == 0:
			if !jumped {
				end = off + 1
			}
			if sb.Len() == 0 {
				return ".", end, nil
			}
			return sb.String(), end, nil
		case c&0xc0 == 0xc0:
			if off+1 >= len(msg) {
				return "", 0, errors.New("probe: short pointer")
			}
			if !jumped {
				end = off + 2
			}
			jumped = true
			off = (c&0x3f)<<8 | int(msg[off+1])
		case c&0xc0 != 0:
			return "", 0, errors.New("probe: bad label")
		default:
			if off+1+c > len(msg) {
				return "", 0, errors.New("probe: label runs past the message")
			}
			sb.Write(msg[off+1 : off+1+c])
			sb.WriteByte('.')
			off += 1 + c
		}
	}
	return "", 0, errors.New("probe: name loops")
}

// ---- DoH

// Label returns a fresh probe label of 26 characters of [a-z2-7] from the system CSPRNG. It is a DoH name only and never sent
// in a DNS query.
func Label() (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	var b [LabelLen]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = alphabet[b[i]&31]
	}
	return string(b[:]), nil
}

type verifyBody struct {
	Seen      *bool   `json:"seen"`
	N         *string `json:"n"`
	RidTag    *string `json:"rid_tag"`
	ClientTag *string `json:"client_tag"`
	ProtoTag  *string `json:"proto_tag"`
}

func hex32(s *string) bool {
	if s == nil || len(*s) != 32 {
		return false
	}
	_, err := hex.DecodeString(*s)
	return err == nil
}

// ParseVerify says whether a body is the /v JSON (p4-nodes 7.6), whatever `seen` says.
func ParseVerify(b []byte) error {
	var v verifyBody
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	if v.Seen == nil || !hex32(v.N) || !hex32(v.RidTag) || !hex32(v.ClientTag) || !hex32(v.ProtoTag) {
		return errors.New("probe: not the /v body")
	}
	return nil
}

func (p *Prober) doh(ctx context.Context, addr netip.Addr, zoneName string) error {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()
	label, err := Label()
	if err != nil {
		return err
	}
	host := label + ".verify." + strings.TrimSuffix(strings.ToLower(zoneName), ".")
	tr := &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		ForceAttemptHTTP2: true,
		TLSClientConfig:   p.tlsConfig(host, "h2", "http/1.1"),
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return p.dial(ctx, addr, p.cfg.DoHPort)
		},
		TLSHandshakeTimeout: p.cfg.Timeout,
	}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/v", nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("probe: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return err
	}
	if len(body) > maxBody {
		return errors.New("probe: body too long")
	}
	return ParseVerify(body)
}
