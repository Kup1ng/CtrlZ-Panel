// Package hubinstall serves GET /install/* on the node port (p4-nodes 4.2, 5.1): the files a host needs
// to install a node and enrol it, under the hub's key pin and before it has any identity.
//
// Two classes of request. Static and public: node.sh, ctrlz-verify, root.json and node_ca.pem, which are
// signed or checked by hash in the install command, so anyone may read them. Bundle files, which hold
// the whole node (every package it installs) and are served only to a request that carries a live
// enrolment token (an `Authorization: Bearer` header, which the install script reads from a 0600 file
// and never puts in an argument). Neither class takes a path from the client: a file is found by exact
// lookup of the client's string in the index of its bundle's verified manifest, after manifest.CheckPath,
// and opened under an os.Root on that bundle's directory, so no client string is joined to a path.
//
// What the hub does not do here: it does not hash a file it serves. The node verifies every file against
// the manifest it checked against the root it was given, and the hub is not trusted past the pin.
package hubinstall

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/manifest"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hublimit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubnet"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubtoken"
	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
)

// Limits of D31 (p4-nodes 5.1).
const (
	StaticPerMinute   = 60
	TokenPerMinute    = 240
	BundleConcurrency = 2
	BundleBytesPerSec = 4 << 20
	// StaticInFlight and StaticPerSource bound the static responses in progress; the rate limit counts starts.
	StaticInFlight  = 32
	StaticPerSource = 4
	// WriteStall is how long one write may wait for the peer, StaticMaxTime and BundleMaxTime how long a whole
	// response may take, and TokenRecheck how often a running bundle download looks at its token again.
	WriteStall    = 30 * time.Second
	StaticMaxTime = 60 * time.Second
	BundleMaxTime = 10 * time.Minute
	TokenRecheck  = 30 * time.Second
	cacheTTL      = 30 * time.Second
	maxCached     = 8
	maxRoot       = 1 << 20
	maxEnvelope   = manifest.MaxEnvelope
)

// The files of a node bundle the static routes serve (they are listed in the manifest like any other).
const (
	NodeScriptPath = "packaging/install/node.sh"
	VerifyPath     = "bin/ctrlz-verify"
)

// TokenChecker says whether an enrolment token is live. The hub passes the enrollment pool's store.
type TokenChecker interface {
	HubTokenLive(ctx context.Context, hash []byte) (bool, error)
}

// Config builds a Handler.
type Config struct {
	// BundlesDir holds root.json and <kind>/<version>/ directories (deploy/bundles).
	BundlesDir string
	NodeCAPEM  []byte
	Tokens     TokenChecker
	Now        func() time.Time
	Log        *slog.Logger
	// DenyRootKeys are key ids (hex) a production root must not hold: the lab test root's.
	DenyRootKeys []string
}

// Handler is the http.Handler of /install/.
type Handler struct {
	cfg        Config
	static     *hublimit.Keyed
	tokened    *hublimit.Keyed
	slots      *hublimit.Slots
	staticOpen *hublimit.Slots
	staticSrc  *hublimit.Counts
	bytes      *hublimit.Keyed
	mu         sync.Mutex
	rootAt     time.Time
	root       *signv1.Root
	rootJSON   []byte
	bundles    map[uint64]*cachedBundle
	recheck    time.Duration
}

type cachedBundle struct {
	at    time.Time
	m     *signv1.Manifest
	sizes map[string]uint64 // exact lookup: path to the signed size, built from a manifest NewIndex accepted
	raw   []byte            // manifest.json as stored, which the manifest route serves
}

// New builds the handler.
func New(cfg Config) *Handler {
	if cfg.Now == nil {
		cfg.Now = appclock.Now
	}
	return &Handler{
		cfg:        cfg,
		static:     hublimit.NewKeyed(StaticPerMinute/60.0, StaticPerMinute, cfg.Now),
		tokened:    hublimit.NewKeyed(TokenPerMinute/60.0, TokenPerMinute, cfg.Now),
		slots:      hublimit.NewSlots(BundleConcurrency),
		staticOpen: hublimit.NewSlots(StaticInFlight),
		staticSrc:  hublimit.NewCounts(StaticPerSource),
		bytes:      hublimit.NewKeyed(BundleBytesPerSec, 2*BundleBytesPerSec, cfg.Now),
		bundles:    make(map[uint64]*cachedBundle),
		recheck:    TokenRecheck,
	}
}

func notFound(w http.ResponseWriter) { http.Error(w, "not found", http.StatusNotFound) }

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		notFound(w)
		return
	}
	id := hubnet.IdentityFrom(r.Context())
	src := hublimit.NetKey(id.Source)
	p := strings.TrimPrefix(r.URL.Path, "/install/")
	switch {
	case p == "node.sh", p == "ctrlz-verify":
		if !h.static.Allow(src) {
			tooMany(w)
			return
		}
		rel, ok := h.enterStatic(w, src)
		if !ok {
			return
		}
		defer rel()
		h.serveNewest(w, r, p)
	case p == "root.json":
		if !h.static.Allow(src) {
			tooMany(w)
			return
		}
		rel, ok := h.enterStatic(w, src)
		if !ok {
			return
		}
		defer rel()
		armWrite(w)
		h.serveRoot(w)
	case p == "node_ca.pem":
		if !h.static.Allow(src) {
			tooMany(w)
			return
		}
		rel, ok := h.enterStatic(w, src)
		if !ok {
			return
		}
		defer rel()
		armWrite(w)
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Length", strconv.Itoa(len(h.cfg.NodeCAPEM)))
		_, _ = w.Write(h.cfg.NodeCAPEM)
	case strings.HasPrefix(p, "bundle/"):
		h.serveBundle(w, r, strings.TrimPrefix(p, "bundle/"), src)
	default:
		notFound(w)
	}
}

func tooMany(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "15")
	http.Error(w, "slow down", http.StatusTooManyRequests)
}

// ---------------------------------------------------------------------------------------------------
// root.json and the bundles' manifests.

// loadRoot reads root.json, which is a protojson Root, and keeps it for cacheTTL.
func (h *Handler) loadRoot() (*signv1.Root, []byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.cfg.Now()
	if h.root != nil && now.Sub(h.rootAt) < cacheTTL {
		return h.root, h.rootJSON, nil
	}
	b, err := readCapped(filepath.Join(h.cfg.BundlesDir, "root.json"), maxRoot)
	if err != nil {
		return nil, nil, err
	}
	root := &signv1.Root{}
	if err := (protojson.UnmarshalOptions{}).Unmarshal(b, root); err != nil {
		return nil, nil, errors.New("hubinstall: root.json does not decode")
	}
	if err := checkRootKeys(root, h.cfg.DenyRootKeys); err != nil {
		return nil, nil, err
	}
	h.root, h.rootJSON, h.rootAt = root, b, now
	return root, b, nil
}

// checkRootKeys refuses a root that holds a denied key id (the lab test root, in production).
func checkRootKeys(root *signv1.Root, deny []string) error {
	for _, k := range root.GetKeys() {
		id := hex.EncodeToString(k.GetKeyId())
		for _, d := range deny {
			if id == d {
				return errors.New("hubinstall: root.json holds a test key")
			}
		}
	}
	return nil
}

func readCapped(p string, limit int64) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("hubinstall: file over its limit")
	}
	return b, nil
}

func (h *Handler) nodeDir(version uint64) string {
	return filepath.Join(h.cfg.BundlesDir, "node", strconv.FormatUint(version, 10))
}

// bundle loads and verifies the manifest of node bundle version: its signature against the root's
// bundle grant before it is parsed (manifest.VerifyManifest), and the version it says against the
// directory it is in.
func (h *Handler) bundle(version uint64) (*cachedBundle, error) {
	h.mu.Lock()
	if c := h.bundles[version]; c != nil && h.cfg.Now().Sub(c.at) < cacheTTL {
		h.mu.Unlock()
		return c, nil
	}
	h.mu.Unlock()
	root, _, err := h.loadRoot()
	if err != nil {
		return nil, err
	}
	raw, err := readCapped(filepath.Join(h.nodeDir(version), "manifest.json"), maxEnvelope)
	if err != nil {
		return nil, err
	}
	env := &signv1.Envelope{}
	if err := (protojson.UnmarshalOptions{}).Unmarshal(raw, env); err != nil {
		return nil, errors.New("hubinstall: the manifest does not decode")
	}
	m, err := manifest.VerifyManifest(env, root, signv1.Kind_KIND_NODE, h.cfg.Now().Unix())
	if err != nil {
		return nil, errors.New("hubinstall: the manifest does not verify")
	}
	if err := manifest.CheckManifestFresh(m, h.cfg.Now().Unix(), 0); err != nil {
		return nil, errors.New("hubinstall: the manifest is expired")
	}
	if m.GetVersion() != version {
		return nil, errors.New("hubinstall: the manifest is for another version")
	}
	if _, err := manifest.NewIndex(m); err != nil {
		return nil, errors.New("hubinstall: the manifest has no usable index")
	}
	sizes := make(map[string]uint64, len(m.GetFiles()))
	for _, f := range m.GetFiles() {
		sizes[f.GetPath()] = f.GetSize()
	}
	c := &cachedBundle{at: h.cfg.Now(), m: m, sizes: sizes, raw: raw}
	h.mu.Lock()
	if len(h.bundles) >= maxCached {
		clear(h.bundles)
	}
	h.bundles[version] = c
	h.mu.Unlock()
	return c, nil
}

// newest is the highest version directory under bundles/node whose manifest verifies.
func (h *Handler) newest() (uint64, *cachedBundle, error) {
	ents, err := os.ReadDir(filepath.Join(h.cfg.BundlesDir, "node"))
	if err != nil {
		return 0, nil, err
	}
	var vs []uint64
	for _, e := range ents {
		if v, ok := parseVersion(e.Name()); ok && e.IsDir() {
			vs = append(vs, v)
		}
	}
	// Highest first: a newer directory whose manifest does not verify (a half-copied release) is skipped,
	// not served and not allowed to hide the one below it.
	for len(vs) > 0 {
		best, at := vs[0], 0
		for i, v := range vs {
			if v > best {
				best, at = v, i
			}
		}
		if c, err := h.bundle(best); err == nil {
			return best, c, nil
		}
		vs = append(vs[:at], vs[at+1:]...)
	}
	return 0, nil, errors.New("hubinstall: no node bundle")
}

func parseVersion(s string) (uint64, bool) {
	if s == "" || len(s) > 18 || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	v, err := strconv.ParseUint(s, 10, 64)
	return v, err == nil && v > 0
}

// ---------------------------------------------------------------------------------------------------
// Serving.

func (h *Handler) serveRoot(w http.ResponseWriter) {
	_, b, err := h.loadRoot()
	if err != nil {
		h.fail(w, lackRoot)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	_, _ = w.Write(b)
}

// lacking says which part of the install was not there, as a closed word a log line may carry.
type lacking string

const (
	lackRoot   lacking = "root"
	lackBundle lacking = "bundle"
	lackDir    lacking = "dir"
)

func (l lacking) Valid() bool { return l == lackRoot || l == lackBundle || l == lackDir }

func (h *Handler) fail(w http.ResponseWriter, what lacking) {
	// The cause is a configuration of the operator (no release yet, a manifest that does not verify). It
	// is said in the log in a closed word, never with a path, and the client sees a 503.
	if h.cfg.Log != nil {
		h.cfg.Log.Warn("install file unavailable", logattr.Enum("what", what))
	}
	w.Header().Set("Retry-After", "30")
	http.Error(w, "unavailable", http.StatusServiceUnavailable)
}

func (h *Handler) serveNewest(w http.ResponseWriter, r *http.Request, name string) {
	ver, c, err := h.newest()
	if err != nil {
		h.fail(w, lackBundle)
		return
	}
	rel := NodeScriptPath
	if name == "ctrlz-verify" {
		rel = VerifyPath
	}
	h.sendFile(w, r, ver, c, rel, "static", StaticMaxTime, nil)
}

// sendFile opens rel of bundle version under an os.Root and writes it, paced by the limiter named by
// pace. rel is already a path the manifest lists.
func (h *Handler) sendFile(w http.ResponseWriter, r *http.Request, ver uint64, c *cachedBundle, rel, pace string, maxTime time.Duration, alive func() bool) {
	if err := manifest.CheckPath(rel); err != nil {
		notFound(w)
		return
	}
	size, found := c.sizes[rel]
	if !found {
		notFound(w)
		return
	}
	root, err := os.OpenRoot(h.nodeDir(ver))
	if err != nil {
		h.fail(w, lackDir)
		return
	}
	defer root.Close()
	f, err := root.Open(rel)
	if err != nil {
		notFound(w)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || uint64(st.Size()) != size {
		// A symlink, a directory or a file that is not the size the manifest says is not served.
		notFound(w)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(st.Size(), 10))
	h.copyPaced(r.Context(), w, f, pace, maxTime, alive)
}

func (h *Handler) copyPaced(ctx context.Context, w http.ResponseWriter, src io.Reader, key string, maxTime time.Duration, alive func() bool) {
	buf := make([]byte, 64<<10)
	rc := http.NewResponseController(w)
	start := appclock.Now()
	lastAlive := start
	for {
		n, err := src.Read(buf)
		if n > 0 {
			for !h.bytes.AllowN(key, float64(n)) {
				wait := h.bytes.Wait(key, float64(n))
				if wait < time.Millisecond {
					wait = time.Millisecond
				}
				t := time.NewTimer(wait)
				select {
				case <-ctx.Done():
					t.Stop()
					return
				case <-t.C:
				}
			}
			// Real clock throughout: these bound how long a peer may hold the handler, and a test's
			// frozen clock must not stretch them. A stalled peer (no HTTP/2 window, a socket that is
			// never read) fails the write after WriteStall, and the whole response ends at maxTime.
			now := appclock.Now()
			if now.Sub(start) > maxTime {
				return
			}
			if alive != nil && now.Sub(lastAlive) >= h.recheck {
				if !alive() {
					return
				}
				lastAlive = now
			}
			_ = rc.SetWriteDeadline(minTime(now.Add(WriteStall), start.Add(maxTime)))
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// armWrite gives a response that is written in one call (a small file held in memory) a deadline for
// the whole of it.
func armWrite(w http.ResponseWriter) {
	_ = http.NewResponseController(w).SetWriteDeadline(appclock.Now().Add(WriteStall))
}

// enterStatic takes a place for a static response: a few hub-wide and a few per source network, so
// stalled downloads of a public file cannot pile up one buffer, one open file and one goroutine each.
func (h *Handler) enterStatic(w http.ResponseWriter, src string) (release func(), ok bool) {
	relSrc, ok := h.staticSrc.Take(src)
	if !ok {
		tooMany(w)
		return nil, false
	}
	relAll, ok := h.staticOpen.Try()
	if !ok {
		relSrc()
		w.Header().Set("Retry-After", "5")
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return nil, false
	}
	return func() { relAll(); relSrc() }, true
}

// serveBundle is GET /install/bundle/<version>/<file>.
func (h *Handler) serveBundle(w http.ResponseWriter, r *http.Request, rest string, src string) {
	vs, file, ok := strings.Cut(rest, "/")
	ver, vok := parseVersion(vs)
	if !ok || !vok || file == "" {
		notFound(w)
		return
	}
	// Syntax of the token before anything else costs a database read: a request with no token, or with
	// text that is not one, is refused here and never reaches the pool.
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, prefix) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	hash, ok := hubtoken.Parse(auth[len(prefix):])
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// A first install makes dozens of requests that carry the token; their own, larger, limit.
	if !h.tokened.Allow(src) {
		tooMany(w)
		return
	}
	rel, ok := h.slots.Try()
	if !ok {
		// At most two bundle requests at once hub-wide: the script's curl --retry waits this out.
		w.Header().Set("Retry-After", "5")
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}
	defer rel()
	live, err := h.cfg.Tokens.HubTokenLive(r.Context(), hash)
	if err != nil {
		w.Header().Set("Retry-After", "5")
		http.Error(w, "try again", http.StatusServiceUnavailable)
		return
	}
	if !live {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	c, err := h.bundle(ver)
	if err != nil {
		notFound(w)
		return
	}
	if file == "manifest.json" {
		w.Header().Set("Content-Type", "application/json")
		armWrite(w)
		w.Header().Set("Content-Length", strconv.Itoa(len(c.raw)))
		_, _ = io.Copy(w, bytes.NewReader(c.raw))
		return
	}
	// sendFile looks the name up exactly in the manifest: a name it does not list is a 404.
	alive := func() bool {
		ctx, cancel := context.WithTimeout(r.Context(), TokenRecheck)
		defer cancel()
		live, err := h.cfg.Tokens.HubTokenLive(ctx, hash)
		return err == nil && live
	}
	h.sendFile(w, r, ver, c, file, "bundle", BundleMaxTime, alive)
}
