package domainapply

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/certcheck"
	"github.com/Kup1ng/CtrlZ-Panel/internal/intakeseal"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

var now = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

// fakeSource is the database side. commitErr makes the commit fail, to test a crash between the files and the columns.
type fakeSource struct {
	settings  store.DomainSettings
	certs     []store.DomainApplyCert
	commitErr error
	commits   []store.DomainApplyCommitIn
}

func (f *fakeSource) DomainApplyLoad(context.Context) (store.DomainSettings, []store.DomainApplyCert, error) {
	return f.settings, f.certs, nil
}

func (f *fakeSource) DomainApplyCommit(_ context.Context, in store.DomainApplyCommitIn) error {
	if f.commitErr != nil {
		return f.commitErr
	}
	f.commits = append(f.commits, in)
	return nil
}

// world is a test root with one intermediate, the intake key pair, and a directory.
type world struct {
	t      *testing.T
	root   *x509.Certificate
	inter  *x509.Certificate
	ikey   *ecdsa.PrivateKey
	pool   *x509.CertPool
	webPEM []byte
	webPub intakeseal.PublicKey
	dir    string
	envf   string
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{t: t, dir: t.TempDir()}
	rkey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"}, NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(1000 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rder, err := x509.CreateCertificate(rand.Reader, rt, rt, &rkey.PublicKey, rkey)
	if err != nil {
		t.Fatal(err)
	}
	w.root, _ = x509.ParseCertificate(rder)
	w.ikey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	it := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test intermediate"}, NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(900 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	ider, err := x509.CreateCertificate(rand.Reader, it, w.root, &w.ikey.PublicKey, rkey)
	if err != nil {
		t.Fatal(err)
	}
	w.inter, _ = x509.ParseCertificate(ider)
	w.pool = x509.NewCertPool()
	w.pool.AddCert(w.root)

	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := x509.MarshalPKCS8PrivateKey(k)
	pb, _ := x509.MarshalPKIXPublicKey(k.PublicKey())
	w.webPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})
	w.webPub, err = intakeseal.ParsePublicKey(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pb}))
	if err != nil {
		t.Fatal(err)
	}
	w.envf = filepath.Join(t.TempDir(), ".env")
	w.writeEnv("# kept\nCTRLZ_ENV_FORMAT_2=1\nCTRLZ_PANEL_HOST=panel.localhost\nCTRLZ_HTTP_PORT=80\n")
	return w
}

func (w *world) writeEnv(s string) {
	w.t.Helper()
	if err := os.WriteFile(w.envf, []byte(s), 0o600); err != nil {
		w.t.Fatal(err)
	}
}

// cert issues a leaf for the names and returns the row as the store reads it, with the key sealed to the web intake.
// keyFrom, when set, seals that leaf's key instead (a row whose key is not the leaf's).
func (w *world) cert(names []string, life time.Duration, keyFrom *ecdsa.PrivateKey) (store.DomainApplyCert, *ecdsa.PrivateKey) {
	w.t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "leaf"}, DNSNames: names,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(life), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, w.inter, &key.PublicKey, w.ikey)
	if err != nil {
		w.t.Fatal(err)
	}
	chain := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: w.inter.Raw}))
	sealKey := key
	if keyFrom != nil {
		sealKey = keyFrom
	}
	k8, _ := x509.MarshalPKCS8PrivateKey(sealKey)
	sealed, err := intakeseal.Seal(w.webPub, intakeseal.Web, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k8}))
	if err != nil {
		w.t.Fatal(err)
	}
	return store.DomainApplyCert{ID: uuid.Must(uuid.NewV7()), ChainPEM: chain, SealedKey: sealed}, key
}

func (w *world) apply(src *fakeSource) (env, log string, err error) {
	var out, lg bytes.Buffer
	err = Apply(context.Background(), Inputs{Source: src, EnvFile: w.envf, TLSDir: w.dir, WebKey: w.webPEM, Now: now, Roots: w.pool, Out: &out, Log: &lg})
	return out.String(), lg.String(), err
}

// commit is the second run of the script: the .env it printed is in place, and `domain-apply --commit` runs.
func (w *world) commit(src *fakeSource) (log string, err error) {
	var lg bytes.Buffer
	err = Commit(context.Background(), Inputs{Source: src, EnvFile: w.envf, TLSDir: w.dir, WebKey: w.webPEM, Now: now, Roots: w.pool, Out: &bytes.Buffer{}, Log: &lg})
	return lg.String(), err
}

// prune is the third run of the script, after the recreate.
func (w *world) prune() error {
	return Prune(Inputs{EnvFile: w.envf, TLSDir: w.dir})
}

func (w *world) files() map[string]string {
	w.t.Helper()
	got := map[string]string{}
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		w.t.Fatal(err)
	}
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(w.dir, e.Name()))
		got[e.Name()] = string(b)
	}
	return got
}

func settings() store.DomainSettings {
	until := now.Add(24 * time.Hour)
	return store.DomainSettings{DNSZone: "dns.example.ir", PrevDNSZone: "dns.old.ir", TransitionUntil: &until,
		PanelHost: "panel.example.ir", AdminHost: "admin.example.ir"}
}

func TestApplyInstallsThePairAndTheEnv(t *testing.T) {
	w := newWorld(t)
	pc, pkey := w.cert([]string{"panel.example.ir"}, 60*24*time.Hour, nil)
	pc.Kind = "panel"
	ac, _ := w.cert([]string{"admin.example.ir"}, 60*24*time.Hour, nil)
	ac.Kind = "admin"
	src := &fakeSource{settings: settings(), certs: []store.DomainApplyCert{pc, ac}}

	env, log, err := w.apply(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# kept\n", "CTRLZ_ENV_FORMAT_2=1\n", "CTRLZ_PANEL_HOST=panel.example.ir\n", "CTRLZ_HTTP_PORT=80\n", "CTRLZ_ADMIN_HOST=admin.example.ir\n",
		"CTRLZ_VERIFY_ORIGIN=https://*.verify.dns.example.ir,https://*.verify.dns.old.ir\n"} {
		if !strings.Contains(env, want) {
			t.Errorf("the new .env lacks %q:\n%s", want, env)
		}
	}
	if strings.Count(env, "CTRLZ_PANEL_HOST") != 1 {
		t.Errorf("the panel host is written %d times", strings.Count(env, "CTRLZ_PANEL_HOST"))
	}

	files := w.files()
	crt, key := pairNames(certcheck.Panel, pc.ID)
	snip := files[snippetName("panel.example.ir")]
	if want := "tls " + caddyTLSDir + "/" + crt + " " + caddyTLSDir + "/" + key; !strings.Contains(snip, want) {
		t.Errorf("the snippet is %q, want it to hold %q", snip, want)
	}
	if !strings.Contains(files[crt], "BEGIN CERTIFICATE") || !strings.Contains(files[key], "BEGIN PRIVATE") {
		t.Errorf("the pair is not written as PEM")
	}
	// The key written is the leaf's own.
	b, _ := pem.Decode([]byte(files[key]))
	got, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil || !got.(*ecdsa.PrivateKey).Equal(pkey) {
		t.Errorf("the key file is not the leaf's private key")
	}
	if len(files) != 6 {
		t.Errorf("the directory holds %d files, want 2 pairs and 2 snippets: %v", len(files), keysOf(files))
	}
	if runtime.GOOS != "windows" {
		for name := range files {
			if st, _ := os.Stat(filepath.Join(w.dir, name)); st.Mode().Perm() != 0o600 {
				t.Errorf("%s has mode %v, want 0600", name, st.Mode().Perm())
			}
		}
	}

	// The first run moves no database row: the columns follow the rename of the .env (R34-r1-2, r1-7).
	if len(src.commits) != 0 {
		t.Fatalf("the first run committed %d times", len(src.commits))
	}
	w.writeEnv(env)
	clog, err := w.commit(src)
	if err != nil {
		t.Fatal(err)
	}
	log += clog
	if len(src.commits) != 1 {
		t.Fatalf("%d commits, want 1", len(src.commits))
	}
	c := src.commits[0]
	if c.PanelHost != "panel.example.ir" || c.AdminHost != "admin.example.ir" || *c.PanelCert != pc.ID || *c.AdminCert != ac.ID {
		t.Errorf("the commit says %+v", c)
	}
	if !strings.Contains(log, pc.ID.String()) {
		t.Errorf("the log does not name the certificate: %q", log)
	}
	// Nothing a key is written as reaches the output or the log.
	if strings.Contains(env+log, "PRIVATE") {
		t.Errorf("a key reached the output or the log")
	}
}

func TestApplyWithNoCertificateUsesThePrivateCA(t *testing.T) {
	w := newWorld(t)
	src := &fakeSource{settings: settings()}
	// An old snippet and its pair, left by a former apply, go away: the host falls back to Caddy's own CA.
	for _, n := range []string{"panel.example.ir.caddy", "panel.example.ir.x.crt", "panel.example.ir.x.key", ".tmp-half.crt", "keep.txt"} {
		if err := os.WriteFile(filepath.Join(w.dir, n), []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	env, _, err := w.apply(src)
	if err != nil {
		t.Fatal(err)
	}
	// The snippet of a planned host with no certificate goes at once (the commit would refuse it); the rest is the
	// clean-up's, after the recreate.
	if files := w.files(); files["panel.example.ir.caddy"] != "" {
		t.Errorf("the snippet of a host with no certificate stays: %v", keysOf(files))
	}
	w.writeEnv(env)
	if _, err := w.commit(src); err != nil {
		t.Fatal(err)
	}
	if err := w.prune(); err != nil {
		t.Fatal(err)
	}
	files := w.files()
	if len(files) != 1 || files["keep.txt"] != "old" {
		t.Errorf("only a file this tool does not write stays: %v", keysOf(files))
	}
	if c := src.commits[0]; c.PanelCert != nil || c.AdminCert != nil {
		t.Errorf("a host with no certificate must commit a NULL certificate id: %+v", c)
	}
}

func TestApplyRefusesBeforeItWritesAnything(t *testing.T) {
	good := func(w *world) *fakeSource {
		pc, _ := w.cert([]string{"panel.example.ir"}, 60*24*time.Hour, nil)
		pc.Kind = "panel"
		return &fakeSource{settings: settings(), certs: []store.DomainApplyCert{pc}}
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cases := map[string]func(w *world, s *fakeSource){
		"a host with an upper-case letter":   func(w *world, s *fakeSource) { s.settings.PanelHost = "Panel.example.ir" },
		"a host with a newline":              func(w *world, s *fakeSource) { s.settings.AdminHost = "admin.example.ir\nCTRLZ_X=1" },
		"a host with a slash":                func(w *world, s *fakeSource) { s.settings.PanelHost = "../x" },
		"a host with a leading hyphen label": func(w *world, s *fakeSource) { s.settings.PanelHost = "-a.example.ir" },
		"the same name for both":             func(w *world, s *fakeSource) { s.settings.AdminHost = s.settings.PanelHost },
		"a zone that is not dns.":            func(w *world, s *fakeSource) { s.settings.DNSZone = "example.ir" },
		"a zone with a comma":                func(w *world, s *fakeSource) { s.settings.PrevDNSZone = "dns.a.ir,evil" },
		"a key that is not the leaf's": func(w *world, s *fakeSource) {
			c, _ := w.cert([]string{"panel.example.ir"}, 90*24*time.Hour, other)
			c.Kind = "panel"
			s.certs = []store.DomainApplyCert{c}
		},
		"a sealed key that does not open": func(w *world, s *fakeSource) { s.certs[0].SealedKey = []byte("not a seal") },
		// What the script would refuse after the run is refused before it (R34-r1-7).
		"an .env line with export": func(w *world, s *fakeSource) {
			w.writeEnv("CTRLZ_ENV_FORMAT_2=1\nexport CTRLZ_HTTP_PORT=80\n")
		},
		"an .env line of spaces":     func(w *world, s *fakeSource) { w.writeEnv("CTRLZ_ENV_FORMAT_2=1\n  \n") },
		"an indented comment":        func(w *world, s *fakeSource) { w.writeEnv("CTRLZ_ENV_FORMAT_2=1\n  # x\n") },
		"an .env without the marker": func(w *world, s *fakeSource) { w.writeEnv("CTRLZ_HTTP_PORT=80\n") },
		"a host too long for a snippet name": func(w *world, s *fakeSource) {
			s.settings.PanelHost = strings.Repeat(strings.Repeat("a", 61)+".", 4) + "bb"
		},
		"a requested host under the zone": func(w *world, s *fakeSource) { s.settings.PanelHost = "a.dns.example.ir" },
		"a served host under the zone": func(w *world, s *fakeSource) {
			s.settings.PanelHost, s.settings.AppliedPanelHost = "", "p.dns.example.ir"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			s := good(w)
			mutate(w, s)
			env, _, err := w.apply(s)
			if err == nil {
				t.Fatal("the run was not refused")
			}
			if env != "" || len(w.files()) != 0 || len(s.commits) != 0 {
				t.Errorf("a refused run wrote output %q, files %v or a commit %v", env, keysOf(w.files()), s.commits)
			}
			if strings.Contains(err.Error(), "PRIVATE") {
				t.Errorf("the error carries key text: %v", err)
			}
		})
	}
}

// A crash between the files and the columns leaves new files and old columns; the second run puts the same state and
// commits, and a certificate that changed in between replaces the pair as a whole.
func TestApplyCrashThenRepair(t *testing.T) {
	w := newWorld(t)
	c1, _ := w.cert([]string{"panel.example.ir"}, 30*24*time.Hour, nil)
	c1.Kind = "panel"
	src := &fakeSource{settings: settings(), certs: []store.DomainApplyCert{c1}, commitErr: store.ErrDomainChanged}
	env, _, err := w.apply(src)
	if err != nil {
		t.Fatal(err)
	}
	w.writeEnv(env)
	if _, err := w.commit(src); !errors.Is(err, store.ErrDomainChanged) {
		t.Fatalf("got %v, want the commit's error", err)
	}
	if len(src.commits) != 0 {
		t.Fatal("a failed commit was recorded")
	}
	before := w.files()

	// A longer-lived certificate arrives; the choice rule prefers it, and the old pair goes with the next apply.
	c2, _ := w.cert([]string{"panel.example.ir"}, 80*24*time.Hour, nil)
	c2.Kind = "panel"
	src.certs, src.commitErr = []store.DomainApplyCert{c1, c2}, nil
	env, _, err = w.apply(src)
	if err != nil {
		t.Fatal(err)
	}
	w.writeEnv(env)
	if _, err := w.commit(src); err != nil {
		t.Fatal(err)
	}
	oldCrt, _ := pairNames(certcheck.Panel, c1.ID)
	if _, there := w.files()[oldCrt]; !there {
		t.Errorf("the pair of the old certificate went before the recreate")
	}
	if err := w.prune(); err != nil {
		t.Fatal(err)
	}
	after := w.files()
	newCrt, newKey := pairNames(certcheck.Panel, c2.ID)
	if _, stale := after[oldCrt]; stale {
		t.Errorf("the pair of the old certificate is still there")
	}
	if after[newCrt] == "" || after[newKey] == "" || !strings.Contains(after[snippetName("panel.example.ir")], newCrt) {
		t.Errorf("the new pair or its snippet is missing: %v", keysOf(after))
	}
	if len(before) == 0 {
		t.Error("the failed run wrote no files at all")
	}
	if *src.commits[0].PanelCert != c2.ID {
		t.Errorf("committed %v, want %v", *src.commits[0].PanelCert, c2.ID)
	}
	// A third run changes nothing.
	if _, _, err := w.apply(src); err != nil {
		t.Fatal(err)
	}
	if err := w.prune(); err != nil {
		t.Fatal(err)
	}
	again := w.files()
	if len(again) != len(after) {
		t.Errorf("a repeated run changed the directory: %v then %v", keysOf(after), keysOf(again))
	}
}

// The columns are what the api's Host gate reads, so a run whose .env was not put in place must not set them, and a plan
// that moved between the two runs must not either (R34-r1-2, r1-7).
func TestCommitRefusesWhatTheFirstRunDidNotLeave(t *testing.T) {
	setup := func(t *testing.T) (*world, *fakeSource, string, store.DomainApplyCert) {
		w := newWorld(t)
		c1, _ := w.cert([]string{"panel.example.ir"}, 30*24*time.Hour, nil)
		c1.Kind = "panel"
		src := &fakeSource{settings: settings(), certs: []store.DomainApplyCert{c1}}
		env, _, err := w.apply(src)
		if err != nil {
			t.Fatal(err)
		}
		return w, src, env, c1
	}
	t.Run("the .env was not replaced", func(t *testing.T) {
		w, src, _, _ := setup(t)
		if _, err := w.commit(src); err == nil || len(src.commits) != 0 {
			t.Errorf("the commit ran on the old .env: %v", err)
		}
	})
	t.Run("the settings moved after the first run", func(t *testing.T) {
		w, src, env, _ := setup(t)
		w.writeEnv(env)
		src.settings.PanelHost = "other.example.ir"
		if _, err := w.commit(src); err == nil || len(src.commits) != 0 {
			t.Errorf("the commit ran for hosts the .env does not hold: %v", err)
		}
	})
	t.Run("a better certificate arrived after the first run", func(t *testing.T) {
		w, src, env, c1 := setup(t)
		w.writeEnv(env)
		c2, _ := w.cert([]string{"panel.example.ir"}, 80*24*time.Hour, nil)
		c2.Kind = "panel"
		src.certs = []store.DomainApplyCert{c1, c2}
		if _, err := w.commit(src); err == nil || len(src.commits) != 0 {
			t.Errorf("the commit recorded a certificate whose snippet is not written: %v", err)
		}
	})
	t.Run("a snippet that the plan does not have", func(t *testing.T) {
		w, src, env, _ := setup(t)
		w.writeEnv(env)
		src.certs = nil // the certificate was retired after the first run
		if _, err := w.commit(src); err == nil || len(src.commits) != 0 {
			t.Errorf("the commit ran with a snippet the plan no longer has: %v", err)
		}
	})
}

// A host nobody requested and no run applied is the .env's own: the commit leaves it NULL, so the .env keeps deciding and
// the page's apply_pending compares nothing against it (R34-r1-9).
func TestCommitLeavesAnEnvHostNull(t *testing.T) {
	w := newWorld(t)
	s := settings()
	s.PanelHost, s.AdminHost = "", ""
	w.writeEnv("CTRLZ_ENV_FORMAT_2=1\nCTRLZ_PANEL_HOST=p.example.ir\nCTRLZ_ADMIN_HOST=a.example.ir\n")
	src := &fakeSource{settings: s}
	env, _, err := w.apply(src)
	if err != nil {
		t.Fatal(err)
	}
	w.writeEnv(env)
	if _, err := w.commit(src); err != nil {
		t.Fatal(err)
	}
	if c := src.commits[0]; c.PanelHost != "" || c.AdminHost != "" {
		t.Errorf("hosts nobody requested were recorded as applied: %+v", c)
	}
	// A requested host is recorded.
	s.PanelHost = "q.example.ir"
	src.settings = s
	w.writeEnv("CTRLZ_ENV_FORMAT_2=1\nCTRLZ_PANEL_HOST=p.example.ir\nCTRLZ_ADMIN_HOST=a.example.ir\n")
	env, _, err = w.apply(src)
	if err != nil {
		t.Fatal(err)
	}
	w.writeEnv(env)
	if _, err := w.commit(src); err != nil {
		t.Fatal(err)
	}
	if c := src.commits[1]; c.PanelHost != "q.example.ir" || c.AdminHost != "" {
		t.Errorf("the commit says %+v", c)
	}
}

// What the running containers read stays until the recreate has succeeded and the clean-up runs: a run that fails after
// the files, the rerun after it, or a restart before the recreate, must not find the old host's certificate gone, and the
// old host's key must not outlive the clean-up (R34-r1-8, r2-1, r2-5, r2-6).
func TestTheServedHostKeepsItsFilesUntilALaterRun(t *testing.T) {
	w := newWorld(t)
	old, _ := w.cert([]string{"old.example.ir"}, 30*24*time.Hour, nil)
	old.Kind = "panel"
	neu, _ := w.cert([]string{"panel.example.ir"}, 30*24*time.Hour, nil)
	neu.Kind = "panel"
	// The old generation: .env on old.example.ir, with its pair and snippet written by an earlier run.
	w.writeEnv("CTRLZ_ENV_FORMAT_2=1\nCTRLZ_PANEL_HOST=old.example.ir\nCTRLZ_ADMIN_HOST=admin.example.ir\n")
	s := settings()
	s.PanelHost = "old.example.ir"
	src := &fakeSource{settings: s, certs: []store.DomainApplyCert{old}}
	if _, _, err := w.apply(src); err != nil {
		t.Fatal(err)
	}
	oldCrt, oldKey := pairNames(certcheck.Panel, old.ID)
	if files := w.files(); files[oldCrt] == "" || files[snippetName("old.example.ir")] == "" {
		t.Fatalf("the first generation is not in place: %v", keysOf(files))
	}

	// The admin asks for a new host. The run writes the new files and leaves the old ones.
	src.settings.PanelHost = "panel.example.ir"
	src.certs = []store.DomainApplyCert{neu}
	env, _, err := w.apply(src)
	if err != nil {
		t.Fatal(err)
	}
	files := w.files()
	for _, n := range []string{oldCrt, oldKey, snippetName("old.example.ir")} {
		if files[n] == "" {
			t.Errorf("%s of the host that still serves was removed before the .env moved", n)
		}
	}
	if files[snippetName("panel.example.ir")] == "" {
		t.Errorf("the new snippet is missing")
	}

	// The script replaced the .env and recorded the hosts, and the recreate failed: the old Caddy still runs, and the run
	// the script asks for now sees a .env that already names the new host. It must not take the old host's files either
	// (R34-r2-1, r2-5).
	w.writeEnv(env)
	if _, err := w.commit(src); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.apply(src); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{oldCrt, oldKey, snippetName("old.example.ir")} {
		if w.files()[n] == "" {
			t.Errorf("%s of the host the old Caddy serves was removed by the rerun", n)
		}
	}

	// The recreate succeeded: only now do the old host's snippet, pair and private key go (R34-r2-6).
	if err := w.prune(); err != nil {
		t.Fatal(err)
	}
	files = w.files()
	for n := range files {
		if strings.Contains(n, "old.example.ir") || n == oldCrt || n == oldKey {
			t.Errorf("%s of the retired host is still there", n)
		}
	}
	newCrt, newKey := pairNames(certcheck.Panel, neu.ID)
	for _, n := range []string{newCrt, newKey, snippetName("panel.example.ir")} {
		if files[n] == "" {
			t.Errorf("%s of the host that serves now was removed by the clean-up", n)
		}
	}
	// A directory that was never made is nothing to clean.
	if err := Prune(Inputs{EnvFile: w.envf, TLSDir: filepath.Join(t.TempDir(), "absent")}); err != nil {
		t.Errorf("a missing directory is an error: %v", err)
	}
}

// The names of the files stay inside the 255 bytes of a file name for the longest host the route accepts.
func TestFileNamesFitForTheLongestHost(t *testing.T) {
	host := strings.Repeat("a", 59) + strings.Repeat("."+strings.Repeat("a", 59), 3) + "." + strings.Repeat("b", 9) // 249 bytes
	if len(host) != nodeadminMax {
		t.Fatalf("the test host is %d bytes", len(host))
	}
	id := uuid.Must(uuid.NewV7())
	crt, key := pairNames(certcheck.Admin, id)
	for _, n := range []string{snippetName(host), crt, key, tmpName(snippetName(host)), tmpName(crt)} {
		if len(n) > 255 {
			t.Errorf("%q... is %d bytes", n[:20], len(n))
		}
	}
}

const nodeadminMax = 249 // nodeadmin.MaxServedHost, restated so that a change of it fails this test

func TestWriteAtomicReplacesWholeAndLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	if err := writeAtomic(dir, "a.key", []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A stale temp file of a crashed run does not block the next write.
	if err := os.WriteFile(filepath.Join(dir, tmpName("a.key")), []byte("half"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(dir, "a.key", []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "a.key"))
	if string(b) != "two" {
		t.Errorf("a.key holds %q", b)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("the directory holds %d entries, want only a.key", len(entries))
	}
	// A write into a directory that is not there fails and leaves nothing.
	if err := writeAtomic(filepath.Join(dir, "missing"), "x.key", []byte("x"), 0o600); err == nil {
		t.Error("a write into a missing directory succeeded")
	}
}

func TestSetEnv(t *testing.T) {
	in := "# c\nCTRLZ_PANEL_HOST=old\nA=1\n\nCTRLZ_PANEL_HOST=dup\n"
	out, err := setEnv([]byte(in), []envPair{{envPanelHost, "p.example.ir"}, {envVerifyOrigin, ""}})
	if err != nil {
		t.Fatal(err)
	}
	want := "# c\nCTRLZ_PANEL_HOST=p.example.ir\nA=1\n\nCTRLZ_VERIFY_ORIGIN=\n"
	if string(out) != want {
		t.Errorf("got %q, want %q", out, want)
	}
	// Every line the script's check would refuse is refused here first.
	for _, bad := range []string{"export A=1\n", "A = 1\n", "  # c\n", "  \n", "1A=1\n", "rm -rf /\n"} {
		if _, err := setEnv([]byte(bad), nil); err == nil {
			t.Errorf("the line %q was accepted", bad)
		}
	}
	if _, err := setEnv([]byte("A=1\r\n"), nil); err == nil {
		t.Error("a file with a carriage return was edited")
	}
	for _, bad := range []string{"a b", "a\nb", "a#b", "a=b", "A", "a'b", "a$b"} {
		if _, err := setEnv([]byte("A=1\n"), []envPair{{envPanelHost, bad}}); err == nil {
			t.Errorf("the value %q was written", bad)
		}
	}
	if got := envValue([]byte("X=1\nCTRLZ_PANEL_HOST=\"q.example.ir\" \nCTRLZ_PANEL_HOST=z.example.ir # c\n"), envPanelHost); got != "z.example.ir" {
		t.Errorf("the last value wins, got %q", got)
	}
}

func TestHostGrammar(t *testing.T) {
	for h, want := range map[string]bool{"a.example.ir": true, "a-b.c1.ir": true, "x": true, "": false, "a..b": false, "A.b": false, "a_b.c": false,
		"-a.b": false, "a-.b": false, strings.Repeat("a", 64) + ".ir": false, strings.Repeat("a.", 127) + "a": false, "a.b.": false} {
		if validHost(h) != want {
			t.Errorf("validHost(%q) = %v, want %v", h, !want, want)
		}
	}
	if validZone("dns.") || validZone("example.ir") || !validZone("dns.example.ir") {
		t.Error("validZone is wrong")
	}
	until := now.Add(-time.Hour)
	if got := verifyOrigins("dns.a.ir", "dns.b.ir", &until, now); got != "https://*.verify.dns.a.ir" {
		t.Errorf("an ended transition still lists the old zone: %q", got)
	}
	if got := verifyOrigins("", "", nil, now); got != "" {
		t.Errorf("no zone gives %q", got)
	}
}

func keysOf(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// A host nobody requested and no run applied is the .env's own value, read from the file as it was before the rename. The
// admin may withdraw a request between the two runs; read from the new .env, the host the first run printed would agree
// with itself and go into force (R34-r3-1).
func TestCommitJudgesAnUnrequestedHostFromThePreSwapEnv(t *testing.T) {
	const oldEnv = "CTRLZ_ENV_FORMAT_2=1\nCTRLZ_PANEL_HOST=old.example.ir\nCTRLZ_ADMIN_HOST=admin.example.ir\n"
	writePrev := func(t *testing.T) string {
		prev := filepath.Join(t.TempDir(), ".env.prev")
		if err := os.WriteFile(prev, []byte(oldEnv), 0o600); err != nil {
			t.Fatal(err)
		}
		return prev
	}
	setup := func(t *testing.T) (*world, *fakeSource, string) {
		w := newWorld(t)
		w.writeEnv(oldEnv)
		s := settings()
		s.AdminHost = ""
		s.PanelHost = "new.example.ir"
		src := &fakeSource{settings: s}
		printed, _, err := w.apply(src)
		if err != nil {
			t.Fatal(err)
		}
		prev := writePrev(t)
		w.writeEnv(printed)
		return w, src, prev
	}
	commit := func(w *world, src *fakeSource, prev string) error {
		return Commit(context.Background(), Inputs{Source: src, EnvFile: w.envf, PrevEnvFile: prev, TLSDir: w.dir, WebKey: w.webPEM, Now: now, Roots: w.pool, Out: &bytes.Buffer{}, Log: &bytes.Buffer{}})
	}
	t.Run("the request was withdrawn", func(t *testing.T) {
		w, src, prev := setup(t)
		src.settings.PanelHost = ""
		if err := commit(w, src, prev); err == nil || len(src.commits) != 0 {
			t.Fatalf("the withdrawn host went into force: %v, %+v", err, src.commits)
		}
	})
	t.Run("the request stands", func(t *testing.T) {
		w, src, prev := setup(t)
		if err := commit(w, src, prev); err != nil {
			t.Fatal(err)
		}
		if c := src.commits[0]; c.PanelHost != "new.example.ir" {
			t.Errorf("the commit says %+v", c)
		}
	})
	t.Run("a host from the .env alone, the file only changed its origin", func(t *testing.T) {
		w := newWorld(t)
		w.writeEnv(oldEnv)
		s := settings()
		s.PanelHost, s.AdminHost = "", ""
		src := &fakeSource{settings: s}
		printed, _, err := w.apply(src)
		if err != nil {
			t.Fatal(err)
		}
		prev := writePrev(t)
		w.writeEnv(printed)
		if err := commit(w, src, prev); err != nil {
			t.Fatal(err)
		}
		if c := src.commits[0]; c.PanelHost != "" || c.AdminHost != "" {
			t.Errorf("hosts nobody requested were recorded: %+v", c)
		}
	})
	t.Run("the previous file is missing", func(t *testing.T) {
		w, src, _ := setup(t)
		if err := commit(w, src, filepath.Join(t.TempDir(), "absent")); err == nil || len(src.commits) != 0 {
			t.Errorf("the commit ran without the file it was told to read: %v", err)
		}
	})
}

// The script restores the old .env on exit code 3 only, so only a failure before the UPDATE, or an UPDATE that matched no
// row, may answer 3; an UPDATE that was sent and did not answer clean may have moved the columns (R34-r3-2).
func TestCommitSaysWhetherTheColumnsMayHaveMoved(t *testing.T) {
	setup := func(t *testing.T, commitErr error) (*world, *fakeSource) {
		w := newWorld(t)
		src := &fakeSource{settings: settings(), commitErr: commitErr}
		printed, _, err := w.apply(src)
		if err != nil {
			t.Fatal(err)
		}
		w.writeEnv(printed)
		return w, src
	}
	w, src := setup(t, errors.New("connection lost"))
	_, err := w.commit(src)
	if !OutcomeUnknown(err) || failureCode(true, err) != 1 {
		t.Errorf("a lost answer: unknown %v, code %d", OutcomeUnknown(err), failureCode(true, err))
	}
	w, src = setup(t, store.ErrDomainChanged)
	_, err = w.commit(src)
	if err == nil || OutcomeUnknown(err) || failureCode(true, err) != exitNothingRecorded {
		t.Errorf("no row matched: %v, code %d", err, failureCode(true, err))
	}
	w, src = setup(t, nil)
	w.writeEnv("CTRLZ_ENV_FORMAT_2=1\nCTRLZ_PANEL_HOST=other.example.ir\n")
	_, err = w.commit(src)
	if err == nil || OutcomeUnknown(err) || failureCode(true, err) != exitNothingRecorded {
		t.Errorf("a refused plan: %v, code %d", err, failureCode(true, err))
	}
	// The first run and the clean-up keep the one code of a failure.
	if failureCode(false, errors.New("x")) != 1 {
		t.Errorf("a failed first run does not answer 1")
	}
}

// A snippet of a served host that cannot be read is no reason to delete what it names (R34-r3-3).
func TestPruneStopsWhenAServedSnippetCannotBeRead(t *testing.T) {
	w := newWorld(t)
	c, _ := w.cert([]string{"panel.example.ir"}, 30*24*time.Hour, nil)
	c.Kind = "panel"
	w.writeEnv("CTRLZ_ENV_FORMAT_2=1\nCTRLZ_PANEL_HOST=panel.example.ir\nCTRLZ_ADMIN_HOST=admin.example.ir\n")
	src := &fakeSource{settings: settings(), certs: []store.DomainApplyCert{c}}
	if _, _, err := w.apply(src); err != nil {
		t.Fatal(err)
	}
	crt, key := pairNames(certcheck.Panel, c.ID)
	// A directory where the snippet is: reading it fails with something other than "not found", on every platform.
	snip := filepath.Join(w.dir, snippetName("panel.example.ir"))
	if err := os.Remove(snip); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(snip, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := w.prune(); err == nil {
		t.Fatal("the clean-up reported success on a snippet it could not read")
	}
	files := w.files()
	if _, ok := files[crt]; !ok {
		t.Errorf("the certificate of the served host was removed")
	}
	if _, ok := files[key]; !ok {
		t.Errorf("the key of the served host was removed")
	}
}
