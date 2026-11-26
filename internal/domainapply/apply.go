// Package domainapply is `ctrlz domain-apply` (p4-nodes 10.4): the host step that turns the requested panel and admin
// hostnames and the chosen web certificates into what Compose and Caddy read, and then records what it did.
//
// It runs in a one-shot container as the database login ctrlz_domain_apply, which reads domain_settings and the active
// panel and admin certificates (their sealed keys included) and writes only the applied_* columns. The one secret it holds
// that no other container does is web_intake_key, which opens the sealed keys.
//
// The host script runs it twice, `domain-apply` and then `domain-apply --commit`, and renames the new .env between the two.
// The applied_* columns are what the api's Host gate reads, so they must not move before the .env that Caddy and the
// services start from has been put in place: a run that failed after the columns moved would leave the gate on a host
// that nothing serves, with no hint on the page (R34-r1-2, r1-7).
//
// The first run (Apply), in order, and why:
//
//  1. Read the settings and the certificates in one transaction, and the current .env.
//  2. Decide: the hosts, the certificate each host serves (certcheck.Choose, the one choice rule of 4.3), the value of
//     CTRLZ_VERIFY_ORIGIN. Open the key of each chosen certificate and check it belongs to the leaf. Any refusal here
//     stops the run before a file is touched.
//  3. Write the certificate chain and key of each host under names that carry the certificate id, then, last, the small
//     Caddy snippet that names them. Caddy reads the snippet and nothing else, so a crash between two renames leaves the
//     old snippet pointing at the old, complete pair or the new snippet pointing at the new, complete pair, never a
//     certificate with another certificate's key. Nothing the running containers read is removed here (Prune does it, below).
//  4. Print the new .env to the output. The script puts it in place with one rename on the host (a container running as
//     the Caddy user must not hold write access to the compose directory), only after this process has exited with success.
//
// The second run (Commit), after the rename:
//
//  5. Plan again from the settings as they are now and check that the .env holds exactly the planned hosts and origins and
//     that each snippet is the planned one. Anything else means the settings moved, or the rename did not happen, and the
//     answer is an error that no column follows. A host nobody requested is read from the .env as it was before the rename
//     (Inputs.PrevEnvFile), not from the file the first run printed, or a request withdrawn in between would agree with
//     itself.
//  6. Set the applied_* columns, if the requested values are still what step 5 read.
//
// A run that fails before step 6 has changed no database row, and the script puts the old .env back, so that the .env's
// own host, which decides a host nobody requested, is the one that worked and not the one that was refused (R34-r2-4). A
// second run repairs. Only that failure puts the old .env back: a Commit whose UPDATE was sent and did not answer clean
// may have moved the columns, and the script then keeps the new .env, which is the one the columns name (R34-r3-2). The window between step 6 and the recreate of the four services that the script ends with is the one
// the spec accepts.
//
// The third run (Prune), after the recreate has succeeded:
//
//  7. Remove every file of ours that no snippet of a host the .env names reads. Only now are the old containers gone, so
//     only now may the old host's snippet and pair, and with them its private key, leave the Caddy volume.
package domainapply

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/certcheck"
	"github.com/Kup1ng/CtrlZ-Panel/internal/intakeseal"
	"github.com/Kup1ng/CtrlZ-Panel/internal/nodeadmin"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// caddyTLSDir is where Caddy sees the directory this tool fills: the Caddy data volume is /data in its container
// (deploy/compose/docker-compose.yml). The one-shot mounts the same volume elsewhere, so the snippet names the path of the
// reader and not of the writer.
const caddyTLSDir = "/data/ctrlz-tls"

// Default hosts: the ones the Caddyfile and the compose file fall back to when nothing is set.
const (
	defaultPanelHost = "panel.localhost"
	defaultAdminHost = "admin.localhost"
)

// Source is the database side of the apply step; *store.Store is the real one.
type Source interface {
	DomainApplyLoad(ctx context.Context) (store.DomainSettings, []store.DomainApplyCert, error)
	DomainApplyCommit(ctx context.Context, in store.DomainApplyCommitIn) error
}

// Inputs is everything one run needs.
type Inputs struct {
	Source Source
	// EnvFile is the current deploy/compose/.env, read and never written.
	EnvFile string
	// PrevEnvFile (Commit only; empty when the script replaced nothing) is the .env as it was before the script's rename.
	// A host that nobody requested and no run applied is the .env's own value, and the first run read that value from the
	// old file. Read from the new one, the value would be whatever the first run printed, so a host the admin withdrew
	// between the two runs would agree with itself and go into force (R34-r3-1).
	PrevEnvFile string
	// TLSDir is the directory of the Caddy data volume this tool fills.
	TLSDir string
	// WebKey is the PEM of web_intake_key.
	WebKey []byte
	Now    time.Time
	// Roots replaces the embedded public roots. Only tests set it.
	Roots *x509.CertPool
	// Out receives the new .env (Apply only). Log receives one line for each host. Neither receives a key.
	Out io.Writer
	Log io.Writer
}

// install is a certificate chosen for a host, with the files it becomes.
type install struct {
	id    uuid.UUID
	chain []byte
	key   []byte
}

// target is one of the two hosts.
type target struct {
	kind certcheck.Kind
	host string
	inst *install // nil: no certificate, the host runs on Caddy's private CA
}

// plan is the decision of steps 1 and 2.
type plan struct {
	settings  store.DomainSettings
	envText   []byte // the .env as it is now
	envOut    []byte // the .env as it must become
	pairs     []envPair
	targets   []*target
	panelHost string
	adminHost string
}

// wipe clears the keys the plan holds.
func (p *plan) wipe() {
	for _, t := range p.targets {
		if t.inst != nil {
			clear(t.inst.key)
		}
	}
}

// makePlan reads and decides, and touches nothing.
func makePlan(ctx context.Context, in Inputs) (*plan, error) {
	settings, certs, err := in.Source.DomainApplyLoad(ctx)
	if err != nil {
		return nil, fmt.Errorf("read the domain settings: %w", err)
	}
	envText, err := os.ReadFile(in.EnvFile)
	if err != nil {
		return nil, fmt.Errorf("read the .env file: %w", err)
	}

	// The text the .env's own hosts are read from: the file as it was before the rename when the script replaced it.
	ownText := envText
	if in.PrevEnvFile != "" {
		if ownText, err = os.ReadFile(in.PrevEnvFile); err != nil {
			return nil, fmt.Errorf("read the previous .env file: %w", err)
		}
	}

	panelHost, err := pickHost("panel", settings.PanelHost, settings.AppliedPanelHost, envValue(ownText, envPanelHost), defaultPanelHost)
	if err != nil {
		return nil, err
	}
	adminHost, err := pickHost("admin", settings.AdminHost, settings.AppliedAdminHost, envValue(ownText, envAdminHost), defaultAdminHost)
	if err != nil {
		return nil, err
	}
	if panelHost == adminHost {
		// One name cannot serve both dashboards: they have separate cookies, containers and certificates.
		return nil, errors.New("the panel host and the admin host are the same name")
	}
	for _, z := range []string{settings.DNSZone, settings.PrevDNSZone} {
		if z != "" && !validZone(z) {
			return nil, errors.New("a DNS zone in the settings is not a zone name")
		}
	}
	// A host the nodes' zone covers would be answered by a node (R17). The route judges the same at the PUT; this is the
	// judgment at the moment a host is put in force, whichever of the four sources it came from.
	live := nodeadmin.DomainState{DNSZone: settings.DNSZone, PrevDNSZone: settings.PrevDNSZone, TransitionUntil: settings.TransitionUntil}.LiveZones(in.Now)
	for _, h := range []struct{ what, host string }{{"panel", panelHost}, {"admin", adminHost}} {
		for _, z := range live {
			if nodeadmin.Below(h.host, z) {
				return nil, fmt.Errorf("the %s host %s lies under the DNS zone %s", h.what, h.host, z)
			}
		}
	}

	roots := in.Roots
	if roots == nil {
		roots = certcheck.EmbeddedRoots()
	}
	p := &plan{settings: settings, envText: envText, panelHost: panelHost, adminHost: adminHost,
		targets: []*target{{kind: certcheck.Panel, host: panelHost}, {kind: certcheck.Admin, host: adminHost}}}
	for _, t := range p.targets {
		if t.inst, err = choose(certs, t, in, roots); err != nil {
			p.wipe()
			return nil, err
		}
	}
	p.pairs = []envPair{
		{envPanelHost, panelHost},
		{envAdminHost, adminHost},
		{envVerifyOrigin, verifyOrigins(settings.DNSZone, settings.PrevDNSZone, settings.TransitionUntil, in.Now)},
	}
	if p.envOut, err = setEnv(envText, p.pairs); err != nil {
		p.wipe()
		return nil, err
	}
	// The script refuses an .env without the layout marker, and only after the first run is over: refuse it here, before any
	// file is written (R34-r1-7).
	if !envMarker.Match(p.envOut) {
		p.wipe()
		return nil, errors.New("the .env has no CTRLZ_ENV_FORMAT_2 line: run scripts/select-profile.sh first")
	}
	return p, nil
}

// Apply is the first run: steps 1 to 4 of the package comment.
func Apply(ctx context.Context, in Inputs) error {
	p, err := makePlan(ctx, in)
	if err != nil {
		return err
	}
	defer p.wipe()
	if err := writeFiles(in.TLSDir, p.targets); err != nil {
		return err
	}
	if _, err := in.Out.Write(p.envOut); err != nil {
		return fmt.Errorf("write the new .env to the output: %w", err)
	}
	return nil
}

// Commit is the second run: steps 5 and 6. EnvFile is the .env the script has put in place by now.
func Commit(ctx context.Context, in Inputs) error {
	p, err := makePlan(ctx, in)
	if err != nil {
		return err
	}
	defer p.wipe()
	for _, kv := range p.pairs {
		if envValue(p.envText, kv.key) != kv.value {
			return errors.New("the .env does not hold the hosts this run plans (the settings moved since the first run, or the file was not replaced); run domain-apply.sh again")
		}
	}
	for _, t := range p.targets {
		if err := checkSnippet(in.TLSDir, t); err != nil {
			return err
		}
	}

	commit := store.DomainApplyCommitIn{Seen: p.settings, PanelHost: p.panelHost, AdminHost: p.adminHost}
	// A host nobody requested and no earlier run applied came from the .env or the default. Recording it would pin it in
	// the database, where it wins over the .env from then on, so it stays NULL and the .env keeps deciding.
	if p.settings.PanelHost == "" && p.settings.AppliedPanelHost == "" {
		commit.PanelHost = ""
	}
	if p.settings.AdminHost == "" && p.settings.AppliedAdminHost == "" {
		commit.AdminHost = ""
	}
	if p.targets[0].inst != nil {
		commit.PanelCert = &p.targets[0].inst.id
	}
	if p.targets[1].inst != nil {
		commit.AdminCert = &p.targets[1].inst.id
	}
	if err := in.Source.DomainApplyCommit(ctx, commit); err != nil {
		if errors.Is(err, store.ErrDomainChanged) {
			// The UPDATE matched no row: nothing was recorded.
			return fmt.Errorf("record the applied values: %w", err)
		}
		// A lost connection can drop the answer of an UPDATE that went through.
		return &outcomeUnknownError{fmt.Errorf("record the applied values: %w", err)}
	}
	for _, t := range p.targets {
		if t.inst != nil {
			fmt.Fprintf(in.Log, "%s host %s: certificate %s\n", t.kind, t.host, t.inst.id)
		} else {
			fmt.Fprintf(in.Log, "%s host %s: no usable certificate, Caddy's private CA serves it\n", t.kind, t.host)
		}
	}
	return nil
}

// outcomeUnknownError is Commit's answer when the UPDATE was sent and the result did not come back clean: the columns may
// have moved. Every other Commit error happened before the UPDATE or was its "no row matched", so nothing was recorded.
// The script restores the old .env only for those, and asks again for this one (R34-r3-2).
type outcomeUnknownError struct{ err error }

func (e *outcomeUnknownError) Error() string { return e.err.Error() }
func (e *outcomeUnknownError) Unwrap() error { return e.err }

// OutcomeUnknown says whether err is a Commit failure after which the applied_* columns may have moved.
func OutcomeUnknown(err error) bool {
	var u *outcomeUnknownError
	return errors.As(err, &u)
}

// pickHost is the host a service answers on: the requested one, else the one served now, else what the .env says now
// (the install's own choice before any domain was set), else the default. Each candidate is judged by the grammar; a
// candidate that fails is an error and not a reason to try the next, since a wrong value silently replaced by another
// is a host nobody asked for. A host also has to fit in the name of its Caddy snippet.
func pickHost(what, requested, applied, current, def string) (string, error) {
	for _, h := range []string{requested, applied, current} {
		if h == "" {
			continue
		}
		if !validHost(h) {
			return "", fmt.Errorf("the %s host is not a hostname", what)
		}
		if len(h) > nodeadmin.MaxServedHost {
			return "", fmt.Errorf("the %s host is longer than %d characters, too long for the name of its Caddy snippet", what, nodeadmin.MaxServedHost)
		}
		return h, nil
	}
	return def, nil
}

// choose picks the certificate for a host by the one rule of 4.3 and opens its key. A host with no certificate that
// passes the rule gets nil, and runs on the private CA; a chosen row whose key does not open or does not belong to its
// leaf is an error, because that is a damaged row and not a reason to serve another certificate in silence.
func choose(certs []store.DomainApplyCert, t *target, in Inputs, roots *x509.CertPool) (*install, error) {
	var rows []certcheck.Row
	sealed := map[uuid.UUID][]byte{}
	for _, c := range certs {
		if c.Kind != string(t.kind) {
			continue
		}
		rows = append(rows, certcheck.Row{ID: c.ID, State: "active", ChainPEM: c.ChainPEM})
		sealed[c.ID] = c.SealedKey
	}
	scope := certcheck.Scope{Host: t.host}
	row, _, ok := certcheck.Choose(rows, t.kind, scope, in.Now, certcheck.Options{Roots: roots})
	if !ok {
		return nil, nil
	}
	keyPEM, err := intakeseal.Open(in.WebKey, intakeseal.Web, sealed[row.ID])
	if err != nil {
		return nil, fmt.Errorf("the key of certificate %s does not open with web_intake_key", row.ID)
	}
	pub, pkcs8, err := certcheck.ParseKey(keyPEM)
	clear(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("the key of certificate %s is not a private key", row.ID)
	}
	res, err := certcheck.Check([]byte(row.ChainPEM), t.kind, scope, in.Now, certcheck.Options{Roots: roots, KeyPublic: pub})
	if err != nil {
		clear(pkcs8)
		return nil, fmt.Errorf("the key of certificate %s does not belong to it: %w", row.ID, err)
	}
	return &install{id: row.ID, chain: []byte(res.ChainPEM), key: pkcs8}, nil
}

// snippetName is the file Caddy imports for a host. The Caddyfile imports it by a glob with one `?`, so a missing file is
// no error there.
func snippetName(host string) string { return host + ".caddy" }

// pairNames are the certificate and key files of an install. The kind and the certificate id are in the name and the host
// is not: the host is already in the snippet's name, and a long host would push this name past the 255 bytes of a file
// name (R34-r1-12). A new certificate for the same host is a new pair beside the old one until the snippet moves.
func pairNames(kind certcheck.Kind, id uuid.UUID) (crt, key string) {
	return string(kind) + "." + id.String() + ".crt", string(kind) + "." + id.String() + ".key"
}

// snippetText is the content of the snippet of an install.
func snippetText(kind certcheck.Kind, id uuid.UUID) string {
	crt, key := pairNames(kind, id)
	return "# Written by ctrlz domain-apply; the Caddyfile imports it. Do not edit.\n" +
		"tls " + caddyTLSDir + "/" + crt + " " + caddyTLSDir + "/" + key + "\n"
}

// writeFiles puts the pairs in place, then the snippets. It removes nothing that a running container may read: the old
// host's snippet and pair, and the pair a new certificate replaces, stay until Prune runs after the recreate. Removing
// them here would take them from the old Caddy while it still runs, on the first run and, worse, on the second run the
// script asks for after a failed commit or recreate, when the .env already names the new hosts (R34-r2-1, r2-5).
func writeFiles(dir string, targets []*target) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("make the certificate directory: %w", err)
	}
	for _, t := range targets {
		if t.inst == nil {
			continue
		}
		crt, key := pairNames(t.kind, t.inst.id)
		if err := writeAtomic(dir, crt, t.inst.chain, 0o600); err != nil {
			return fmt.Errorf("write the certificate of the %s host: %w", t.kind, err)
		}
		if err := writeAtomic(dir, key, t.inst.key, 0o600); err != nil {
			return fmt.Errorf("write the key of the %s host: %w", t.kind, err)
		}
	}
	for _, t := range targets {
		if t.inst == nil {
			// A host with no certificate that passes the rule has no snippet and runs on the private CA. A snippet left
			// by an earlier plan would keep naming a certificate the rule no longer accepts.
			if err := os.Remove(snippetPath(dir, t.host)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove the snippet of the %s host: %w", t.kind, err)
			}
			continue
		}
		if err := writeAtomic(dir, snippetName(t.host), []byte(snippetText(t.kind, t.inst.id)), 0o600); err != nil {
			return fmt.Errorf("write the snippet of the %s host: %w", t.kind, err)
		}
	}
	return nil
}

// Prune is the third run, `domain-apply --prune`, which the script makes only after the recreate has succeeded. The
// running containers are then the ones of the .env in place, so whatever no snippet of a host that .env names reads is
// read by nothing: the pairs and snippets of a host that was moved away, the pair a new certificate replaced, and the
// leftovers of a crashed run. The old host's private key leaves the Caddy volume here and not before (R34-r2-6). It reads
// the .env and the directory and touches no database row. What those snippets name stays whatever the settings say now:
// a change made since the commit is not in force until the next run.
func Prune(in Inputs) error {
	envText, err := os.ReadFile(in.EnvFile)
	if err != nil {
		return fmt.Errorf("read the .env file: %w", err)
	}
	keep := map[string]bool{}
	if err := keepNamed(in.TLSDir, servedHosts(envText), keep); err != nil {
		// Nothing is removed: what cannot be read as it is must not be judged stale.
		return fmt.Errorf("keep the files of the served hosts: %w", err)
	}
	if err := prune(in.TLSDir, keep); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale certificate files: %w", err)
	}
	return nil
}

// checkSnippet says the directory holds the snippet the plan makes for a target, or none when the plan has no
// certificate for it. It is what ties the certificate ids Commit records to the files Caddy reads.
func checkSnippet(dir string, t *target) error {
	got, err := os.ReadFile(snippetPath(dir, t.host))
	if t.inst == nil {
		if err == nil {
			return fmt.Errorf("the %s host has a snippet but the plan has no certificate for it; run domain-apply.sh again", t.kind)
		}
		return nil
	}
	if err != nil || string(got) != snippetText(t.kind, t.inst.id) {
		return fmt.Errorf("the snippet of the %s host is not the one this run plans (the certificates changed since the first run); run domain-apply.sh again", t.kind)
	}
	return nil
}

// servedHosts are the hosts the .env names now. Prune runs after the recreate, so these are the hosts the running
// containers belong to.
func servedHosts(envText []byte) []string {
	h := func(key, def string) string {
		if v := envValue(envText, key); v != "" {
			return v
		}
		return def
	}
	return []string{h(envPanelHost, defaultPanelHost), h(envAdminHost, defaultAdminHost)}
}
