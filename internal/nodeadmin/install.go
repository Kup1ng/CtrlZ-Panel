package nodeadmin

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/manifest"
)

// ErrNoInstall is returned when what the install command is made of is not there: no pin file yet (the hub
// has not started), no root.json, or no node bundle whose manifest verifies. The route answers 503 and
// creates no enrolment, because a token whose command cannot be shown would only expire.
var ErrNoInstall = errors.New("nodeadmin: the install files are not available")

// nodeScriptPath is the file of a node bundle the command downloads first; the hub serves the same one
// (internal/hub/hubinstall).
const nodeScriptPath = "packaging/install/node.sh"

const (
	maxFile = 1 << 20
	// hubPort is the node port the hub listens on (p4-nodes open question 1).
	hubPort = "9443"
	// pinFile is what the hub writes to the volume it shares read-only with admin (3.3).
	pinFile = "hub_tls.spki"
)

// InstallConfig is what the command is made from. Public and Bundles are file systems, so a test uses an
// in-memory one and production passes the two read-only volumes.
type InstallConfig struct {
	// HubHost is CTRLZ_HUB_HOST, comma separated; the first entry is the host the command names.
	HubHost string
	// Public holds hub_tls.spki, Bundles holds root.json and node/<version>/manifest.json.
	Public, Bundles fs.FS
	// DenyRootKeys are key ids (hex) a production root must not hold (the lab test root's).
	DenyRootKeys []string
}

// Installer makes the install command of 4.2 step 1.
type Installer struct {
	host string
	cfg  InstallConfig
}

// NewInstaller checks the host list. A host that is not a name or an address the script accepts is refused
// at start, because the command is a line the admin pastes into a root shell.
func NewInstaller(cfg InstallConfig) (*Installer, error) {
	first, _, _ := strings.Cut(cfg.HubHost, ",")
	first = strings.TrimSpace(first)
	if first == "" || len(first) > 253 {
		return nil, errors.New("nodeadmin: no hub host")
	}
	for _, c := range first {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '.' || c == '-' || c == ':') {
			return nil, errors.New("nodeadmin: the hub host has a character the install script refuses")
		}
	}
	if cfg.Public == nil || cfg.Bundles == nil {
		return nil, errors.New("nodeadmin: the install files are not mounted")
	}
	if strings.Contains(first, ":") { // an IPv6 literal is written in brackets in a URL and for --hub
		first = "[" + first + "]"
	}
	return &Installer{host: first, cfg: cfg}, nil
}

// EnrollAddrs are the four addresses of a new node (4.2 step 1).
type EnrollAddrs struct {
	DNSBind, DNSAdv, ProxyBind, ProxyAdv netip.Addr
}

// Command is the line shown once. token is the 43 characters of hubtoken.New. The line starts with a space so
// that Ubuntu's default HISTCONTROL=ignoreboth keeps it out of the shell history; the token goes to the script
// on stdin through the builtin printf, so it is in no process list.
func (i *Installer) Command(token string, a EnrollAddrs, now time.Time) (string, error) {
	pin, err := i.pin()
	if err != nil {
		return "", err
	}
	rootJSON, root, err := i.root()
	if err != nil {
		return "", err
	}
	script, err := i.scriptHash(root, now)
	if err != nil {
		return "", err
	}
	rootSum := sha256.Sum256(rootJSON)
	var b strings.Builder
	b.WriteString(" curl -k --pinnedpubkey sha256//" + pin + " -o /tmp/ctrlz-node.sh https://" + i.host + ":" + hubPort + "/install/node.sh")
	b.WriteString(" && echo '" + script + "  /tmp/ctrlz-node.sh' | sha256sum -c")
	b.WriteString(" && printf %s '" + token + "' | sudo sh /tmp/ctrlz-node.sh --hub " + i.host + " --pin sha256//" + pin)
	b.WriteString(" --token-stdin --root " + hex.EncodeToString(rootSum[:]))
	b.WriteString(" --dns-bind-ip " + AddrText(a.DNSBind) + " --dns-advertised-ip " + AddrText(a.DNSAdv))
	b.WriteString(" --proxy-bind-ip " + AddrText(a.ProxyBind) + " --proxy-advertised-ip " + AddrText(a.ProxyAdv))
	return b.String(), nil
}

func readCapped(fsys fs.FS, name string) ([]byte, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, ErrNoInstall
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil || len(b) > maxFile {
		return nil, ErrNoInstall
	}
	return b, nil
}

// pin is the text after sha256// in curl's --pinnedpubkey: the standard base64 of 32 bytes.
func (i *Installer) pin() (string, error) {
	b, err := readCapped(i.cfg.Public, pinFile)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != sha256.Size {
		return "", ErrNoInstall
	}
	return s, nil
}

func (i *Installer) root() ([]byte, *signv1.Root, error) {
	b, err := readCapped(i.cfg.Bundles, "root.json")
	if err != nil {
		return nil, nil, err
	}
	root := &signv1.Root{}
	if err := (protojson.UnmarshalOptions{}).Unmarshal(b, root); err != nil {
		return nil, nil, ErrNoInstall
	}
	for _, k := range root.GetKeys() {
		id := hex.EncodeToString(k.GetKeyId())
		for _, d := range i.cfg.DenyRootKeys {
			if id == d {
				return nil, nil, ErrNoInstall
			}
		}
	}
	return b, root, nil
}

// scriptHash is the SHA-256 of node.sh as the newest node bundle whose manifest verifies lists it. The
// manifest is checked against the root first (the signature before anything is parsed), the way the hub
// checks it before it serves the file, so the admin is never shown the hash of a bundle the hub will not
// serve. A newer directory that does not verify (a half-copied release) is skipped, as the hub skips it.
func (i *Installer) scriptHash(root *signv1.Root, now time.Time) (string, error) {
	ents, err := fs.ReadDir(i.cfg.Bundles, "node")
	if err != nil {
		return "", ErrNoInstall
	}
	var versions []uint64
	for _, e := range ents {
		if v, ok := parseVersion(e.Name()); ok && e.IsDir() {
			versions = append(versions, v)
		}
	}
	for len(versions) > 0 {
		best, at := versions[0], 0
		for k, v := range versions {
			if v > best {
				best, at = v, k
			}
		}
		versions = append(versions[:at], versions[at+1:]...)
		if h, ok := i.bundleScript(root, best, now); ok {
			return h, nil
		}
	}
	return "", ErrNoInstall
}

func (i *Installer) bundleScript(root *signv1.Root, version uint64, now time.Time) (string, bool) {
	raw, err := readCapped(i.cfg.Bundles, "node/"+strconv.FormatUint(version, 10)+"/manifest.json")
	if err != nil {
		return "", false
	}
	env := &signv1.Envelope{}
	if err := (protojson.UnmarshalOptions{}).Unmarshal(raw, env); err != nil {
		return "", false
	}
	m, err := manifest.VerifyManifest(env, root, signv1.Kind_KIND_NODE, now.Unix())
	if err != nil || m.GetVersion() != version || manifest.CheckManifestFresh(m, now.Unix(), 0) != nil {
		return "", false
	}
	if _, err := manifest.NewIndex(m); err != nil {
		return "", false
	}
	for _, f := range m.GetFiles() {
		if f.GetPath() == nodeScriptPath && len(f.GetSha256()) == sha256.Size {
			return hex.EncodeToString(f.GetSha256()), true
		}
	}
	return "", false
}

func parseVersion(s string) (uint64, bool) {
	if s == "" || len(s) > 18 || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 64)
	return v, err == nil && v > 0
}
