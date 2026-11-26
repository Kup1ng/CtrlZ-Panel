package hubtrust

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubpki"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The NTS leaf of the panel host's chrony (p4-nodes 7.10, T-087). Nodes take their time from the panel over NTS and trust only
// the node CA for it (nosystemcert), so chrony's NTS-KE server needs a certificate that CA signed, for the name the nodes dial.
// The hub is the one process that holds the CA key, so it writes the leaf into the directory the host's chrony reads
// (deploy/chrony/nts/, bind-mounted into the hub) when it is missing or a third of its life is left.
//
// chrony reads the files only at start, so writing them is not enough: the operator restarts chrony, and the hub says so with an
// alert. The key is a fresh one made for this leaf and kept in no table: the file is its only copy, and a lost file is a new
// leaf and one more restart.

// NTS file names, read by deploy/chrony/panel.conf (ntsservercert, ntsserverkey).
const (
	NTSCertFile = "nts.crt"
	NTSKeyFile  = "nts.key"

	// ntsOwedFile marks an alert that is owed: it is written before the leaf and removed once the alert is in the database,
	// so a database that fails at that moment, or a hub that restarts, still gets the operator told to restart chrony.
	ntsOwedFile = ".nts-restart-owed"
)

// NTS keeps the files current.
type NTS struct {
	CA     *hubpki.NodeCA
	Dir    string
	Hosts  string // CTRLZ_HUB_HOST: the names the nodes dial, which are the leaf's SANs
	Now    func() time.Time
	Alerts Alerter
	Log    *slog.Logger // may be nil; it carries the one warning that a renewed key lost its group

	chgrp func(path string, uid, gid int) error // os.Chown unless a test says otherwise
}

// Ensure writes a leaf when the directory has none that is usable, and says whether it did. A usable leaf is one the current
// node CA signed, for the wanted names, matched by the key file beside it, with more than a third of its life left. An alert
// asks the operator to restart chrony after every write (the first one included, because chrony cannot have started on files
// that did not exist); a failed write returns the error and raises none. An alert that could not be stored is owed, and the next
// pass raises it before anything else, so the one signal the operator is given is never lost with a failed insert.
func (n *NTS) Ensure(ctx context.Context) (bool, error) {
	dns, ips, err := hubpki.Names(n.Hosts)
	if err != nil {
		return false, fmt.Errorf("hubtrust: the NTS names: %w", err)
	}
	now := n.Now()
	if n.usable(dns, ips, now) {
		return false, n.settle(ctx)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return false, err
	}
	iss, err := n.CA.IssueServer(&key.PublicKey, "ctrlz-ntp", dns, ips, hubpki.NTSLife, now)
	if err != nil {
		return false, err
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return false, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder})
	// The leaf and the node CA, so a client that holds only a part of the chain still verifies it.
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: iss.DER}), n.CA.PEM()...)
	// The key goes first: a reader that finds the new certificate always finds its key, and a crash between the two leaves the
	// old certificate over a new key, which usable() sees as a mismatch and replaces on the next pass.
	// The debt is recorded first: if this is the file that cannot be written nothing else was, and no alert is wanted.
	// A marker an earlier pass left is a debt for a leaf that is already on disk (its alert insert failed); this call may remove
	// only a marker it made itself, or a disk error here would erase that debt and nobody would be told to restart chrony (GP-r1-3).
	owed := filepath.Join(n.Dir, ntsOwedFile)
	_, statErr := os.Stat(owed)
	hadDebt := statErr == nil
	if err := os.WriteFile(owed, nil, 0o600); err != nil {
		return false, err
	}
	keptGroup, err := writeAtomic(n.chown(), filepath.Join(n.Dir, NTSKeyFile), keyPEM, 0o640)
	if err != nil {
		if !hadDebt {
			_ = os.Remove(owed)
		}
		return false, err
	}
	if !keptGroup && n.Log != nil {
		// Said at the write, before the restart the operator is asked for: afterwards chrony may not read the key and NTS-KE
		// is down for every node. No path, no key, no group id in the text.
		n.Log.Warn("the renewed NTS key could not keep the group of the old one; give chrony a default ACL on the NTS directory (deploy/chrony/panel.conf) or it may not read the key after its restart")
	}
	if _, err := writeAtomic(n.chown(), filepath.Join(n.Dir, NTSCertFile), chain, 0o644); err != nil {
		// The key is new and the certificate old: usable() sees the mismatch, the next pass writes both again, and the debt
		// stays until that pass pays it.
		return false, err
	}
	return true, n.settle(ctx)
}

// settle pays an owed alert and clears the debt. A failure leaves the debt for the next pass; the leaf itself is already
// written, so the caller learns the alert failed and not that the leaf did.
func (n *NTS) settle(ctx context.Context) error {
	owed := filepath.Join(n.Dir, ntsOwedFile)
	if _, err := os.Stat(owed); err != nil {
		return nil
	}
	if n.Alerts != nil {
		// Names only: the alert carries no key, path or serial.
		if err := n.Alerts.HubAlert(ctx, "warning", store.HubAlertNTSLeafWritten, map[string]string{"action": "restart_chrony"}); err != nil {
			return fmt.Errorf("hubtrust: the NTS alert: %w", err)
		}
	}
	return os.Remove(owed)
}

// usable reads the two files back and judges them. Anything unreadable is not usable: the answer to every doubt is a new leaf.
func (n *NTS) usable(dns []string, ips []net.IP, now time.Time) bool {
	certPEM, err := os.ReadFile(filepath.Join(n.Dir, NTSCertFile))
	if err != nil {
		return false
	}
	keyPEM, err := os.ReadFile(filepath.Join(n.Dir, NTSKeyFile))
	if err != nil {
		return false
	}
	blk, _ := pem.Decode(certPEM)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return false
	}
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return false
	}
	kblk, _ := pem.Decode(keyPEM)
	if kblk == nil {
		return false
	}
	k, err := x509.ParsePKCS8PrivateKey(kblk.Bytes)
	if err != nil {
		return false
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok || !ek.PublicKey.Equal(leaf.PublicKey) {
		return false
	}
	// Signed by the CA in force now: a node CA that was replaced orphans every leaf of the old one.
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: n.CA.Pool(), CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return false
	}
	// The names the nodes dial are the names the leaf has: a changed CTRLZ_HUB_HOST needs a new leaf.
	have := slices.Clone(leaf.DNSNames)
	want := slices.Clone(dns)
	slices.Sort(have)
	slices.Sort(want)
	if !slices.Equal(have, want) || len(leaf.IPAddresses) != len(ips) {
		return false
	}
	for _, ip := range ips {
		if !slices.ContainsFunc(leaf.IPAddresses, ip.Equal) {
			return false
		}
	}
	life := leaf.NotAfter.Sub(leaf.NotBefore)
	return leaf.NotAfter.Sub(now) > life/3
}

// writeAtomic writes a file through a temporary file and a rename, so chrony never reads half of one.
// keptGroup is false when the group of the file it replaces could not be handed on.
func writeAtomic(chown func(string, int, int) error, path string, data []byte, mode os.FileMode) (keptGroup bool, err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".nts-*")
	if err != nil {
		return true, err
	}
	name := tmp.Name()
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	// A file renamed over another is a new inode, and the operator's grant for chrony (a group, or an ACL entry) sat on the old
	// one. Keep the group where the process may; an ACL needs the directory's default ACL (deploy/chrony/panel.conf says so).
	keptGroup = keepGroup(chown, path, name)
	if err := errors.Join(werr, cerr, os.Chmod(name, mode)); err != nil {
		_ = os.Remove(name)
		return keptGroup, err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return keptGroup, err
	}
	return keptGroup, nil
}

func (n *NTS) chown() func(string, int, int) error {
	if n.chgrp != nil {
		return n.chgrp
	}
	return os.Chown
}
