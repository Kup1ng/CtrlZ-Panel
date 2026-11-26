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
)

// NTS keeps the files current.
type NTS struct {
	CA     *hubpki.NodeCA
	Dir    string
	Hosts  string // CTRLZ_HUB_HOST: the names the nodes dial, which are the leaf's SANs
	Now    func() time.Time
	Alerts Alerter
}

// Ensure writes a leaf when the directory has none that is usable, and says whether it did. A usable leaf is one the current
// node CA signed, for the wanted names, matched by the key file beside it, with more than a third of its life left. An alert
// asks the operator to restart chrony after every write (the first one included, because chrony cannot have started on files
// that did not exist); a failed write returns the error and raises none.
func (n *NTS) Ensure(ctx context.Context) (bool, error) {
	dns, ips, err := hubpki.Names(n.Hosts)
	if err != nil {
		return false, fmt.Errorf("hubtrust: the NTS names: %w", err)
	}
	now := n.Now()
	if n.usable(dns, ips, now) {
		return false, nil
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
	if err := writeAtomic(filepath.Join(n.Dir, NTSKeyFile), keyPEM, 0o640); err != nil {
		return false, err
	}
	if err := writeAtomic(filepath.Join(n.Dir, NTSCertFile), chain, 0o644); err != nil {
		return false, err
	}
	if n.Alerts != nil {
		// Names only: the alert carries no key, path or serial.
		if err := n.Alerts.HubAlert(ctx, "warning", store.HubAlertNTSLeafWritten, map[string]string{"action": "restart_chrony"}); err != nil {
			return true, fmt.Errorf("hubtrust: the NTS alert: %w", err)
		}
	}
	return true, nil
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
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".nts-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if err := errors.Join(werr, cerr, os.Chmod(name, mode)); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}
