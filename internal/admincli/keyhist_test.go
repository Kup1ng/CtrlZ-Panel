package admincli_test

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// Generated key histories (review round 5, rule key-identity).
//
// A history is a host: which kek_root is on disk, which lines each kek_<domain>
// file holds, and which sealed values the database holds. Every line and every
// value records the ROOT THAT MADE IT, which the code under test can never see.
// That provenance is the ground truth: a key tool is right when what it does
// agrees with it, and a tool that guessed from a key number or from a file being
// there agrees only by accident. Numbers repeat across roots on purpose: after a
// total loss the host regenerates the root and the files, and key 1 is a different
// key that the old seeds still name.

// rootID names a kek_root by the install it belongs to; its bytes derive from it.
type rootID string

func (r rootID) raw() []byte {
	h := sha256.Sum256([]byte("keyhist root " + string(r)))
	return h[:]
}

func (r rootID) secret() secret.Bytes { return secret.NewBytes(r.raw()) }

// keyLine is one numbered line of a key file and the root that derived it.
type keyLine struct {
	n    uint16
	from rootID
}

// stored is a sealed value in the database: its domain, the row slot it sits in,
// the key number its header names and the root whose key sealed it. slot picks the
// row: user_totp 0 and 1 are tenant A's and B's users, sms_cred 0 and 1 are two
// gateways, admin_totp 0 is the seed admin.
type stored struct {
	domain string
	slot   int
	n      uint16
	from   rootID
}

// slots is how many rows each database domain has room for in the fixtures.
func slots() map[string]int {
	return map[string]int{keyring.DomainUserTOTP: 2, keyring.DomainAdminTOTP: 1, keyring.DomainSMSCred: 2}
}

// dbDomains lists the domains with a sealed column the tools read.
func dbDomains() []string {
	return []string{keyring.DomainUserTOTP, keyring.DomainAdminTOTP, keyring.DomainSMSCred}
}

type history struct {
	name  string
	disk  rootID               // kek_root on the host; "" when it is not there
	files map[string][]keyLine // kek_<domain> on the host; a missing key is a missing file
	data  []stored
}

func (h history) clone(name string) history {
	c := history{name: name, disk: h.disk, files: map[string][]keyLine{}, data: slices.Clone(h.data)}
	for d, ls := range h.files {
		c.files[d] = slices.Clone(ls)
	}
	return c
}

func empty() history { return history{name: "fresh install", files: map[string][]keyLine{}} }

// install is what gen-secrets.sh does on a bare host: a root and key 1 of every domain.
func (h history) install(name string, root rootID) history {
	c := h.clone(name)
	c.disk = root
	for _, d := range keyring.Domains() {
		c.files[d] = []keyLine{{1, root}}
	}
	return c
}

// seal puts a value in a slot under a given key, replacing what was there.
func (h history) seal(name, domain string, slot int, n uint16, from rootID) history {
	c := h.clone(name)
	c.data = slices.DeleteFunc(c.data, func(s stored) bool { return s.domain == domain && s.slot == slot })
	c.data = append(c.data, stored{domain, slot, n, from})
	return c
}

// sealCurrent seals every slot of every database domain under the key the file
// holds now, the way a running install fills its columns.
func (h history) sealCurrent(name string) history {
	c := h.clone(name)
	for _, d := range dbDomains() {
		ls := c.files[d]
		top := ls[len(ls)-1]
		for slot := 0; slot < slots()[d]; slot++ {
			c = c.seal(name, d, slot, top.n, top.from)
		}
	}
	return c
}

func (h history) rotate(name string, from rootID) history {
	c := h.clone(name)
	for d, ls := range c.files {
		c.files[d] = append(ls, keyLine{ls[len(ls)-1].n + 1, from})
	}
	return c
}

func (h history) withRoot(name string, root rootID) history {
	c := h.clone(name)
	c.disk = root
	return c
}

func (h history) deleteFile(name, domain string) history {
	c := h.clone(name)
	delete(c.files, domain)
	return c
}

// regenerate is the total loss of 8.5: root and every key file made again from
// nothing, key 1 under a different root, the sealed values untouched.
func (h history) regenerate(name string, root rootID) history {
	c := h.clone(name)
	c.disk = root
	for _, d := range keyring.Domains() {
		c.files[d] = []keyLine{{1, root}}
	}
	return c
}

// histories is the set every key command is run over.
func histories() []history {
	installed := empty().install("installed", "A").sealCurrent("installed")
	rotated := installed.rotate("rotated", "A").
		seal("rotated", keyring.DomainUserTOTP, 1, 2, "A").
		seal("rotated", keyring.DomainSMSCred, 1, 2, "A")
	deleted := installed.withRoot("root deleted", "")
	regenerated := deleted.withRoot("root regenerated", "B")
	ontoNew := regenerated.rotate("rotated onto a new root", "B").
		seal("rotated onto a new root", keyring.DomainUserTOTP, 1, 2, "B").
		seal("rotated onto a new root", keyring.DomainSMSCred, 1, 2, "B")
	lost := installed.regenerate("total loss, number 1 reused", "B")
	partial := empty().withRoot("interrupted install", "A")
	for _, d := range keyring.Domains()[:3] {
		partial.files[d] = []keyLine{{1, "A"}}
	}
	return []history{
		empty(),
		installed,
		rotated,
		deleted,
		regenerated,
		installed.withRoot("wrong backup restored", "C"),
		rotated.withRoot("wrong backup after a rotation", "C"),
		ontoNew,
		ontoNew.withRoot("old backup after a new root", "A"),
		lost,
		lost.seal("total loss, one value enrolled after", keyring.DomainUserTOTP, 0, 1, "B"),
		// Number 1 names two different keys at once: one gateway credential entered again under the new
		// kek_sms_cred opens, the other still under the old one does not (admin-r14-2).
		lost.seal("total loss, one gateway credential entered after", keyring.DomainSMSCred, 0, 1, "B"),
		lost.seal("total loss, every gateway credential entered after", keyring.DomainSMSCred, 0, 1, "B").
			seal("total loss, every gateway credential entered after", keyring.DomainSMSCred, 1, 1, "B"),
		installed.deleteFile("one key file missing", keyring.DomainUserTOTP),
		// The root is off the host and a release added a key domain (or a file was lost): the files that
		// are there cannot be proved and the missing one cannot be made (admin-r14-7).
		deleted.deleteFile("root deleted and one key file missing", keyring.DomainUserTOTP),
		partial,
	}
}

// fileText renders a domain's key file with each line derived from the root that
// made it.
func (h history) fileText(domain string) []byte {
	var b strings.Builder
	b.WriteString("# ctrlz keyring domain=" + domain + "\n")
	for _, l := range h.files[domain] {
		text, err := keyring.FileText(l.from.secret(), domain, l.n)
		if err != nil {
			panic(err)
		}
		_, line, _ := strings.Cut(string(text.Reveal()), "\n")
		b.WriteString(line)
	}
	return []byte(b.String())
}

// write puts the host on disk the way an operator would have left it.
func (h history) write(t testing.TB, dir string) {
	t.Helper()
	if h.disk != "" {
		if err := os.WriteFile(filepath.Join(dir, "kek_root"), h.disk.raw(), 0o400); err != nil {
			t.Fatal(err)
		}
	}
	for d := range h.files {
		if err := os.WriteFile(filepath.Join(dir, "kek_"+d), h.fileText(d), 0o444); err != nil {
			t.Fatal(err)
		}
		// The public half of a signing domain sits beside its key file, as derive left it (D67).
		if slices.Contains(keyring.PublicDomains(), d) {
			if err := os.WriteFile(filepath.Join(dir, keyring.PublicFileName(d)), h.publicText(t, d), 0o444); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// publicText is the public key file the host holds for a signing domain: a pure function of its key file.
func (h history) publicText(t testing.TB, domain string) []byte {
	t.Helper()
	out, err := keyring.PublicText(domain, secret.NewBytes(h.fileText(domain)))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// ring loads the domains the way a container does. It reports false when a file
// is missing, which is the start-up refusal of 18.3 and not a key decision.
func (h history) ring(t testing.TB, domains ...string) (*keyring.Ring, bool) {
	t.Helper()
	dir := t.TempDir()
	h.write(t, dir)
	r, err := keyring.Load(dir, domains...)
	if err != nil {
		return nil, false
	}
	return r, true
}

// ---- ground truth ----------------------------------------------------------

// derivePlan is what `keys derive` must do on this host.
type derivePlan struct {
	ok      bool
	created []string // the files that did not exist and are made from the root
	// refusedMissing: the derive refuses and a key file is also missing, so nothing was written and the
	// file was not made either (admin-r14-7). It has its own exit code, which gen-secrets must not carry on after.
	refusedMissing bool
}

// deriveTruth: the root is the only authority. A file belongs to it when the
// newest key in it is the key the root derives (any older line may be history from
// an earlier root); a file that does not belong is refused with nothing written,
// unless the operator asked for a new root by name.
func (h history) deriveTruth(newRoot bool) derivePlan {
	if h.disk == "" {
		return derivePlan{}
	}
	var created []string
	for _, d := range keyring.Domains() {
		ls := h.files[d]
		if len(ls) == 0 {
			created = append(created, d)
			continue
		}
		if ls[len(ls)-1].from != h.disk && !newRoot {
			return derivePlan{refusedMissing: hasMissingFile(h)}
		}
	}
	return derivePlan{ok: true, created: created}
}

// hasMissingFile says some domain has no key file on the host.
func hasMissingFile(h history) bool {
	for _, d := range keyring.Domains() {
		if len(h.files[d]) == 0 {
			return true
		}
	}
	return false
}

// rotateTruth: appends top+1 derived from the root when the file belongs to the
// root (or the operator said new root); refuses otherwise, and when there is no
// file to extend.
func (h history) rotateTruth(domain string, newRoot bool) (ok bool, next uint16) {
	ls := h.files[domain]
	if h.disk == "" || len(ls) == 0 {
		return false, 0
	}
	top := ls[len(ls)-1]
	if top.from != h.disk && !newRoot {
		return false, 0
	}
	return true, top.n + 1
}

// opens: a value opens exactly when the container's file holds the line that
// sealed it. The number alone is not enough and neither is the file's presence.
func (h history) opens(s stored) bool {
	for _, l := range h.files[s.domain] {
		if l.n == s.n && l.from == s.from {
			return true
		}
	}
	return false
}

func (h history) newest(domain string) uint16 {
	ls := h.files[domain]
	if len(ls) == 0 {
		return 0
	}
	return ls[len(ls)-1].n
}

func (h history) dataOf(domain string) []stored {
	var out []stored
	for _, s := range h.data {
		if s.domain == domain {
			out = append(out, s)
		}
	}
	return out
}

// numbersOf lists the distinct key numbers the values of a domain name, ascending.
func (h history) numbersOf(domain string) []uint16 {
	var out []uint16
	for _, s := range h.dataOf(domain) {
		if !slices.Contains(out, s.n) {
			out = append(out, s.n)
		}
	}
	slices.Sort(out)
	return out
}

// declareLostClears is the truth of `ctrlz declare-lost user_totp` (admin-r13-3): it clears exactly the
// values that name N and do not open. A value that opens is not lost, whatever its number, and
// it does not stop the others from being cleared: after a total loss the regenerated key reuses
// the number, so a value enrolled after the recovery names N and opens beside the old ones.
func (h history) declareLostClears(s stored, n uint16) bool { return s.n == n && !h.opens(s) }

// declareLostRefuses is the truth of the admin side `keys declare-lost` for sms_cred (admin-r14-2): it
// decides per sealed value like the user_totp tool, so it records a loss when at least one credential that
// names N does not open, and refuses only when credentials name N and every one of them opens. With none
// naming N there is nothing stuck and the record is made.
func (h history) declareLostRefuses(domain string, n uint16) bool {
	named, opened := 0, 0
	for _, s := range h.dataOf(domain) {
		if s.n == n {
			named++
			if h.opens(s) {
				opened++
			}
		}
	}
	return named > 0 && opened == named
}

// rekeyCounts is what a rekey must report for a domain.
type rekeyCounts struct{ rewritten, current, failed int }

func (h history) rekeyTruth(domain string) rekeyCounts {
	var c rekeyCounts
	for _, s := range h.dataOf(domain) {
		switch {
		case !h.opens(s):
			c.failed++
		case s.n == h.newest(domain):
			c.current++
		default:
			c.rewritten++
		}
	}
	return c
}
