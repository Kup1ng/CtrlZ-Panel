package nodeadmin

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/manifest"
	"github.com/Kup1ng/CtrlZ-Shared/netclass"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestParseAddrRefusesWhatTheDatabaseRefuses(t *testing.T) {
	for _, ok := range []string{"93.184.216.34", "2606:4700::1111", "10.0.0.5", "fd00::1"} {
		if _, err := ParseAddr(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	// The five forms that carry an IPv4 address, a zone, a prefix, text that is no address, and the empty string.
	for _, bad := range []string{
		"::ffff:93.184.216.34", "64:ff9b::5db8:d822", "::5db8:d822", "::1", "2002:5db8:d822::1", "2001:0:5db8:d822::1",
		"fe80::1%eth0", "93.184.216.34/32", "93.184.216.034", "example.com", "", " 93.184.216.34",
	} {
		if _, err := ParseAddr(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCheckBindAndAdvertised(t *testing.T) {
	for _, s := range []string{"0.0.0.0", "::", "127.0.0.1", "224.0.0.1", "ff02::1"} {
		if CheckBind(addr(s)) == nil {
			t.Errorf("bind %s accepted", s)
		}
	}
	if CheckBind(addr("10.1.2.3")) != nil {
		t.Error("a private bind address (1:1 NAT) was refused")
	}
	if err := CheckAdvertised(addr("93.184.216.34")); err != nil {
		t.Errorf("a public advertised address was refused: %v", err)
	}
	for _, s := range []string{"100.64.0.1", "169.254.1.1", "198.51.100.7", "203.0.113.9", "10.10.34.5"} {
		if CheckAdvertised(addr(s)) == nil {
			t.Errorf("advertised %s accepted", s)
		}
	}
	// Private space is the lab build's alone (SC 8a.7).
	if got := CheckAdvertised(addr("10.1.2.3")) == nil; got != netclass.AllowPrivatePairAddrs {
		t.Errorf("a private advertised address: accepted=%v, lab build=%v", got, netclass.AllowPrivatePairAddrs)
	}
	if CheckBind(netip.Addr{}) == nil {
		t.Error("the zero address was accepted")
	}
}

func TestAddrText(t *testing.T) {
	if got := AddrText(addr("2606:4700::1111")); got != "2606:4700::1111" {
		t.Errorf("v6 text %q", got)
	}
	if got := AddrText(netip.Addr{}); got != "" {
		t.Errorf("zero address text %q", got)
	}
}

// member makes a node row for the table tests.
func member(slot int, status, dns, proxy string) store.MemberNode {
	return store.MemberNode{ID: uuid.New(), Slot: slot, Status: status, SPKI: sha32(byte(slot)), DNSIP: dns, ProxyIP: proxy}
}

func sha32(b byte) []byte {
	h := sha256.Sum256([]byte{b})
	return h[:]
}

func TestTableOfNodesAndPairs(t *testing.T) {
	a := member(1, "active", "93.184.216.34", "93.184.216.134")
	b := member(2, "active", "93.184.216.35", "93.184.216.135")
	c := member(3, "pending", "93.184.216.36", "93.184.216.136")
	pair := store.MemberPair{ID: uuid.New(), Primary: a.ID, Fallback: b.ID}
	m := &Membership{Nodes: []store.MemberNode{a, b, c}, Pairs: []store.MemberPair{pair}, Global: pair.ID}

	pt := BuildTable(m, uuid.Nil)
	if len(pt.Nodes) != 2 || len(pt.Pairs) != 1 || string(pt.GlobalPairId) != string(pair.ID[:]) {
		t.Fatalf("table = %d nodes, %d pairs", len(pt.Nodes), len(pt.Pairs))
	}
	if err := ValidateTable(pt); err != nil {
		t.Fatalf("a good table is refused: %v", err)
	}
	// A pending node is in no table; counted as active it is, with its key.
	if pt := BuildTable(m, c.ID); len(pt.Nodes) != 3 || len(pt.Nodes[2].SpkiSha256) != 32 {
		t.Fatalf("the activated node is not in the table with its key: %v", pt.Nodes)
	}
	if err := CheckMembership(m, c.ID); err != nil {
		t.Fatalf("a third active node is refused: %v", err)
	}

	// A revoked node keeps its address in the table with an empty SPKI, so a new node that repeats it is refused
	// until the old row is removed (4.5).
	rev := member(3, "revoked", "93.184.216.36", "93.184.216.136")
	dup := member(4, "pending", "93.184.216.36", "93.184.216.137")
	m2 := &Membership{Nodes: []store.MemberNode{a, b, rev, dup}}
	err := CheckMembership(m2, dup.ID)
	var te *TableError
	if !errors.As(err, &te) || !strings.Contains(te.Reason, "duplicate dns_ip") {
		t.Fatalf("a repeated address: %v", err)
	}
	if pt := BuildTable(m2, uuid.Nil); len(pt.Nodes) != 3 || len(pt.Nodes[2].SpkiSha256) != 0 {
		t.Fatalf("a revoked node must stay in the table with an empty key: %v", pt.Nodes)
	}

	// A node with no proxy address would fail the compiler's table, so it is refused at the confirmation.
	noProxy := member(3, "pending", "93.184.216.36", "")
	if err := CheckMembership(&Membership{Nodes: []store.MemberNode{a, b, noProxy}}, noProxy.ID); err == nil {
		t.Error("a node with no proxy address was accepted")
	}
	// A node with no advertised address at all.
	noDNS := member(3, "pending", "", "93.184.216.136")
	if err := CheckMembership(&Membership{Nodes: []store.MemberNode{a, noDNS}}, noDNS.ID); err == nil {
		t.Error("a node with no dns address was accepted")
	}
	// A pair of which one node is out of the table is not carried, so the table stays valid.
	pr := store.MemberPair{ID: uuid.New(), Primary: a.ID, Fallback: c.ID}
	if pt := BuildTable(&Membership{Nodes: []store.MemberNode{a, b, c}, Pairs: []store.MemberPair{pr}, Global: pr.ID}, uuid.Nil); len(pt.Pairs) != 0 || len(pt.GlobalPairId) != 0 {
		t.Errorf("a pair with a pending node was carried: %v", pt)
	}
	// A node with two pair peers is refused (SC 8a.4: (A,B) beside (A,C)).
	p1 := store.MemberPair{ID: uuid.New(), Primary: a.ID, Fallback: b.ID}
	p2 := store.MemberPair{ID: uuid.New(), Primary: a.ID, Fallback: c.ID}
	if err := CheckMembership(&Membership{Nodes: []store.MemberNode{a, b, c}, Pairs: []store.MemberPair{p1, p2}}, c.ID); err == nil {
		t.Error("a node with two peers was accepted")
	}
}

// An active row with no 32-byte key is a table the compiler refuses and keeps the last one for, so the route
// refuses it too; a revoked row has an empty key by design.
func TestCheckMembershipRefusesAnActiveNodeWithoutAKey(t *testing.T) {
	a := member(1, "active", "93.184.216.34", "93.184.216.134")
	b := member(2, "active", "93.184.216.35", "93.184.216.135")
	var te *TableError
	for _, key := range [][]byte{nil, make([]byte, 31)} {
		keyless := b
		keyless.SPKI = key
		if err := CheckMembership(&Membership{Nodes: []store.MemberNode{a, keyless}}, uuid.Nil); !errors.As(err, &te) {
			t.Fatalf("an active node with a %d-byte key: %v", len(key), err)
		}
		pending := member(3, "pending", "93.184.216.36", "93.184.216.136")
		pending.SPKI = key
		if err := CheckMembership(&Membership{Nodes: []store.MemberNode{a, b, pending}}, pending.ID); !errors.As(err, &te) {
			t.Fatalf("an approved node with a %d-byte key: %v", len(key), err)
		}
	}
	revoked := member(3, "revoked", "93.184.216.36", "93.184.216.136")
	revoked.SPKI = nil
	if err := CheckMembership(&Membership{Nodes: []store.MemberNode{a, b, revoked}}, uuid.Nil); err != nil {
		t.Fatalf("a revoked node's empty key: %v", err)
	}
}

// ---------------------------------------------------------------------------------------------------
// The install command.

type bundleSet struct {
	public, bundles fstest.MapFS
	script          []byte
	rootJSON        []byte
	rootKeyIDs      []string
}

// writeBundle makes a root of three keys (two sign), a node bundle at each version in versions (the last one
// listed is signed with a key the root does not know when badLast is set) and the pin file.
func writeBundle(t *testing.T, now time.Time, versions []uint64, badLast bool) *bundleSet {
	t.Helper()
	var keys []*signv1.PublicKey
	var priv []ed25519.PrivateKey
	var ids [][]byte
	for i := 0; i < 3; i++ {
		pub, pk, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		id := manifest.KeyID(pub)
		keys = append(keys, &signv1.PublicKey{KeyId: id, Ed25519: pub})
		priv, ids = append(priv, pk), append(ids, id)
	}
	exp := now.Add(365 * 24 * time.Hour).Unix()
	root := &signv1.Root{Version: 1, ExpiresAt: exp, Keys: keys, Threshold: 2, RootKeyIds: ids,
		Roles: []*signv1.RoleGrant{{Role: signv1.Role_ROLE_BUNDLE, KeyIds: ids, Threshold: 2, ExpiresAt: exp}}}
	rj, err := protojson.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256([]byte("hub key"))
	set := &bundleSet{
		public:   fstest.MapFS{"hub_tls.spki": {Data: []byte(base64.StdEncoding.EncodeToString(pin[:]) + "\n")}},
		bundles:  fstest.MapFS{"root.json": {Data: rj}},
		rootJSON: rj,
	}
	for _, id := range ids {
		set.rootKeyIDs = append(set.rootKeyIDs, hex.EncodeToString(id))
	}
	for n, v := range versions {
		script := []byte("#!/bin/sh\necho node " + string(rune('0'+v)) + "\n")
		m := &signv1.Manifest{Kind: signv1.Kind_KIND_NODE, Version: v, CreatedAt: now.Unix(), ExpiresAt: exp, MinVersion: 1}
		sum := sha256.Sum256(script)
		m.Files = []*signv1.FileEntry{{Path: nodeScriptPath, Sha256: sum[:], Size: uint64(len(script))}}
		payload, err := proto.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		typ := manifest.ManifestPayloadType(signv1.Kind_KIND_NODE)
		env := &signv1.Envelope{PayloadType: typ, Payload: payload}
		signers := []int{0, 1}
		if badLast && n == len(versions)-1 {
			_, stranger, _ := ed25519.GenerateKey(rand.Reader)
			env.Signatures = append(env.Signatures, &signv1.Signature{KeyId: ids[0], Sig: ed25519.Sign(stranger, manifest.SigningInput(typ, payload))})
			signers = nil
		}
		for _, i := range signers {
			env.Signatures = append(env.Signatures, &signv1.Signature{KeyId: ids[i], Sig: ed25519.Sign(priv[i], manifest.SigningInput(typ, payload))})
		}
		ej, err := protojson.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		set.bundles["node/"+string(rune('0'+v))+"/manifest.json"] = &fstest.MapFile{Data: ej}
		set.script = script
	}
	return set
}

func installer(t *testing.T, s *bundleSet, deny ...string) *Installer {
	t.Helper()
	i, err := NewInstaller(InstallConfig{HubHost: "203.0.113.5, hub.example.test", Public: s.public, Bundles: s.bundles, DenyRootKeys: deny})
	if err != nil {
		t.Fatal(err)
	}
	return i
}

var testAddrs = EnrollAddrs{DNSBind: addr("10.0.0.5"), DNSAdv: addr("93.184.216.34"), ProxyBind: addr("10.0.0.6"), ProxyAdv: addr("93.184.216.134")}

func TestInstallCommandIsTheOneOfTheSpec(t *testing.T) {
	now := time.Now()
	s := writeBundle(t, now, []uint64{1, 2}, false)
	cmd, err := installer(t, s).Command("TOKEN-43-CHARS", testAddrs, now)
	if err != nil {
		t.Fatal(err)
	}
	pin := strings.TrimSpace(string(s.public["hub_tls.spki"].Data))
	script := sha256.Sum256(s.script)
	root := sha256.Sum256(s.rootJSON)
	want := " curl -k --pinnedpubkey sha256//" + pin + " -o /tmp/ctrlz-node.sh https://203.0.113.5:9443/install/node.sh" +
		" && echo '" + hex.EncodeToString(script[:]) + "  /tmp/ctrlz-node.sh' | sha256sum -c" +
		" && printf %s 'TOKEN-43-CHARS' | sudo sh /tmp/ctrlz-node.sh --hub 203.0.113.5 --pin sha256//" + pin +
		" --token-stdin --root " + hex.EncodeToString(root[:]) +
		" --dns-bind-ip 10.0.0.5 --dns-advertised-ip 93.184.216.34 --proxy-bind-ip 10.0.0.6 --proxy-advertised-ip 93.184.216.134"
	if cmd != want {
		t.Errorf("command\n got %q\nwant %q", cmd, want)
	}
	if !strings.HasPrefix(cmd, " ") {
		t.Error("the line must start with a space so the shell keeps it out of its history")
	}
}

func TestInstallCommandNeedsEveryFile(t *testing.T) {
	now := time.Now()
	good := writeBundle(t, now, []uint64{1}, false)
	for name, mutate := range map[string]func(*bundleSet){
		"no pin file":      func(s *bundleSet) { delete(s.public, "hub_tls.spki") },
		"a pin of 5 bytes": func(s *bundleSet) { s.public["hub_tls.spki"] = &fstest.MapFile{Data: []byte("AAAA\n")} },
		"no root":          func(s *bundleSet) { delete(s.bundles, "root.json") },
		"root not json":    func(s *bundleSet) { s.bundles["root.json"] = &fstest.MapFile{Data: []byte("{")} },
		"no bundle":        func(s *bundleSet) { delete(s.bundles, "node/1/manifest.json") },
	} {
		s := writeBundle(t, now, []uint64{1}, false)
		_ = good
		mutate(s)
		if _, err := installer(t, s).Command("T", testAddrs, now); !errors.Is(err, ErrNoInstall) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// An expired manifest is no bundle.
	s := writeBundle(t, now, []uint64{1}, false)
	if _, err := installer(t, s).Command("T", testAddrs, now.Add(400*24*time.Hour)); !errors.Is(err, ErrNoInstall) {
		t.Errorf("an expired bundle: %v", err)
	}
}

func TestInstallCommandSkipsABundleThatDoesNotVerify(t *testing.T) {
	now := time.Now()
	// Version 2 is signed by a key outside the root: the hub does not serve it, so the command names version 1.
	s := writeBundle(t, now, []uint64{1, 2}, true)
	cmd, err := installer(t, s).Command("T", testAddrs, now)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cmd, "echo '") || strings.Contains(cmd, "'  /tmp") {
		t.Errorf("command %q", cmd)
	}
}

func TestInstallCommandRefusesAProductionRootWithATestKey(t *testing.T) {
	now := time.Now()
	s := writeBundle(t, now, []uint64{1}, false)
	if _, err := installer(t, s, s.rootKeyIDs[1]).Command("T", testAddrs, now); !errors.Is(err, ErrNoInstall) {
		t.Errorf("a root with a denied key: %v", err)
	}
}

func TestNewInstallerChecksTheHost(t *testing.T) {
	s := writeBundle(t, time.Now(), []uint64{1}, false)
	for _, bad := range []string{"", " ", "a b", "host;rm", "ho'st", "$(x)"} {
		if _, err := NewInstaller(InstallConfig{HubHost: bad, Public: s.public, Bundles: s.bundles}); err == nil {
			t.Errorf("host %q accepted", bad)
		}
	}
	i, err := NewInstaller(InstallConfig{HubHost: "2606:4700::1111", Public: s.public, Bundles: s.bundles})
	if err != nil {
		t.Fatal(err)
	}
	cmd, err := i.Command("T", testAddrs, time.Now())
	if err != nil || !strings.Contains(cmd, "https://[2606:4700::1111]:9443/") || !strings.Contains(cmd, "--hub [2606:4700::1111] ") {
		t.Errorf("an IPv6 host must be in brackets: %v %q", err, cmd)
	}
}
