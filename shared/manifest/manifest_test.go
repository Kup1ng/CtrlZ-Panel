package manifest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"google.golang.org/protobuf/proto"
	"io/fs"
	"strconv"
	"testing"
	"time"

	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
)

var nodeType = ManifestPayloadType(signv1.Kind_KIND_NODE)

type keyring struct {
	pub  []*signv1.PublicKey
	priv []ed25519.PrivateKey
}

func newKeys(t *testing.T, n int) keyring {
	t.Helper()
	var k keyring
	for i := 0; i < n; i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		k.pub = append(k.pub, &signv1.PublicKey{KeyId: KeyID(pub), Ed25519: pub})
		k.priv = append(k.priv, priv)
	}
	return k
}

// far is an expiry that no test reaches (the tests run at times near 100):
// expires_at 0 is not "never", it is malformed.
const far = int64(1) << 40

// rootFor builds a root with one grant. The root keys are the granted keys for
// the bundle role (bundle keys are root keys) and every other key otherwise
// (policy and catalog keys are online, so they are never root keys).
func rootFor(k keyring, role signv1.Role, threshold uint32, ids ...int) *signv1.Root {
	g := &signv1.RoleGrant{Role: role, Threshold: threshold, ExpiresAt: far}
	granted := map[int]bool{}
	for _, i := range ids {
		g.KeyIds = append(g.KeyIds, k.pub[i].KeyId)
		granted[i] = true
	}
	r := &signv1.Root{Version: 1, ExpiresAt: far, Keys: k.pub, Threshold: 2, Roles: []*signv1.RoleGrant{g}}
	for i, pk := range k.pub {
		if granted[i] == (role == signv1.Role_ROLE_BUNDLE) {
			r.RootKeyIds = append(r.RootKeyIds, pk.KeyId)
		}
	}
	return r
}

func sign(k keyring, i int, typ string, payload []byte) *signv1.Signature {
	return &signv1.Signature{KeyId: k.pub[i].KeyId, Sig: ed25519.Sign(k.priv[i], SigningInput(typ, payload))}
}

func TestVerifyThreshold(t *testing.T) {
	k := newKeys(t, 3)
	root := rootFor(k, signv1.Role_ROLE_BUNDLE, 2, 0, 1, 2)
	payload := []byte("manifest bytes")
	env := &signv1.Envelope{PayloadType: nodeType, Payload: payload, Signatures: []*signv1.Signature{sign(k, 0, nodeType, payload), sign(k, 2, nodeType, payload)}}
	got, err := Verify(env, root, signv1.Role_ROLE_BUNDLE, nodeType, 100)
	if err != nil || string(got) != "manifest bytes" {
		t.Fatalf("%v", err)
	}
	// One signature is not enough.
	env.Signatures = env.Signatures[:1]
	if _, err := Verify(env, root, signv1.Role_ROLE_BUNDLE, nodeType, 100); !errors.Is(err, ErrThreshold) {
		t.Fatalf("one signature: %v", err)
	}
	// The same key twice counts once.
	env.Signatures = []*signv1.Signature{sign(k, 0, nodeType, payload), sign(k, 0, nodeType, payload)}
	if _, err := Verify(env, root, signv1.Role_ROLE_BUNDLE, nodeType, 100); !errors.Is(err, ErrThreshold) {
		t.Fatalf("duplicate key: %v", err)
	}
}

func TestVerifyBindsTypeAndPayload(t *testing.T) {
	k := newKeys(t, 2)
	root := rootFor(k, signv1.Role_ROLE_POLICY, 1, 0)
	payload := []byte("head")
	sig := sign(k, 0, TypeHead, payload)
	for name, env := range map[string]*signv1.Envelope{
		"other type":    {PayloadType: TypePairTable, Payload: payload, Signatures: []*signv1.Signature{sig}},
		"other payload": {PayloadType: TypeHead, Payload: []byte("hex"), Signatures: []*signv1.Signature{sig}},
		// A shifted split between type and payload must not verify: the length prefix prevents it.
		"shifted split": {PayloadType: TypeHead[:len(TypeHead)-1], Payload: []byte("dhead"), Signatures: []*signv1.Signature{sig}},
	} {
		if _, err := Verify(env, root, signv1.Role_ROLE_POLICY, TypeHead, 100); err == nil {
			t.Errorf("%s verified", name)
		}
	}
}

func TestVerifyRoleAndExpiry(t *testing.T) {
	k := newKeys(t, 2)
	payload := []byte("x")
	env := &signv1.Envelope{PayloadType: nodeType, Payload: payload, Signatures: []*signv1.Signature{sign(k, 0, nodeType, payload)}}
	root := rootFor(k, signv1.Role_ROLE_CATALOG, 1, 0)
	if _, err := Verify(env, root, signv1.Role_ROLE_BUNDLE, nodeType, 100); !errors.Is(err, ErrNoRole) {
		t.Errorf("wrong role: %v", err)
	}
	// The online catalog key does not sign bundles: a key of another role is ignored.
	root = rootFor(k, signv1.Role_ROLE_BUNDLE, 1, 1)
	if _, err := Verify(env, root, signv1.Role_ROLE_BUNDLE, nodeType, 100); !errors.Is(err, ErrThreshold) {
		t.Errorf("key outside the role: %v", err)
	}
	root = rootFor(k, signv1.Role_ROLE_BUNDLE, 1, 0)
	root.Roles[0].ExpiresAt = 50
	if _, err := Verify(env, root, signv1.Role_ROLE_BUNDLE, nodeType, 100); !errors.Is(err, ErrRoleExpired) {
		t.Errorf("expired delegation: %v", err)
	}
	root.Roles[0].ExpiresAt = far
	root.ExpiresAt = 50
	if _, err := Verify(env, root, signv1.Role_ROLE_BUNDLE, nodeType, 100); !errors.Is(err, ErrRootExpired) {
		t.Errorf("expired root: %v", err)
	}
	// A corrupted signature fails.
	root.ExpiresAt = far
	env.Signatures[0].Sig[0] ^= 1
	if _, err := Verify(env, root, signv1.Role_ROLE_BUNDLE, nodeType, 100); !errors.Is(err, ErrThreshold) {
		t.Errorf("corrupted signature: %v", err)
	}
	if _, err := Verify(&signv1.Envelope{Payload: make([]byte, MaxEnvelope+1)}, root, signv1.Role_ROLE_BUNDLE, nodeType, 100); !errors.Is(err, ErrTooLarge) {
		t.Errorf("oversize: %v", err)
	}
}

func TestCheckPath(t *testing.T) {
	good := []string{"a", "bin/ctrlz-node", "etc/unbound/root.hints", "a.b/c-d_e"}
	bad := []string{"", "/etc/passwd", "../x", "a/../b", "a/./b", "a//b", "a/", "C:/x", "C:x", "a\\b", "a\x00b", "//server/share", "a/..", "."}
	for _, p := range good {
		if err := CheckPath(p); err != nil {
			t.Errorf("%q: %v", p, err)
		}
	}
	for _, p := range bad {
		if CheckPath(p) == nil {
			t.Errorf("%q accepted", p)
		}
	}
	long := make([]byte, 256)
	for i := range long {
		long[i] = 'a'
	}
	if CheckPath(string(long)) == nil {
		t.Error("256-byte path accepted")
	}
}

func TestCheckEntryAndManifest(t *testing.T) {
	m := &signv1.Manifest{Files: []*signv1.FileEntry{{Path: "bin/node", Sha256: make([]byte, 32), Size: 10}}}
	if err := CheckManifest(m); err != nil {
		t.Fatal(err)
	}
	ix, err := NewIndex(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := ix.CheckEntry("bin/node", 0o644, 10); err != nil {
		t.Errorf("good entry: %v", err)
	}
	if err := ix.CheckEntry("bin/node", fs.ModeSymlink|0o777, 10); !errors.Is(err, ErrNotRegular) {
		t.Errorf("symlink: %v", err)
	}
	if err := ix.CheckEntry("bin/node", fs.ModeDevice, 10); !errors.Is(err, ErrNotRegular) {
		t.Errorf("device: %v", err)
	}
	if err := ix.CheckEntry("bin/other", 0o644, 10); !errors.Is(err, ErrNotListed) {
		t.Errorf("unlisted: %v", err)
	}
	if err := ix.CheckEntry("bin/node", 0o644, 11); !errors.Is(err, ErrSizeMismatch) {
		t.Errorf("size: %v", err)
	}
	if err := ix.CheckEntry("../bin/node", 0o644, 10); !errors.Is(err, ErrBadPath) {
		t.Errorf("traversal: %v", err)
	}
	if _, err := NewIndex(&signv1.Manifest{Files: []*signv1.FileEntry{{Path: "../x", Sha256: make([]byte, 32)}}}); !errors.Is(err, ErrBadPath) {
		t.Errorf("an index over an unsafe manifest: %v", err)
	}
	dup := &signv1.Manifest{Files: []*signv1.FileEntry{{Path: "A.txt", Sha256: make([]byte, 32)}, {Path: "a.txt", Sha256: make([]byte, 32)}}}
	if CheckManifest(dup) == nil {
		t.Error("paths equal under case folding accepted")
	}
}

func FuzzCheckPath(f *testing.F) {
	for _, s := range []string{"a/b", "../x", "/etc", "C:/x", "a\\b", "a//b", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		if CheckPath(p) != nil {
			return
		}
		// An accepted path must be relative and free of traversal.
		if p[0] == '/' || p[0] == '.' && (len(p) == 1 || p[1] == '/' || p[1] == '.' && (len(p) == 2 || p[2] == '/')) {
			t.Fatalf("accepted %q", p)
		}
	})
}

func mustMarshal(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fullRoot has an offline bundle role (keys 0 and 1, 2 of 2), an online policy
// key (2) and an online catalog key (3).
func fullRoot(k keyring) *signv1.Root {
	return &signv1.Root{Version: 1, ExpiresAt: far, Keys: k.pub[:4], Threshold: 2, RootKeyIds: [][]byte{k.pub[0].KeyId, k.pub[1].KeyId}, Roles: []*signv1.RoleGrant{
		{Role: signv1.Role_ROLE_BUNDLE, KeyIds: [][]byte{k.pub[0].KeyId, k.pub[1].KeyId}, Threshold: 2, ExpiresAt: far},
		{Role: signv1.Role_ROLE_POLICY, KeyIds: [][]byte{k.pub[2].KeyId}, Threshold: 1, ExpiresAt: far},
		{Role: signv1.Role_ROLE_CATALOG, KeyIds: [][]byte{k.pub[3].KeyId}, Threshold: 1, ExpiresAt: far},
	}}
}

func envelope(k keyring, typ string, payload []byte, signers ...int) *signv1.Envelope {
	e := &signv1.Envelope{PayloadType: typ, Payload: payload}
	for _, i := range signers {
		e.Signatures = append(e.Signatures, sign(k, i, typ, payload))
	}
	return e
}

// TestVerifyBindsPayloadTypeToRole is the regression test for review F06: the
// role used to come from the caller, so the online policy key could sign a
// node-binary manifest and the caller choosing RolePolicy accepted it.
func TestVerifyBindsPayloadTypeToRole(t *testing.T) {
	k := newKeys(t, 6)
	root := fullRoot(k)
	payload := []byte("p")
	cases := []struct {
		name    string
		typ     string
		role    signv1.Role
		signers []int
		want    error
		wantTyp string // what the caller expects; typ when empty
	}{
		{"head by policy", TypeHead, signv1.Role_ROLE_POLICY, []int{2}, nil, ""},
		{"pair table by policy", TypePairTable, signv1.Role_ROLE_POLICY, []int{2}, nil, ""},
		{"filters by catalog", ManifestPayloadType(signv1.Kind_KIND_FILTERS), signv1.Role_ROLE_CATALOG, []int{3}, nil, ""},
		{"node binary by bundle", nodeType, signv1.Role_ROLE_BUNDLE, []int{0, 1}, nil, ""},
		{"node binary claimed under the policy role", nodeType, signv1.Role_ROLE_POLICY, []int{2}, ErrRoleMismatch, ""},
		{"node binary claimed under the catalog role", nodeType, signv1.Role_ROLE_CATALOG, []int{3}, ErrRoleMismatch, ""},
		{"xray signed by the online catalog key", ManifestPayloadType(signv1.Kind_KIND_XRAY), signv1.Role_ROLE_CATALOG, []int{3}, ErrRoleMismatch, ""},
		{"head under the bundle role", TypeHead, signv1.Role_ROLE_BUNDLE, []int{0, 1}, ErrRoleMismatch, ""},
		{"filters under the policy role", ManifestPayloadType(signv1.Kind_KIND_FILTERS), signv1.Role_ROLE_POLICY, []int{2}, ErrRoleMismatch, ""},
		{"unknown type", "ctrlz/whatever", signv1.Role_ROLE_POLICY, []int{2}, ErrPayloadType, ""},
		{"a root through Verify", TypeRoot, signv1.Role_ROLE_BUNDLE, []int{0, 1}, ErrPayloadType, ""},
		// L2-F20: the same key signs both policy payloads, so the type the
		// caller expects has to be compared, not only the role.
		{"a pair table where a head is expected", TypePairTable, signv1.Role_ROLE_POLICY, []int{2}, ErrPayloadType, TypeHead},
		{"a head where a pair table is expected", TypeHead, signv1.Role_ROLE_POLICY, []int{2}, ErrPayloadType, TypePairTable},
		{"a filters manifest where a geoip manifest is expected", ManifestPayloadType(signv1.Kind_KIND_FILTERS), signv1.Role_ROLE_CATALOG, []int{3}, ErrPayloadType, ManifestPayloadType(signv1.Kind_KIND_GEOIP)},
	}
	for _, c := range cases {
		want := c.wantTyp
		if want == "" {
			want = c.typ
		}
		_, err := Verify(envelope(k, c.typ, payload, c.signers...), root, c.role, want, 100)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
	// Every kind lands on exactly one of the two data roles; xray, images, node,
	// unbound, os_debs and panel are offline-only.
	catalog := map[signv1.Kind]bool{
		signv1.Kind_KIND_FILTERS: true, signv1.Kind_KIND_GEOIP: true, signv1.Kind_KIND_SERVICES: true,
		signv1.Kind_KIND_DNSROOT: true, signv1.Kind_KIND_CERTS: true,
	}
	for n := range signv1.Kind_name {
		kind := signv1.Kind(n)
		if kind == signv1.Kind_KIND_UNSPECIFIED {
			continue
		}
		role, ok := RoleFor(ManifestPayloadType(kind))
		want := signv1.Role_ROLE_BUNDLE
		if catalog[kind] {
			want = signv1.Role_ROLE_CATALOG
		}
		if !ok || role != want {
			t.Errorf("kind %v bound to %v (found %v), want %v", kind, role, ok, want)
		}
	}
	// The length prefix makes a shifted split a different message.
	if bytes.Equal(SigningInput("ctrlz/hea", []byte("dhead")), SigningInput("ctrlz/head", []byte("head"))) {
		t.Error("shifted type/payload split signs the same bytes")
	}
}

// Tenant policy keeps flowing when the root or the policy delegation has
// lapsed (contract 13); catalog and binary installs stop.
func TestPolicyRoleIgnoresExpiry(t *testing.T) {
	k := newKeys(t, 4)
	root := fullRoot(k)
	root.ExpiresAt = 50
	for _, g := range root.Roles {
		g.ExpiresAt = 60
	}
	head := envelope(k, TypeHead, []byte("h"), 2)
	if _, err := Verify(head, root, signv1.Role_ROLE_POLICY, TypeHead, 1000); err != nil {
		t.Errorf("policy with an expired root and delegation: %v", err)
	}
	if !DelegationExpired(root, signv1.Role_ROLE_POLICY, 1000) {
		t.Error("DelegationExpired must report the lapse so the caller can alert")
	}
	if _, err := Verify(envelope(k, nodeType, []byte("n"), 0, 1), root, signv1.Role_ROLE_BUNDLE, nodeType, 1000); !errors.Is(err, ErrRootExpired) {
		t.Errorf("binary install with an expired root: %v", err)
	}
	root.ExpiresAt = far
	if _, err := Verify(envelope(k, ManifestPayloadType(signv1.Kind_KIND_FILTERS), []byte("n"), 3), root, signv1.Role_ROLE_CATALOG, ManifestPayloadType(signv1.Kind_KIND_FILTERS), 1000); !errors.Is(err, ErrRoleExpired) {
		t.Errorf("catalog with an expired delegation: %v", err)
	}
}

func TestVerifyRoot(t *testing.T) {
	k := newKeys(t, 6) // 0 and 1 offline; 2 policy; 3 catalog; 4 and 5 spare
	old := fullRoot(k)
	// A new root names its root keys: every key of it except the one granted to
	// the policy role.
	mkNext := func(version uint64, threshold uint32, keys []*signv1.PublicKey) *signv1.Root {
		r := &signv1.Root{Version: version, ExpiresAt: far, Keys: keys, Threshold: threshold, Roles: []*signv1.RoleGrant{
			{Role: signv1.Role_ROLE_POLICY, KeyIds: [][]byte{k.pub[2].KeyId}, Threshold: 1, ExpiresAt: far},
		}}
		for _, pk := range keys {
			if !bytes.Equal(pk.KeyId, k.pub[2].KeyId) {
				r.RootKeyIds = append(r.RootKeyIds, pk.KeyId)
			}
		}
		return r
	}
	keys := []*signv1.PublicKey{k.pub[0], k.pub[1], k.pub[2]}
	body := mustMarshal(t, mkNext(2, 2, keys))
	got, err := VerifyRoot(envelope(k, TypeRoot, body, 0, 1), old)
	if err != nil || got.Version != 2 {
		t.Fatalf("a good rotation: %v", err)
	}
	bad := map[string]struct {
		env *signv1.Envelope
		err error
	}{
		"one signature of two":        {envelope(k, TypeRoot, body, 0), ErrThreshold},
		"signed by the online keys":   {envelope(k, TypeRoot, body, 2, 3), ErrThreshold},
		"wrong payload type":          {envelope(k, nodeType, body, 0, 1), ErrPayloadType},
		"version skipped":             {envelope(k, TypeRoot, mustMarshal(t, mkNext(3, 2, keys)), 0, 1), ErrRootVersion},
		"version not advanced":        {envelope(k, TypeRoot, mustMarshal(t, mkNext(1, 2, keys)), 0, 1), ErrRootVersion},
		"threshold above offline set": {envelope(k, TypeRoot, mustMarshal(t, mkNext(2, 3, keys)), 0, 1), ErrUnsignableRoot},
		"garbage payload":             {envelope(k, TypeRoot, []byte{0xff, 0xff, 0xff}, 0, 1), ErrBadRoot},
	}
	for name, c := range bad {
		if _, err := VerifyRoot(c.env, old); !errors.Is(err, c.err) {
			t.Errorf("%s: err = %v, want %v", name, err, c.err)
		}
	}
	// The new root must be signable by its own keys: rotating to keys that did
	// not sign locks the root out.
	other := mkNext(2, 2, []*signv1.PublicKey{k.pub[4], k.pub[5], k.pub[2]})
	if _, err := VerifyRoot(envelope(k, TypeRoot, mustMarshal(t, other), 0, 1), old); !errors.Is(err, ErrRootNotCoSigned) {
		t.Errorf("new root not signed by its own keys: %v", err)
	}
	// An expired old root can still be rotated away from.
	old.ExpiresAt = 1
	if _, err := VerifyRoot(envelope(k, TypeRoot, body, 0, 1), old); err != nil {
		t.Errorf("rotation from an expired root: %v", err)
	}
}

func TestVerifyManifestAndFreshness(t *testing.T) {
	k := newKeys(t, 4)
	root := fullRoot(k)
	file := &signv1.FileEntry{Path: "bin/node", Sha256: bytes.Repeat([]byte{1}, 32), Size: 10}
	m := &signv1.Manifest{Kind: signv1.Kind_KIND_NODE, Version: 5, MinVersion: 3, ExpiresAt: 1000, Files: []*signv1.FileEntry{file}}
	got, err := VerifyManifest(envelope(k, nodeType, mustMarshal(t, m), 0, 1), root, signv1.Kind_KIND_NODE, 100)
	if err != nil || got.Version != 5 {
		t.Fatalf("a good manifest: %v", err)
	}
	// A signature for one kind does not install another.
	if _, err := VerifyManifest(envelope(k, ManifestPayloadType(signv1.Kind_KIND_XRAY), mustMarshal(t, m), 0, 1), root, signv1.Kind_KIND_XRAY, 100); !errors.Is(err, ErrKindMismatch) {
		t.Errorf("kind differs from payload type: %v", err)
	}
	// A valid manifest of another kind is not the one the caller is installing.
	if _, err := VerifyManifest(envelope(k, nodeType, mustMarshal(t, m), 0, 1), root, signv1.Kind_KIND_XRAY, 100); !errors.Is(err, ErrPayloadType) {
		t.Errorf("a node manifest presented as xray: %v", err)
	}
	// A head is not a manifest.
	if _, err := VerifyManifest(envelope(k, TypeHead, mustMarshal(t, m), 2), root, signv1.Kind_KIND_NODE, 100); !errors.Is(err, ErrPayloadType) {
		t.Errorf("head through VerifyManifest: %v", err)
	}

	// Freshness: a replayed, validly signed old manifest must fail.
	if err := CheckManifestFresh(m, 100, 5); err != nil {
		t.Errorf("same version: %v", err)
	}
	if err := CheckManifestFresh(m, 100, 6); !errors.Is(err, ErrRollback) {
		t.Errorf("older than the highest seen: %v", err)
	}
	if err := CheckManifestFresh(m, 1000, 0); !errors.Is(err, ErrManifestExpired) {
		t.Errorf("expired manifest: %v", err)
	}
	if err := CheckManifestFresh(&signv1.Manifest{Version: 1, MinVersion: 2}, 0, 0); !errors.Is(err, ErrBadManifest) {
		t.Errorf("min_version above version: %v", err)
	}
	if err := CheckRollbackTarget(m, 3); err != nil {
		t.Errorf("rollback to min_version: %v", err)
	}
	if err := CheckRollbackTarget(m, 2); !errors.Is(err, ErrBelowMinVersion) {
		t.Errorf("rollback below min_version: %v", err)
	}
}

// L2-F20: a root that never expires, a key listed twice and a key id that is
// not derived from the key are malformed, whatever else is right with them.
func TestVerifyRefusesAMalformedRoot(t *testing.T) {
	k := newKeys(t, 4)
	payload := []byte("n")
	env := envelope(k, nodeType, payload, 0, 1)
	good := func() *signv1.Root { r := fullRoot(k); r.Roles = r.Roles[:1]; return r }
	if _, err := Verify(env, good(), signv1.Role_ROLE_BUNDLE, nodeType, 100); err != nil {
		t.Fatalf("the control root: %v", err)
	}

	r := good()
	r.ExpiresAt = 0
	if _, err := Verify(env, r, signv1.Role_ROLE_BUNDLE, nodeType, 100); !errors.Is(err, ErrNoExpiry) {
		t.Errorf("a root with expires_at 0: %v", err)
	}
	r = good()
	r.Roles[0].ExpiresAt = 0
	if _, err := Verify(env, r, signv1.Role_ROLE_BUNDLE, nodeType, 100); !errors.Is(err, ErrNoExpiry) {
		t.Errorf("a grant with expires_at 0: %v", err)
	}
	if !DelegationExpired(r, signv1.Role_ROLE_BUNDLE, 100) {
		t.Error("a grant with no expiry must read as expired to the alert")
	}

	// The same public key under a second id: the threshold of 2 would be met
	// by one signer. The derived id makes the second entry a wrong id, and a
	// copy with the right id is a duplicate key.
	r = good()
	dup := &signv1.PublicKey{KeyId: KeyID(k.pub[0].Ed25519), Ed25519: k.pub[0].Ed25519}
	r.Keys = append(append([]*signv1.PublicKey{}, r.Keys...), dup)
	if _, err := Verify(env, r, signv1.Role_ROLE_BUNDLE, nodeType, 100); !errors.Is(err, ErrBadRoot) {
		t.Errorf("a key listed twice: %v", err)
	}
	r = good()
	r.Keys = append(append([]*signv1.PublicKey{}, r.Keys...), &signv1.PublicKey{KeyId: []byte("alias"), Ed25519: k.pub[0].Ed25519})
	if _, err := Verify(env, r, signv1.Role_ROLE_BUNDLE, nodeType, 100); !errors.Is(err, ErrBadRoot) {
		t.Errorf("a key under a made-up id: %v", err)
	}
	// A grant that names one key twice is malformed: one signer under two entries
	// could never meet a threshold of 2, and the root says it can.
	r = good()
	r.Roles[0].KeyIds = [][]byte{k.pub[0].KeyId, k.pub[0].KeyId}
	one := envelope(k, nodeType, payload, 0)
	if _, err := Verify(one, r, signv1.Role_ROLE_BUNDLE, nodeType, 100); !errors.Is(err, ErrBadRoot) {
		t.Errorf("one key counted twice through the grant: %v", err)
	}

	// A new root without expiry cannot be installed either.
	old := fullRoot(k)
	next := &signv1.Root{Version: 2, ExpiresAt: 0, Keys: []*signv1.PublicKey{k.pub[0], k.pub[1], k.pub[2]}, Threshold: 2,
		RootKeyIds: [][]byte{k.pub[0].KeyId, k.pub[1].KeyId},
		Roles:      []*signv1.RoleGrant{{Role: signv1.Role_ROLE_POLICY, KeyIds: [][]byte{k.pub[2].KeyId}, Threshold: 1, ExpiresAt: far}}}
	if _, err := VerifyRoot(envelope(k, TypeRoot, mustMarshal(t, next), 0, 1), old); !errors.Is(err, ErrNoExpiry) {
		t.Errorf("a new root with expires_at 0: %v", err)
	}
	next.ExpiresAt = far
	next.Roles[0].ExpiresAt = 0
	if _, err := VerifyRoot(envelope(k, TypeRoot, mustMarshal(t, next), 0, 1), old); !errors.Is(err, ErrNoExpiry) {
		t.Errorf("a new root with a grant without expiry: %v", err)
	}
}

// L1-F17: Windows names that open something other than a file.
func TestCheckPathWindowsNames(t *testing.T) {
	for _, p := range []string{
		"a:b", "bin/node:stream", "bin/node::$DATA", "x/y:z/w", "a:", ":a",
		"con", "CON", "bin/nul", "aux.txt", "dir/PRN.tar.gz", "com1", "LPT9.log", "bin/Com5",
		"name.", "dir./x", "name ", "dir /x", "con .txt",
	} {
		if CheckPath(p) == nil {
			t.Errorf("%q accepted", p)
		}
	}
	for _, p := range []string{"console", "bin/con1", "com0", "com10", "lpt", "nullable", "auxiliary/x", "a.b.c", "com1x", "x/.hidden"} {
		if err := CheckPath(p); err != nil {
			t.Errorf("%q refused: %v", p, err)
		}
	}
}

// L1-F17: a bundle at the file limit is checked in linear time. The scan used
// to be linear per entry, which is 10^10 comparisons at 100,000 files.
func TestIndexScalesToTheFileLimit(t *testing.T) {
	m := &signv1.Manifest{}
	for i := 0; i < MaxBundleFiles; i++ {
		m.Files = append(m.Files, &signv1.FileEntry{Path: "dir/f" + strconv.Itoa(i), Sha256: make([]byte, 32), Size: uint64(i)})
	}
	ix, err := NewIndex(m)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for i := MaxBundleFiles - 1; i >= 0; i-- {
		if err := ix.CheckEntry("dir/f"+strconv.Itoa(i), 0o644, uint64(i)); err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
	}
	// 100,000 lookups take milliseconds; the quadratic scan took minutes. The
	// bound is loose enough to survive a loaded CI machine.
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("checking %d entries took %v", MaxBundleFiles, d)
	}
}
