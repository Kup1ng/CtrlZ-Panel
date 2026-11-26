package vectors

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"strconv"
	"strings"

	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/manifest"
)

// The manifest group runs on text cases. The keys are derived from fixed seed
// names, so the vectors are the same bytes on every machine and a node's own
// harness can reproduce them: offline o1..o3 (bundle role, 2 of 3), online p1
// (policy) and c1 (catalog).

func vectorKey(name string) (ed25519.PrivateKey, *signv1.PublicKey) {
	seed := sha256.Sum256([]byte("ctrlz-vector-key:" + name))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	return priv, &signv1.PublicKey{KeyId: manifest.KeyID(pub), Ed25519: pub}
}

func vectorRoot(rootExpires, roleExpires int64) *signv1.Root {
	var keys []*signv1.PublicKey
	for _, n := range []string{"o1", "o2", "o3", "p1", "c1"} {
		_, pub := vectorKey(n)
		keys = append(keys, pub)
	}
	id := func(n string) []byte { _, p := vectorKey(n); return p.KeyId }
	return &signv1.Root{Version: 1, ExpiresAt: rootExpires, Keys: keys, Threshold: 2, RootKeyIds: [][]byte{id("o1"), id("o2"), id("o3")}, Roles: []*signv1.RoleGrant{
		{Role: signv1.Role_ROLE_BUNDLE, KeyIds: [][]byte{id("o1"), id("o2"), id("o3")}, Threshold: 2, ExpiresAt: roleExpires},
		{Role: signv1.Role_ROLE_POLICY, KeyIds: [][]byte{id("p1")}, Threshold: 1, ExpiresAt: roleExpires},
		{Role: signv1.Role_ROLE_CATALOG, KeyIds: [][]byte{id("c1")}, Threshold: 1, ExpiresAt: roleExpires},
	}}
}

func roleOf(s string) signv1.Role {
	switch s {
	case "policy":
		return signv1.Role_ROLE_POLICY
	case "catalog":
		return signv1.Role_ROLE_CATALOG
	case "bundle":
		return signv1.Role_ROLE_BUNDLE
	}
	return signv1.Role_ROLE_UNSPECIFIED
}

func atoi64(s string) int64 {
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		panic("vector number: " + err.Error())
	}
	return v
}

// manifestErr names an error for the expect column. An unlisted error is a
// vector bug, so it is returned as its full text and fails the comparison.
func manifestErr(err error) string {
	if err == nil {
		return "ok"
	}
	for name, target := range map[string]error{
		"role_mismatch":    manifest.ErrRoleMismatch,
		"no_expiry":        manifest.ErrNoExpiry,
		"payload_type":     manifest.ErrPayloadType,
		"threshold":        manifest.ErrThreshold,
		"root_expired":     manifest.ErrRootExpired,
		"role_expired":     manifest.ErrRoleExpired,
		"no_role":          manifest.ErrNoRole,
		"manifest_expired": manifest.ErrManifestExpired,
		"rollback":         manifest.ErrRollback,
		"below_min":        manifest.ErrBelowMinVersion,
		"bad_manifest":     manifest.ErrBadManifest,
	} {
		if errors.Is(err, target) {
			return name
		}
	}
	return err.Error()
}

// manifestOp implements the manifest_* ops of the text runner.
//
//	manifest_verify  args: payload_type, role, signers (comma list of key names), now, root_expires, role_expires [, want_type]
//	                 want_type is the type the caller expects; it defaults to payload_type.
//	manifest_fresh   args: version, min_version, expires_at, now, highest_seen
//	manifest_rollback args: min_version, target
func manifestOp(op string, a []string) (string, bool) {
	switch op {
	case "manifest_verify":
		root := vectorRoot(atoi64(a[4]), atoi64(a[5]))
		payload := []byte("vector payload")
		env := &signv1.Envelope{PayloadType: a[0], Payload: payload}
		for _, n := range strings.Split(a[2], ",") {
			if n == "" {
				continue
			}
			priv, _ := vectorKey(n)
			_, pub := vectorKey(n)
			env.Signatures = append(env.Signatures, &signv1.Signature{KeyId: pub.KeyId, Sig: ed25519.Sign(priv, manifest.SigningInput(a[0], payload))})
		}
		wantType := a[0]
		if len(a) > 6 {
			wantType = a[6]
		}
		_, err := manifest.Verify(env, root, roleOf(a[1]), wantType, atoi64(a[3]))
		return manifestErr(err), true
	case "manifest_fresh":
		m := &signv1.Manifest{Version: uint64(atoi64(a[0])), MinVersion: uint64(atoi64(a[1])), ExpiresAt: atoi64(a[2])}
		return manifestErr(manifest.CheckManifestFresh(m, atoi64(a[3]), uint64(atoi64(a[4])))), true
	case "manifest_rollback":
		m := &signv1.Manifest{MinVersion: uint64(atoi64(a[0]))}
		return manifestErr(manifest.CheckRollbackTarget(m, uint64(atoi64(a[1])))), true
	}
	return "", false
}
