package manifest

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
)

// The root keys are named in the root, never derived from the grants. These
// cases are the ways a key that is not an offline root key used to gain the
// power to rotate the root, or to sign code.
func TestRootKeysAreNamed(t *testing.T) {
	k := newKeys(t, 6) // 0 and 1 root keys, 2 policy, 3 catalog, 4 and 5 spare
	payload := []byte("n")
	// nextRoot is a good version 2 of fullRoot with a change applied.
	nextRoot := func(mut func(*signv1.Root)) *signv1.Root {
		r := fullRoot(k)
		r.Version = 2
		mut(r)
		return r
	}
	rotate := func(next *signv1.Root, old *signv1.Root) error {
		_, err := VerifyRoot(envelope(k, TypeRoot, mustMarshal(t, next), 0, 1), old)
		return err
	}

	t.Run("a good rotation still passes", func(t *testing.T) {
		if err := rotate(nextRoot(func(*signv1.Root) {}), fullRoot(k)); err != nil {
			t.Errorf("control: %v", err)
		}
	})

	t.Run("a bundle key that is not a root key", func(t *testing.T) {
		// Root v1 gives the bundle role to keys 4 and 5, which are not root keys.
		// Under the old derivation those two keys alone could then rotate the root.
		old := fullRoot(k)
		old.Keys = k.pub
		old.Roles[0].KeyIds = [][]byte{k.pub[4].KeyId, k.pub[5].KeyId}
		next := nextRoot(func(*signv1.Root) {})
		if _, err := VerifyRoot(envelope(k, TypeRoot, mustMarshal(t, next), 4, 5), old); !errors.Is(err, ErrBadRoot) {
			t.Errorf("VerifyRoot signed by the two bundle keys: %v", err)
		}
		if _, err := Verify(envelope(k, nodeType, payload, 4, 5), old, signv1.Role_ROLE_BUNDLE, nodeType, 100); !errors.Is(err, ErrBadRoot) {
			t.Errorf("Verify against the same root: %v", err)
		}
	})

	t.Run("an online key in the bundle grant", func(t *testing.T) {
		// A root that gives the bundle role to the online policy key would let
		// that key alone sign a node binary (contract 13).
		bad := fullRoot(k)
		bad.Roles[0].KeyIds = [][]byte{k.pub[2].KeyId}
		bad.Roles[0].Threshold = 1
		if _, err := Verify(envelope(k, nodeType, payload, 2), bad, signv1.Role_ROLE_BUNDLE, nodeType, 100); !errors.Is(err, ErrBadRoot) {
			t.Errorf("Verify: a node binary signed by the online key alone: %v", err)
		}
		if err := rotate(nextRoot(func(r *signv1.Root) { r.Roles[0] = bad.Roles[0] }), fullRoot(k)); !errors.Is(err, ErrBadRoot) {
			t.Errorf("VerifyRoot: a new root that grants bundle to an online key: %v", err)
		}
	})

	t.Run("a root key in the policy grant", func(t *testing.T) {
		bad := fullRoot(k)
		bad.Roles[1].KeyIds = [][]byte{k.pub[0].KeyId}
		if err := rotate(nextRoot(func(r *signv1.Root) { r.Roles[1] = bad.Roles[1] }), fullRoot(k)); !errors.Is(err, ErrBadRoot) {
			t.Errorf("VerifyRoot: %v", err)
		}
		if _, err := Verify(envelope(k, TypeHead, payload, 0), bad, signv1.Role_ROLE_POLICY, TypeHead, 100); !errors.Is(err, ErrBadRoot) {
			t.Errorf("Verify: %v", err)
		}
	})

	t.Run("a root key in the catalog grant", func(t *testing.T) {
		bad := fullRoot(k)
		bad.Roles[2].KeyIds = [][]byte{k.pub[1].KeyId}
		if err := rotate(nextRoot(func(r *signv1.Root) { r.Roles[2] = bad.Roles[2] }), fullRoot(k)); !errors.Is(err, ErrBadRoot) {
			t.Errorf("VerifyRoot: %v", err)
		}
		filters := ManifestPayloadType(signv1.Kind_KIND_FILTERS)
		if _, err := Verify(envelope(k, filters, payload, 1), bad, signv1.Role_ROLE_CATALOG, filters, 100); !errors.Is(err, ErrBadRoot) {
			t.Errorf("Verify: %v", err)
		}
	})

	t.Run("a key retired from its role does not become a root signer", func(t *testing.T) {
		// Online keys 2 and 3 were stolen. The owner moves the policy grant to a
		// new key but leaves key 2 in keys. Under the old derivation key 2 then
		// counted as a root key, and 2 with 3 could sign the next root.
		old := fullRoot(k)
		old.Version = 2
		old.Keys = k.pub[:5]
		old.Roles[1].KeyIds = [][]byte{k.pub[4].KeyId}
		old.Roles = old.Roles[:2] // the catalog grant is gone too
		next := &signv1.Root{Version: 3, ExpiresAt: far, Keys: k.pub[:5], Threshold: 2, RootKeyIds: [][]byte{k.pub[2].KeyId, k.pub[3].KeyId},
			Roles: []*signv1.RoleGrant{{Role: signv1.Role_ROLE_POLICY, KeyIds: [][]byte{k.pub[4].KeyId}, Threshold: 1, ExpiresAt: far}}}
		if _, err := VerifyRoot(envelope(k, TypeRoot, mustMarshal(t, next), 2, 3), old); !errors.Is(err, ErrThreshold) {
			t.Errorf("two retired keys rotated the root: %v", err)
		}
	})

	t.Run("root_key_ids names a key the root does not hold", func(t *testing.T) {
		bad := nextRoot(func(r *signv1.Root) { r.RootKeyIds = append(r.RootKeyIds, k.pub[5].KeyId) })
		if err := rotate(bad, fullRoot(k)); !errors.Is(err, ErrBadRoot) {
			t.Errorf("an unknown root key id: %v", err)
		}
	})

	t.Run("root_key_ids lists a key twice", func(t *testing.T) {
		bad := nextRoot(func(r *signv1.Root) { r.RootKeyIds = [][]byte{k.pub[0].KeyId, k.pub[0].KeyId, k.pub[1].KeyId} })
		if err := rotate(bad, fullRoot(k)); !errors.Is(err, ErrBadRoot) {
			t.Errorf("a repeated root key id: %v", err)
		}
	})

	// The threshold is compared with the number of ids a grant lists, but a
	// signature counts once per key. A repeated id would let the threshold look
	// reachable while no set of signers could ever meet it.
	t.Run("a grant that lists a key twice", func(t *testing.T) {
		for _, c := range []struct {
			name  string
			grant int // index in fullRoot().Roles
			id    int // key repeated in that grant
			role  signv1.Role
			typ   string
			sign  int
		}{
			{"bundle", 0, 0, signv1.Role_ROLE_BUNDLE, nodeType, 0},
			{"policy", 1, 2, signv1.Role_ROLE_POLICY, TypeHead, 2},
			{"catalog", 2, 3, signv1.Role_ROLE_CATALOG, ManifestPayloadType(signv1.Kind_KIND_FILTERS), 3},
		} {
			bad := fullRoot(k)
			g := bad.Roles[c.grant]
			g.KeyIds = [][]byte{k.pub[c.id].KeyId, k.pub[c.id].KeyId}
			g.Threshold = 2
			if err := rotate(nextRoot(func(r *signv1.Root) { r.Roles[c.grant] = g }), fullRoot(k)); !errors.Is(err, ErrBadRoot) {
				t.Errorf("%s: VerifyRoot accepted a repeated key id: %v", c.name, err)
			}
			if _, err := Verify(envelope(k, c.typ, payload, c.sign), bad, c.role, c.typ, 100); !errors.Is(err, ErrBadRoot) {
				t.Errorf("%s: Verify against a root with a repeated key id: %v", c.name, err)
			}
		}
	})

	t.Run("a new root with no root keys", func(t *testing.T) {
		bad := nextRoot(func(r *signv1.Root) { r.RootKeyIds = nil; r.Roles = r.Roles[1:] })
		if err := rotate(bad, fullRoot(k)); !errors.Is(err, ErrUnsignableRoot) {
			t.Errorf("no root keys in the new root: %v", err)
		}
	})

	t.Run("an old root with no root keys cannot rotate", func(t *testing.T) {
		old := fullRoot(k)
		old.RootKeyIds = nil
		old.Roles = old.Roles[1:]
		if err := rotate(nextRoot(func(*signv1.Root) {}), old); !errors.Is(err, ErrThreshold) {
			t.Errorf("rotating from a root with no root keys: %v", err)
		}
	})
}

// A key id must be KeyID of the key. A key with an id of its own choosing, in a
// grant or not, makes the root malformed.
func TestKeyIDMustBeDerivedFromTheKey(t *testing.T) {
	k := newKeys(t, 5)
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	r := fullRoot(k)
	r.Keys = append(append([]*signv1.PublicKey{}, r.Keys...), &signv1.PublicKey{KeyId: random, Ed25519: k.pub[4].Ed25519})
	env := envelope(k, nodeType, []byte("n"), 0, 1)
	if _, err := Verify(env, r, signv1.Role_ROLE_BUNDLE, nodeType, 100); !errors.Is(err, ErrBadRoot) {
		t.Errorf("a key under an id that is not its hash: %v", err)
	}
	// The same key under its real id is fine, so the failure above is the id.
	r.Keys[len(r.Keys)-1].KeyId = KeyID(k.pub[4].Ed25519)
	if _, err := Verify(env, r, signv1.Role_ROLE_BUNDLE, nodeType, 100); err != nil {
		t.Errorf("control: %v", err)
	}
}

// counter wraps ed25519.Verify and counts how often it runs.
type counter struct{ n int }

func (c *counter) check(pub ed25519.PublicKey, msg, sig []byte) bool {
	c.n++
	return ed25519.Verify(pub, msg, sig)
}

// One envelope must not be able to cost thousands of verifications over a
// payload of megabytes: more signatures than keys that could sign is refused
// before the first one is checked, and a key id is verified at most once.
func TestSignatureWorkIsBounded(t *testing.T) {
	k := newKeys(t, 6)
	root := fullRoot(k) // bundle grant: keys 0 and 1
	bad := &signv1.Signature{KeyId: k.pub[0].KeyId, Sig: make([]byte, ed25519.SignatureSize)}
	flood := func(n int) []*signv1.Signature {
		out := make([]*signv1.Signature, n)
		for i := range out {
			out[i] = bad
		}
		return out
	}

	t.Run("more signatures than the grant has keys", func(t *testing.T) {
		calls := &counter{}
		env := &signv1.Envelope{PayloadType: nodeType, Payload: []byte("n"), Signatures: flood(3)}
		if _, err := verify(env, root, signv1.Role_ROLE_BUNDLE, nodeType, 100, calls.check); !errors.Is(err, ErrTooManySignatures) {
			t.Errorf("err = %v", err)
		}
		if calls.n != 0 {
			t.Errorf("%d verifications ran before the refusal", calls.n)
		}
	})

	t.Run("a flood is refused without any verification", func(t *testing.T) {
		calls := &counter{}
		env := &signv1.Envelope{PayloadType: nodeType, Payload: make([]byte, 1<<20), Signatures: flood(20_000)}
		if _, err := verify(env, root, signv1.Role_ROLE_BUNDLE, nodeType, 100, calls.check); !errors.Is(err, ErrTooManySignatures) {
			t.Errorf("err = %v", err)
		}
		if calls.n != 0 {
			t.Errorf("%d verifications ran", calls.n)
		}
	})

	t.Run("a key id is verified once", func(t *testing.T) {
		calls := &counter{}
		// Two signatures fit a grant of two keys, but both are for key 0.
		env := &signv1.Envelope{PayloadType: nodeType, Payload: []byte("n"), Signatures: flood(2)}
		if _, err := verify(env, root, signv1.Role_ROLE_BUNDLE, nodeType, 100, calls.check); !errors.Is(err, ErrThreshold) {
			t.Errorf("err = %v", err)
		}
		if calls.n != 1 {
			t.Errorf("%d verifications for one key id, want 1", calls.n)
		}
	})

	t.Run("a good envelope still verifies", func(t *testing.T) {
		if _, err := Verify(envelope(k, nodeType, []byte("n"), 0, 1), root, signv1.Role_ROLE_BUNDLE, nodeType, 100); err != nil {
			t.Errorf("control: %v", err)
		}
	})

	t.Run("a root rotation has the same bounds", func(t *testing.T) {
		calls := &counter{}
		body := mustMarshal(t, &signv1.Root{Version: 2, ExpiresAt: far, Keys: k.pub[:3], Threshold: 2, RootKeyIds: [][]byte{k.pub[0].KeyId, k.pub[1].KeyId}})
		env := &signv1.Envelope{PayloadType: TypeRoot, Payload: body, Signatures: flood(MaxSignatures + 1)}
		if _, err := verifyRoot(env, root, calls.check); !errors.Is(err, ErrTooManySignatures) {
			t.Errorf("more than MaxSignatures: %v", err)
		}
		if calls.n != 0 {
			t.Errorf("%d verifications ran before the refusal", calls.n)
		}
		env.Signatures = flood(MaxSignatures)
		if _, err := verifyRoot(env, root, calls.check); !errors.Is(err, ErrThreshold) {
			t.Errorf("a flood within the cap: %v", err)
		}
		if calls.n != 1 {
			t.Errorf("%d verifications for one key id, want 1", calls.n)
		}
	})
}
