package totp

import "github.com/google/uuid"

// UserAAD is the context a user's TOTP seed is sealed under (spec 6.2):
// tenant_id 0x00 user_id, as the text forms of the ids. Binding both means a
// ciphertext copied to another row fails to open. The api, the rekey tool and
// the tests build it here so the bytes cannot drift.
func UserAAD(tenant, user uuid.UUID) []byte {
	return []byte(tenant.String() + "\x00" + user.String())
}

// AdminAAD is the context of an admin's seed: the admin id alone.
func AdminAAD(admin uuid.UUID) []byte { return []byte(admin.String()) }
