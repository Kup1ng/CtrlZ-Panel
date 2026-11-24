package totp

import (
	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
)

// UserAAD is the context a user's TOTP seed is sealed under (spec 6.2):
// tenant_id 0x00 user_id, as the text forms of the ids. Binding both means a
// ciphertext copied to another row fails to open. The api, the rekey tool and
// the tests build it here so the bytes cannot drift. A zero id gives the zero
// Context, which the ring refuses (keyring.RowContext).
func UserAAD(tenant, user uuid.UUID) keyring.Context {
	return keyring.RowContext([]uuid.UUID{tenant, user})
}

// AdminAAD is the context of an admin's seed: the admin id alone.
func AdminAAD(admin uuid.UUID) keyring.Context { return keyring.RowContext([]uuid.UUID{admin}) }
