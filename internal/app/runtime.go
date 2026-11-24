package app

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
)

// Runtime is what the long-running roles build once at start and hand to their
// handlers. It carries no database pool: the Store is opened separately, and
// the role's own file puts the two together.
//
// Roles read the fields they are meant to hold. Keys is nil for hub and
// migrate, which hold no domain; Hasher is nil for roles that do not hash
// passwords.
type Runtime struct {
	Keys   *keyring.Ring
	Hasher *password.Hasher
	// Public holds the public keys of the signing domains the role only verifies (the api and the invite
	// links, D67). Nil for the roles that have none. It is read from pub_<domain> in the key directory, and
	// is a throw-away ring in the test environment, like the keys.
	Public *keyring.PublicRing
}

// newRuntime loads the role's key domains and builds its password hasher. A
// consoleTool (ctrlz-admin) gets the one-time hasher instead of the service's.
//
// Production and dev read kek_<domain> from CTRLZ_KEK_DIR and refuse to start
// if any file of the role's domains is missing or malformed (spec 8.2, 18.3),
// so the failure shows at start-up and not at the first login. The error names
// the domain and never a key.
//
// Only the test environment may run without a key directory, on random keys
// that die with the process. That is what lets the stub tests of P0 and the
// flow tests of later phases start a role with no secrets mounted, while a
// deployment that forgets its secrets cannot: CTRLZ_ENV defaults to
// production.
func newRuntime(cfg Config, log *slog.Logger, consoleTool bool) (*Runtime, error) {
	rt := &Runtime{}
	if domains := cfg.Role.KeyDomains(); len(domains) > 0 {
		switch {
		case cfg.KEKDir != "":
			ring, err := keyring.Load(cfg.KEKDir, domains...)
			if err != nil {
				return nil, fmt.Errorf("keys: %w", err)
			}
			rt.Keys = ring
			log.Info("keys loaded", logattr.Enums("domains", ring.LoadedNames()))
		case cfg.Env == EnvTest:
			ring, err := keyring.NewEphemeral(domains...)
			if err != nil {
				return nil, fmt.Errorf("keys: %w", err)
			}
			rt.Keys = ring
			log.Warn("test environment: using throw-away keys", logattr.Enums("domains", ring.LoadedNames()))
		default:
			return nil, errors.New("keys: CTRLZ_KEK_DIR is not set (only CTRLZ_ENV=test may run without key files)")
		}
		if err := rt.Keys.Require(domains...); err != nil {
			return nil, fmt.Errorf("keys: %w", err)
		}
	}
	for _, d := range cfg.Role.PublicDomains() {
		switch {
		case cfg.KEKDir != "":
			pub, err := keyring.LoadPublic(cfg.KEKDir, d)
			if err != nil {
				return nil, fmt.Errorf("keys: %w", err)
			}
			rt.Public = pub
			log.Info("public keys loaded", logattr.Enums("domains", []keyring.DomainName{pub.Name()}))
		case cfg.Env == EnvTest:
			// One process cannot share a key with another, so the links of a test process open only in itself.
			ring, err := keyring.NewEphemeral(d)
			if err != nil {
				return nil, fmt.Errorf("keys: %w", err)
			}
			if rt.Public, err = ring.Public(d); err != nil {
				return nil, fmt.Errorf("keys: %w", err)
			}
		default:
			return nil, errors.New("keys: CTRLZ_KEK_DIR is not set (only CTRLZ_ENV=test may run without key files)")
		}
	}
	switch {
	case cfg.Role.hashesPasswords() && consoleTool:
		// A command of ctrlz-admin runs in the live admin service's cgroup and
		// only makes one-time hashes (8 KiB). The full-cost dummy hash of the
		// service's hasher would add 46 MiB outside the service's Argon2 gate
		// (review round 4, admin-r4-2).
		h, err := password.NewOneTimeHasher()
		if err != nil {
			return nil, fmt.Errorf("password hashing: %w", err)
		}
		rt.Hasher = h
	case cfg.Role.hashesPasswords():
		h, err := cfg.Argon2.NewHasher()
		if err != nil {
			return nil, fmt.Errorf("password hashing: %w", err)
		}
		// One closed line and a counter, no hash and no account: the operator who lowered the memory budget
		// needs to hear that old hashes are now read as wrong passwords (primitives-r8-5).
		h.OnUnreadable(func() { log.Warn("a stored password hash could not be read") })
		rt.Hasher = h
		log.Info("password hashing ready",
			logattr.Int("memory_kib", int(cfg.Argon2.Params.MemoryKiB)), logattr.Int("time", int(cfg.Argon2.Params.Time)), logattr.Int("concurrency", int(cfg.Argon2.Concurrency)))
	}
	return rt, nil
}
