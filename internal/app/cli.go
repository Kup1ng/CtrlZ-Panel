package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The command-line tools (internal/admincli) start the same way a service does:
// the same environment, the same secret files, the same key rings. They differ
// in two ways. They hold one database connection, because a command does one
// thing at a time, and they say nothing through slog: their output is the
// command's output (spec 10.1).

// discardLog is the logger the tools hand to code that logs. Command output
// never goes through slog, so a one-time password cannot reach `docker logs`.
func discardLog() *slog.Logger { return slog.New(slog.DiscardHandler) }

// ConnectAdmin loads the admin role's configuration, keys and hasher from the
// environment and opens a one-connection store as ctrlz_admin. It is what
// `docker compose exec admin ctrlz-admin ...` runs, so it sees exactly the
// secret files and variables the admin service has.
func ConnectAdmin(ctx context.Context, getenv Getenv) (Config, *Runtime, *store.Store, error) {
	cfg, err := LoadConfig(RoleAdmin, getenv)
	if err != nil {
		return Config{}, nil, nil, fmt.Errorf("config: %w", err)
	}
	if cfg.DBHost == "" {
		return Config{}, nil, nil, errors.New("config: CTRLZ_DB_HOST is not set")
	}
	cfg.DBMaxConns = 1
	rt, err := newRuntime(cfg, discardLog(), true)
	if err != nil {
		return Config{}, nil, nil, err
	}
	st, err := store.Open(ctx, cfg.storeConfig(store.RoleAdmin, cfg.DBPassword))
	if err != nil {
		return Config{}, nil, nil, fmt.Errorf("database: %w", err)
	}
	return cfg, rt, st, nil
}

// ConnectRekey loads what the one-shot key tool needs: the key tool database
// role (ctrlz_keytool, db-r4-3) and the user_totp key domain, and nothing else.
// The long-running worker
// holds the ciphertext rights but not this key; this container is the one place
// the role meets it (spec 8.4).
func ConnectRekey(ctx context.Context, getenv Getenv) (Config, *keyring.Ring, *store.Store, error) {
	cfg, err := LoadConfig(RoleWorker, getenv)
	if err != nil {
		return Config{}, nil, nil, fmt.Errorf("config: %w", err)
	}
	if cfg.DBHost == "" {
		return Config{}, nil, nil, errors.New("config: CTRLZ_DB_HOST is not set")
	}
	cfg.DBMaxConns = 1
	var ring *keyring.Ring
	switch {
	case cfg.KEKDir != "":
		ring, err = keyring.Load(cfg.KEKDir, keyring.DomainUserTOTP)
	case cfg.Env == EnvTest:
		ring, err = keyring.NewEphemeral(keyring.DomainUserTOTP)
	default:
		err = errors.New("CTRLZ_KEK_DIR is not set (only CTRLZ_ENV=test may run without key files)")
	}
	if err != nil {
		return Config{}, nil, nil, fmt.Errorf("keys: %w", err)
	}
	st, err := store.Open(ctx, cfg.storeConfig(store.RoleKeytool, cfg.DBPassword))
	if err != nil {
		return Config{}, nil, nil, fmt.Errorf("database: %w", err)
	}
	return cfg, ring, st, nil
}
