// Package app is the shared start-up of the five Panel roles: api, admin,
// worker, hub and migrate. In P0 each role is a stub that starts, checks its
// database role, serves /healthz and /readyz, and stops cleanly. Real work
// arrives phase by phase and changes only the role's own file.
package app

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Role is one of the roles the ctrlz binary can run as.
type Role string

// The roles. Each maps to one database role (spec section 2).
const (
	RoleAPI     Role = "api"
	RoleAdmin   Role = "admin"
	RoleWorker  Role = "worker"
	RoleHub     Role = "hub"
	RoleMigrate Role = "migrate"
)

// Roles lists every role, in the order help text shows them.
func Roles() []Role { return []Role{RoleAPI, RoleAdmin, RoleWorker, RoleHub, RoleMigrate} }

// ParseRole accepts a role name.
func ParseRole(s string) (Role, error) {
	for _, r := range Roles() {
		if string(r) == s {
			return r, nil
		}
	}
	return "", fmt.Errorf("unknown role %q", s)
}

// dbRole is the Postgres role this process logs in as.
func (r Role) dbRole() dbRoleName {
	switch r {
	case RoleAPI:
		return "ctrlz_tenant"
	case RoleAdmin:
		return "ctrlz_admin"
	case RoleWorker:
		return "ctrlz_worker"
	case RoleHub:
		return "ctrlz_hub"
	case RoleMigrate:
		return "ctrlz_migrator"
	}
	return ""
}

// dbRoleName is a Postgres login role as a closed string, so a log line may carry it.
type dbRoleName string

// Valid reports membership: the roles a process may log in as.
func (d dbRoleName) Valid() bool {
	switch d {
	case "ctrlz_tenant", "ctrlz_admin", "ctrlz_worker", "ctrlz_hub", "ctrlz_migrator", "ctrlz_compiler":
		return true
	}
	return false
}

// defaultListen is the health and (later) API address of each role.
func (r Role) defaultListen() string {
	switch r {
	case RoleAPI:
		return ":8080"
	case RoleAdmin:
		return ":8081"
	// The hub and the worker serve only the health mux in P1, so their default is loopback
	// (requireLoopbackIfHealthOnly); the hub's node listener is a separate one in P4.
	case RoleHub:
		return "127.0.0.1:8082"
	case RoleWorker:
		return "127.0.0.1:8083"
	}
	return ""
}

// Config is the environment of one process. Secrets are read from files, the
// way Docker secrets arrive, and held as secret.String from the first moment.
type Config struct {
	Role   Role
	Listen string

	// DBHost empty means no database: the stub still starts, and /readyz says
	// so. Compose always sets it.
	DBHost     string
	DBPort     uint16
	DBName     string
	DBSSLMode  string
	DBPassword secret.String
	DBMaxConns int32

	// CompilerPassword is the worker's second pool, as ctrlz_compiler (spec
	// section 13, item 1). Empty means the compiler job is not enabled.
	CompilerPassword secret.String

	// ProofKey is the key the hub derives UDP proof codes from (contract 3.5).
	// Hub only: it lives in a Docker secret mounted into that one service, and
	// is never in Postgres or in another role, so a tenant that reads any table
	// still cannot compute the code that went to somebody else's address.
	ProofKey secret.String

	// Env is production (the default), dev or test. Only test may run without
	// key files (see keyring wiring in runtime.go); anything else is a start
	// error, so a typo cannot loosen a deployment.
	Env Env

	// KEKDir holds kek_<domain> key files, /run/secrets under Compose (spec 8,
	// 17.2). The variable is named KEK on purpose: the compose test treats any
	// variable matching KEY as a secret file, and this one is a directory.
	KEKDir string

	// PanelHost and AdminHost are the hostnames the two services answer to, the
	// same variables Caddy reads (spec 2.3 step 6). The panel host can later be
	// overridden by domain_settings.panel_host.
	PanelHost string
	AdminHost string

	// ValkeyAddr is host:port of the rate limit store; empty means none. Its
	// password is read from a file like the other secrets. Valkey is optional at
	// start: the limiter falls back to an in-process bucket (spec 14.1).
	ValkeyAddr     string
	ValkeyUsername string // the ACL user; empty means the default user
	ValkeyPassword secret.String

	// TrustedProxies are the peers allowed to set X-Forwarded-For on api and admin
	// (CTRLZ_TRUSTED_PROXY): Caddy's fixed address on the app network. Any other
	// container that can reach the port could otherwise write the header itself and
	// pick its own address for every per-network limit (review round 3, admin-r3-13).
	TrustedProxies []netip.Prefix

	// NoopSMSFile is where the noop SMS gateway appends messages. dev and test
	// only: it exists so a flow test can read an OTP, and a deployment that set
	// it would write codes to disk.
	NoopSMSFile string

	// Argon2 is read for api and admin, the roles that hash passwords (4.1).
	Argon2 password.Settings

	ShutdownTimeout time.Duration
}

// Getenv is os.Getenv, replaceable in tests.
type Getenv func(string) string

// LoadConfig reads the environment. Variable names:
//
//	CTRLZ_LISTEN                   listen address
//	CTRLZ_DB_HOST, _PORT, _NAME    database address
//	CTRLZ_DB_SSLMODE               disable (default) or require
//	CTRLZ_DB_PASSWORD_FILE         file holding this role's password
//	CTRLZ_DB_COMPILER_PASSWORD_FILE  worker only: the compiler role's password
//	CTRLZ_PROOF_KEY_FILE           hub only: the proof_key secret
//	CTRLZ_DB_MAX_CONNS             pool size
//	CTRLZ_ENV                      production (default), dev or test
//	CTRLZ_KEK_DIR                  directory of kek_<domain> key files (spec 8)
//	CTRLZ_ARGON2_M_KIB, _T, _CONCURRENCY, _BUDGET_MIB   password hashing cost (spec 4.1)
//	CTRLZ_PANEL_HOST, CTRLZ_ADMIN_HOST     the hostnames of the api and admin services
//	CTRLZ_VALKEY_ADDR, _PASSWORD_FILE      rate limit store (optional)
//	CTRLZ_TRUSTED_PROXY            api and admin: addresses or prefixes allowed to set X-Forwarded-For (required in production)
//	CTRLZ_NOOP_SMS_FILE                    dev and test only
func LoadConfig(role Role, getenv Getenv) (Config, error) {
	c := Config{
		Role:            role,
		Listen:          orDefault(getenv("CTRLZ_LISTEN"), role.defaultListen()),
		DBHost:          getenv("CTRLZ_DB_HOST"),
		DBName:          orDefault(getenv("CTRLZ_DB_NAME"), "ctrlz"),
		DBSSLMode:       orDefault(getenv("CTRLZ_DB_SSLMODE"), "disable"),
		ShutdownTimeout: 15 * time.Second,
	}
	var err error
	if c.Env, err = parseEnv(getenv("CTRLZ_ENV")); err != nil {
		return Config{}, err
	}
	c.KEKDir = getenv("CTRLZ_KEK_DIR")
	// The defaults are the ones Compose passes, so a bare local run answers to the
	// same names Caddy serves.
	c.PanelHost = orDefault(getenv("CTRLZ_PANEL_HOST"), "panel.localhost")
	c.AdminHost = orDefault(getenv("CTRLZ_ADMIN_HOST"), "admin.localhost")
	c.ValkeyAddr = getenv("CTRLZ_VALKEY_ADDR")
	c.ValkeyUsername = getenv("CTRLZ_VALKEY_USER")
	if c.TrustedProxies, err = httpx.ParseTrustedProxies(getenv("CTRLZ_TRUSTED_PROXY")); err != nil {
		return Config{}, errors.New("CTRLZ_TRUSTED_PROXY is not a list of addresses or prefixes")
	}
	if f := getenv("CTRLZ_VALKEY_PASSWORD_FILE"); f != "" {
		pw, err := secret.FromFile(f)
		if err != nil {
			return Config{}, err
		}
		c.ValkeyPassword = pw
	}
	if f := getenv("CTRLZ_NOOP_SMS_FILE"); f != "" {
		if c.Env == EnvProduction {
			return Config{}, errors.New("CTRLZ_NOOP_SMS_FILE is for dev and test only")
		}
		c.NoopSMSFile = f
	}
	if role.hashesPasswords() {
		if c.Argon2, err = password.FromEnv(getenv); err != nil {
			return Config{}, err
		}
	}
	port, err := strconv.ParseUint(orDefault(getenv("CTRLZ_DB_PORT"), "5432"), 10, 16)
	if err != nil {
		return Config{}, errors.New("CTRLZ_DB_PORT is not a port number")
	}
	c.DBPort = uint16(port)
	if v := getenv("CTRLZ_DB_MAX_CONNS"); v != "" {
		n, err := strconv.ParseInt(v, 10, 32)
		if err != nil || n < 1 {
			return Config{}, errors.New("CTRLZ_DB_MAX_CONNS is not a positive number")
		}
		c.DBMaxConns = int32(n)
	}
	if f := getenv("CTRLZ_DB_PASSWORD_FILE"); f != "" {
		pw, err := secret.FromFile(f)
		if err != nil {
			return Config{}, err
		}
		c.DBPassword = pw
	}
	if f := getenv("CTRLZ_DB_COMPILER_PASSWORD_FILE"); f != "" {
		if role != RoleWorker {
			return Config{}, errors.New("CTRLZ_DB_COMPILER_PASSWORD_FILE is for the worker only")
		}
		pw, err := secret.FromFile(f)
		if err != nil {
			return Config{}, err
		}
		c.CompilerPassword = pw
	}
	if f := getenv("CTRLZ_PROOF_KEY_FILE"); f != "" {
		if role != RoleHub {
			return Config{}, errors.New("CTRLZ_PROOF_KEY_FILE is for the hub only")
		}
		k, err := secret.FromFile(f)
		if err != nil {
			return Config{}, err
		}
		c.ProofKey = k
	}
	if c.DBHost != "" && c.DBPassword.IsZero() {
		return Config{}, errors.New("CTRLZ_DB_HOST is set but CTRLZ_DB_PASSWORD_FILE is not")
	}
	if role == RoleMigrate && c.DBHost == "" {
		return Config{}, errors.New("migrate needs CTRLZ_DB_HOST")
	}
	return c, nil
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

// storeConfig builds the store configuration for a service role.
func (c Config) storeConfig(dbRole store.Role, pw secret.String) store.Config {
	return store.Config{
		Host:            c.DBHost,
		Port:            c.DBPort,
		Database:        c.DBName,
		Role:            dbRole,
		Password:        pw,
		SSLMode:         c.DBSSLMode,
		MaxConns:        c.DBMaxConns,
		ConnectTimeout:  10 * time.Second,
		MaxConnLifetime: time.Hour,
		ApplicationName: "ctrlz-" + string(c.Role),
	}
}

// Env is the deployment kind, CTRLZ_ENV.
type Env string

// The environments of spec 17.2.
const (
	EnvProduction Env = "production"
	EnvDev        Env = "dev"
	EnvTest       Env = "test"
)

func parseEnv(s string) (Env, error) {
	switch Env(s) {
	case "":
		// Unset means production: a deployment that forgot the variable must get
		// the strict behaviour, not the lenient one.
		return EnvProduction, nil
	case EnvProduction, EnvDev, EnvTest:
		return Env(s), nil
	}
	return "", errors.New("CTRLZ_ENV must be production, dev or test")
}

// KeyDomains are the key domains this role holds (spec 2.1). The split is the
// point of the design: a compromised api cannot read SMS credentials, and a
// compromised worker cannot read TOTP seeds. hub and migrate hold none.
func (r Role) KeyDomains() []string {
	switch r {
	case RoleAPI:
		return []string{keyring.DomainUserTOTP, keyring.DomainOTPDelivery, keyring.DomainAuthMAC}
	case RoleAdmin:
		return []string{keyring.DomainAdminTOTP, keyring.DomainSMSCred, keyring.DomainAdminMAC, keyring.DomainInviteSign}
	case RoleWorker:
		return []string{keyring.DomainSMSCred, keyring.DomainOTPDelivery}
	}
	return nil
}

// PublicDomains are the signing domains whose public half this role holds (spec 8.3, D67). The api opens
// invite links and can never make one: it gets pub_invite_sign, which is no secret, and not the key.
func (r Role) PublicDomains() []string {
	if r == RoleAPI {
		return []string{keyring.DomainInviteSign}
	}
	return nil
}

// hashesPasswords is true for the roles that run Argon2 (4.1).
func (r Role) hashesPasswords() bool { return r == RoleAPI || r == RoleAdmin }

// Valid reports whether r is one of the roles, so a log line may carry it.
func (r Role) Valid() bool {
	for _, k := range Roles() {
		if r == k {
			return true
		}
	}
	return false
}
