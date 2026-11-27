package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub"
	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
	"github.com/Kup1ng/CtrlZ-Panel/internal/nodeadmin"
	"github.com/Kup1ng/CtrlZ-Panel/internal/safego"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// HubConfig is the node port of the hub role (p4-nodes 3.3, 5.1). It is on when CTRLZ_HUB_HOST is set; a hub
// with none serves the health mux alone, as it did before P4, and every other file variable is then refused,
// so a half-configured hub cannot start looking like a whole one.
//
//	CTRLZ_HUB_HOST            the names and addresses of the hub leaf, comma separated (the install command's host); the admin
//	                          role reads it too, for that command, and no other variable of this list
//	CTRLZ_HUB_LISTEN          the node port, default 0.0.0.0:9443
//	CTRLZ_NODE_CA_KEY_FILE    the node CA key (PKCS#8 PEM)
//	CTRLZ_NODE_CA_PEM_FILE    the node CA certificate
//	CTRLZ_HUB_TLS_KEY_FILE    the key of the hub's leaf, whose SPKI the nodes pin
//	CTRLZ_ZONE_CA_KEY_FILE    the zone CA key
//	CTRLZ_HUB_PUBLIC_DIR      the volume hub_tls.spki is written to
//	CTRLZ_BUNDLES_DIR         root.json and the signed bundles, read-only
//	CTRLZ_POLICY_KEY_FILE     the policy key (Ed25519) that signs heads
//	CTRLZ_WILDCARD_INTAKE_KEY_FILE  the private half of the wildcard intake key (X25519): the one key that opens the private
//	                          key of an uploaded wildcard certificate, so the hub can seal it again for each node (4.3)
//	CTRLZ_HUB_NTS_DIR         optional: where the NTS leaf of the panel host's chrony is written (deploy/chrony/nts, 7.10); unset writes none
//	CTRLZ_HUB_ARTIFACTS_DIR   the blobs and snapshots the compiler wrote, read-only (the worker has CTRLZ_ARTIFACTS_DIR)
type HubConfig struct {
	Host, Listen                 string
	NodeCAKeyFile, NodeCAPEMFile string
	TLSKeyFile, ZoneCAKeyFile    string
	PublicDir, BundlesDir        string
	PolicyKeyFile, ArtifactsDir  string
	WildcardKeyFile              string
	NTSDir                       string // optional
	nodeCAKey, tlsKey, zoneCAKey secret.Bytes
	policyKey, wildcardKey       secret.Bytes
}

// Enabled says whether the node port is on.
func (h HubConfig) Enabled() bool { return h.Host != "" }

const defaultHubListen = "0.0.0.0:9443"

func loadHubConfig(role Role, getenv Getenv, c *Config) error {
	names := []string{"CTRLZ_HUB_HOST", "CTRLZ_HUB_LISTEN", "CTRLZ_NODE_CA_KEY_FILE", "CTRLZ_NODE_CA_PEM_FILE", "CTRLZ_HUB_TLS_KEY_FILE",
		"CTRLZ_ZONE_CA_KEY_FILE", "CTRLZ_HUB_PUBLIC_DIR", "CTRLZ_BUNDLES_DIR", "CTRLZ_POLICY_KEY_FILE", "CTRLZ_HUB_ARTIFACTS_DIR",
		"CTRLZ_WILDCARD_INTAKE_KEY_FILE", "CTRLZ_HUB_NTS_DIR"}
	// The admin has its own, smaller set (loadInstallConfig): the host and the two read-only volumes of the
	// install command, and none of the hub's keys.
	if role == RoleAdmin {
		return loadInstallConfig(getenv, c)
	}
	if role != RoleHub {
		for _, n := range names {
			if getenv(n) != "" {
				return fmt.Errorf("%s is for the hub only", n)
			}
		}
		return nil
	}
	h := HubConfig{Host: getenv("CTRLZ_HUB_HOST")}
	if h.Host == "" {
		for _, n := range names[1:] {
			if getenv(n) != "" {
				return fmt.Errorf("%s is set but CTRLZ_HUB_HOST is not", n)
			}
		}
		return nil
	}
	h.Listen = orDefault(getenv("CTRLZ_HUB_LISTEN"), defaultHubListen)
	h.NodeCAKeyFile, h.NodeCAPEMFile = getenv("CTRLZ_NODE_CA_KEY_FILE"), getenv("CTRLZ_NODE_CA_PEM_FILE")
	h.TLSKeyFile, h.ZoneCAKeyFile = getenv("CTRLZ_HUB_TLS_KEY_FILE"), getenv("CTRLZ_ZONE_CA_KEY_FILE")
	h.PublicDir, h.BundlesDir = getenv("CTRLZ_HUB_PUBLIC_DIR"), getenv("CTRLZ_BUNDLES_DIR")
	h.PolicyKeyFile, h.ArtifactsDir = getenv("CTRLZ_POLICY_KEY_FILE"), getenv("CTRLZ_HUB_ARTIFACTS_DIR")
	h.WildcardKeyFile = getenv("CTRLZ_WILDCARD_INTAKE_KEY_FILE")
	h.NTSDir = getenv("CTRLZ_HUB_NTS_DIR")
	for n, v := range map[string]string{"CTRLZ_NODE_CA_KEY_FILE": h.NodeCAKeyFile, "CTRLZ_NODE_CA_PEM_FILE": h.NodeCAPEMFile, "CTRLZ_HUB_TLS_KEY_FILE": h.TLSKeyFile,
		"CTRLZ_ZONE_CA_KEY_FILE": h.ZoneCAKeyFile, "CTRLZ_HUB_PUBLIC_DIR": h.PublicDir, "CTRLZ_BUNDLES_DIR": h.BundlesDir,
		"CTRLZ_POLICY_KEY_FILE": h.PolicyKeyFile, "CTRLZ_HUB_ARTIFACTS_DIR": h.ArtifactsDir, "CTRLZ_WILDCARD_INTAKE_KEY_FILE": h.WildcardKeyFile} {
		if v == "" {
			return fmt.Errorf("CTRLZ_HUB_HOST is set but %s is not", n)
		}
	}
	// The pools are fixed by their sizes (5.7): the hub's CTRLZ_DB_MAX_CONNS is their sum, and a different
	// number would be a configuration that does not match the pools it is meant to size.
	if c.DBMaxConns != 0 && c.DBMaxConns != hub.PoolTotal {
		return errors.New("CTRLZ_DB_MAX_CONNS of the hub must be " + strconv.Itoa(hub.PoolTotal) + ", the sum of its pools")
	}
	var err error
	if h.nodeCAKey, err = secret.BytesFromFile(h.NodeCAKeyFile); err != nil {
		return err
	}
	if h.tlsKey, err = secret.BytesFromFile(h.TLSKeyFile); err != nil {
		return err
	}
	if h.zoneCAKey, err = secret.BytesFromFile(h.ZoneCAKeyFile); err != nil {
		return err
	}
	if h.policyKey, err = secret.BytesFromFile(h.PolicyKeyFile); err != nil {
		return err
	}
	// Required, not optional: the admin takes an uploaded wildcard whenever its public half is mounted, and a hub that could
	// not open the key would serve the private CA's leaf for a zone the admin told its tenants needs no reinstall.
	if h.wildcardKey, err = secret.BytesFromFile(h.WildcardKeyFile); err != nil {
		return err
	}
	// The proof key goes to every node in NodeConfig; the hub that serves the node port needs it.
	if c.ProofKey.IsZero() {
		return errors.New("CTRLZ_HUB_HOST is set but CTRLZ_PROOF_KEY_FILE is not")
	}
	c.Hub = h
	return nil
}

// InstallConfig is what the admin role needs to print an install command (p4-nodes 3.3, 4.2 step 1): the host
// the nodes call, and the two volumes it mounts read-only, hub_public (the pin the hub writes) and the signed
// bundles with root.json. All three are set or none: a half set would print a command that cannot work.
//
//	CTRLZ_HUB_HOST         the names and addresses of the hub leaf; the first is the install host
//	CTRLZ_HUB_PUBLIC_DIR   the volume hub_tls.spki is read from
//	CTRLZ_BUNDLES_DIR      root.json and the signed bundles
type InstallConfig struct {
	Host, PublicDir, BundlesDir string
}

// Enabled says whether the admin can print install commands.
func (i InstallConfig) Enabled() bool { return i.Host != "" }

func loadInstallConfig(getenv Getenv, c *Config) error {
	i := InstallConfig{Host: getenv("CTRLZ_HUB_HOST"), PublicDir: getenv("CTRLZ_HUB_PUBLIC_DIR"), BundlesDir: getenv("CTRLZ_BUNDLES_DIR")}
	for n, v := range map[string]string{"CTRLZ_HUB_HOST": i.Host, "CTRLZ_HUB_PUBLIC_DIR": i.PublicDir, "CTRLZ_BUNDLES_DIR": i.BundlesDir} {
		if v == "" && (i.Host != "" || i.PublicDir != "" || i.BundlesDir != "") {
			return fmt.Errorf("the install command needs CTRLZ_HUB_HOST, CTRLZ_HUB_PUBLIC_DIR and CTRLZ_BUNDLES_DIR together, and %s is not set", n)
		}
	}
	// The keys and the listen address are the hub's alone; the admin mounts no private key (N8).
	for _, n := range []string{"CTRLZ_HUB_LISTEN", "CTRLZ_NODE_CA_KEY_FILE", "CTRLZ_NODE_CA_PEM_FILE", "CTRLZ_HUB_TLS_KEY_FILE", "CTRLZ_ZONE_CA_KEY_FILE", "CTRLZ_POLICY_KEY_FILE", "CTRLZ_HUB_ARTIFACTS_DIR", "CTRLZ_WILDCARD_INTAKE_KEY_FILE"} {
		if getenv(n) != "" {
			return fmt.Errorf("%s is for the hub only", n)
		}
	}
	c.Install = i
	return nil
}

// newInstaller builds the install command maker of the admin role, or nil when the deployment has no hub host.
// The directories are read through os.DirFS, which cannot leave its root, so a name in a manifest or a pin file
// can never reach another file. A production admin refuses the lab test root, as the hub does.
func newInstaller(cfg Config) (*nodeadmin.Installer, error) {
	if !cfg.Install.Enabled() {
		return nil, nil
	}
	ic := nodeadmin.InstallConfig{HubHost: cfg.Install.Host, Public: os.DirFS(cfg.Install.PublicDir), Bundles: os.DirFS(cfg.Install.BundlesDir)}
	if cfg.Env == EnvProduction {
		ic.DenyRootKeys = hub.LabRootKeyIDs()
	}
	return nodeadmin.NewInstaller(ic)
}

type hubUnit string

const unitHub hubUnit = "hub_node_port"

func (u hubUnit) Valid() bool { return u == unitHub }

// startHub builds the hub and serves its node port until ctx ends. The returned channel receives the one
// error that stops it (or nil after a clean stop).
func startHub(ctx context.Context, cfg Config, pools *hub.Pools, log *slog.Logger) (<-chan error, error) {
	caPEM, err := os.ReadFile(cfg.Hub.NodeCAPEMFile)
	if err != nil {
		return nil, errors.New("hub: cannot read the node CA certificate")
	}
	deps := hub.Deps{
		Stores: pools.Stores(), Now: appclock.Now, Log: log,
		NodeCAKeyPEM: cfg.Hub.nodeCAKey.Reveal(), NodeCAPEM: caPEM, HubKeyPEM: cfg.Hub.tlsKey.Reveal(), ZoneKeyPEM: cfg.Hub.zoneCAKey.Reveal(),
		HubHost: cfg.Hub.Host, PublicDir: cfg.Hub.PublicDir, BundlesDir: cfg.Hub.BundlesDir, NTSDir: cfg.Hub.NTSDir,
		PolicyKeyPEM: cfg.Hub.policyKey.Reveal(), WildcardKeyPEM: cfg.Hub.wildcardKey.Reveal(), ProofKey: []byte(cfg.ProofKey.Reveal()), ArtifactsDir: cfg.Hub.ArtifactsDir,
	}
	if cfg.Env == EnvProduction {
		deps.DenyRootKeys = hub.LabRootKeyIDs()
	}
	h, err := hub.Build(ctx, deps)
	if err != nil {
		return nil, fmt.Errorf("hub: %w", err)
	}
	ln, err := net.Listen("tcp", cfg.Hub.Listen)
	if err != nil {
		return nil, fmt.Errorf("hub: listen: %w", err)
	}
	log.Info("node port started", logattr.Addr("listen", listenAddr(ln)))
	errc := make(chan error, 1)
	safego.Go(log, unitHub, func() {
		var err error
		if safego.Run(log, unitHub, func() { err = h.Serve(ctx, ln) }) {
			err = errors.New("hub: the node port stopped by a panic")
		}
		errc <- err
	})
	return errc, nil
}
