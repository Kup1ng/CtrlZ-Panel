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
	"github.com/Kup1ng/CtrlZ-Panel/internal/safego"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// HubConfig is the node port of the hub role (p4-nodes 3.3, 5.1). It is on when CTRLZ_HUB_HOST is set; a hub
// with none serves the health mux alone, as it did before P4, and every other file variable is then refused,
// so a half-configured hub cannot start looking like a whole one.
//
//	CTRLZ_HUB_HOST            the names and addresses of the hub leaf, comma separated (the install command's host)
//	CTRLZ_HUB_LISTEN          the node port, default 0.0.0.0:9443
//	CTRLZ_NODE_CA_KEY_FILE    the node CA key (PKCS#8 PEM)
//	CTRLZ_NODE_CA_PEM_FILE    the node CA certificate
//	CTRLZ_HUB_TLS_KEY_FILE    the key of the hub's leaf, whose SPKI the nodes pin
//	CTRLZ_ZONE_CA_KEY_FILE    the zone CA key
//	CTRLZ_HUB_PUBLIC_DIR      the volume hub_tls.spki is written to
//	CTRLZ_BUNDLES_DIR         root.json and the signed bundles, read-only
type HubConfig struct {
	Host, Listen                 string
	NodeCAKeyFile, NodeCAPEMFile string
	TLSKeyFile, ZoneCAKeyFile    string
	PublicDir, BundlesDir        string
	nodeCAKey, tlsKey, zoneCAKey secret.Bytes
}

// Enabled says whether the node port is on.
func (h HubConfig) Enabled() bool { return h.Host != "" }

const defaultHubListen = "0.0.0.0:9443"

func loadHubConfig(role Role, getenv Getenv, c *Config) error {
	names := []string{"CTRLZ_HUB_HOST", "CTRLZ_HUB_LISTEN", "CTRLZ_NODE_CA_KEY_FILE", "CTRLZ_NODE_CA_PEM_FILE", "CTRLZ_HUB_TLS_KEY_FILE",
		"CTRLZ_ZONE_CA_KEY_FILE", "CTRLZ_HUB_PUBLIC_DIR", "CTRLZ_BUNDLES_DIR"}
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
	for n, v := range map[string]string{"CTRLZ_NODE_CA_KEY_FILE": h.NodeCAKeyFile, "CTRLZ_NODE_CA_PEM_FILE": h.NodeCAPEMFile, "CTRLZ_HUB_TLS_KEY_FILE": h.TLSKeyFile,
		"CTRLZ_ZONE_CA_KEY_FILE": h.ZoneCAKeyFile, "CTRLZ_HUB_PUBLIC_DIR": h.PublicDir, "CTRLZ_BUNDLES_DIR": h.BundlesDir} {
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
	c.Hub = h
	return nil
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
		HubHost: cfg.Hub.Host, PublicDir: cfg.Hub.PublicDir, BundlesDir: cfg.Hub.BundlesDir,
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
