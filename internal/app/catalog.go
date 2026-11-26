package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/Kup1ng/CtrlZ-Shared/netclass"

	"github.com/Kup1ng/CtrlZ-Panel/internal/catalogfx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/compiler"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// RunCatalog is `ctrlz catalog <command>`. P4 has one command, load-fixture FILE (6.3): it makes a catalog version of a
// fixture file in the format of shared/vectors/fixtures, so the compiler has a catalog to carry before P6. A binary built without the ctrlz_lab tag
// refuses it when CTRLZ_ENV is production (netclass.AllowPrivatePairAddrs is the one constant the tag sets), and the
// command runs as the worker role with one connection, in the container that has the artifacts volume.
func RunCatalog(ctx context.Context, args []string, getenv Getenv, out, errOut io.Writer) int {
	if len(args) != 2 || args[0] != "load-fixture" {
		fmt.Fprintln(errOut, "usage: ctrlz catalog load-fixture FILE")
		return 2
	}
	if err := loadFixture(ctx, args[1], getenv, out); err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	return 0
}

// RunCatalogMain is RunCatalog on the process's own environment and streams.
func RunCatalogMain(ctx context.Context, args []string) int {
	return RunCatalog(ctx, args, os.Getenv, os.Stdout, os.Stderr)
}

func loadFixture(ctx context.Context, path string, getenv Getenv, out io.Writer) error {
	cfg, err := LoadConfig(RoleWorker, getenv)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if cfg.Env == EnvProduction && !netclass.AllowPrivatePairAddrs {
		return errors.New("load-fixture is for lab and development builds: this binary has no ctrlz_lab tag and CTRLZ_ENV is production")
	}
	if cfg.DBHost == "" || cfg.ArtifactsDir == "" {
		return errors.New("load-fixture needs CTRLZ_DB_HOST and CTRLZ_ARTIFACTS_DIR")
	}
	cfg.DBMaxConns = 1
	st, err := store.Open(ctx, cfg.storeConfig(store.RoleWorker, cfg.DBPassword))
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer st.Close()
	arts, err := compiler.NewDirArtifacts(cfg.ArtifactsDir)
	if err != nil {
		return err
	}
	data, err := readFixture(path)
	if err != nil {
		return err
	}
	res, err := catalogfx.Load(ctx, st, arts, data)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "catalog version %d: %d filter tables written, %d left out (not in the seed)\n", res.Version, res.Tables, res.Skipped)
	return nil
}

// readFixture reads the fixture file, bounded: the path is the operator's own (the lab mounts shared/vectors/fixtures into the
// container), and the file is JSON that catalogfx parses.
func readFixture(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open the fixture file")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, catalogfx.MaxFixture+1))
	if err != nil {
		return nil, errors.New("cannot read the fixture file")
	}
	return data, nil
}
