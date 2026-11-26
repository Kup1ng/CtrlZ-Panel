// Package catalogfx writes a catalog version from a fixture file in the format of shared/vectors/fixtures (P4 6.3), so that
// the compiler has a catalog to carry and the nodes something to apply until P6 brings the real importer.
//
// It is for the lab and development. The command that calls it (`ctrlz catalog load-fixture FILE`) refuses a production
// build. What it writes is what the compiler reads (6.2, CatalogRef): a catalog_versions row that is current, with the key of
// the fixture, and a catalog_filter_table row for each filter table of the fixture whose filter and mode the seed knows by
// wire id. The tables are CZGT files in the artifact store, named by hash, and carry the number of the new version. A fixture
// filter the seed does not have is counted and left out, because catalog_filter_table has a foreign key to the seed's modes;
// the service and category tables have no table of their own before P6 (catalog_file), so they are not written.
//
// The file is read, not imported: shared/vectors is a test package (it holds a *testing.T runner), and no production code may
// import it.
package catalogfx

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Kup1ng/CtrlZ-Shared/gtable"
	"github.com/Kup1ng/CtrlZ-Shared/names"

	"github.com/Kup1ng/CtrlZ-Panel/internal/compiler"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// MaxFixture bounds the file that is read.
const MaxFixture = 16 << 20

// Result says what was written.
type Result struct {
	Version int64
	Tables  int
	Skipped int
}

// fixture is the part of a vectors fixture this loader reads. Other members (profiles, endpoints, geo) are ignored.
type fixture struct {
	Catalog struct {
		KeyHex  string `json:"key_hex"`
		Filters []struct {
			ID      uint16   `json:"id"`
			Mode    uint16   `json:"mode"`
			Domains []string `json:"domains"`
		} `json:"filters"`
	} `json:"catalog"`
}

type table struct {
	filter, mode uint16
	entries      []gtable.Entry
}

// parse reads the fixture file into one table per (filter, mode) wire pair, in wire order.
func parse(data []byte) (key []byte, tables []table, err error) {
	if len(data) > MaxFixture {
		return key, nil, errors.New("the fixture file is too large")
	}
	var f fixture
	if err := json.Unmarshal(data, &f); err != nil {
		return key, nil, errors.New("the fixture file is not JSON of the vectors format")
	}
	raw, err := hex.DecodeString(f.Catalog.KeyHex)
	if err != nil || len(raw) != 16 {
		return key, nil, errors.New("the fixture's catalog key is not 16 bytes")
	}
	key = raw
	by := map[uint32]*table{}
	for _, fl := range f.Catalog.Filters {
		w := uint32(fl.ID)<<16 | uint32(fl.Mode)
		t := by[w]
		if t == nil {
			t = &table{filter: fl.ID, mode: fl.Mode}
			by[w] = t
		}
		for _, d := range fl.Domains {
			e := gtable.Entry{}
			if v, ok := strings.CutPrefix(d, "full:"); ok {
				e.Exact, d = true, v
			} else if v, ok := strings.CutPrefix(d, "suffix:"); ok {
				d = v
			}
			n, err := names.FromString(d)
			if err != nil {
				return key, nil, fmt.Errorf("fixture domain %q: %w", d, err)
			}
			e.Name = append([]byte(nil), n.Wire()...)
			t.entries = append(t.entries, e)
		}
	}
	for _, t := range by {
		tables = append(tables, *t)
	}
	sort.Slice(tables, func(i, j int) bool {
		if tables[i].filter != tables[j].filter {
			return tables[i].filter < tables[j].filter
		}
		return tables[i].mode < tables[j].mode
	})
	return key, tables, nil
}

// Load makes the fixture in data the current catalog version. st is opened as ctrlz_worker (S, I and U on the catalog tables).
func Load(ctx context.Context, st *store.Store, arts compiler.Artifacts, data []byte) (Result, error) {
	key, tables, err := parse(data)
	if err != nil {
		return Result{}, err
	}
	var res Result
	err = st.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		cur, err := g.FixtureCurrent()
		if err != nil {
			return err
		}
		if res.Version, err = g.FixtureNextVersion(); err != nil {
			return err
		}
		res.Tables, res.Skipped = 0, 0
		for _, t := range tables {
			filter, mode, found, err := g.FixtureFilterMode(int(t.filter), int(t.mode))
			if err != nil {
				return err
			}
			if !found {
				res.Skipped++
				continue
			}
			b, err := (&gtable.Builder{Kind: gtable.KindFilter, CatalogVersion: uint64(res.Version), Key: [16]byte(key), Entries: t.entries}).Build()
			if err != nil {
				return err
			}
			sum := sha256.Sum256(b)
			// The file first: a row that names a hash with no file is the worse failure, and a file with no row is only space.
			if err := arts.Put(sum[:], b); err != nil {
				return err
			}
			if err := g.FixtureTableInsert(filter, mode, res.Version, sum[:], hex.EncodeToString(sum[:])); err != nil {
				return err
			}
			res.Tables++
		}
		for _, v := range cur {
			if err := g.FixtureDemote(v); err != nil {
				return err
			}
		}
		return g.FixtureVersionInsert(res.Version, key, 0)
	})
	return res, err
}
