package store

// The statements of `ctrlz catalog load-fixture` (P4 6.3): a catalog version written from a shared/vectors fixture so that
// the compiler has a catalog to carry until P6 brings the importer. It runs as ctrlz_worker, which holds S, I and U on the
// catalog tables. Lab and development only: the command refuses to run in a production build.

const qFixtureCurrent = `SELECT version FROM ctrlz.catalog_versions WHERE state = 'current' ORDER BY version`

// FixtureCurrent lists the versions that are current.
func (g GlobalTx) FixtureCurrent() ([]int64, error) {
	rows, err := g.tx.Query(g.ctx, qFixtureCurrent)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, v)
	}
	return out, sanitize(rows.Err())
}

const qFixtureNextVersion = `SELECT COALESCE(max(version), 0) + 1 FROM ctrlz.catalog_versions`

// FixtureNextVersion is the number of the version the fixture becomes.
func (g GlobalTx) FixtureNextVersion() (int64, error) {
	var v int64
	err := g.tx.QueryRow(g.ctx, qFixtureNextVersion).Scan(&v)
	return v, sanitize(err)
}

const qFixtureDemote = `UPDATE ctrlz.catalog_versions SET state = 'previous' WHERE version = $1`

// FixtureDemote makes a current version the previous one.
func (g GlobalTx) FixtureDemote(version int64) error {
	_, err := g.tx.Exec(g.ctx, qFixtureDemote, version)
	return sanitize(err)
}

const qFixtureVersionInsert = `INSERT INTO ctrlz.catalog_versions (version, key, sysnames_version, state) VALUES ($1, $2, $3, 'current')`

// FixtureVersionInsert writes the current version.
func (g GlobalTx) FixtureVersionInsert(version int64, key []byte, sysnames int64) error {
	_, err := g.tx.Exec(g.ctx, qFixtureVersionInsert, version, key, sysnames)
	return sanitize(err)
}

const qFixtureFilterModeOf = `SELECT f.id, m.mode FROM ctrlz.catalog_filter f JOIN ctrlz.catalog_filter_mode m ON m.filter_id = f.id WHERE f.wire_id = $1 AND m.wire_id = $2`

// FixtureFilterMode names the filter and the mode of a pair of wire ids; found is false for a pair the seed does not have.
func (g GlobalTx) FixtureFilterMode(filterWire, modeWire int) (filter, mode string, found bool, err error) {
	found, err = notFound(g.tx.QueryRow(g.ctx, qFixtureFilterModeOf, int32(filterWire), int32(modeWire)).Scan(&filter, &mode))
	return filter, mode, found, err
}

const qFixtureTableInsert = `INSERT INTO ctrlz.catalog_filter_table (filter_id, mode, version, hash, store_ref, state) VALUES ($1, $2, $3, $4, $5, 'current')`

// FixtureTableInsert records a filter table of the version; its file is in the artifact store under its hash.
func (g GlobalTx) FixtureTableInsert(filter, mode string, version int64, hash []byte, ref string) error {
	_, err := g.tx.Exec(g.ctx, qFixtureTableInsert, filter, mode, version, hash, ref)
	return sanitize(err)
}
