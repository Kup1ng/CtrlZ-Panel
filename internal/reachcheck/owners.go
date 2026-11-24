package reachcheck

import (
	"context"
	"sort"
)

// WrongOwners lists every object, of every kind a schema can hold, that sits in a schema of schemaOwners and
// is owned by another role than the one its schema is listed with (P1 auth review round 17, db-r17-15).
//
// Why one map. Round 17 first asked the owners of the relations and the functions through two maps of their
// own (relation_owners, function_owners), and nothing required a schema to appear in all of them: river and
// ctrlz_ext were asked for relations or not at all, and the functions of river and ctrlz_ext, and every type,
// operator, operator class, collation, conversion, text search object, statistics object and extension,
// were never asked. An owner holds every right on an object whatever its ACL says, so a function of the
// extension schema owned by a service role could be redefined by it. There is now ONE map, schema_owners
// (roles.yaml), and the rule is "an object belongs to the owner of its schema": no second list to forget a
// schema or a kind, and an object added to a listed schema is asked without a line anywhere.
//
// The kinds are the catalogs of pg_catalog that carry both a schema and an owner column; the query below
// reads each of them, and internal/migrate TestTheOwnerQuestionAsksEveryOwnedKind finds that set in the live
// catalog (any pg_catalog table with a column ending in "namespace" and one ending in "owner") and fails when
// the query leaves one out, so a kind a later Postgres adds is a failing test and not a silent gap.
//
// A schema that is listed and does not exist asks nothing. It judges names and owners only, never
// privileges (catalog checks 09 to 13).
func WrongOwners(ctx context.Context, q Querier, schemaOwners map[string]string) ([]WrongOwner, error) {
	return WrongOwnersWith(ctx, q, schemaOwners, nil)
}

// WrongOwnersWith is WrongOwners with a second owner a FUNCTION of a schema may have besides the schema's
// (functionOwners maps the schema to that role; db-r18-1). It is one pair and for functions only: the definer
// functions of ctrlz_fn that act for a tenant belong to ctrlz_scoped, a role with no policy but tenant_isolation,
// and every other kind of object in the schema stays the schema owner's. Which of the two a function has is
// judged against functions.yaml by catalog check 10, so an owner here is permission and not a verdict.
func WrongOwnersWith(ctx context.Context, q Querier, schemaOwners, functionOwners map[string]string) ([]WrongOwner, error) {
	fnSchemas := make([]string, 0, len(functionOwners))
	for s := range functionOwners {
		fnSchemas = append(fnSchemas, s)
	}
	sort.Strings(fnSchemas)
	fnOwners := make([]string, len(fnSchemas))
	for i, s := range fnSchemas {
		fnOwners[i] = functionOwners[s]
	}
	schemas := make([]string, 0, len(schemaOwners))
	for s := range schemaOwners {
		schemas = append(schemas, s)
	}
	sort.Strings(schemas)
	owners := make([]string, len(schemas))
	for i, s := range schemas {
		owners[i] = schemaOwners[s]
	}
	rows, err := q.Query(ctx, OwnedObjectsQuery, schemas, owners, fnSchemas, fnOwners)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WrongOwner
	for rows.Next() {
		var w WrongOwner
		if err := rows.Scan(&w.Kind, &w.Schema, &w.Name, &w.Owner, &w.Want); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// WrongOwner is one object owned by a role other than the one it should be: its schema's owner, or the
// owner of its extension for a member of one (Want).
type WrongOwner struct{ Kind, Schema, Name, Owner, Want string }

// OwnedCatalogs are the catalogs OwnedObjectsQuery reads, for the test that compares them with the live set. It
// is a function and not a variable (the workspace rule: no package-level mutable state), so no caller can edit
// the list the next one reads.
func OwnedCatalogs() []string {
	return []string{
		"pg_class", "pg_collation", "pg_conversion", "pg_extension", "pg_opclass", "pg_operator", "pg_opfamily",
		"pg_proc", "pg_statistic_ext", "pg_ts_config", "pg_ts_dict", "pg_type",
	}
}

// OwnedObjectsQuery takes the schemas and the owners as two parallel arrays, and then the schemas whose functions
// may have a second owner and that owner, as two more. A relation of any relkind
// (tables, partitioned tables, indexes, views, materialized views, sequences, composite types, foreign tables)
// and an array or row type follow their parent's owner, so a mismatch there is still a finding.
const OwnedObjectsQuery = `
WITH want AS (SELECT * FROM unnest($1::text[], $2::text[]) AS e(nsp, own)),
objs(kind, cls, id, nsp, name, ownerid) AS (
  SELECT 'relation', 'pg_class'::regclass::oid, c.oid, n.nspname, c.relname::text, c.relowner FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  UNION ALL SELECT 'function', 'pg_proc'::regclass::oid, p.oid, n.nspname, p.proname::text, p.proowner FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  UNION ALL SELECT 'type', 'pg_type'::regclass::oid, t.oid, n.nspname, t.typname::text, t.typowner FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
  UNION ALL SELECT 'operator', 'pg_operator'::regclass::oid, o.oid, n.nspname, o.oprname::text, o.oprowner FROM pg_operator o JOIN pg_namespace n ON n.oid = o.oprnamespace
  UNION ALL SELECT 'operator class', 'pg_opclass'::regclass::oid, o.oid, n.nspname, o.opcname::text, o.opcowner FROM pg_opclass o JOIN pg_namespace n ON n.oid = o.opcnamespace
  UNION ALL SELECT 'operator family', 'pg_opfamily'::regclass::oid, o.oid, n.nspname, o.opfname::text, o.opfowner FROM pg_opfamily o JOIN pg_namespace n ON n.oid = o.opfnamespace
  UNION ALL SELECT 'collation', 'pg_collation'::regclass::oid, o.oid, n.nspname, o.collname::text, o.collowner FROM pg_collation o JOIN pg_namespace n ON n.oid = o.collnamespace
  UNION ALL SELECT 'conversion', 'pg_conversion'::regclass::oid, o.oid, n.nspname, o.conname::text, o.conowner FROM pg_conversion o JOIN pg_namespace n ON n.oid = o.connamespace
  UNION ALL SELECT 'text search configuration', 'pg_ts_config'::regclass::oid, o.oid, n.nspname, o.cfgname::text, o.cfgowner FROM pg_ts_config o JOIN pg_namespace n ON n.oid = o.cfgnamespace
  UNION ALL SELECT 'text search dictionary', 'pg_ts_dict'::regclass::oid, o.oid, n.nspname, o.dictname::text, o.dictowner FROM pg_ts_dict o JOIN pg_namespace n ON n.oid = o.dictnamespace
  UNION ALL SELECT 'statistics object', 'pg_statistic_ext'::regclass::oid, o.oid, n.nspname, o.stxname::text, o.stxowner FROM pg_statistic_ext o JOIN pg_namespace n ON n.oid = o.stxnamespace
  UNION ALL SELECT 'extension', 'pg_extension'::regclass::oid, o.oid, n.nspname, o.extname::text, o.extowner FROM pg_extension o JOIN pg_namespace n ON n.oid = o.extnamespace
),
member AS (
  SELECT d.classid AS cls, d.objid AS id, e.extowner FROM pg_depend d JOIN pg_extension e ON e.oid = d.refobjid
  WHERE d.refclassid = 'pg_extension'::regclass AND d.deptype = 'e'
)
SELECT o.kind, o.nsp, o.name, pg_get_userbyid(o.ownerid), CASE WHEN m.id IS NOT NULL THEN pg_get_userbyid(m.extowner) ELSE w.own END
FROM objs o
JOIN want w ON w.nsp = o.nsp
LEFT JOIN member m ON m.cls = o.cls AND m.id = o.id
WHERE CASE
  -- a member of an extension belongs to whoever installed it: the extension's owner, or the superuser when
  -- the extension is trusted and a lesser role ran CREATE EXTENSION (the members are then the bootstrap
  -- superuser's and the extension is the installer's). It must not be re-owned to anybody else.
  WHEN m.id IS NOT NULL THEN o.ownerid <> m.extowner AND NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.oid = o.ownerid AND r.rolsuper)
  -- the extension itself: the schema's owner, or a superuser, never a service role
  WHEN o.kind = 'extension' THEN pg_get_userbyid(o.ownerid) <> w.own AND NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.oid = o.ownerid AND r.rolsuper)
  -- a function of a schema that lists a second owner for its functions (db-r18-1)
  WHEN o.kind = 'function' THEN pg_get_userbyid(o.ownerid) <> w.own
    AND NOT EXISTS (SELECT 1 FROM unnest($3::text[], $4::text[]) AS f(nsp, own) WHERE f.nsp = o.nsp AND f.own = pg_get_userbyid(o.ownerid))
  ELSE pg_get_userbyid(o.ownerid) <> w.own
END
ORDER BY 1, 2, 3`
