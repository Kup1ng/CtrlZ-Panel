-- P2, package B2 (docs/specs/p2-profiles.md 3.4): the lock that serialises the creators of
-- profiles of one tenant, so that max_profiles is decided by one statement under it (RULES
-- rule 7) and an Import job of the worker and a Create of the API meet in the same order.
--
-- It is a function and not a bare advisory call because no role that serves requests holds the
-- advisory family (catalog_reach.yaml, advisory-locks); ctrlz_auth owns the definer function,
-- as for audit_lock. The key is the caller's tenant (current_tenant_id), never an argument, so a
-- tenant cannot hold another tenant's lock. A call with no tenant setting locks nothing and answers false.
--
-- A new file and not an edit of an applied one (README, Rules).

-- +goose Up

SET LOCAL search_path = pg_catalog;

SET ROLE ctrlz_auth;

-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.profile_tenant_lock() RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF ctrlz.current_tenant_id() IS NULL THEN
    RETURN false;
  END IF;
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('ctrlz.profile_create:' || ctrlz.current_tenant_id()::text, 0));
  RETURN true;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.profile_tenant_lock() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.profile_tenant_lock() TO ctrlz_tenant, ctrlz_worker;

RESET ROLE;
