-- P4, package V1 (docs/specs/p4-nodes.md 4.3, 10.2 and 10.3, T-237): `ctrlz domain-apply` may read the uploaded wildcard rows.
--
-- CTRLZ_VERIFY_ORIGIN, the origin the verify probe of a zone may open a connection to, is written by the apply step. The
-- probe needs a certificate a browser trusts, and the nodes serve one for a zone only when an active uploaded wildcard row
-- covers it (4.3); without one the zone is in private-CA mode, the browser would reject every probe, and the page must show the
-- manual check instead. The apply step therefore has to judge coverage with the rule the hub uses (certcheck.Choose), which
-- needs the rows of kind `wildcard`. It reads their chain and names, never their key: the key is sealed to the hub's
-- wildcard intake key, which this role does not hold (it holds web_intake_key only), so the ciphertext it can select opens for nobody here.
--
-- A new file and not an edit of 0100, which has been applied.

-- +goose Up

SET LOCAL search_path = pg_catalog;

DROP POLICY domain_apply_read ON ctrlz.certificates;
CREATE POLICY domain_apply_read ON ctrlz.certificates AS PERMISSIVE FOR SELECT TO ctrlz_domain_apply
  USING (kind IN ('panel', 'admin', 'wildcard'));
