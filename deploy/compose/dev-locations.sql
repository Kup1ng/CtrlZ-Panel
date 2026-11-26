-- Development and e2e locations (docs/specs/p2-profiles.md 4.1). Applied by the e2e seed, as the
-- Postgres superuser on the local socket, after the migrations. It fills the tables P4b will fill with
-- real data (nodes, the global pair, locations and their availability) so that the pickers of P2 have
-- something to show. A production stack never applies it and so offers no location, and says so.
--
-- Two nodes form the global pair. Both have Frankfurt, Amsterdam (country level, no city), New York and
-- the label-only location "edge-lab"; only the first has Los Angeles, so Los Angeles is a location that
-- exists and is outside every profile's allowed set (an imported document that names it is flagged).
-- Idempotent: it can run again.

INSERT INTO ctrlz.nodes (id, slot, name, status) VALUES
  ('00000000-0000-7000-8000-00000000d001', 1, 'dev-node-1', 'active'),
  ('00000000-0000-7000-8000-00000000d002', 2, 'dev-node-2', 'active')
ON CONFLICT (id) DO NOTHING;

INSERT INTO ctrlz.node_pairs (id, primary_node_id, fallback_node_id) VALUES
  ('00000000-0000-7000-8000-00000000d0a1', '00000000-0000-7000-8000-00000000d001', '00000000-0000-7000-8000-00000000d002')
ON CONFLICT (id) DO NOTHING;

UPDATE ctrlz.public_settings SET global_pair_id = '00000000-0000-7000-8000-00000000d0a1' WHERE singleton;

INSERT INTO ctrlz.locations (id, wire_id, country_code, city, label) VALUES
  ('00000000-0000-7000-8000-00000000d101', 101, 'DE', 'Frankfurt', 'Frankfurt'),
  ('00000000-0000-7000-8000-00000000d102', 102, 'NL', NULL, 'Amsterdam'),
  ('00000000-0000-7000-8000-00000000d103', 103, 'US', 'New York', 'New York'),
  ('00000000-0000-7000-8000-00000000d104', 104, 'US', 'Los Angeles', 'Los Angeles'),
  ('00000000-0000-7000-8000-00000000d105', 105, NULL, NULL, 'edge-lab')
ON CONFLICT (id) DO NOTHING;

INSERT INTO ctrlz.location_availability (node_id, location_id)
SELECT n.id, l.id
FROM ctrlz.nodes n CROSS JOIN ctrlz.locations l
WHERE n.id IN ('00000000-0000-7000-8000-00000000d001', '00000000-0000-7000-8000-00000000d002')
  AND l.id IN ('00000000-0000-7000-8000-00000000d101', '00000000-0000-7000-8000-00000000d102',
               '00000000-0000-7000-8000-00000000d103', '00000000-0000-7000-8000-00000000d105')
ON CONFLICT (node_id, location_id) DO NOTHING;

INSERT INTO ctrlz.location_availability (node_id, location_id) VALUES
  ('00000000-0000-7000-8000-00000000d001', '00000000-0000-7000-8000-00000000d104')
ON CONFLICT (node_id, location_id) DO NOTHING;
