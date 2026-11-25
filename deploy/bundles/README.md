# Signed bundles and root.json

The panel server's `deploy/bundles/` is mounted read-only into `hub` and `admin` (spec P4 3.3).

- `root.json` is the signed `Root` made by `ctrlz root init` on the offline signing machine. It is a public file.
- `<kind>/<version>/` holds a bundle that `ctrlz root sign-manifest` signed offline (manifest, signatures, files).

Nothing here is a secret and nothing here is written by a container. The directory is empty in a fresh clone.
