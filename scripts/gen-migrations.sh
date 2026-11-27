#!/bin/sh
# Expand migrations/postgres/src (macros) into migrations/postgres (plain SQL).
# Commit both. `-check` fails if they differ, which CI and a Go test both run.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
cd "$here"
exec go run ./tools/genmig "$@"
