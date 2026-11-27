#!/bin/sh
# Fails when a Go test file would run in no job: a _test.go file that go leaves out on this
# runner (a GOOS suffix such as _windows_test.go, or a build tag nobody sets), a directory with
# Go files that `go list ./...` does not list at all (every file in it is left out), or a Go
# module that no job runs. `shardrun module .` judges only the packages of `go list ./...`, so
# such a test would run nowhere on GitHub and the run would stay green (CI review round 6,
# ci-r6-1). The Panel's planner has the same proof for its root module (.github/ci/plan: prove)
# and not for shared/, so the Panel runs this on shared/ only (round 7, ci-r7-2); the Node has no
# planner and runs it on the root module and on shared/. One file in both overlays
# (identical_overlay_files in ci/publish.json).
#   sh .github/ci/gofiles.sh <module directory> <repository root>
# Run it once per module of the repository: the root (both arguments the same) and shared/
# (the root as the second argument).
#
# What counts as built. A test file is fine when go builds it under the default build, or under a
# tag set that a job of the repository runs (the table of tag sets below). Both repositories have
# the set ctrlz_lab, run by the job "tests (lab)" (.github/ci/lab.sh of each overlay): the
# lab-tagged files and the lab-only golden vectors run there, and no release job builds them. The
# second set, unboundlab, is the Node's T-031 test against a real Unbound, run by the job "unbound"
# (.github/ci/unbound.sh), which runs that one package with the tag on the go test command line (the Panel has no such job and no such set); the
# test files that need it are built by that job only. A file
# built under neither is refused. The table is keyed by the module path of the repository root, so a
# repository that has no such job keeps the default build alone. The Panel runs this script on
# shared/ only (its planner proves the root module), so for the Panel the table judges the lab files
# of shared/ (shared/netclass/lab_test.go), which came with P4. A job that builds with
# GOFLAGS=-tags=<set> must name a set of the table, so a tag set that a job runs and this table
# does not know is refused too.
#
# Exceptions. There is one list of test files that no job builds, by design, each with its reason
# (excepted below): paths relative to the repository root and nothing else. A test that must be
# left out is named there, in review, and never by a rename that nobody notices.
set -eu
dir=$(cd "${1:?usage: gofiles.sh <module directory> <repository root>}" && pwd)
root=$(cd "${2:?usage: gofiles.sh <module directory> <repository root>}" && pwd)
case "$dir" in
  "$root" | "$root/shared") ;;
  *) echo "gofiles: $dir is neither the repository root $root nor its shared/ directory" >&2; exit 1 ;;
esac
cd "$dir"
mod=$(go list -m)
bad=0

# The tag sets that a job runs besides the default build, by the module of the repository root. A
# new one is a reviewed change that adds the job (ci.yml), names it here, and is read against the
# workflow by ci/github/gofiles.test.mjs.
case "$(cd "$root" && go list -m)" in
  github.com/Kup1ng/CtrlZ-Node) tagsets="ctrlz_lab unboundlab" ;;
  # The Panel has no job that runs unboundlab, so a Panel test behind it would be built by no job.
  github.com/Kup1ng/CtrlZ-Panel) tagsets="ctrlz_lab" ;;
  *) tagsets="" ;;
esac

# Test files that no job builds, on purpose, by path relative to the repository root. Each needs its
# reason here, and the same file is refused under any other path.
excepted() {
  case "$1" in
    # T-551, the load measurement of the resolver (build tag loadtest): minutes long and dependent on
    # the machine, so it is run by hand when the resolver changes and never by a job.
    internal/resolve/load_test.go) return 0 ;;
  esac
  return 1
}
# The directory of this module relative to the repository root, with its slash, for excepted().
prefix=""
[ "$dir" = "$root" ] || prefix="${dir#"$root"/}/"

# The tags that the environment builds with (GOFLAGS=-tags=...) are a job's own tag set, and the
# default build here is the one without them, so the script judges the same files in every job.
base_flags=$(printf '%s' "${GOFLAGS:-}" | sed -E 's/(^| )-tags[= ][^ ]*//g')
env_tags=$(printf '%s' "${GOFLAGS:-}" | sed -nE 's/.*(^| )-tags[= ]([^ ]*).*/\2/p')
if [ -n "$env_tags" ]; then
  found=0
  for ts in $tagsets; do
    if [ "$ts" = "$env_tags" ]; then found=1; fi
  done
  if [ "$found" = 0 ]; then
    echo "gofiles: this job builds with the tags $env_tags, which are not a tag set of the table of gofiles.sh (${tagsets:-none}): a tag set that a job runs is named there" >&2
    bad=1
  fi
fi
# golist <tags> <go list arguments>: go list under the default build (empty tags) or under a tag set.
golist() {
  t=$1
  shift
  if [ -n "$t" ]; then GOFLAGS="$base_flags -tags=$t" go list "$@"; else GOFLAGS="$base_flags" go list "$@"; fi
}

# 0. The Go modules of the repository are the root and shared/, and no other (ci-r8-2). A module
# of its own is not in `go list ./...` of either, so its tests are in no shard, in no job and not
# in ci/local-only.sh: a fail-closed list, not a skip. A new module is a reviewed change that adds
# a job for it and then names it here. What go itself never reads (testdata, vendor, node_modules)
# and the repository's own .git are not searched.
modules=$(cd "$root" && find . \( -name .git -o -name testdata -o -name vendor -o -name node_modules \) -prune -o -type f -name go.mod -print | sort)
for m in $modules; do
  case "$m" in
    ./go.mod | ./shared/go.mod) ;;
    *) echo "gofiles: $m is a Go module that no job runs (only the root and shared/ are): add a job for it and name it in .github/ci/gofiles.sh" >&2; bad=1 ;;
  esac
done

# 1. Test files that no package builds. The list of what exists is the file system and the list of
# what is built is go's own TestGoFiles and XTestGoFiles, so a file is refused for whatever reason go
# leaves it out: a GOOS suffix, a build tag, a name that starts with _ or . (go drops such a file
# without a word, and not in IgnoredGoFiles, which this step read before: ci-r9-4), or a directory go
# does not list. The walk skips only what go never reads (testdata, vendor, node_modules, .git) and
# the directory of a module of its own (step 0 refuses every one but shared/, which has its own run).
# Directories that start with . or _ ARE searched: a test file there never runs.
# The files built are the union over the default build and every tag set that a job runs.
built=$(for t in "" $tagsets; do
  golist "$t" -f '{{.ImportPath}}|{{join .TestGoFiles ","}},{{join .XTestGoFiles ","}}' ./... | awk -F'|' -v m="$mod" '
  { rel = ($1 == m) ? "." : substr($1, length(m) + 2)
    n = split($2, f, ",")
    for (i = 1; i <= n; i++) if (f[i] != "") print "./" ((rel == ".") ? "" : rel "/") f[i] }'
done | sort -u)
nested=$(find . -mindepth 2 -name go.mod | sed 's|/go.mod$||')
unbuilt=$(find . \( -name .git -o -name testdata -o -name vendor -o -name node_modules \) -prune -o -type f -name '*_test.go' -print | sort | while IFS= read -r f; do
    skip=0
    for n in $nested; do
      case "$f" in "$n"/*) skip=1 ;; esac
    done
    [ "$skip" = 1 ] && continue
    printf '%s\n' "$built" | grep -qxF -- "$f" && continue
    excepted "$prefix${f#./}" && continue
    printf '%s\n' "$f"
  done)
if [ -n "$unbuilt" ]; then
  echo "gofiles: these test files are built by no package on this runner, under the default build or under a tag set that a job runs (${tagsets:-none}) (GOOS suffix, another build tag, a name or directory that starts with _ or ., or a directory go does not list), so no job runs them:" >&2
  printf '  %s\n' $unbuilt >&2
  bad=1
fi

# 2. Directories with Go files that `go list ./...` does not list. The walk skips what ./... skips
# itself (testdata, vendor, names that start with . or _) and the directory of a module of its own
# (./... stops there too; step 0 has already refused every module but shared/, which has its own run).
listed=$(for t in "" $tagsets; do
  golist "$t" -f '{{.ImportPath}}' ./... | awk -v m="$mod" '{ if ($0 == m) print "."; else print substr($0, length(m) + 2) }'
done | sort -u)
nested=$(find . -mindepth 2 -name go.mod | sed 's|/go.mod$||')
unlisted=$(find . \( -name testdata -o -name vendor -o -name node_modules -o -name '.?*' -o -name '_*' \) -prune -o -type f -name '*.go' -print |
  sed 's|/[^/]*$||' | sort -u | while IFS= read -r d; do
    skip=0
    for n in $nested; do
      case "$d" in "$n" | "$n"/*) skip=1 ;; esac
    done
    [ "$skip" = 1 ] && continue
    rel=${d#./}
    [ "$d" = . ] && rel=.
    printf '%s\n' "$listed" | grep -qxF -- "$rel" || printf '%s\n' "$rel"
  done)
if [ -n "$unlisted" ]; then
  echo "gofiles: these directories hold Go files but are not packages of go list ./... on this runner, so no job runs their tests:" >&2
  printf '  %s\n' $unlisted >&2
  bad=1
fi
[ "$bad" = 0 ] || exit 1
echo "gofiles: ok ($mod: every Go module is run, every Go test file is built by the default build or a tag set of a job (${tagsets:-none}) or is excepted, every Go directory is listed)"
