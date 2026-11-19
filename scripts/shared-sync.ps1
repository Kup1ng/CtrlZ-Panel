# Copies Ctrl Z Panel/shared to Ctrl Z Node/shared and proves the copies match.
# No logic here: everything is in shared/cmd/sharedtool.
$ErrorActionPreference = 'Stop'
$here = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$node = Join-Path (Split-Path $here -Parent) 'Ctrl Z Node\shared'
& go -C (Join-Path $here 'shared') run ./cmd/sharedtool sync --from (Join-Path $here 'shared') --to $node @args
exit $LASTEXITCODE
