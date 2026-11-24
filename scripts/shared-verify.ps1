# Verifies this copy of shared against its CHECKSUMS, and against the Node copy
# when the two repositories sit side by side. No logic here.
$ErrorActionPreference = 'Stop'
$here = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$node = Join-Path (Split-Path $here -Parent) 'Ctrl Z Node\shared'
if (Test-Path $node) {
    & go -C (Join-Path $here 'shared') run ./cmd/sharedtool verify (Join-Path $here 'shared') $node
} else {
    & go -C (Join-Path $here 'shared') run ./cmd/sharedtool verify (Join-Path $here 'shared')
}
exit $LASTEXITCODE
