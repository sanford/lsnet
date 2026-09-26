# Build lsnet, install it to ~\.local\bin, and run it. The Windows twin of run.sh.
# Any arguments are passed through: .\run.ps1 -v, .\run.ps1 --json, ...
$ErrorActionPreference = 'Stop'

Set-Location $PSScriptRoot
$binDir = Join-Path $HOME '.local\bin'

cargo build --release --quiet
if ($LASTEXITCODE) { exit $LASTEXITCODE }
New-Item -ItemType Directory -Force $binDir | Out-Null
Copy-Item target\release\lsnet.exe $binDir -Force

& (Join-Path $binDir 'lsnet.exe') @args
exit $LASTEXITCODE
