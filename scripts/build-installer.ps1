# Builds the per-user Windows installer from the portable package.
# Run scripts/build-rust.ps1 -Package first. Produces, in dist/:
#   MacVNC-Setup-<version>-win-x64.exe  (versioned, kept per release)
#   MacVNC-Setup-win-x64.exe            (same bytes; releases/latest/download link)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$package = Join-Path $repo 'dist/macvnc-rust'
if (-not (Test-Path -LiteralPath "$package/macvnc-app.exe")) { throw 'Run scripts/build-rust.ps1 -Package first.' }
$manifest = Get-Content -LiteralPath "$repo/rust/crates/macvnc-app/Cargo.toml" -Raw
$version = [regex]::Match($manifest, '(?m)^version\s*=\s*"([^"]+)"\s*$').Groups[1].Value
if ($version -notmatch '^\d+\.\d+\.\d+$') { throw 'Invalid app version' }

$makensis = Get-Command makensis -ErrorAction SilentlyContinue
$makensisPath = if ($makensis) { $makensis.Source } else { Join-Path ${env:ProgramFiles(x86)} 'NSIS/makensis.exe' }
if (-not (Test-Path -LiteralPath $makensisPath)) {
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) { throw 'Install NSIS 3 (https://nsis.sourceforge.io) first.' }
    choco install nsis -y --no-progress | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not install NSIS' }
}
if (-not (Test-Path -LiteralPath $makensisPath)) { throw "makensis not found at $makensisPath" }

$setup = Join-Path $repo "dist/MacVNC-Setup-$version-win-x64.exe"
$latest = Join-Path $repo 'dist/MacVNC-Setup-win-x64.exe'
& $makensisPath /V2 "/DVERSION=$version" "/DSOURCE=$((Resolve-Path $package).Path)" "/DOUTFILE=$setup" (Join-Path $PSScriptRoot 'installer/macvnc.nsi')
if ($LASTEXITCODE -ne 0) { throw 'Installer build failed' }
Copy-Item -LiteralPath $setup -Destination $latest -Force
Write-Output "Installer ready: $setup"
