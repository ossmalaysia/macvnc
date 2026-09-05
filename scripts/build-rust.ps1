param([switch]$Package, [switch]$Run)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
Push-Location $repo
try {
    $cargo = Get-Command cargo -ErrorAction SilentlyContinue
    $cargoPath = if ($cargo) { $cargo.Source } else { Join-Path $env:USERPROFILE '.cargo/bin/cargo.exe' }
    if (-not (Test-Path -LiteralPath $cargoPath)) { throw 'Install Rust using rustup and the MSVC C++ build tools first.' }
    & $cargoPath build --release --locked -p macvnc-app
    if ($LASTEXITCODE -ne 0) { throw 'Rust release build failed' }
    if ($Package -or $Run) { & "$PSScriptRoot/package-rust.ps1" }
    if ($Run) { Start-Process -FilePath "$repo/dist/macvnc-rust/macvnc-app.exe" -WorkingDirectory "$repo/dist/macvnc-rust" }
} finally { Pop-Location }
