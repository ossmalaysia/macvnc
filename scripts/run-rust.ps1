$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
& "$PSScriptRoot/build-rust.ps1" -Package
if ($LASTEXITCODE -ne 0) { throw 'Native build failed' }
& "$repo/dist/macvnc-rust/macvnc-app.exe"
