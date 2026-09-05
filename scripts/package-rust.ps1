$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$runtime = Join-Path $repo 'rust/runtime'
$archive = Join-Path $runtime 'ffmpeg7.zip'
$version = 'ffmpeg-n7.1.5-12-g1fdbca85aa-win64-lgpl-shared-7.1'
$url = "https://github.com/BtbN/FFmpeg-Builds/releases/download/autobuild-2026-07-31-14-10/$version.zip"
$sha256 = '0f376f96fb38554ccefb1b2ae9c7c6a7b351f0e60a372b38262c320e8392c5d0'
$extracted = Join-Path $runtime $version
$package = Join-Path $repo 'dist/macvnc-rust'
New-Item -ItemType Directory -Force $runtime,$package | Out-Null
if (-not (Test-Path -LiteralPath $archive)) { Invoke-WebRequest $url -OutFile $archive }
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $sha256) { throw 'FFmpeg archive checksum mismatch' }
if (-not (Test-Path -LiteralPath "$extracted/bin/avcodec-61.dll")) { Expand-Archive -LiteralPath $archive -DestinationPath $runtime -Force }
Copy-Item -LiteralPath "$repo/target/release/macvnc-app.exe" -Destination $package
Get-ChildItem -LiteralPath "$extracted/bin" -Filter '*.dll' | Copy-Item -Destination $package
Copy-Item -LiteralPath "$extracted/LICENSE.txt" -Destination "$package/FFMPEG-LICENSE.txt"
Copy-Item -LiteralPath "$repo/LICENSE" -Destination "$package/LICENSE.txt"
Copy-Item -LiteralPath "$repo/rust/LICENSE-AGPL-3.0.txt" -Destination "$package/LICENSE-AGPL-3.0.txt"
Copy-Item -LiteralPath "$repo/docs/THIRD_PARTY.md" -Destination "$package/THIRD_PARTY.md"

# Bundle the working-tree source: the rewritten application may not yet exist
# in any public Git revision. Deliberately enumerate source roots, never copy
# the repository wholesale (which would include private validation artifacts).
$source = Join-Path $package 'source'
New-Item -ItemType Directory -Force $source,"$source/rust/crates","$source/docs","$source/scripts","$source/.cargo" | Out-Null
foreach ($file in @('Cargo.toml','Cargo.lock','rust-toolchain.toml','LICENSE','README.md','AGENTS.md','SECURITY.md','NOTICE.md','LICENSING.md','CONTRIBUTING.md')) {
    Copy-Item -LiteralPath (Join-Path $repo $file) -Destination $source
}
Copy-Item -LiteralPath "$repo/rust/LICENSE-AGPL-3.0.txt" -Destination "$source/rust"
Copy-Item -LiteralPath "$repo/rust/AGENTS.md" -Destination "$source/rust"
Copy-Item -LiteralPath "$repo/docs/THIRD_PARTY.md" -Destination "$source/docs"
Copy-Item -LiteralPath "$repo/docs/rust-validation-2026-09-05.md" -Destination "$source/docs"
Copy-Item -LiteralPath "$repo/docs/legacy-security.md" -Destination "$source/docs"
Copy-Item -LiteralPath "$repo/docs/security-review-2026-09-05.md" -Destination "$source/docs"
Copy-Item -LiteralPath "$repo/docs/CONTRACTS.md" -Destination "$source/docs"
foreach ($crate in @('hp-protocol','hp-media','macvnc-app')) {
    $crateSource = Join-Path $repo "rust/crates/$crate"
    $crateDestination = Join-Path $source "rust/crates/$crate"
    New-Item -ItemType Directory -Force $crateDestination | Out-Null
    foreach ($entry in @('Cargo.toml','build.rs','assets','src','tests','README.md','AGENTS.md')) {
        $entryPath = Join-Path $crateSource $entry
        if (Test-Path -LiteralPath $entryPath) {
            Copy-Item -LiteralPath $entryPath -Destination $crateDestination -Recurse -Force
        }
    }
}
foreach ($script in @('build-rust.ps1','run-rust.ps1','package-rust.ps1')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $script) -Destination "$source/scripts"
}
$cargoCommand = Get-Command cargo -ErrorAction SilentlyContinue
$cargoPath = if ($cargoCommand) { $cargoCommand.Source } else { Join-Path $env:USERPROFILE '.cargo/bin/cargo.exe' }
Push-Location $repo
try {
    $lockHash = (Get-FileHash -LiteralPath "$repo/Cargo.lock" -Algorithm SHA256).Hash
    $vendorStamp = "$source/.cargo/vendor-lock.sha256"
    $vendorReady = (Test-Path -LiteralPath "$source/vendor") -and (Test-Path -LiteralPath "$source/.cargo/config.toml") -and (Test-Path -LiteralPath $vendorStamp)
    if (-not $vendorReady -or (Get-Content -LiteralPath $vendorStamp -Raw).Trim() -ne $lockHash) {
        $vendorLog = Join-Path $runtime 'cargo-vendor.log'
        $vendorConfig = & $cargoPath vendor --locked --versioned-dirs "$source/vendor" 2> $vendorLog
        if ($LASTEXITCODE -ne 0) { throw "Could not bundle Rust dependency source and licenses; see $vendorLog" }
        # Cargo prints an absolute directory; make the source tree portable.
        $configText = ($vendorConfig -join "`n") -replace '(?m)^directory = .+$', 'directory = "vendor"'
        $configText | Set-Content -Encoding utf8 "$source/.cargo/config.toml"
        $lockHash | Set-Content -Encoding ascii $vendorStamp
    }
} finally { Pop-Location }

$ffmpegSources = Join-Path $source 'third-party/ffmpeg'
New-Item -ItemType Directory -Force $ffmpegSources | Out-Null
$sourceDownloads = @(
    @{ Name='ffmpeg-source-1fdbca85aa.tar.gz'; Url='https://github.com/FFmpeg/FFmpeg/archive/1fdbca85aa.tar.gz'; Hash='1312ecd4b87383182530278450c204c27e6787d033b190a28072a149cca59ed3' },
    @{ Name='btbn-build-recipes.tar.gz'; Url='https://github.com/BtbN/FFmpeg-Builds/archive/refs/tags/autobuild-2026-07-31-14-10.tar.gz'; Hash='bd36d96d8f1667325bb67f6a0c4811a55fff68f80eab4ba2f60f1cba9e70f440' },
    @{ Name='GPL-3.0.txt'; Url='https://raw.githubusercontent.com/FFmpeg/FFmpeg/1fdbca85aa/COPYING.GPLv3'; Hash='8ceb4b9ee5adedde47b31e975c1d90c73ad27b6b165a1dcd80c7c545eb65b903' }
)
$sourceManifest = @()
foreach ($download in $sourceDownloads) {
    $cachedSource = Join-Path $runtime $download.Name
    if (-not (Test-Path -LiteralPath $cachedSource)) { Invoke-WebRequest $download.Url -OutFile $cachedSource }
    if ((Get-FileHash -LiteralPath $cachedSource -Algorithm SHA256).Hash -ne $download.Hash) { throw "Source archive checksum mismatch: $($download.Name)" }
    Copy-Item -LiteralPath $cachedSource -Destination $ffmpegSources
    $sourceManifest += "$($download.Name)`nURL: $($download.Url)`nSHA256: $((Get-FileHash -LiteralPath $cachedSource -Algorithm SHA256).Hash)`n"
}
$sourceManifest | Set-Content -Encoding utf8 "$ffmpegSources/SOURCES.txt"
Copy-Item -LiteralPath "$ffmpegSources/GPL-3.0.txt" -Destination "$package/FFMPEG-GPL-3.0.txt"
@"
macvnc Rust native HP client
Developed by AnchorSprint: https://anchorsprint.com
Commercial/customization enquiries: oss@anchorsprint.com
Run macvnc-app.exe. The DLLs must stay beside the executable.

Native combined application: AGPL-3.0-or-later; see LICENSE-AGPL-3.0.txt.
See source/LICENSING.md for current rights and the proposed future model.
Original independently licensed code: MIT; see LICENSE.txt.
Provenance and third-party notices: THIRD_PARTY.md.
Current application source and vendored dependencies: source/.
Rebuild with Rust and MSVC/Windows SDK: cd source; cargo build --release --locked --offline -p macvnc-app

Application source: https://github.com/ossmalaysia/macvnc
FFmpeg binary source: $url
Archive SHA256: $sha256
FFmpeg corresponding build/source materials:
https://github.com/BtbN/FFmpeg-Builds/releases/tag/autobuild-2026-07-31-14-10
https://github.com/FFmpeg/FFmpeg/commit/1fdbca85aa
This build uses FFmpeg under LGPLv3. See FFMPEG-LICENSE.txt and FFMPEG-GPL-3.0.txt.
FFmpeg source and build recipes: source/third-party/ffmpeg/.
The DLLs remain replaceable. No credentials or desktop captures are included.
"@ | Set-Content -Encoding utf8 "$package/README.txt"
Write-Output "Native package ready: $package"
