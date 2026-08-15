<#
.SYNOPSIS
    Build both architectures and produce the release archive.

.DESCRIPTION
    Emits dist\release\<name>-<version>-win.zip containing everything a user
    needs: both plugins, the index, install.ps1 and the licence notices. One
    archive rather than several, because "download this, extract, run
    install.ps1" is the whole installation story we want to be able to write.

    Pass -NoIndex to build the small plugin-only archive instead, for users who
    already have the index and just want a newer plugin.

.EXAMPLE
    .\package.ps1 -X64dbgRoot "D:\Tools\x64dbg"

.EXAMPLE
    .\package.ps1 -SkipBuild        # package what is already built
#>
[CmdletBinding()]
param(
    [string]$X64dbgRoot = $env:X64DBG_ROOT,

    # Defaults to the version in CMakeLists.txt.
    [string]$Version,

    # Prebuilt index to ship. Defaults to dist\apisignature.db.
    [string]$Index,

    # Package the existing build output without rebuilding.
    [switch]$SkipBuild,

    # Omit the index, producing a ~2 MB plugin-only archive.
    [switch]$NoIndex
)

$ErrorActionPreference = 'Stop'
$repo = $PSScriptRoot

$PluginName = 'APISignature'
$IndexName  = 'apisignature.db'

if (-not $Index) { $Index = Join-Path $repo "dist\$IndexName" }

# --- version -----------------------------------------------------------------

if (-not $Version) {
    $cmake = Get-Content (Join-Path $repo 'CMakeLists.txt') -Raw
    if ($cmake -match 'project\s*\([^)]*VERSION\s+([0-9]+\.[0-9]+\.[0-9]+)') {
        $Version = $Matches[1]
    } else {
        throw "Could not read VERSION from CMakeLists.txt; pass -Version explicitly."
    }
}

Write-Host "Packaging $PluginName $Version" -ForegroundColor Cyan

# --- build -------------------------------------------------------------------

if (-not $SkipBuild) {
    & (Join-Path $repo 'build.ps1') -Arch both -Config Release -X64dbgRoot $X64dbgRoot
    if ($LASTEXITCODE -ne 0) { throw "Build failed." }
}

$plugin64 = Join-Path $repo "build64\src\$PluginName.dp64"
$plugin32 = Join-Path $repo "build32\src\$PluginName.dp32"

foreach ($required in @($plugin64, $plugin32)) {
    if (-not (Test-Path $required)) {
        throw "Missing $required. Build first, or drop -SkipBuild."
    }
}

if (-not $NoIndex -and -not (Test-Path $Index)) {
    throw @"
No index at '$Index'.

Build one with `python etl\build_index.py`, point -Index at an existing file,
or pass -NoIndex to ship a plugin-only archive.
"@
}

# --- stage -------------------------------------------------------------------

# Staged in a directory named after the archive so extracting produces one
# tidy folder rather than scattering files into the user's Downloads.
$suffix  = if ($NoIndex) { 'plugin-only' } else { 'win' }
$stem    = "$PluginName-$Version-$suffix"
$outDir  = Join-Path $repo 'dist\release'
$staging = Join-Path $outDir $stem

Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $staging -Force | Out-Null

Copy-Item $plugin64 $staging
Copy-Item $plugin32 $staging
Copy-Item (Join-Path $repo 'install.ps1') $staging

foreach ($doc in @('LICENSE', 'THIRD_PARTY_NOTICES.md')) {
    $path = Join-Path $repo $doc
    if (Test-Path $path) { Copy-Item $path $staging }
}

if (-not $NoIndex) {
    # Renamed on the way in: -Index may point at a file called anything, but the
    # plugin looks for exactly $IndexName beside itself.
    Copy-Item $Index (Join-Path $staging $IndexName)
}

# A short read-me inside the archive, since someone who downloads a zip is not
# necessarily looking at the GitHub page while they extract it.
$indexNote = if ($NoIndex) {
    "This archive does not include $IndexName. Copy the one from your existing`r`ninstall, or download the full archive."
} else {
    "$IndexName is the prebuilt index. install.ps1 places it beside the plugin,`r`nwhich is where the plugin looks for it."
}

@"
$PluginName $Version
$('=' * ($PluginName.Length + $Version.Length + 1))

Install:

    1. Close x64dbg.
    2. Right-click install.ps1 -> Run with PowerShell

   or from a PowerShell prompt in this directory:

    .\install.ps1

   If x64dbg is not found automatically:

    .\install.ps1 -X64dbgRoot "C:\path\to\x64dbg"

Manual install:

    Copy $PluginName.dp64 and $IndexName into <x64dbg>\release\x64\plugins\
    Copy $PluginName.dp32 and $IndexName into <x64dbg>\release\x32\plugins\

$indexNote

Requires an x64dbg snapshot from 2025-06-30 or newer.

See THIRD_PARTY_NOTICES.md for the licences of the bundled documentation.
"@ | Set-Content (Join-Path $staging 'README.txt') -Encoding utf8

# --- archive -----------------------------------------------------------------

$zip = Join-Path $outDir "$stem.zip"
Remove-Item $zip -Force -ErrorAction SilentlyContinue
Compress-Archive -Path "$staging\*" -DestinationPath $zip -CompressionLevel Optimal

Remove-Item $staging -Recurse -Force

$mb = [math]::Round((Get-Item $zip).Length / 1MB, 1)
Write-Host ""
Write-Host "  $zip ($mb MB)" -ForegroundColor Green
Write-Host ""
Write-Host "Upload that to a GitHub release. Users download it, extract, and run" -ForegroundColor DarkGray
Write-Host "install.ps1." -ForegroundColor DarkGray
