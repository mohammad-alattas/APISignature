<#
.SYNOPSIS
    Install APISignature into an x64dbg installation.

.DESCRIPTION
    Copies the plugin and its index into x64dbg's plugins directories. Run it
    from an extracted release archive, or from a source tree you have built.

    x64dbg is found in this order: -X64dbgRoot, then $env:X64DBG_ROOT, then a
    running x64dbg/x32dbg process, then the usual install locations.

.EXAMPLE
    .\install.ps1

.EXAMPLE
    .\install.ps1 -X64dbgRoot "D:\Tools\x64dbg"
#>
[CmdletBinding()]
param(
    # Directory containing release\. Passing release\ itself also works.
    [string]$X64dbgRoot = $env:X64DBG_ROOT,

    # Where to find the plugin and index. Defaults to this script's directory.
    [string]$Source = $PSScriptRoot,

    # Overwrite an existing install without asking.
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

# Single point of truth for the artifact names, so renaming the plugin is a
# one-line change here rather than a search across the repo.
$PluginName = 'APISignature'
$IndexName  = 'apisignature.db'

function Write-Step { param([string]$Text) Write-Host $Text -ForegroundColor Cyan }
function Write-Ok   { param([string]$Text) Write-Host "  $Text" -ForegroundColor Green }
function Write-Note { param([string]$Text) Write-Host "  $Text" -ForegroundColor DarkGray }

# --- locate x64dbg -----------------------------------------------------------

# A directory qualifies if either architecture is present. Plenty of people keep
# only the 64-bit build, and refusing to install for them would be wrong.
function Test-X64dbgRoot {
    param([string]$Path)
    if (-not $Path) { return $false }
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    return (Test-Path (Join-Path $Path 'release\x64\x64dbg.exe')) -or
           (Test-Path (Join-Path $Path 'release\x32\x32dbg.exe'))
}

function Resolve-X64dbgRoot {
    param([string]$Hint)

    if ($Hint) {
        if (Test-X64dbgRoot $Hint) { return (Resolve-Path -LiteralPath $Hint).Path }

        # Pointing at release\ instead of the root is an easy mistake and a
        # cheap one to absorb.
        $parent = Split-Path -Parent $Hint
        if (Test-X64dbgRoot $parent) { return (Resolve-Path -LiteralPath $parent).Path }

        throw "'$Hint' does not look like an x64dbg install -- expected release\x64\x64dbg.exe or release\x32\x32dbg.exe beneath it."
    }

    # A running instance tells us exactly where it lives. We cannot install into
    # it while it is running, but knowing the path lets us say so precisely.
    $running = Get-Process -Name 'x64dbg', 'x32dbg' -ErrorAction SilentlyContinue |
               Where-Object { $_.Path } | Select-Object -First 1
    if ($running) {
        # ...\release\x64\x64dbg.exe -> ...\
        $root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $running.Path))
        if (Test-X64dbgRoot $root) { return $root }
    }

    $candidates = @(
        'C:\x64dbg', 'D:\x64dbg', 'C:\Tools\x64dbg', 'D:\Tools\x64dbg',
        (Join-Path $env:ProgramFiles 'x64dbg'),
        (Join-Path $env:USERPROFILE 'Desktop\x64dbg'),
        (Join-Path $env:USERPROFILE 'Downloads\x64dbg')
    )
    foreach ($candidate in $candidates) {
        if (Test-X64dbgRoot $candidate) { return $candidate }
    }

    throw @"
Could not find x64dbg. Pass it explicitly:

    .\install.ps1 -X64dbgRoot "C:\path\to\x64dbg"

That is the directory containing release\, the one with x64dbg.exe under
release\x64\. Set `$env:X64DBG_ROOT to skip this next time.
"@
}

# --- locate what we are installing -------------------------------------------

# Release archives put everything in one directory; a source tree scatters the
# binaries into per-architecture build directories. Accept both so the same
# script serves users and contributors.
function Find-Payload {
    param([string]$Root, [string]$FileName, [string[]]$ExtraDirs)

    $searchDirs = @($Root) + ($ExtraDirs | ForEach-Object { Join-Path $Root $_ })
    foreach ($dir in $searchDirs) {
        $path = Join-Path $dir $FileName
        if (Test-Path -LiteralPath $path) { return (Resolve-Path -LiteralPath $path).Path }
    }
    return $null
}

$plugin64 = Find-Payload $Source "$PluginName.dp64" @('x64', 'build64\src')
$plugin32 = Find-Payload $Source "$PluginName.dp32" @('x32', 'build32\src')
$index    = Find-Payload $Source $IndexName        @('x64', 'x32', 'dist')

if (-not $plugin64 -and -not $plugin32) {
    throw @"
No plugin found under '$Source'.

Run this from an extracted release archive, or build first:

    .\build.ps1 -X64dbgRoot "C:\path\to\x64dbg"
"@
}

# --- refuse to fight a running debugger --------------------------------------

# Windows locks a loaded DLL, so copying over a plugin while x64dbg is open
# fails with a bare "Permission denied" that gives no hint what to do.
$running = @(Get-Process -Name 'x64dbg', 'x32dbg' -ErrorAction SilentlyContinue)
if ($running.Count -gt 0) {
    $names = ($running | ForEach-Object { "$($_.ProcessName) (PID $($_.Id))" }) -join ', '
    throw "Close x64dbg first -- it holds the plugin DLL open. Running: $names"
}

# --- install -----------------------------------------------------------------

$root = Resolve-X64dbgRoot $X64dbgRoot
Write-Step "x64dbg"
Write-Note $root

if (-not $index) {
    Write-Host ""
    Write-Warning @"
No $IndexName found under '$Source'.

The plugin will load but every lookup will report "No index loaded". Download
$IndexName from the releases page into this directory and run install.ps1
again, or build it with: python etl\build_index.py
"@
}

$installed = @()

foreach ($target in @(
    @{ Arch = 'x64'; Plugin = $plugin64 },
    @{ Arch = 'x32'; Plugin = $plugin32 }
)) {
    $arch   = $target.Arch
    $source = $target.Plugin
    if (-not $source) { continue }

    $pluginDir = Join-Path $root "release\$arch\plugins"

    # Only install for architectures this x64dbg actually has. Copying a .dp32
    # into an x64-only install leaves a file nothing will ever load.
    $exe = Join-Path $root "release\$arch\${arch}dbg.exe"
    if (-not (Test-Path $exe)) {
        Write-Step "$arch"
        Write-Note "not present in this install, skipping"
        continue
    }

    Write-Step "$arch"

    if (-not (Test-Path $pluginDir)) {
        New-Item -ItemType Directory -Path $pluginDir -Force | Out-Null
    }

    $destPlugin = Join-Path $pluginDir (Split-Path -Leaf $source)
    if ((Test-Path $destPlugin) -and -not $Force) {
        Write-Note "replacing existing $(Split-Path -Leaf $source)"
    }

    Copy-Item -LiteralPath $source -Destination $destPlugin -Force
    Write-Ok "$(Split-Path -Leaf $source)"

    if ($index) {
        # The index sits beside the plugin because that is where plugin.cpp
        # looks for it -- see open_index().
        Copy-Item -LiteralPath $index -Destination (Join-Path $pluginDir $IndexName) -Force
        $mb = [math]::Round((Get-Item $index).Length / 1MB)
        Write-Ok "$IndexName ($mb MB)"
    }

    $installed += $pluginDir
}

if ($installed.Count -eq 0) {
    throw "Nothing installed: no architecture in '$root' matched the plugins in '$Source'."
}

Write-Host ""
Write-Host "Installed into:" -ForegroundColor Green
$installed | ForEach-Object { Write-Host "  $_" }
Write-Host ""
Write-Host "Start x64dbg and look for the APISignature tab, then select an API call in" -ForegroundColor DarkGray
Write-Host "the disassembly. If the tab is missing, check the Log tab for a line" -ForegroundColor DarkGray
Write-Host "beginning [$PluginName]." -ForegroundColor DarkGray
