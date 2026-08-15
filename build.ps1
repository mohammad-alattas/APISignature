<#
.SYNOPSIS
    Build the APISignature plugin for x64dbg and/or x32dbg.

.DESCRIPTION
    Wraps the toolchain quirks so a build is one command:

      * Selects MSVC 14.44 (the v143 toolset). Qt 5.12 does not compile under
        14.51+, which removed stdext::checked_array_iterator. See src/CMakeLists.txt.
      * Uses the Ninja generator. CMake's "Visual Studio 18 2026" generator
        rejects `-T version=14.44...` under the v145 toolset, so the tools
        version has to come from vcvarsall instead of from CMake.
      * Points each architecture at the matching Qt kit; a 64-bit plugin
        against 32-bit Qt fails obscurely at link time.

.EXAMPLE
    .\build.ps1 -X64dbgRoot "D:\Malware Analysis\x64_86dbg"

.EXAMPLE
    .\build.ps1 -Arch x64 -Install     # drop it straight into x64dbg\plugins
#>
[CmdletBinding()]
param(
    [ValidateSet('x64', 'x86', 'both')]
    [string]$Arch = 'both',

    [ValidateSet('Release', 'Debug', 'RelWithDebInfo')]
    [string]$Config = 'Release',

    # Directory containing pluginsdk\ and release\. Defaults to $env:X64DBG_ROOT.
    [string]$X64dbgRoot = $env:X64DBG_ROOT,

    # Qt kits. Default to the layout x64dbg's own Qt download produces.
    [string]$Qt64,
    [string]$Qt32,

    [string]$ToolsVersion = '14.44',

    # Copy the built plugin into x64dbg's plugins directory.
    [switch]$Install,

    [switch]$Clean
)

$ErrorActionPreference = 'Stop'
$repo = $PSScriptRoot

if (-not $X64dbgRoot) {
    throw "Set -X64dbgRoot (or `$env:X64DBG_ROOT) to your x64dbg install -- the directory containing pluginsdk\ and release\."
}
if (-not (Test-Path (Join-Path $X64dbgRoot 'pluginsdk\_plugins.h'))) {
    throw "No plugin SDK under '$X64dbgRoot'. Expected pluginsdk\_plugins.h."
}

if (-not $Qt64) { $Qt64 = Join-Path $X64dbgRoot 'Qt\qt5.12.12-msvc2017_64' }
if (-not $Qt32) { $Qt32 = Join-Path $X64dbgRoot 'Qt\qt5.12.12-msvc2017' }

# --- locate Visual Studio ----------------------------------------------------

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) { throw "vswhere.exe not found; is Visual Studio installed?" }

$vs = & $vswhere -latest -prerelease -products * -property installationPath
if (-not $vs) { throw "No Visual Studio installation found." }

$vcvarsall = Join-Path $vs 'VC\Auxiliary\Build\vcvarsall.bat'
if (-not (Test-Path $vcvarsall)) {
    throw "No C++ tools in '$vs'. Install the 'Desktop development with C++' workload."
}

$toolsDir = Join-Path $vs "VC\Tools\MSVC"
$hasTools = Get-ChildItem $toolsDir -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name.StartsWith($ToolsVersion) }
if (-not $hasTools) {
    $have = (Get-ChildItem $toolsDir -Directory -ErrorAction SilentlyContinue | ForEach-Object Name) -join ', '
    throw "MSVC $ToolsVersion is not installed (found: $have). Add the 'MSVC v143 - VS 2022 C++ build tools' component, or pass -ToolsVersion."
}

$cmakeBin = Join-Path $vs 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin'
$ninjaBin = Join-Path $vs 'Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja'

# --- build -------------------------------------------------------------------

function Build-Arch {
    param([string]$Target)

    $isX64    = $Target -eq 'x64'
    $buildDir = Join-Path $repo $(if ($isX64) { 'build64' } else { 'build32' })
    $qtPath   = if ($isX64) { $Qt64 } else { $Qt32 }
    $hostArch = if ($isX64) { 'x64' } else { 'x64_x86' }

    if (-not (Test-Path (Join-Path $qtPath 'lib\cmake\Qt5Widgets'))) {
        throw "No Qt kit at '$qtPath'. The $Target plugin needs a $Target Qt matching the one x64dbg ships."
    }
    if ($Clean -and (Test-Path $buildDir)) { Remove-Item -Recurse -Force $buildDir }

    Write-Host "`n=== $Target ($Config, MSVC $ToolsVersion) ===" -ForegroundColor Cyan

    # vcvarsall only sets variables in its own process, so the whole sequence
    # has to run inside one cmd invocation.
    # vcvarsall shells out to vswhere by bare name, so its directory has to be on
    # PATH or it writes a "not recognized" line to stderr on every invocation.
    $installerDir = Split-Path $vswhere -Parent

    $script = @"
@set "PATH=$installerDir;%PATH%"
@call "$vcvarsall" $hostArch -vcvars_ver=$ToolsVersion >nul || exit /b 1
@set "PATH=$cmakeBin;$ninjaBin;%PATH%"
cmake -G Ninja -B "$buildDir" -S "$repo" ^
      -DCMAKE_BUILD_TYPE=$Config ^
      -DX64DBG_ROOT="$($X64dbgRoot -replace '\\','/')" ^
      -DCMAKE_PREFIX_PATH="$($qtPath -replace '\\','/')" ^
      -DMALAPI_INSTALL_TO_X64DBG=$(if ($Install) { 'ON' } else { 'OFF' }) || exit /b 1
cmake --build "$buildDir" || exit /b 1
ctest --test-dir "$buildDir" --output-on-failure || exit /b 1
"@

    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "malapi-build-$Target.bat"
    Set-Content -Path $tmp -Value $script -Encoding ascii
    try {
        # Windows PowerShell turns any stderr from a native command into a
        # terminating error under ErrorActionPreference=Stop, which would abort
        # the build on warnings the compiler is entitled to emit. The exit code
        # is the thing that decides success.
        $previous = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        & cmd /c $tmp
        $code = $LASTEXITCODE
        $ErrorActionPreference = $previous

        if ($code -ne 0) { throw "$Target build failed (exit $code)." }
    } finally {
        Remove-Item $tmp -ErrorAction SilentlyContinue
    }

    $suffix = if ($isX64) { '.dp64' } else { '.dp32' }
    Write-Host "  -> $buildDir\src\APISignature$suffix" -ForegroundColor Green
}

if ($Arch -in 'x64', 'both') { Build-Arch 'x64' }
if ($Arch -in 'x86', 'both') { Build-Arch 'x86' }

Write-Host "`nDone." -ForegroundColor Green
