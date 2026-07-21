#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Build the reeflex-holds MCPB bundle for the CURRENT Windows platform/arch.

.DESCRIPTION
    reeflex-holds' only declared dependency is `mcp>=1.2.0`, but that pulls in
    compiled wheels (pydantic_core -- Rust, cryptography/cffi -- C, rpds-py --
    Rust). Those wheels are platform+ABI specific, so an .mcpb built here is
    ONLY valid for Windows on this machine's Python ABI (win_amd64 wheels,
    matching this script's target arch detection below). It will NOT run on
    macOS or Linux, and won't run on win32 (32-bit) either.

    This script does NOT run the reeflex-holds server. It only:
      1. pip installs reeflex-holds==<version> (declared below) from PyPI
         into mcpb/server/lib/ (--target, so deps land alongside the shim,
         not in the ambient environment).
      2. Packs manifest.json + server/ into a versioned .mcpb via the mcpb
         CLI (falls back to a plain zip if the CLI is unavailable).

    See README.md in this directory for the full platform-matrix reality:
    this script only ever produces ONE platform+arch combination per run --
    the one it is invoked on. darwin-arm64 / darwin-x64 / linux-x64 bundles
    must be built by running this recipe (or build.sh) ON those platforms,
    or via a CI matrix (documented, NOT built, in README.md).

.NOTES
    Run from anywhere; paths below are relative to this script's own
    location, not the caller's working directory.
#>

param(
    [string]$Version = "0.1.1"
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$LibDir    = Join-Path $ScriptDir "server\lib"

# ---- 1. Platform/arch tag (informational + used in the output filename) ----
# mcpb bundles are OS+ABI specific because of the compiled deps pulled in by
# `mcp` (pydantic_core/cryptography/rpds-py). We tag the filename so nobody
# mistakes this artifact for a universal bundle.
$PlatformTag = "win32"
switch ([System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture) {
    "X64"   { $ArchTag = "x64" }
    "Arm64" { $ArchTag = "arm64" }
    default { $ArchTag = "x86" }
}

Write-Host "Building reeflex-holds $Version for $PlatformTag-$ArchTag ..."

# ---- 2. Fresh server/lib/ (idempotent: wipe any previous install) ----
if (Test-Path $LibDir) {
    Remove-Item -Recurse -Force $LibDir
}
New-Item -ItemType Directory -Path $LibDir -Force | Out-Null

# ---- 3. pip install reeflex-holds + its deps into server/lib/ ----
# This is a BUILD step, not running the server -- reeflex-holds' console
# script / __main__ entry point is never invoked here.
& python -m pip install --target $LibDir "reeflex-holds==$Version" --no-compile
if ($LASTEXITCODE -ne 0) {
    throw "pip install failed (exit $LASTEXITCODE) -- see output above."
}

# Drop __pycache__ / *.dist-info test payloads pip may have left behind
# (belt-and-suspenders alongside .mcpbignore, in case the packer used
# below doesn't honor it, e.g. the plain-zip fallback).
Get-ChildItem -Path $LibDir -Recurse -Directory -Filter "__pycache__" |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

# ---- 4. Pack manifest.json (zip root) + server/ into the .mcpb ----
$OutputName = "reeflex-holds-$Version-$PlatformTag-$ArchTag.mcpb"
$OutputPath = Join-Path $ScriptDir $OutputName

if (Test-Path $OutputPath) {
    Remove-Item -Force $OutputPath
}

$mcpbAvailable = $null -ne (Get-Command npx -ErrorAction SilentlyContinue)

if ($mcpbAvailable) {
    Write-Host "Packing via 'mcpb pack' (npx @anthropic-ai/mcpb) ..."
    & npx -y "@anthropic-ai/mcpb" pack $ScriptDir $OutputPath
    if ($LASTEXITCODE -ne 0) {
        throw "mcpb pack failed (exit $LASTEXITCODE)."
    }
} else {
    Write-Host "mcpb CLI not found; falling back to plain zip (Compress-Archive)."
    Write-Host "NOTE: the plain-zip fallback does NOT honor .mcpbignore -- prefer the mcpb CLI."
    $tmpZipDir = Join-Path ([System.IO.Path]::GetTempPath()) ("reeflex-holds-mcpb-" + [Guid]::NewGuid())
    New-Item -ItemType Directory -Path $tmpZipDir -Force | Out-Null
    Copy-Item -Path (Join-Path $ScriptDir "manifest.json") -Destination $tmpZipDir
    Copy-Item -Path (Join-Path $ScriptDir "server") -Destination $tmpZipDir -Recurse
    Compress-Archive -Path (Join-Path $tmpZipDir "*") -DestinationPath $OutputPath -Force
    Remove-Item -Recurse -Force $tmpZipDir
}

Write-Host "Built: $OutputPath"
Write-Host ""
Write-Host "This bundle targets $PlatformTag-$ArchTag ONLY (compiled deps are ABI-specific)."
Write-Host "See README.md for the full platform matrix and the CI-matrix upgrade path."
