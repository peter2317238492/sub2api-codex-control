#Requires -Version 5.1
[CmdletBinding()]
param(
  [string]$OutputDir,
  [string]$GoExe,
  [string[]]$Arch = @('amd64', 'arm64')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Fail {
  param([string]$Message)
  [Console]::Error.WriteLine("build-windows-package: $Message")
  exit 1
}

function Report {
  param([string]$Message = '')
  [Console]::Out.WriteLine($Message)
}

trap { Fail $_.Exception.Message }

$packagingDir = Split-Path -Parent $PSScriptRoot
$connectorDir = Split-Path -Parent $packagingDir
$repoRoot = Split-Path -Parent $connectorDir

foreach ($architecture in $Arch) {
  if ($architecture -ne 'amd64' -and $architecture -ne 'arm64') {
    Fail "unsupported architecture: $architecture"
  }
}

if ([string]::IsNullOrWhiteSpace($GoExe)) {
  $go = Get-Command 'go' -ErrorAction SilentlyContinue
  if ($null -eq $go) {
    Fail 'go is not on PATH; pass -GoExe with the pinned toolchain'
  }
  $GoExe = $go.Source
} elseif (-not (Test-Path -LiteralPath $GoExe -PathType Leaf)) {
  Fail "-GoExe does not exist: $GoExe"
}

$releaseConfigPath = Join-Path $connectorDir 'release\release-config.json'
if (-not (Test-Path -LiteralPath $releaseConfigPath -PathType Leaf)) {
  Fail "the release configuration is missing: $releaseConfigPath"
}
$releaseConfig = (Get-Content -LiteralPath $releaseConfigPath -Raw) | ConvertFrom-Json
$version = $releaseConfig.connector_version

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
  $OutputDir = Join-Path $repoRoot 'dist\windows'
}
if (-not (Test-Path -LiteralPath $OutputDir -PathType Container)) {
  [void](New-Item -ItemType Directory -Path $OutputDir -Force)
}
$OutputDir = (Resolve-Path -LiteralPath $OutputDir).ProviderPath

$stage = Join-Path $OutputDir "sub2api-codex-connector_${version}_windows"
if (Test-Path -LiteralPath $stage) {
  Remove-Item -LiteralPath $stage -Recurse -Force
}
[void](New-Item -ItemType Directory -Path $stage)

$environment = @{
  'CGO_ENABLED' = $releaseConfig.go_build_environment.CGO_ENABLED
  'GOTOOLCHAIN' = $releaseConfig.go_build_environment.GOTOOLCHAIN
  'GOAMD64'     = $releaseConfig.go_build_environment.GOAMD64
  'GOARM64'     = $releaseConfig.go_build_environment.GOARM64
  'GOOS'        = 'windows'
  'GOARCH'      = ''
  'GOFLAGS'     = ''
}
$saved = @{}
foreach ($name in $environment.Keys) {
  $saved[$name] = [Environment]::GetEnvironmentVariable($name)
}

try {
  foreach ($name in $environment.Keys) {
    [Environment]::SetEnvironmentVariable($name, $environment[$name])
  }
  Push-Location -LiteralPath $connectorDir
  try {
    foreach ($architecture in $Arch) {
      [Environment]::SetEnvironmentVariable('GOARCH', $architecture)
      $target = Join-Path $stage "bin\windows-$architecture\sub2api-codex-connector.exe"
      [void](New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force)
      Report "building windows/$architecture"
      & $GoExe build -trimpath -buildvcs=false -o $target ./cmd/connector
      if ($LASTEXITCODE -ne 0) {
        Fail "go build failed for windows/$architecture"
      }
    }
  } finally {
    Pop-Location
  }
} finally {
  foreach ($name in $saved.Keys) {
    [Environment]::SetEnvironmentVariable($name, $saved[$name])
  }
}

foreach ($name in @('install.ps1', 'uninstall.ps1', 'sub2api-codex-connector-ctl.ps1', 'connector.example.json')) {
  Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $stage $name)
}
foreach ($name in @('LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md')) {
  Copy-Item -LiteralPath (Join-Path $repoRoot $name) -Destination (Join-Path $stage $name)
}

$notice = @"
This archive is NOT a reproducible-release artifact.

It was produced by connector/packaging/windows/build-windows-package.ps1 on an
operator workstation. It carries none of the evidence that the Linux and macOS
release artifacts carry:

  - no Sigstore signature and no OIDC workflow identity;
  - no SLSA provenance and no SPDX SBOM;
  - no reproducible build inputs and no SOURCE_DATE_EPOCH normalization;
  - no protected-tag release workflow and no immutable GitHub Release.

The upstream release pipeline is deliberately not extended to Windows. Do not
distribute, promote, or install this archive as a release. See
connector/release/README.md for the release boundary that does apply.

Connector version: $version
Built:             $([DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))
"@
[IO.File]::WriteAllText((Join-Path $stage 'RELEASE-NOT-FOR-DISTRIBUTION'), $notice,
  (New-Object System.Text.UTF8Encoding($false)))

$lines = @()
foreach ($file in (Get-ChildItem -LiteralPath $stage -Recurse -File | Sort-Object FullName)) {
  $relative = $file.FullName.Substring($stage.Length + 1).Replace('\', '/')
  $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
  $lines += "$hash  $relative"
}
[IO.File]::WriteAllText((Join-Path $stage 'SHA256SUMS'), (($lines -join "`n") + "`n"),
  (New-Object System.Text.UTF8Encoding($false)))

$zip = "$stage.zip"
if (Test-Path -LiteralPath $zip) {
  Remove-Item -LiteralPath $zip -Force
}
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -CompressionLevel Optimal

Report ''
Report "Wrote $zip"
Report "SHA-256 $((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant())"
Report ''
Report 'NOT A RELEASE ARTIFACT: this zip has no Sigstore signature, no SLSA provenance,'
Report 'no SPDX SBOM, and no reproducible-build guarantee. The Windows target is outside'
Report 'the release matrix in connector/release/release-config.json. Do not distribute it.'
