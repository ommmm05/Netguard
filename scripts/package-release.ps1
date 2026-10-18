#Requires -Version 5.1
<#
.SYNOPSIS
  Create a source-only NetGuard release ZIP (does not modify project files).

.DESCRIPTION
  Packages the repository excluding virtualenvs, node_modules, caches,
  databases, uploaded PCAPs, logs, secrets, and build artifacts.

.EXAMPLE
  .\scripts\package-release.ps1
  .\scripts\package-release.ps1 -OutDir D:\releases
#>
param(
  [string]$OutDir = (Join-Path (Split-Path -Parent $PSScriptRoot) "releases"),
  [string]$Name = ("NetGuard-source-{0:yyyyMMdd-HHmmss}" -f (Get-Date))
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if (-not (Test-Path $OutDir)) {
  New-Item -ItemType Directory -Path $OutDir | Out-Null
}

$ZipPath = Join-Path $OutDir ($Name + ".zip")
if (Test-Path $ZipPath) {
  Remove-Item -Force $ZipPath
}

$excludeDirNames = @(
  "venv", ".venv", "env", "node_modules", ".git", ".pytest_cache",
  "__pycache__", "dist", "releases", ".mypy_cache", ".ruff_cache",
  "htmlcov", ".idea", ".vscode"
)
$excludeFileGlobs = @(
  "*.pyc", "*.pyo", "*.db", "*.db-journal", "*.db-wal", "*.db-shm",
  ".env", ".env.*", "*.log", "*.joblib", "*.pkl"
)

$staging = Join-Path $env:TEMP ("netguard-pkg-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $staging | Out-Null

try {
  $files = Get-ChildItem -Path $Root -Recurse -Force -File | Where-Object {
    $rel = $_.FullName.Substring($Root.Length).TrimStart("\", "/")
    $parts = $rel -split "[\\/]"
    foreach ($p in $parts) {
      if ($excludeDirNames -contains $p) { return $false }
    }
    # Exclude runtime uploads and local DBs under data/
    if ($rel -match '(?i)^data[\\/]uploads[\\/]') { return $false }
    if ($rel -match '(?i)^data[\\/][^\\/]+\.db') { return $false }
    if ($rel -match '(?i)^data[\\/]models[\\/].+\.(joblib|pkl)$') { return $false }
    if ($rel -match '(?i)^data[\\/]cicids_uploads[\\/]') { return $false }
    foreach ($g in $excludeFileGlobs) {
      if ($_.Name -like $g) { return $false }
    }
    if ($_.Name -eq ".env") { return $false }
    return $true
  }

  foreach ($f in $files) {
    $rel = $f.FullName.Substring($Root.Length).TrimStart("\", "/")
    $dest = Join-Path $staging $rel
    $destDir = Split-Path -Parent $dest
    if (-not (Test-Path $destDir)) {
      New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    }
    Copy-Item -LiteralPath $f.FullName -Destination $dest -Force
  }

  # Ensure empty data placeholders exist for first-run
  $dataDirs = @(
    (Join-Path $staging "data"),
    (Join-Path $staging "data\uploads"),
    (Join-Path $staging "data\models")
  )
  foreach ($d in $dataDirs) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
  }
  $keep = Join-Path $staging "data\uploads\.gitkeep"
  if (-not (Test-Path $keep)) { Set-Content -Path $keep -Value "" }

  Compress-Archive -Path (Join-Path $staging "*") -DestinationPath $ZipPath -CompressionLevel Optimal
  Write-Host "Created: $ZipPath"
  Write-Host ("Files packaged: {0}" -f $files.Count)
}
finally {
  if (Test-Path $staging) {
    Remove-Item -Recurse -Force $staging
  }
}
