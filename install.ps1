# Copyright 2026 masqr contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# masqr installer for Windows (PowerShell).
#
#   irm https://masqr.dev/install.ps1 | iex
#
# Downloads the right prebuilt masqr.exe for your CPU from the latest GitHub
# release, verifies its SHA-256, installs to %LOCALAPPDATA%\masqr\bin (no admin),
# and adds it to your user PATH. Re-running upgrades in place.
#
# Overrides (set before running):
#   $env:MASQR_VERSION      pin a release tag (e.g. v0.3.1); default: latest
#   $env:MASQR_INSTALL_DIR  install location; default: %LOCALAPPDATA%\masqr\bin
#   $env:MASQR_REPO         owner/repo; default: masqrhq/masqr

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocol]::Tls12

$Repo       = if ($env:MASQR_REPO)        { $env:MASQR_REPO }        else { 'masqrhq/masqr' }
$InstallDir = if ($env:MASQR_INSTALL_DIR) { $env:MASQR_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'masqr\bin' }

function Die($msg) { Write-Host "x $msg" -ForegroundColor Red; exit 1 }
function Info($msg) { Write-Host "masqr: $msg" -ForegroundColor DarkGray }
function Ok($msg)   { Write-Host "+ $msg" -ForegroundColor Green }

# --- Detect CPU architecture (handles 32-bit PowerShell on 64-bit Windows) ---
$rawArch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
switch ($rawArch) {
  'AMD64' { $goarch = 'amd64' }
  'ARM64' { $goarch = 'arm64' }
  default { Die "unsupported architecture: $rawArch" }
}

# --- Resolve version ----------------------------------------------------------
$tag = $env:MASQR_VERSION
if (-not $tag) {
  Info 'resolving latest release...'
  try {
    $rel = Invoke-RestMethod -UseBasicParsing -Headers @{ 'User-Agent' = 'masqr-installer' } `
             -Uri "https://api.github.com/repos/$Repo/releases/latest"
    $tag = $rel.tag_name
  } catch {
    Die "couldn't determine the latest release. Set `$env:MASQR_VERSION=vX.Y.Z, or see https://github.com/$Repo/releases."
  }
}
if (-not $tag) { Die "no release tag found for $Repo." }
Info "installing masqr $tag (windows/$goarch)"

$stem    = "masqr-$tag-windows-$goarch"
$base    = "https://github.com/$Repo/releases/download/$tag"
$exeUrl  = "$base/$stem.exe"
$shaUrl  = "$base/$stem.exe.sha256"

# --- Download + verify in a temp dir ------------------------------------------
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("masqr-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
try {
  # The asset is the bare .exe — no extraction step.
  $src = Join-Path $tmp 'masqr.exe'
  Info "downloading $stem.exe..."
  try { Invoke-WebRequest -UseBasicParsing -Uri $exeUrl -OutFile $src }
  catch { Die "download failed: $exeUrl (asset may not exist for this platform/version)" }

  # Verify SHA-256 against the published sidecar.
  try {
    $shaFile = Join-Path $tmp "$stem.exe.sha256"
    Invoke-WebRequest -UseBasicParsing -Uri $shaUrl -OutFile $shaFile
    $expected = ((Get-Content $shaFile -Raw).Trim() -split '\s+')[0].ToLower()
    $actual   = (Get-FileHash -Algorithm SHA256 -Path $src).Hash.ToLower()
    if ($expected -ne $actual) { Die "checksum mismatch!`n    expected $expected`n    got      $actual" }
    Ok 'checksum verified'
  } catch {
    if ($_.Exception.Message -like '*checksum mismatch*') { throw }
    Write-Host "! no .sha256 sidecar; skipping checksum verification" -ForegroundColor Yellow
  }

  # --- Install ----------------------------------------------------------------
  New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
  $dest = Join-Path $InstallDir 'masqr.exe'
  Copy-Item -Path $src -Destination $dest -Force
  Unblock-File -Path $dest -ErrorAction SilentlyContinue
  Ok "installed to $dest"

  # Best-effort: run what we just installed so a broken binary surfaces here
  # rather than on first use. Non-fatal.
  try {
    $ver = (& $dest --version 2>$null | Select-Object -First 1)
    if ($ver) { Ok $ver }
  } catch {
    Write-Host "! installed, but 'masqr --version' didn't run cleanly here" -ForegroundColor Yellow
  }
} finally {
  Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

# --- Add to user PATH ---------------------------------------------------------
$userPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
if (($userPath -split ';') -notcontains $InstallDir) {
  $newPath = if ([string]::IsNullOrEmpty($userPath)) { $InstallDir } else { "$userPath;$InstallDir" }
  [Environment]::SetEnvironmentVariable('PATH', $newPath, 'User')
  Write-Host "+ added $InstallDir to your user PATH (restart the terminal to pick it up)" -ForegroundColor Green
}
# Make it usable in the current session too.
if (($env:PATH -split ';') -notcontains $InstallDir) { $env:PATH = "$env:PATH;$InstallDir" }

Write-Host ''
Ok "masqr $tag is ready."
Write-Host 'Wrap your coding CLI so secrets never leave your machine:' -ForegroundColor DarkGray
Write-Host '  masqr agy             # Google Antigravity'
Write-Host '  masqr claude          # Anthropic Claude Code'
Write-Host '  masqr codex           # OpenAI Codex'
Write-Host '  masqr gemini -p "..."  # Google Gemini'
Write-Host '  masqr vibe            # Mistral vibe CLI'
Write-Host "Docs: https://github.com/$Repo"
