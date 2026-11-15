<#
  Mini-SOAR — daily launcher for WINDOWS (Docker Desktop). No Kali needed.

  .\start.ps1                      start everything + health check
  .\start.ps1 scan                 ...and scan the whole authorized scope
  .\start.ps1 scan 192.168.103.105 ...and scan one host
  .\start.ps1 update               after new code: rebuild, sync CVEs, scan
  .\start.ps1 enroll <ip> [admin]  prepare a lab host for auto-fix (asks its admin password once)
  .\start.ps1 check  <ip>          test if a host is ready for auto-fix (changes nothing)
  .\start.ps1 logs [service]       live logs (soar, api, scanner, dashboard)
  .\start.ps1 stop                 stop everything
  .\start.ps1 train                train the ML risk model again
  .\start.ps1 totp-reset <email>   remove a user's 2FA so they can enrol again

  If Windows blocks the script:  powershell -ExecutionPolicy Bypass -File .\start.ps1
  (or just use run.bat, which does that for you)
#>
param(
  [Parameter(Position = 0)][string]$Command = "",
  [Parameter(Position = 1)][string]$Arg1 = "",
  [Parameter(Position = 2)][string]$Arg2 = ""
)

$ErrorActionPreference = "Continue"
Set-Location -Path $PSScriptRoot

# --- NETWORK_MODE=native: no Docker, everything runs directly on Windows -----
if (Test-Path ".env") {
  $modeHit = Select-String -Path ".env" -Pattern '^\s*NETWORK_MODE\s*=\s*"?([A-Za-z-]+)' | Select-Object -First 1
  if ($modeHit -and ($modeHit.Matches[0].Groups[1].Value.ToLower() -in @("native", "windows-native", "direct"))) {
    & (Join-Path $PSScriptRoot "start-native.ps1") $Command $Arg1 $Arg2
    exit $LASTEXITCODE
  }
}

$Compose = @("compose", "-f", "docker-compose.windows.yml")

function Ok($m)  { Write-Host "  [OK] $m" -ForegroundColor Green }
function Bad($m) { Write-Host "  [X]  $m" -ForegroundColor Red }
function Dc { & docker @Compose @args }

Write-Host "== Mini-SOAR (Windows) =="

# --- Docker Desktop running? -------------------------------------------------
docker info *> $null
if ($LASTEXITCODE -ne 0) { Bad "Docker Desktop is not running. Start it, wait for 'Engine running', then retry."; exit 1 }
Ok "Docker Desktop running"

if ($Command -eq "stop") { Dc down; exit 0 }
if ($Command -eq "logs") { if ($Arg1) { Dc logs -f --tail 100 $Arg1 } else { Dc logs -f --tail 50 }; exit 0 }

# --- .env present? -----------------------------------------------------------
if (-not (Test-Path ".env")) { Bad ".env missing. Copy .env.example to .env and fill it (see docs\WINDOWS_ENGINE.md)."; exit 1 }
Ok ".env found"
$envText = Get-Content ".env" -Raw
if ($envText -notmatch "(?m)^\s*NETWORK_MODE\s*=\s*nat") {
  Write-Host "  [!]  Tip: add NETWORK_MODE=nat to .env (the Windows compose file also forces it)." -ForegroundColor Yellow
}

# --- enroll / check a target -------------------------------------------------
if ($Command -eq "enroll" -or $Command -eq "check") {
  if (-not $Arg1) { Write-Host "usage: .\start.ps1 enroll <target-ip> [admin-user]"; exit 1 }
  if ($Command -eq "enroll" -and -not (Test-Path "secrets\lab_id_rsa")) {
    Write-Host "-- no engine SSH key yet: creating secrets\lab_id_rsa (RSA, works with old servers too)"
    New-Item -ItemType Directory -Force -Path "secrets" | Out-Null
    $secretsDir = (Resolve-Path "secrets").Path
    Dc build api | Out-Null
    & docker run --rm -v "${secretsDir}:/s" --entrypoint python mini-soar-engine:latest -c `
      "import paramiko; k=paramiko.RSAKey.generate(2048); k.write_private_key_file('/s/lab_id_rsa'); open('/s/lab_id_rsa.pub','w').write(k.get_name()+' '+k.get_base64()+' mini-soar-engine\n')"
    if (Test-Path "secrets\lab_id_rsa") { Ok "key created" } else { Bad "could not create the key"; exit 1 }
  }
  if ($Command -eq "check") {
    Dc run --rm --entrypoint python api -m soar.enroll $Arg1 --check-only
  } elseif ($Arg2) {
    Dc run --rm --entrypoint python api -m soar.enroll $Arg1 --admin-user $Arg2
  } else {
    Dc run --rm --entrypoint python api -m soar.enroll $Arg1
  }
  exit $LASTEXITCODE
}

# --- one-off tools ---------------------------------------------------------------
if ($Command -eq "train") { Dc run --rm --entrypoint python api -m ml.train; exit $LASTEXITCODE }
if ($Command -eq "totp-reset") {
  if (-not $Arg1) { Write-Host "usage: .\start.ps1 totp-reset <email>"; exit 1 }
  Dc run --rm --entrypoint python api -m soar.totp_2fa reset $Arg1
  exit $LASTEXITCODE
}

# --- start ---------------------------------------------------------------------
if ($Command -eq "update") {
  Write-Host "-- rebuilding images (first time can take 10+ minutes)"
  Dc build
  if ($LASTEXITCODE -ne 0) { Bad "build failed"; exit 1 }
}

Dc up -d *> $null
if ($LASTEXITCODE -eq 0) { Ok "containers started" } else { Bad "docker compose up failed (run: .\start.ps1 logs)"; exit 1 }

$healthy = $false
for ($i = 0; $i -lt 30; $i++) {
  try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 "http://localhost:8000/health" | Out-Null; $healthy = $true; break } catch { Start-Sleep 1 }
}
if ($healthy) { Ok "API healthy" } else { Bad "API not answering (.\start.ps1 logs api)" }

Dc run --rm scanner show-scope 2>$null | Select-Object -First 9

if ($Command -eq "update") {
  Write-Host "-- syncing CVE data: CISA KEV, EPSS, and CVEs for the software found in the lab"
  Dc run --rm --entrypoint python api -m intel.cli sync-lab
  Write-Host "-- ML risk model (trained once, about a minute)"
  Dc run --rm --entrypoint python api -m ml.train --if-missing
}

if ($Command -eq "scan" -or $Command -eq "update") {
  if ($Arg1) {
    Write-Host "-- scanning $Arg1"
    Dc run --rm scanner scan --targets $Arg1
  } else {
    Write-Host "-- scanning the whole authorized scope (a few minutes)"
    Dc run --rm scanner scan
  }
}

Write-Host ""
Write-Host "Dashboard: http://localhost:3000" -ForegroundColor Cyan
