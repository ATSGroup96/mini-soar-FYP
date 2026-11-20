<#
  Mini-SOAR on WINDOWS WITHOUT DOCKER  (.env: NETWORK_MODE=native)

  Full scan like on Kali: ARP discovery + MAC address, SYN scan, nmap OS
  detection. Everything runs as normal
  Windows processes (Administrator), no Docker Desktop.

  Install once (all free):  Python 3.11, Nmap for Windows (with Npcap), Node.js 20 LTS
  (Nuclei and NetExec are downloaded by ".\run.bat update" into tools\)
  Guide: docs\WINDOWS_NATIVE.md

  .\run.bat                        start everything + health check
  .\run.bat scan [ip[,ip]]         start + scan (whole authorized scope if no ip)
  .\run.bat update                 after new code: install packages, rebuild dashboard, sync CVEs, scan
  .\run.bat enroll <ip> [admin]    prepare a lab host for auto-fix (asks its admin password once)
  .\run.bat check  <ip>            test if a host is ready for auto-fix (changes nothing)
  .\run.bat logs [service]         live log: api (default), soar, dashboard
  .\run.bat stop                   stop everything
  .\run.bat test                   run the automated test suite (tests\)
  .\run.bat train                  train the ML risk model again
  .\run.bat totp-reset <email>     remove a user's 2FA so they can enrol again

  start.ps1 / run.bat call this script automatically when .env says NETWORK_MODE=native.
#>
param(
  [Parameter(Position = 0)][string]$Command = "",
  [Parameter(Position = 1)][string]$Arg1 = "",
  [Parameter(Position = 2)][string]$Arg2 = ""
)

$ErrorActionPreference = "Continue"
Set-Location -Path $PSScriptRoot
$Root     = $PSScriptRoot
$Py       = Join-Path $Root ".venv\Scripts\python.exe"
$DepsMark = Join-Path $Root ".venv\.deps-ok"
$LogDir   = Join-Path $Root "logs"
$PidDir   = Join-Path $Root "data\pids"
$Dash     = Join-Path $Root "dashboard"
$DashOut  = Join-Path $Dash ".next\standalone"
$Services = @("api", "soar", "dashboard")
# removed services: "stop" still ends a copy left running by an older version
$LegacyServices = @("honeypot")

function Ok($m)   { Write-Host "  [OK] $m" -ForegroundColor Green }
function Bad($m)  { Write-Host "  [X]  $m" -ForegroundColor Red }
function Warn($m) { Write-Host "  [!]  $m" -ForegroundColor Yellow }

Write-Host "== Mini-SOAR (Windows native, no Docker) =="

# --- logs: no admin needed ---------------------------------------------------
if ($Command -eq "logs") {
  $svc = if ($Arg1) { $Arg1 } else { "api" }
  $f = Join-Path $LogDir "$svc.log"
  if (-not (Test-Path $f)) { Bad "no log yet: $f"; exit 1 }
  if ($svc -eq "dashboard") { Write-Host "(errors, if any: logs\dashboard.err.log)" }
  Get-Content -Path $f -Tail 60 -Wait
  exit 0
}

# --- Administrator (raw packets: ARP, SYN scan, OS detection) ----------------
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Warn "Administrator rights are needed (ARP / SYN scan / OS detection). Opening an Administrator window..."
  $argLine = "-NoExit -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $Command $Arg1 $Arg2"
  Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $argLine
  exit 0
}
Ok "running as Administrator"

# --- helpers -----------------------------------------------------------------
function Get-SvcPid($name) {
  $pf = Join-Path $PidDir "$name.pid"
  if (-not (Test-Path $pf)) { return $null }
  $procId = Get-Content $pf -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $procId) { return $null }
  $p = Get-Process -Id ([int]$procId) -ErrorAction SilentlyContinue
  if ($p -and ($p.ProcessName -in @("python", "pythonw", "node"))) { return [int]$procId }
  return $null
}

function Stop-StrayDashboard {
  # A dashboard started by an older launcher (through npm.cmd) saved the PID of a
  # cmd window, so it could not be stopped and kept port 3000 busy. Stop any
  # node.exe running from THIS project's dashboard folder.
  Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -and ($_.CommandLine.IndexOf($Dash, [StringComparison]::OrdinalIgnoreCase) -ge 0) } |
    ForEach-Object {
      & taskkill /PID $_.ProcessId /T /F *> $null
      Ok "leftover dashboard process $($_.ProcessId) stopped"
    }
}

function Stop-All {
  foreach ($s in ($Services + $LegacyServices)) {
    $procId = Get-SvcPid $s
    if ($procId) {
      # /T = the whole tree (the .venv python.exe starts the real python as a child)
      & taskkill /PID $procId /T /F *> $null
      Ok "$s stopped"
    }
    Remove-Item (Join-Path $PidDir "$s.pid") -Force -ErrorAction SilentlyContinue
  }
  Stop-StrayDashboard
}

function Read-DotEnv {
  $h = @{}
  foreach ($line in Get-Content ".env") {
    if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$') {
      $v = $Matches[2].Trim()
      if ($v.Length -ge 2 -and (($v.StartsWith('"') -and $v.EndsWith('"')) -or ($v.StartsWith("'") -and $v.EndsWith("'")))) {
        $v = $v.Substring(1, $v.Length - 2)
      }
      $h[$Matches[1]] = $v
    }
  }
  return $h
}

function Find-BasePython {
  if (Get-Command py -ErrorAction SilentlyContinue) {
    foreach ($v in @("3.11", "3.12")) {
      & py "-$v" -c "import sys" 2>$null
      if ($LASTEXITCODE -eq 0) { return @("py", "-$v") }
    }
  }
  $c = Get-Command python -ErrorAction SilentlyContinue
  if ($c -and ($c.Source -notmatch "WindowsApps")) {
    $ver = & $c.Source -c "import sys; print('%d.%d' % sys.version_info[:2])"
    if ($ver -in @("3.11", "3.12")) { return @($c.Source) }
  }
  return $null
}

function Find-Nmap {
  # 1) NMAP_PATH in .env (nmap.exe or the folder that holds it)
  $envs = Read-DotEnv
  if ($envs.ContainsKey("NMAP_PATH") -and $envs["NMAP_PATH"]) {
    $p = $envs["NMAP_PATH"]
    if (Test-Path $p -PathType Container) { $p = Join-Path $p "nmap.exe" }
    if (Test-Path $p -PathType Leaf) { return (Resolve-Path $p).Path }
    Warn "NMAP_PATH in .env does not point to nmap.exe: $p"
  }
  # 2) PATH of this window, 3) Windows' own search (where.exe), 4) usual folders
  $c = Get-Command nmap -ErrorAction SilentlyContinue
  if ($c) { return $c.Source }
  if (Get-Command where.exe -ErrorAction SilentlyContinue) {
    $w = & where.exe nmap 2>$null | Select-Object -First 1
    if ($w -and (Test-Path $w)) { return $w }
  }
  foreach ($p in @("${env:ProgramFiles(x86)}\Nmap\nmap.exe", "$env:ProgramFiles\Nmap\nmap.exe")) {
    if (Test-Path $p) { return $p }
  }
  return $null
}

if ($Command -eq "stop") { Stop-All; exit 0 }

# --- .env + tools ------------------------------------------------------------
if (-not (Test-Path ".env")) { Bad ".env missing. Copy .env.example to .env and fill it (docs\WINDOWS_NATIVE.md)."; exit 1 }
Ok ".env found"

# DEV_MODE=1 in .env: dashboard runs "next dev" (live reload, no build).
# DEV_MODE=0 (or missing): production build + node server.js.
$DevMode = ((Read-DotEnv)["DEV_MODE"] -eq "1")
if ($DevMode) { Warn "DEV_MODE=1: dashboard in development mode (file changes show up live)" }

$nmapPath = Find-Nmap
if (-not $nmapPath) {
  Bad "Nmap not found. Install it from https://nmap.org/download (keep 'Npcap' ticked),"
  Bad "or add its location to .env, e.g.  NMAP_PATH=F:\Tools\Nmap\nmap.exe"
  exit 1
}
$env:NMAP_PATH = $nmapPath
Ok "Nmap: $nmapPath"
if (Test-Path "$env:WINDIR\System32\Npcap") { Ok "Npcap installed" }
else { Bad "Npcap missing (needed for ARP / SYN scan / OS detection). Re-run the Nmap installer and tick Npcap."; exit 1 }

if (-not (Get-Command node -ErrorAction SilentlyContinue)) { Bad "Node.js missing. Install Node.js 20 LTS from https://nodejs.org"; exit 1 }
Ok "Node.js $(& node -v)"

if ($Command -eq "update") { Stop-All }

# --- Python environment (.venv) ----------------------------------------------
if (($Command -eq "update") -or -not (Test-Path $Py) -or -not (Test-Path $DepsMark)) {
  if (-not (Test-Path $Py)) {
    $bp = Find-BasePython
    if (-not $bp) { Bad "Python 3.11 not found. Install it from https://www.python.org/downloads/ (tick 'Add python.exe to PATH')."; exit 1 }
    $bpArgs = @($bp | Select-Object -Skip 1)
    Write-Host "-- creating the Python environment (.venv)"
    & $bp[0] @bpArgs -m venv .venv
    if (-not (Test-Path $Py)) { Bad "could not create .venv"; exit 1 }
  }
  Write-Host "-- installing Python packages (first time 5-15 minutes, about 1 GB)"
  & $Py -m pip install --upgrade pip --quiet
  & $Py -m pip install --index-url https://download.pytorch.org/whl/cpu torch==2.3.1
  if ($LASTEXITCODE -ne 0) { Bad "PyTorch install failed (internet?)"; exit 1 }
  & $Py -m pip install -r requirements.txt
  if ($LASTEXITCODE -ne 0) { Bad "Python packages install failed"; exit 1 }
  # optional package (web push): a failure here must not stop the launcher
  & $Py -m pip install -r requirements-push.txt --quiet
  if ($LASTEXITCODE -ne 0) { Warn "pywebpush not installed: push notifications stay off (everything else works)" }
  Set-Content -Path $DepsMark -Value (Get-Date -Format s)
  Ok "Python packages installed"
}
$env:PYTHONUNBUFFERED = "1"

# --- scan tools: Nuclei + NetExec (optional; the scan works without them) --------
$ToolDir = Join-Path $Root "tools"
function Get-GithubAsset($repo, $pattern, $dest) {
  # newest release of github.com/<repo>: download the first asset whose name matches
  try {
    $rel = Invoke-RestMethod -UseBasicParsing -Headers @{ "User-Agent" = "mini-soar" } `
             "https://api.github.com/repos/$repo/releases/latest"
    $asset = $rel.assets | Where-Object { $_.name -match $pattern } | Select-Object -First 1
    if (-not $asset) { Warn "$repo : no release file matching '$pattern'"; return $false }
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    $file = Join-Path $env:TEMP $asset.name
    Invoke-WebRequest -UseBasicParsing -Uri $asset.browser_download_url -OutFile $file
    if ($file -match "\.zip$") { Expand-Archive -Path $file -DestinationPath $dest -Force }
    else { Copy-Item $file $dest -Force }
    Remove-Item $file -Force -ErrorAction SilentlyContinue
    return $true
  } catch { Warn "$repo download failed: $($_.Exception.Message)"; return $false }
}
function Find-Tool($envName, $names, $folder) {
  $envs = Read-DotEnv
  if ($envs.ContainsKey($envName) -and $envs[$envName] -and (Test-Path $envs[$envName])) { return $envs[$envName] }
  foreach ($n in $names) {
    $c = Get-Command $n -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
  }
  if (Test-Path $folder) {
    $f = Get-ChildItem -Path $folder -Recurse -File -ErrorAction SilentlyContinue |
         Where-Object { $names -contains $_.Name } | Select-Object -First 1
    if ($f) { return $f.FullName }
  }
  return $null
}
$nucleiExe = Find-Tool "NUCLEI_PATH" @("nuclei.exe") (Join-Path $ToolDir "nuclei")
if (-not $nucleiExe -and $Command -eq "update") {
  Write-Host "-- downloading Nuclei (template checks: misconfigurations, exposed panels, default logins)"
  if (Get-GithubAsset "projectdiscovery/nuclei" "windows_amd64\.zip$" (Join-Path $ToolDir "nuclei")) {
    $nucleiExe = Find-Tool "NUCLEI_PATH" @("nuclei.exe") (Join-Path $ToolDir "nuclei")
  }
}
if ($nucleiExe) {
  $env:NUCLEI_PATH = $nucleiExe
  if ($Command -eq "update") {
    Write-Host "-- updating Nuclei templates"
    & $nucleiExe -update-templates -silent -duc *> $null
  }
  Ok "Nuclei: $nucleiExe"
} else { Warn "Nuclei not installed: its checks are skipped (.\run.bat update downloads it)" }

$nxcExe = Find-Tool "NETEXEC_PATH" @("nxc.exe", "netexec.exe") (Join-Path $ToolDir "netexec")
if (-not $nxcExe -and $Command -eq "update") {
  Write-Host "-- downloading NetExec (read-only SMB / RDP / WinRM checks)"
  if (Get-GithubAsset "Pennyw0rth/NetExec" "(?i)windows" (Join-Path $ToolDir "netexec")) {
    $nxcExe = Find-Tool "NETEXEC_PATH" @("nxc.exe", "netexec.exe") (Join-Path $ToolDir "netexec")
  }
}
if ($nxcExe) { $env:NETEXEC_PATH = $nxcExe; Ok "NetExec: $nxcExe" }
else { Warn "NetExec not installed: SMB / RDP / WinRM checks are skipped (.\run.bat update downloads it)" }

# --- enroll / check a target -------------------------------------------------
if ($Command -eq "enroll" -or $Command -eq "check") {
  if (-not $Arg1) { Write-Host "usage: .\run.bat $Command <target-ip> [admin-user]"; exit 1 }
  if ($Command -eq "enroll" -and -not (Test-Path "secrets\lab_id_rsa")) {
    Write-Host "-- no engine SSH key yet: creating secrets\lab_id_rsa (RSA, works with old servers too)"
    New-Item -ItemType Directory -Force -Path "secrets" | Out-Null
    & $Py -c "import paramiko; k=paramiko.RSAKey.generate(2048); k.write_private_key_file('secrets/lab_id_rsa'); open('secrets/lab_id_rsa.pub','w').write(k.get_name()+' '+k.get_base64()+' mini-soar-engine\n')"
    if (Test-Path "secrets\lab_id_rsa") { Ok "key created" } else { Bad "could not create the key"; exit 1 }
  }
  if ($Command -eq "check") { & $Py -m soar.enroll $Arg1 --check-only }
  elseif ($Arg2)            { & $Py -m soar.enroll $Arg1 --admin-user $Arg2 }
  else                      { & $Py -m soar.enroll $Arg1 }
  exit $LASTEXITCODE
}

# --- one-off tools (no services needed) ---------------------------------------
if ($Command -eq "test") {
  & $Py -c "import pytest" 2>$null
  if ($LASTEXITCODE -ne 0) {
    Write-Host "-- installing the test tools (pytest)"
    & $Py -m pip install -r requirements-dev.txt --quiet
  }
  & $Py -m pytest
  exit $LASTEXITCODE
}
if ($Command -eq "train") { & $Py -m ml.train; exit $LASTEXITCODE }
if ($Command -eq "totp-reset") {
  if (-not $Arg1) { Write-Host "usage: .\run.bat totp-reset <email>"; exit 1 }
  & $Py -m soar.totp_2fa reset $Arg1
  exit $LASTEXITCODE
}

# --- dashboard build (Next.js standalone) ------------------------------------
if ($DevMode) {
  if (($Command -eq "update") -or -not (Test-Path (Join-Path $Dash "node_modules"))) {
    Push-Location $Dash
    & npm install --no-audit --no-fund
    $rc = $LASTEXITCODE
    Pop-Location
    if ($rc -ne 0) { Bad "npm install failed (internet?)"; exit 1 }
  }
  Ok "dev mode: dashboard build skipped"
}
elseif (($Command -eq "update") -or -not (Test-Path (Join-Path $DashOut "server.js"))) {
  Write-Host "-- building the dashboard (first time 5-10 minutes)"
  $envs = Read-DotEnv
  # NEXT_PUBLIC_* values are baked into the browser bundle at build time
  foreach ($k in @("NEXT_PUBLIC_SUPABASE_URL", "NEXT_PUBLIC_SUPABASE_ANON_KEY", "NEXT_PUBLIC_API_URL", "NEXT_PUBLIC_VAPID_PUBLIC_KEY")) {
    if ($envs.ContainsKey($k) -and $envs[$k]) { Set-Item -Path "env:$k" -Value $envs[$k] }
  }
  $env:NEXT_TELEMETRY_DISABLED = "1"
  Push-Location $Dash
  & npm install --no-audit --no-fund
  if ($LASTEXITCODE -ne 0) { Pop-Location; Bad "npm install failed (internet?)"; exit 1 }
  & npm run build
  $rc = $LASTEXITCODE
  Pop-Location
  if ($rc -ne 0) { Bad "dashboard build failed"; exit 1 }
  # standalone server needs public\ and .next\static next to it
  Remove-Item -Recurse -Force (Join-Path $DashOut "public") -ErrorAction SilentlyContinue
  Remove-Item -Recurse -Force (Join-Path $DashOut ".next\static") -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Force -Path (Join-Path $DashOut ".next") | Out-Null
  Copy-Item -Recurse -Force (Join-Path $Dash "public") (Join-Path $DashOut "public")
  Copy-Item -Recurse -Force (Join-Path $Dash ".next\static") (Join-Path $DashOut ".next\static")
  Ok "dashboard built"
}

# --- start the services ------------------------------------------------------
New-Item -ItemType Directory -Force -Path $LogDir, $PidDir | Out-Null

function Start-PySvc($name, [string[]]$modArgs) {
  if (Get-SvcPid $name) { Ok "$name already running"; return }
  $p = Start-Process -FilePath $Py -ArgumentList (@("-m", "common.svc", $name) + $modArgs) `
         -WorkingDirectory $Root -WindowStyle Hidden -PassThru
  Set-Content -Path (Join-Path $PidDir "$name.pid") -Value $p.Id
  Ok "$name started (log: logs\$name.log)"
}

Start-PySvc "api"      @("uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000")
Start-PySvc "soar"     @("soar.worker")

if (Get-SvcPid "dashboard") { Ok "dashboard already running" }
elseif ($DevMode) {
  Stop-StrayDashboard
  # run Next.js with node directly (not through npm.cmd): then the saved PID is
  # the dashboard itself, so "run.bat stop" can stop it
  $NextBin = Join-Path $Dash "node_modules\next\dist\bin\next"
  if (-not (Test-Path $NextBin)) { Bad "Next.js not installed in dashboard\node_modules: run .\run.bat update"; exit 1 }
  $envs = Read-DotEnv
  foreach ($k in @("NEXT_PUBLIC_SUPABASE_URL", "NEXT_PUBLIC_SUPABASE_ANON_KEY", "NEXT_PUBLIC_API_URL", "NEXT_PUBLIC_VAPID_PUBLIC_KEY")) {
    if ($envs.ContainsKey($k) -and $envs[$k]) { Set-Item -Path "env:$k" -Value $envs[$k] }
  }
  $env:NEXT_TELEMETRY_DISABLED = "1"; $env:NODE_ENV = "development"
  $p = Start-Process -FilePath "node" -ArgumentList @("`"$NextBin`"", "dev", "-H", "0.0.0.0", "-p", "3000") `
         -WorkingDirectory $Dash -WindowStyle Hidden `
         -RedirectStandardOutput (Join-Path $LogDir "dashboard.log") `
         -RedirectStandardError (Join-Path $LogDir "dashboard.err.log") -PassThru
  Set-Content -Path (Join-Path $PidDir "dashboard.pid") -Value $p.Id
  Ok "dashboard started in DEV mode (log: logs\dashboard.log)"
}
else {
  Stop-StrayDashboard
  $env:HOSTNAME = "0.0.0.0"; $env:PORT = "3000"; $env:NODE_ENV = "production"
  $p = Start-Process -FilePath "node" -ArgumentList "server.js" -WorkingDirectory $DashOut -WindowStyle Hidden `
         -RedirectStandardOutput (Join-Path $LogDir "dashboard.log") `
         -RedirectStandardError (Join-Path $LogDir "dashboard.err.log") -PassThru
  Set-Content -Path (Join-Path $PidDir "dashboard.pid") -Value $p.Id
  Ok "dashboard started (log: logs\dashboard.log)"
}

$healthy = $false
for ($i = 0; $i -lt 60; $i++) {
  try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 "http://localhost:8000/health" | Out-Null; $healthy = $true; break }
  catch { Start-Sleep 1 }
}
if ($healthy) { Ok "API healthy" } else { Bad "API not answering (.\run.bat logs api)" }

& $Py -m scanner.cli show-scope | Select-Object -First 11

function Invoke-Scan {
  if ($Arg1) {
    Write-Host "-- scanning $Arg1"
    & $Py -m scanner.cli scan --targets $Arg1
  } else {
    Write-Host "-- scanning the whole authorized scope (a few minutes)"
    & $Py -m scanner.cli scan
  }
}

if ($Command -eq "update") {
  Write-Host "-- syncing CVE data: CISA KEV, EPSS, and CVEs for the software found in the lab"
  & $Py -m intel.cli sync-lab
  Write-Host "-- ML risk model (trained once, about a minute)"
  & $Py -m ml.train --if-missing
}

if ($Command -eq "scan" -or $Command -eq "update") {
  Invoke-Scan
  if ($Command -eq "update") {
    # software seen for the first time has no CVE data yet: fetch it, scan again
    & $Py -m intel.cli sync-new
    if ($LASTEXITCODE -eq 0) {
      Write-Host "-- new CVE data arrived for software found by the scan: scanning once more"
      Invoke-Scan
    }
  }
}

Write-Host ""
Write-Host "Dashboard: http://localhost:3000" -ForegroundColor Cyan
Write-Host "Stop everything: .\run.bat stop"
