# Mini-SOAR — Network Vulnerability Management & Auto-Remediation Platform (CAASM)

A **defensive** security platform for an **authorized VirtualBox lab**. It
discovers hosts, checks them with Nmap, Nuclei and NetExec, matches CVEs offline, prioritizes with EPSS + CISA KEV,
scores risk with an explainable ML model, ranks fixes by component dependencies, and safely
auto-remediates over SSH — behind a strict safety gate (allowlist → dry-run →
admin approval → TOTP 2FA → rollback → re-scan verify).

> ⚠️ **Scope & ethics.** Every active feature (scanning, default-credential
> checks, SSH remediation) is hard-restricted in code to the CIDR ranges in
> `ALLOWED_RANGES`. The engine refuses to run unless `AUTHORIZED_LAB_ONLY=true`.
> Only ever point this at a lab **you own and are authorized to test**.

---

## 🪟 Quick start on Windows only (Docker Desktop, no Kali)

```powershell
cd "F:\University\FYP MINI SOAR\mini-soar"
copy .env.example .env      # fill it; set NETWORK_MODE=nat, ENGINE_HOST_IPS=192.168.103.1/24
.\run.bat update            # build + CVE sync + scan
.\run.bat enroll 192.168.103.105 msfadmin
```
Dashboard: http://localhost:3000. Full guide and the differences (TCP connect
scan, OS from banners, no MAC) are in **docs/WINDOWS_ENGINE.md**.

## 🪟 Windows without Docker — full scan like Kali (`NETWORK_MODE=native`)

Install once: Python 3.11, Nmap for Windows (with Npcap), Node.js 20 LTS. Then:
```powershell
cd "F:\University\FYP MINI SOAR\mini-soar"
# .env: NETWORK_MODE=native, ALLOWED_RANGES=192.168.56.0/24, DENY_HOSTS=192.168.56.1
.\run.bat update            # asks for Administrator, installs, builds, CVE sync + scan
```
ARP + MAC, SYN scan and nmap OS detection all work. Guide: **docs/WINDOWS_NATIVE.md**.

## ⚡ Quick start on a Kali / Linux VM

The engine (scanner, SOAR worker, API) runs with the host's network so it can
see the VirtualBox Host-only lab directly. Run it inside a Linux VM (e.g. Kali)
with **Adapter 1 = NAT** (internet/Supabase) and **Adapter 2 = Host-only** (lab).

```bash
sudo apt update && sudo apt install -y docker.io docker-compose
sudo systemctl enable --now docker && sudo usermod -aG docker $USER   # then reboot
cd mini-soar && chmod +x run.sh
cp .env.example .env && nano .env      # fill in keys, IPs, Supabase values
./run.sh
```
Open the dashboard from Windows at `http://<Kali-lab-IP>:3000` and sign in with
the user you created in Supabase → Authentication → Users.

---

## Tests

```
.\run.bat test                                  # Windows native mode
.venv\Scripts\python -m pytest                  # or directly (pip install -r requirements-dev.txt first)
```

485 automated test cases in `tests/` cover every module and the full flow
(scan → Nuclei/NetExec → tickets → Fix Impact Preview → approve with 2FA → fix over SSH →
verify → re-scan → prediction checked → closed).
They never read the real `.env`, never contact the real Supabase project and only
connect to 127.0.0.1. Results: `docs/TEST_RESULTS.md`. Live-lab checks: `docs/LAB_CHECKLIST.md`.

**After updating to v14:** run `supabase/migrations/006_proposal_alignment.sql` once in the
Supabase SQL Editor, then `.\run.bat update` (downloads Nuclei + NetExec), then sign in to the
dashboard again. Details: `docs/CHANGELOG.md`.

## Contents
1. [Architecture](#architecture)
2. [Feature checklist (18)](#feature-checklist-18)
3. [Prerequisites](#prerequisites)
4. [Part A — Build the isolated lab (VirtualBox + Metasploitable 2)](#part-a--build-the-isolated-lab)
5. [Part B — Supabase (cloud)](#part-b--supabase-cloud)
6. [Part C — Configure `.env`](#part-c--configure-env)
7. [Part D — Run it](#part-d--run-it)
8. [Part E — Step-by-step testing guide (Metasploitable 2)](#part-e--step-by-step-testing-guide-metasploitable-2)
9. [Deploy the dashboard to Vercel](#deploy-the-dashboard-to-vercel)
10. [Safety model](#safety-model)
11. [Project structure](#project-structure)
12. [Troubleshooting](#troubleshooting)

---

## Architecture

```
 Lab (VirtualBox Host-Only 192.168.56.0/24)        On-prem engine (Docker)                 Cloud (Supabase)        Browser
 ┌───────────────────────────────┐   scan    ┌──────────────────────────────┐  AES+HMAC  ┌────────────────┐   realtime  ┌───────────────┐
 │ Metasploitable2  Ubuntu  ...  │◀─────────▶│ scanner · intel · ml · soar  │───────────▶│ Postgres + RLS │◀───────────▶│ Next.js       │
 │ (targets, you authorize)      │  SSH fix  │ nuclei · netexec · FastAPI    │            │ Auth (RBAC)    │             │ dashboard     │
 └───────────────────────────────┘           └──────────────────────────────┘            │ Realtime       │             │ (Vercel)      │
                                               │ syslog → Wazuh/ELK                         └────────────────┘             └───────────────┘
```

(See the workflow/architecture diagram delivered alongside this project.)

---

## Feature checklist (final proposal)

**1 Discovery and scanning** — host discovery (Scapy ARP), port / service / OS detection
(Nmap), template-based misconfiguration, exposed-panel and default-login checks (**Nuclei**,
non-intrusive), read-only Windows SMB / RDP / WinRM posture checks (**NetExec**), and
default-credential checks. All findings share one format.
**2 Vulnerability intelligence** — offline CVE matching (NVD in SQLite) with EPSS + CISA KEV
prioritization (KEV → EPSS → CVSS), plus a CVE watch-list.
**3 Risk analysis** — explainable PyTorch risk score (findings without a CVE are mapped to the
same inputs), and **dependency-based patch prioritization** with a **Fix Impact Preview**
(method of Jiang et al. 2024, without a digital twin; see `docs/PATCH_PRIORITIZATION.md`).
**4 Safe auto-remediation** — SSH fixes with dry-run, admin approval, TOTP 2FA (each code works
once), a stored rollback, a post-fix check on the host, and the next scan checking the
predicted impact.
**5 Threat monitoring and security** — rogue-device and change detection, TLS certificate
checking, and a tamper-evident hash-chained audit log.
**6 Workflow and reporting** — SLA ticketing with escalation, a dark-mode dashboard with
real-time topology and PWA push notifications, a PDF report (+ MITRE ATT&CK mapping), and
syslog forwarding to a SIEM.

---

## Prerequisites

- **Docker Desktop** (Windows/macOS) or Docker Engine + Compose (Linux)
- **VirtualBox** (for the lab VMs)
- A free **Supabase** account (cloud DB/auth/realtime) — optional for a quick
  offline demo, required for the full dashboard experience
- ~8 GB RAM (16 GB comfortable), ~20 GB disk

Optional free API key: NVD (faster CVE sync). Nuclei and NetExec are free/open-source; the
Docker image includes them and `run.bat update` downloads them on Windows.

---

## Part A — Build the isolated lab

**The golden rule: the lab VMs use a Host-Only adapter so nothing can reach your
real network or the internet.**

1. **Create a Host-Only network** in VirtualBox:
   *File → Host Network Manager → Create*. Note its range (default
   `192.168.56.0/24`, host at `192.168.56.1`).

2. **Metasploitable 2** (the vulnerable target):
   - Download the official image, import/extract it into VirtualBox.
   - VM → *Settings → Network → Adapter 1 → Host-Only Adapter* (select the one
     from step 1). **Disable every other adapter (no NAT, no Bridged).**
   - Boot it. Log in `msfadmin` / `msfadmin`. Run `ifconfig` and note its IP
     (e.g. `192.168.56.101`).

3. **(Optional) Ubuntu Server VM** — a clean target to demo SSH remediation:
   - Adapter 1 = Host-Only. Install `openssh-server` and, for the demo,
     `telnetd` (so there's a risky service to turn off).
   - Create a key the SOAR engine will use to connect, and give its user
     password-less `sudo` for the specific fix commands (lab convenience).

4. **Take a snapshot** of each target VM now (*Machine → Take Snapshot*). After
   a remediation test you can restore in one click.

5. **Where does the engine run?** Docker Desktop on Windows can't send raw
   ARP packets. Two options:
   - **Simplest:** run Docker inside an **Ubuntu "scanner" VM** that has **two**
     adapters — Adapter 1 Host-Only (to see the lab) and Adapter 2 NAT (so it
     can reach Supabase). Clone this repo there and run `./run.sh`.
   - **Windows-direct:** run everything in Docker Desktop with
     `docker-compose.windows.yml` (`run.bat` / `start.ps1`, `NETWORK_MODE=nat`):
     TCP connect scans, OS guessed from banners, no ARP/MAC. See
     docs/WINDOWS_ENGINE.md.

---

## Part B — Supabase (cloud)

1. Create a project at <https://supabase.com> (free tier).
2. Open **SQL Editor**, paste the contents of **`supabase/schema.sql`**, Run.
   This creates all tables, RLS policies, indexes, the realtime publication, and
   a trigger that makes the **first** user who signs up an **admin**.
3. **Project Settings → API**: copy the **Project URL**, the **anon** key, and
   the **service_role** key. **Settings → Database**: copy the connection string.
4. **Authentication → Users**: add yourself (email/password). You become admin.

---

## Part C — Configure `.env`

```bash
cp .env.example .env
```
Fill in, at minimum:
- `ALLOWED_RANGES=192.168.56.0/24` and `AUTHORIZED_LAB_ONLY=true`
- `AES_KEY_B64` — `python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"`
- `HMAC_KEY` — `python -c "import secrets;print(secrets.token_hex(32))"`
- `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY`, `SUPABASE_DB_URL`
- `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`, `NEXT_PUBLIC_API_URL`
- For SSH remediation: put the lab private key at `./secrets/lab_id_ed25519` and
  set `SSH_USERNAME`. Keep `FORCE_DRY_RUN=true` until you've watched a dry-run.

---

## Part D — Run it

**Windows:** `run.bat` (wraps `start.ps1`, uses `docker-compose.windows.yml`).  **Linux/macOS:** `./run.sh` or `./start.sh`.

It checks Docker, creates `.env` if missing, builds the containers, offers to
sync the CVE intel + train the ML model, starts everything, and opens the
dashboard.

Manual equivalent:
```bash
docker compose build
docker compose run --rm api python -m intel.cli init
docker compose run --rm api python -m intel.cli sync-all   # NVD + EPSS + KEV
docker compose run --rm api python -m ml.train             # train risk model
docker compose up -d --remove-orphans api soar dashboard
```
- Dashboard → <http://localhost:3000>
- API health → <http://localhost:8000/health>

Until the ML model is trained, scoring uses a transparent fallback — everything
still works.

---

## Part E — Step-by-step testing guide (Metasploitable 2)

This is the end-to-end demo you can show for your FYP. Metasploitable 2 is
`192.168.56.101` in these steps — use your actual IP.

### 0. Pre-flight — prove the safety gate
```bash
docker compose run --rm scanner show-scope
```
Expected: `Authorization gate: PASS`, and your scope listed. Now prove it
**refuses the internet** — temporarily try an out-of-scope target:
```bash
docker compose run --rm scanner scan --targets 8.8.8.8
```
Expected: `8.8.8.8` is rejected (scope.reject in the audit log) and nothing is
scanned. **This is your headline safety proof.**

### 1. Discover + scan the lab
```bash
docker compose run --rm scanner scan --scope env
```
or click **Run scan** (top-right) in the dashboard.
- **Assets** page: `192.168.56.101` appears, OS guessed "Linux 2.6.x",
  many open ports (21, 22, 23, 25, 80, 139, 445, 3306, 5432, …).
- Because it wasn't pre-authorized, it's flagged **rogue** on first sight.

### 2. See CVEs, EPSS and KEV
- **Vulnerabilities** page: findings for vsftpd 2.3.4, UnrealIRCd, Samba, etc.
  vsftpd 2.3.4 (**CVE-2011-2523**) should carry a high EPSS and a **KEV** badge.
- Click a row → **"explain"** shows the ML risk breakdown
  (e.g. *"Listed on CISA KEV (+…)", "Service still uses a default credential (+…)"*).

### 3. Default-credential + TLS findings
- The scanner tests a tiny set of documented defaults. On Metasploitable 2 it
  flags **FTP/SSH** accepting `msfadmin` / `msfadmin` → the service shows a
  default-cred flag and a high score.
- **TLS Certs** page lists any self-signed/expired certs it found.

### 4. Tickets + SLA
- **Tickets** page: critical/KEV findings auto-open tickets with SLA timers.
  A critical ticket is due in 24 h; if you fast-forward the clock (or edit
  `sla_due_at`), a re-scan marks it **escalated** and raises an alert.

### 5. Patch prioritization + Fix Impact Preview
- **Patch Prioritization** page: the ranked fixes, with the biggest drop in network risk first
  (component risk CRS = criticality × vulnerability score). Next to it is the paper's own
  CVSS-only ranking for comparison. Set an asset's **Importance** on the Assets page and watch
  the ranking change.
- Press **Preview** on a ranked fix (or type your own, e.g. `block_port 21`). The Fix Impact
  Preview shows host and network risk before → after, without changing anything.
- **Topology** page: hosts → OS + services → dependencies, live while a scan runs.

### 6. Safe remediation (the SOAR flow) — best on the Ubuntu VM
Demo turning off a risky **telnet** service with the full gate:
1. Enroll TOTP: **Settings → Enroll TOTP 2FA**, scan the QR in Google
   Authenticator.
2. Create a remediation (via API or the ticket) `stop_service { "service": "telnetd" }`
   or `block_port { "port": 23 }` for the target.
3. **Remediation** page → **Review**: read the exact **dry-run** commands, the stored
   **rollback** commands and the **Fix Impact Preview**. Nothing has run yet.
4. Set `FORCE_DRY_RUN=false` in `.env`, restart the `soar`/`api` services.
5. Enter a fresh **TOTP code** → **Approve & arm** (you must be signed in as an admin).
6. The worker executes over SSH, then **re-scans**: the remediation shows
   **verified ✓** and the ticket flips to **resolved**.
7. Need to undo? The rollback plan re-enables the service.

### 7. Nuclei + NetExec findings
- **Vulnerabilities** page → filter "Nuclei" / "NetExec". On Metasploitable 2, NetExec reports
  **SMBv1 enabled** and **SMB signing not required** on Samba (445), and Nuclei reports
  default logins and exposed panels (e.g. Tomcat on 8180).
- Each one gets a ticket with a suggested fix, appears as a finding of its port component in
  Patch Prioritization, and is shown in the PDF report with its tool.

### 8. Tamper-evident audit + report
- **Audit Log** page: every action is chained; the banner shows **"Hash chain
  intact"**. (Try editing a row directly in Supabase → it flips to "tampering
  detected".)
- **Reports** page: **Download latest PDF** — inventory, prioritized findings,
  grade, and the **MITRE ATT&CK** mapping.

### 9. SIEM (optional)
- Point `SYSLOG_HOST`/`PORT` at a Wazuh/ELK instance; scans, Nuclei/NetExec alerts and
  remediations are forwarded as syslog events.

---

## Deploy the dashboard to Vercel

The dashboard is a standard Next.js app. Import the `dashboard/` folder in
Vercel, set `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`,
`NEXT_PUBLIC_API_URL` (a tunnel to your local gateway, e.g. ngrok/cloudflared)
and `NEXT_PUBLIC_VAPID_PUBLIC_KEY`, and deploy. The engine/API stay on your lab
machine; only the UI is public.

---

## Safety model

| Gate | Where | Effect |
|------|-------|--------|
| Authorization | `common/config.assert_authorized_to_run` | Refuses to run unless `AUTHORIZED_LAB_ONLY=true` + scope set |
| API login | `common/auth` | Every action needs the dashboard login; role (viewer < analyst < admin) comes from the token |
| Non-intrusive tools | `scanner/nuclei_scan`, `scanner/netexec_check` | Nuclei without dos/fuzz/intrusive/OAST; NetExec read-only allow-list |
| Allowlist | `common/allowlist` | Every target filtered; out-of-scope dropped & audited |
| Dry-run | `soar/remediation.dry_run` | Exact commands shown before anything runs |
| Approval | `soar/approval` + DB RLS | Only an **admin** can arm a remediation |
| 2FA | `soar/totp_2fa` | Fresh TOTP required at approval; each code works once |
| Kill-switch | `FORCE_DRY_RUN` | Forces preview-only, globally |
| Rollback | stored `rollback_plan` | Every change is undoable |
| Audit | `common/audit` hash chain | Tamper-evident log of every action |

---

## Project structure

```
mini-soar/
├── run.bat / run.sh            one-command launcher
├── docker-compose.yml          scanner · soar · api · dashboard
├── .env.example                all configuration (copy to .env)
├── supabase/schema.sql         tables + RLS + indexes
├── common/                     config, allowlist guard, API login check, crypto, audit, db, syslog
├── scanner/                    discovery, port/service, nuclei, netexec, default-creds, tls, uplink, cli
├── intel/                      NVD/EPSS/KEV sync + CVE matching
├── ml/                         features, synthetic data, PyTorch model, train, scoring,
│                               mapping of findings without a CVE
├── soar/                       remediation, approval, totp, worker, verify, ticketing,
│                               patch prioritization + Fix Impact Preview
├── api/                        FastAPI gateway
├── reports/                    PDF report + MITRE ATT&CK mapping
└── dashboard/                  Next.js (App Router) + Tailwind + Cytoscape + PWA
```

---

## Troubleshooting

- **"Refusing to run: AUTHORIZED_LAB_ONLY…"** — set it to `true` and define
  `ALLOWED_RANGES` in `.env`. This is the safety gate doing its job.
- **No hosts found on Windows** — Docker Desktop can't ARP-sweep; run the engine
  in an Ubuntu VM (Part A step 5) or pass `--targets` explicitly.
- **Dashboard shows "Supabase not configured"** — fill the `NEXT_PUBLIC_*`
  values and rebuild the dashboard container.
- **Remediation refused** — expected unless it's admin-approved **and**
  TOTP-verified **and** `FORCE_DRY_RUN=false`.
- **CVE matches look sparse** — run `intel sync-all`; matching is best-effort on
  nmap's product/version output.

---

*Built as a final-year project. Defensive, lab-scoped, free/open-source.*

## v2 upgrade (existing installs)

1. Supabase → SQL Editor → run `supabase/migrations/002_v2_fixes.sql`.
2. `docker compose build && docker compose up -d`
3. `docker compose run --rm --entrypoint python api -m intel.cli sync-cpe`
4. Run one scan.
5. Remediation demo: see `docs/REMEDIATION_SETUP.md`.

## v3: Windows targets
Auto-remediation now supports Windows 10/11 and Windows Server (OpenSSH + PowerShell).
Setup and demo: `docs/WINDOWS_SETUP.md`. Rebuild after updating: `docker compose build && docker compose up -d`.
