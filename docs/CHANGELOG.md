# Mini-SOAR — Change log

Every change made to the project, newest first, in simple words. Each entry says
**what changed**, **which files**, **why**, and **what it means for you**.

---

## v11 — IP on CVE tickets, push package clash fixed (16 Nov 2026)

**In one line:** CVE ticket titles now show which machine they are on, and the push
package no longer fights with the rest of the project over the `cryptography` version.

| # | What changed | Files | Why / what it means for you |
|---|---|---|---|
| 1 | CVE ticket titles end with the host IP, like the other tickets: `CVE-2007-2446 on netbios-ssn:445 (192.168.56.101)` | `soar/ticketing.py`, `tests/test_soar_flow.py` | With more than one target you can see at a glance which host a CVE ticket belongs to. Only **new** tickets get the new title; existing ones keep their old title (no duplicates are created, tickets are matched by vulnerability, not by title). |
| 2 | `requirements-push.txt` now pins `py-vapid==1.9.2` and `cryptography==42.0.8` | `requirements-push.txt` | The newest `py-vapid` (1.9.6) needs `cryptography` 46+, but the project pins 42.0.8. pip kept swapping versions and printed a dependency error on `run.bat test`. The older `py-vapid` works with 42.0.8, so nothing else changes. Push is still optional. |

**To apply:** `.\run.bat stop`, `.\run.bat update`, `.\run.bat test`.

---

## v10 — Tested, fixed, and brought in line with the proposal (15 Nov 2026)

**In one line:** the project now has an automated test suite (421 test cases), eight
real bugs found by it are fixed, and the five proposal features that were missing or
half-done are finished.

### A. Bugs found by the tests and fixed

| # | What was wrong | Files | What it means for you |
|---|---|---|---|
| 1 | **A failed scan closed tickets.** When nmap timed out on a host it came back with "0 open ports", and the system believed everything was fixed (13 Nov: 46 CVE tickets + 20 host tickets closed). | `scanner/port_scan.py`, `scanner/engine.py`, `scanner/uplink.py`, `soar/ticketing.py` | A host whose port scan failed or timed out is now marked `scan_ok = false`. Nothing is closed, resolved or re-graded for it, and you get a notification "Scan of a host did not finish". The per-host timeout is now 300 s (`SCAN_HOST_TIMEOUT` in `.env`). |
| 2 | **The SSH honeypot recorded nothing.** Its server class was not a real paramiko server, so every login attempt crashed the connection before the password was seen. | `honeypot/ssh_honeypot.py` | Fake SSH now records every username + password and always refuses. Proven with a real SSH client in the tests. |
| 3 | **HTTP default-password check never fired.** A normal "200 OK" was always skipped. | `scanner/default_creds.py` | It now first checks that the page really asks for a password (401 + Basic), then tries the 7 default pairs. A public website is never reported. |
| 4 | **CVE matching: "fixed in 2.2.8" still matched 2.2.8.** "Before version X" was treated like "up to and including X". | `intel/match.py`, `intel/sync_nvd.py`, `intel/db_init.py` | No more false positives on the fixed version. |
| 5 | **CVE matching missed OpenSSH 4.7p1 and similar.** "4.7p1" was read as 4.7.1. Letter versions (OpenSSL 1.0.2g vs 1.0.2k) were not ordered. | `intel/match.py` | `4.7p1` is 4.7; `1.0.2g` < `1.0.2h` < `1.0.2k`. |
| 6 | **Unknown version = "confirmed".** A service with no version was reported as a confirmed match (and got tickets). | `intel/match.py` | It is now "version-unconfirmed" (shown, no ticket), as the design said. |
| 7 | **PDF report: MITRE mapping was almost empty** (services were never passed to it) and remediated findings were counted as open. | `reports/pdf_report.py` | The report now maps default passwords, telnet, FTP, SSH, databases, KEV and rogue devices to ATT&CK, counts only open findings, and has an Assets table with grades. |
| 8 | **Score reasons doubled** every time a host was scored again. | `ml/risk_score.py` | Reasons are rebuilt each time. |

### B. Proposal features that were missing or half-done

| # | Feature (proposal) | What was added | Files |
|---|---|---|---|
| 1 | **Risk-trend tracking** | After every scan one risk point per host and one for the whole network is saved. The Overview chart now shows real risk (0-100) and open findings over time. | `scanner/uplink.py`, table `risk_history`, `dashboard/app/dashboard/page.tsx` |
| 2 | **CVE watchlist** | Add / remove CVE IDs on the Vulnerabilities page. A watched CVE found by a scan raises an alert and always gets a ticket. | `dashboard/app/vulnerabilities/page.tsx`, `intel/match.py`, `scanner/uplink.py`, `soar/ticketing.py` |
| 3 | **PWA push notifications** | The engine now really sends a web push for medium / high / critical notifications to every subscribed browser. Needs VAPID keys (`python -m common.webpush gen-keys`). | `common/webpush.py`, `common/notify.py` (new) |
| 4 | **Change detection** | New device, port opened, port closed (was the only one before), port reopened, software version changed. Shown in "Recent changes" on the Overview page. | `scanner/uplink.py`, table `asset_changes` |
| 5 | **HMAC-signed results** | The signature was written but never checked. Stored scan bundles are now verified when read back; the Audit page and `scanner.cli verify-bundles` show the result. | `scanner/uplink.py`, `common/crypto.py`, `api/main.py` |
| 6 | **Tests + test results** | `tests/` (14 files), `docs/TEST_RESULTS.md`, `docs/LAB_CHECKLIST.md`. | new |

### C. Other improvements

* **Honeypot:** any touch from inside the lab now raises an alert (reputation `internal`);
  private addresses are never sent to AbuseIPDB / OTX; one alert per source every 5 minutes
  (every attempt is still stored); the HTTP decoy also records HEAD/PUT/DELETE/OPTIONS and
  cannot be crashed by a wrong or huge Content-Length.
* **2FA:** replacing an existing 2FA setup now needs a current code (before, anyone who could
  reach the API could replace an admin's second factor). Lost phone: `run.bat totp-reset <email>`.
* **Launcher:** `run.bat update` now also downloads CISA KEV + EPSS, trains the ML model if it
  is missing, and fetches CVEs for software seen for the first time (then scans once more).
  New commands: `run.bat test`, `run.bat train`, `run.bat totp-reset <email>`.
* **Settings page:** new "Engine status" card (trained model or formula, CVE / KEV / EPSS counts,
  push ready or not), so the demo never claims more than is true.
* **One notification helper** (`common/notify.py`) replaces four copies of the same code.
* `.env.example` added (every setting explained, no values).

### D. What you must do once

1. **Supabase → SQL Editor:** run `supabase/migrations/004_trend_changes.sql`
   (tables `risk_history` and `asset_changes`). Until then scans still work; the trend chart
   and the changes list stay empty.
2. `.\run.bat update` (installs the optional `pywebpush` package, downloads KEV + EPSS, trains the model, scans).
3. `.\run.bat test` and write the result into `docs/TEST_RESULTS.md`.
4. Optional push: `.venv\Scripts\python -m common.webpush gen-keys`, put the three lines in
   `.env`, restart, then Settings → "Enable push on this device".
5. Go through `docs/LAB_CHECKLIST.md` on the live lab.

### E. Honest limits (say them in the viva)

* The test suite proves the logic and the protocols (real SSH, HTTP and TLS on loopback). It does
  **not** replace the live-lab checklist: real nmap + Npcap, real Metasploitable and real
  Supabase were not available where the tests were written.
* Web push was tested with a stand-in for the `pywebpush` package, not with a real browser.
* The PowerShell launcher changes could not be run here (no PowerShell).
* The API still trusts the `admin_user_id` sent by the browser for approvals (the 2FA code is the
  real gate). Checking the Supabase login token in the API is future work.

---

## v9 — Windows without Docker, full scan ("native" mode) (13 Nov 2026)

**In one line:** with `NETWORK_MODE=native` the whole project runs directly on Windows
(Python + Nmap/Npcap + Node.js), no Docker, and the scan is as complete as on Kali.

**Why:** in v8 (Docker Desktop) the engine sat inside a box behind Windows' NAT, so ARP,
MAC addresses, SYN scan and nmap OS detection were not possible. The Windows PC itself is on
the VirtualBox Host-only network, so running the engine directly on Windows removes that limit.

| # | File | What changed | Why |
|---|---|---|---|
| 1 | `common/netmode.py` | New mode `native`; `nmap_scanner()` also finds `nmap.exe` (PATH, `NMAP_PATH`, Program Files) | python-nmap only looked for Linux paths |
| 2 | `common/filelock.py` (new) | One lock helper for Linux (`fcntl`) and Windows (`msvcrt`) | "One scan at a time" and the audit chain lock did nothing on Windows |
| 3 | `common/audit.py`, `scanner/engine.py` | Use the new lock | Same safety on both systems |
| 4 | `common/scope_store.py` | Reads Windows adapters with PowerShell `Get-NetIPAddress` (skips loopback, 169.254.x.x, WSL/Hyper-V) | The engine's own IPs are always denied and shown on Settings |
| 5 | `scanner/discovery.py`, `scanner/port_scan.py` | Windows: discovery by `nmap -sn` (ARP + MAC via Npcap) instead of scapy; nmap found via the new helper | scapy would send on the Wi-Fi adapter |
| 6 | `common/svc.py` (new) | Runs a service with all its output in `logs\<name>.log` | No Docker to collect logs |
| 7 | `start-native.ps1` (new), `start.ps1` | `start.ps1` hands over to `start-native.ps1` when `.env` says `native`: asks for Administrator, checks Python/Nmap/Npcap/Node, creates `.venv`, builds the dashboard, starts api/soar/honeypot/dashboard in the background, `stop`/`logs`/`scan`/`enroll`/`check` | Same commands as before (`run.bat ...`) |
| 8 | `.env.example`, `docs/WINDOWS_NATIVE.md` (new), `.gitignore` (`logs/`) | New setting explained, full guide | |

**Proposal impact:** none removed; on Windows the scan is now equal to the Kali scan.
**Tested here:** Python compiles; lock (2 processes, busy + wait), audit chain with 6 parallel
writers (180 entries intact), Windows adapter parsing, mode switch; both PowerShell scripts parse
(PowerShell 7) and the mode hand-over works. **Not yet tested:** a real Windows PC (Npcap, nmap.exe,
Administrator window, dashboard build with npm on Windows).

---

## v8 — Run the whole engine on Windows (12 Nov 2026)

**In one line:** Mini-SOAR now runs on Windows with Docker Desktop. Kali is no longer
needed; VirtualBox only runs the lab targets (Metasploitable).

**Why:** using Kali for the engine was slow and hard (terminal, internet, copying files).
On Windows the dashboard, scans and fixes all run on one machine.

**The problem we had to solve:** on Kali the engine was plugged straight into the lab
network ("host networking"). Docker Desktop on Windows cannot do that: containers reach the
lab through Windows (NAT), and only normal TCP connections pass. ARP, SYN scans and nmap OS
detection need raw packets, so they do not work there.

| # | File | What changed | Why |
|---|---|---|---|
| 1 | `docker-compose.windows.yml` (new) | Windows version of the Docker setup: no host networking, API published on port 8000, `data/` and `audit/` stored in Docker volumes (`minisoar-data`, `minisoar-audit`), `secrets/` mounted read-only, `NETWORK_MODE=nat` forced | Docker Desktop has no host networking; SQLite and the audit file lock are not reliable on a Windows folder |
| 2 | `common/netmode.py` (new) | Two settings: `NETWORK_MODE` (`host` = Kali/Linux, `nat` = Windows) and `ENGINE_HOST_IPS` (this PC's lab IP, e.g. `192.168.103.1/24`) | The code needs to know where it runs |
| 3 | `scanner/discovery.py` | In `nat` mode: no ARP sweep; live hosts found by trying TCP connections on common ports (21, 22, 23, 25, 80, 139, 445, 3389 …) | ARP cannot pass through Windows NAT |
| 4 | `scanner/port_scan.py` | In `nat` mode: `-sT` connect scan instead of `-sS`, no `-O`; new helper guesses the OS from service banners/CPEs (e.g. "Linux - Ubuntu (from service banners)") | Raw SYN packets and OS fingerprinting need raw sockets |
| 5 | `common/scope_store.py` | Uses `ENGINE_HOST_IPS` for the "Networks the engine is connected to" buttons and always adds it to the never-touch list | Inside a Docker Desktop container, `ip addr` only shows Docker's own network |
| 6 | `start.ps1` (new) | Windows launcher: `start`, `scan [ip]`, `update`, `enroll <ip> [admin]`, `check <ip>`, `logs [service]`, `stop`; creates the engine SSH key with Python (paramiko) inside the image if missing | Same as `start.sh` on Kali |
| 7 | `run.bat` (replaced) | Now only runs `start.ps1` with the right PowerShell policy | Avoid "script is disabled" errors; the old `run.bat` used the Kali setup |
| 8 | `.gitattributes` (new) | Linux line endings for all files except `.ps1` / `.bat` | Windows Git otherwise changes line endings and breaks scripts inside the Linux containers |
| 9 | `.env.example`, `README.md`, `docs/WINDOWS_ENGINE.md` (new), `CLAUDE.md` | New settings explained; Windows quick start; full step-by-step guide | For you and the team |

**New `.env` lines on Windows**
```
NETWORK_MODE=nat
ENGINE_HOST_IPS=192.168.103.1/24
DENY_HOSTS=192.168.103.1
NEXT_PUBLIC_API_URL=auto
```

**What stays exactly the same:** CVE matching (NVD/EPSS/KEV), ML risk score and grade,
tickets and SLA, digital twin, attack paths, approved fixes with 2FA, verify, rollback,
TLS checks, change detection, audit log, dashboard and reports.

**What is weaker on Windows (say this honestly in the viva)**

| | Kali (host mode) | Windows (nat mode) |
|---|---|---|
| Host discovery | ARP + ping | TCP connect on common ports |
| Port scan | SYN (`-sS`) | connect (`-sT`), a bit slower, same ports |
| OS detection | nmap `-O` | guessed from service banners |
| MAC address | yes | no |
| Rogue-device detection | IP + MAC | IP only |
| Honeypot source IP | real attacker IP | may show Docker's gateway IP |

**Proposal impact:** none of the promised features is removed. "OS detection" is still
there (banner-based on Windows) and Scapy is still used in the Linux mode. The Kali way
(`./start.sh`, `docker-compose.yml`) still works unchanged, so both modes can be shown.

**Tested:** Python compiles; NAT-mode logic (scope, never-touch list, OS guess) tested with
sample data. **Not yet tested:** Docker Desktop on the real Windows PC and the PowerShell
script (to be confirmed on the first `run.bat update`).

---

## v7 — One-command target setup ("enroll") (2 Nov 2026)

**In one line:** preparing Metasploitable (or any Linux target) for auto-fix is now one command.

- `soar/enroll.py` (new), `start.sh enroll|check`, API `GET /targets/{ip}/check`, Assets page **Test** button.
- Asks the target admin password once (hidden, never stored), creates the `soar` user, installs
  the engine key, writes only the needed sudo rules (checked with `visudo`, backup kept), locks
  the password, clears the account expiry, then tests key login + sudo.
- Replaced the hard manual steps (vi/visudo, ssh-copy-id with legacy options, `chage`).

## v6 — Network scope from the dashboard (2 Nov 2026)

- **Settings → Network scope:** admin + 2FA sets allowed ranges, never-touch IPs and a written
  authorization note. Table `scope_config` (migration `003_dashboard_scope.sql`).
- Limits only `.env` can change: `AUTHORIZED_LAB_ONLY` master switch, private ranges only,
  /22 or smaller. The engine's own IPs are always denied. Every change is in the audit log.
- `start.sh scan` scans the whole authorized scope; `NEXT_PUBLIC_API_URL=auto` finds the API by itself.

## v5 — Digital twin explained (2 Nov 2026)

- What-if now also shows total exposure, open ports, critical/KEV/default-password counts,
  attack paths and the worst findings left, plus a note when the grade does not change
  (host risk = its single worst finding) or a fix matches nothing (port already closed).
- `stop_service 23` is treated as a port; the target IP is trimmed; a 404 lists scanned hosts.

## v4 — Review fixes (31 Oct 2026)

- Worker: refused plans fail once; auto-rollback only after a command really ran.
- Approval rules: only a dry-run can be approved, only a succeeded fix can be rolled back.
- Rogue alert only on first sight; host-level tickets close on re-scan; audit log file lock;
  one scan at a time (API returns 409 while busy).

## v3 — Windows targets (31 Oct 2026)

- Windows playbooks over OpenSSH/PowerShell: firewall rule, stop service, disable user, each
  with rollback and verification (not yet tested on a real Windows VM).
- Tickets for exposed risky ports (RDP, SMB, databases, backdoor ports).

## v2 — Accuracy and safety (27 Oct 2026)

- No duplicate services/CVEs across scans; closed ports and fixed CVEs detected on re-scan.
- Branch-aware CVE matching ("unconfirmed"), NVD vendor aliases, TLS checks for old servers.
- Suggested playbook on every ticket; protected port 22 / root / management account;
  verification after every fix; automatic and 2FA-protected manual rollback; multi-fix what-if.
