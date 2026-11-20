# Mini-SOAR — handoff for Claude Code

Owner: Muhammad Abdullah Jafri (BSCS FYP, Iqra University). Talk to him in Roman Urdu, short and step-by-step.
Project: **Mini-SOAR — Network Vulnerability Management & Auto-Remediation Platform (CAASM)**. Defensive tool, $0 budget, free tools only.
The final FYDP proposal is the spec (Scapy + Nmap + Nuclei + NetExec; NO honeypot; NO "digital twin": the method of
Jiang et al. 2024 is called **Patch Prioritization** + **Fix Impact Preview**). Never reintroduce the old names.

## Hard rules (never break)
- Scan / remediate ONLY inside `192.168.103.0/24` (the authorized VirtualBox lab). Never touch any other host or network.
- NEVER print, cat, echo or log `.env` contents or any key (Supabase service_role, anon, JWT secret, NVD). Read values only via code that loads them.
- Nuclei only in non-intrusive mode (no dos/fuzz/intrusive/OAST), NetExec only read-only (allow-list in scanner/netexec_check.py). Never add modules, -x, dumps or credential guessing.
- Never ask the user to paste keys/passwords into chat.
- Do not enable Hyper-V on the Windows host (it breaks VirtualBox).
- One scan at a time (concurrent scans create duplicate assets).
- Ask before destructive commands (docker volume rm, truncate, rm -rf).

## Lab
| Machine | IP | Notes |
|---|---|---|
| Windows host | 192.168.103.1 | VirtualBox host |
| Kali (this machine) | 192.168.103.104 (eth1) | runs the engine in Docker; eth0 = NAT for internet |
| Metasploitable 2 "meta" | 192.168.103.105 | target; login msfadmin/msfadmin |

Project folder: `~/Downloads/mini-soar`
Dashboard: http://192.168.103.104:3000 (Supabase login) · API: http://192.168.103.104:8000
Supabase project ref: etxvseodwlnobzosmtfs (legacy JWT anon/service_role keys in `.env`).

## Architecture
- `docker-compose.yml`: `scanner`, `soar`, `api` share image `mini-soar-engine:latest`, `network_mode: host`, run as root. `scanner` is in profile `tools` (run with `docker compose run --rm scanner ...`). `dashboard` (3000) is on bridge. The image includes nuclei + NetExec (/opt/netexec).
- `scanner/` discovery (ARP/nmap -sn), port_scan (nmap -sS -sV), default_creds, tls_check, nuclei_scan, netexec_check, engine, uplink (to Supabase). One finding format: vulnerabilities.source = cve|nuclei|netexec, finding_key, title, evidence.
- `intel/` offline SQLite CVE store: KEV, EPSS, NVD. `sync-cpe` = targeted NVD sync per nmap CPE (full NVD sync is unreliable).
- `ml/` PyTorch risk model (10 features in `ml/features.py`; synthetic training labels from expert formula in `ml/bootstrap_data.py`). Trained: MAE 2.05, RMSE 2.57 on 0–100 scale. Be honest: synthetic data. `ml/finding_map.py` maps Nuclei/NetExec findings (no CVE) to the same features.
- `soar/` ticketing+SLA, prioritization.py + prioritization_store.py (components, dependency rules, CRS = CCS x CVS, fix ranking, paper baseline, Fix Impact Preview, prediction check), remediation (dry-run → approval → TOTP → SSH fix → rollback → re-scan verify).
- `api/main.py` FastAPI, every endpoint except /health needs `Authorization: Bearer <Supabase token>` (common/auth.py, roles viewer<analyst<admin): /scan /topology /prioritization /fix-preview /prioritization/{importance,dependency,dependency/remove} /remediation/{request,approve,reject,rollback} /totp/enroll /audit/verify /report/latest.pdf /scope /targets/{ip}/check
- `dashboard/` Next.js + Supabase AuthGate (RLS needs logged-in user).
- `reports/` PDF + MITRE ATT&CK mapping. Syslog forwarding: `common/syslog_logger.py`.

## Useful commands
```
docker compose up -d --remove-orphans      # start api/soar/dashboard
docker compose ps
docker compose logs -f api
docker compose run --rm scanner scan --targets 192.168.103.105
docker compose run --rm scanner verify-audit
docker compose run --rm scanner show-scope
docker compose run --rm --entrypoint python api -m intel.cli stats
docker compose run --rm --entrypoint python api -m intel.cli sync-cpe "cpe:2.3:a:*:vsftpd"
docker compose build && docker compose up -d   # after code changes
```

## Status (2026-10-27, v2)
Done in v2 (code): CVE port bug fixed (attack path / what-if), services+vulns upserted (no duplicates across scans),
missing ports -> closed, missing CVEs -> remediated (re-scan verification), branch-aware matcher (Apache 2.4 CVEs on 2.2.x
-> "version-unconfirmed"), NVD vendor aliases + keyword fallback in sync-cpe, TLS checker handles old servers + SMTP/Postgres
STARTTLS, auto-suggested playbook on every ticket (soar/playbooks.py), tickets for default creds + clear-text services,
Tickets page "Fix" -> dry-run, portable stop_service (systemd / init.d / inetd), legacy ssh-rsa fallback, protected port 22 /
root / management account, per-action verification, auto-rollback when apply or verify fails, TOTP-gated manual rollback
(API + dashboard), multi-fix what-if.

Verified here: all Python compiles, all TSX parses, matcher/playbook/plan/twin/attack-path checks, shell syntax (bash+sh),
inetd edit+rollback round-trip. NOT run here (no registry/network access): Next.js build, live SSH to meta, Supabase.

## v3 (2026-10-31): Windows support
Windows playbooks (PowerShell over OpenSSH, -EncodedCommand): block_port = Windows Firewall rule, stop_service =
Stop-Service + Disabled (old start type saved), disable_account = Disable-LocalUser; rollback + verification for each.
OS picked from asset os_guess (remediation.os_family) or the Target OS selector on the Tickets page. Tickets now also
open for exposed risky ports (RDP 3389, SMB 445, DBs, backdoor ports) with suggested fixes. Guide: docs/WINDOWS_SETUP.md.
Not yet run against a real Windows VM.

## v4 review fixes (2026-10-31)
Worker: refused plans fail once (no infinite retry); auto-rollback only after a command actually ran (CommandFailed),
not after an SSH/login failure; error text kept with the rollback output. Approval: only dry_run can be approved,
only succeeded can be rolled back, reject only dry_run (ticket goes back to open). Rogue alert only on first sight.
Host-level tickets (exposed port / clear-text / default cred) auto-resolve on re-scan. Audit chain uses a file lock
(6 concurrent writers x 40 entries -> chain intact). One scan at a time (data/.scan.lock; API returns 409).
Dashboard loads up to 1000 vulns and batches realtime reloads (1 s).

## TODO from v4 (old; see "TODO (v14)" at the end)
1. Run supabase/migrations/002_v2_fixes.sql, rebuild (`docker compose build && docker compose up -d`).
2. `sync-cpe` again (vsftpd now found via vendor alias), then ONE clean scan.
3. Follow docs/REMEDIATION_SETUP.md (soar user, RSA key, sudoers, .env, TOTP) and run the demo.
4. Windows VM target (docs/WINDOWS_SETUP.md) and test the 3 Windows playbooks + rollback.
4b. Optional: Ubuntu Server VM (modern systemd path) and network-level what-if with 2+ hosts.
5. Panel evidence: test-case sheet + screenshots.
6. Delete the old Supabase project (key was exposed earlier).

## v5 (2026-11-02): digital twin fixes
What-if now reports total exposure, open ports, critical/KEV/default-cred counts, attack paths and the worst findings
left; explains when the grade stays the same (host risk = worst single finding); lists fixes that matched nothing
(e.g. a port already closed); "stop_service 23" is treated as a port; target IP is trimmed and a 404 lists scanned hosts.

## v6 (2026-11-02): network scope from the dashboard
Settings -> Network scope: admin + TOTP sets allowed ranges, deny hosts and an authorization confirmation + note
(table public.scope_config, migration 003). Engine reads it via common/scope_store.effective_scope() (10 s cache);
falls back to .env if no row / Supabase down. SCOPE_SOURCE=dashboard|env. Limits only .env can change:
AUTHORIZED_LAB_ONLY master switch, SCOPE_CEILING (private ranges), max /22 per range; the engine's own IPs are always
denied. Every change is audit-logged (scope.update). /scope GET shows the networks the engine is connected to.
start.sh scans the whole authorized scope when TARGET is empty. Dashboard NEXT_PUBLIC_API_URL=auto = same host :8000.

## v7 (2026-11-02): one-step target enrollment
`./start.sh enroll <ip> [admin]` (soar/enroll.py, runs in the api container): asks the target admin password once
(getpass, never stored/logged), creates SSH_USERNAME, installs the engine public key (derived from the private key),
detects tool paths and writes sudo rules (/etc/sudoers.d/mini-soar on modern sudo; managed block + backup in
/etc/sudoers on old sudo like meta; validated with visudo -cf, nothing changes if the check fails; old manual
"soar ALL=" lines are replaced), passwd -l + chage -E -1, then checks key login + sudo (sudo -S </dev/null, works on
sudo 1.6). `./start.sh check <ip>` and Assets page "Test" button (GET /targets/{ip}/check) only test.
Verified here: user/key/sudoers (both branches, idempotent, bad input refused) against a real local sudo/visudo.
Not run here: paramiko SSH to meta.

## v8 (2026-11-12): engine on Windows (Docker Desktop), Kali optional
docker-compose.windows.yml (no host networking; api publishes 8000; data/audit in named volumes minisoar-data /
minisoar-audit; secrets bind ro; NETWORK_MODE=nat forced). common/netmode.py: NETWORK_MODE host|nat,
ENGINE_HOST_IPS (Windows lab IP with prefix, e.g. 192.168.103.1/24). nat mode: discovery = nmap -sn --unprivileged
-PS<common ports> (no ARP), port scan = -sT -Pn -sV (no -O), OS guessed from banners/CPEs (port_scan._os_from_services),
no MAC. scope_store uses ENGINE_HOST_IPS for "connected networks" + always-deny. start.ps1 (+ run.bat wrapper, replaces
the old run.bat): start | scan [ip] | update | enroll <ip> [admin] | check <ip> | logs [svc] | stop; enroll key is
generated with paramiko inside the image. .gitattributes keeps LF for Linux files. Guide: docs/WINDOWS_ENGINE.md.
Not run here: Docker Desktop on Windows, PowerShell script (syntax not checked: no pwsh here).

## v9 (2026-11-13): Windows native (no Docker)
NETWORK_MODE=native: engine runs directly on Windows (Python 3.11 .venv + Nmap/Npcap + Node 20), full scan like Kali
(ARP+MAC via nmap -sn, -sS, -O). start.ps1 hands over to start-native.ps1 (Administrator self-elevation, installs
.venv/torch/requirements, builds dashboard standalone, starts api/soar/honeypot/dashboard with PIDs in data\pids,
logs in logs\ via common/svc.py, taskkill /T on stop). common/filelock.py (fcntl/msvcrt) for scan + audit locks;
scope_store reads Windows adapters via PowerShell Get-NetIPAddress; netmode.nmap_scanner() finds nmap.exe / NMAP_PATH.
Guide: docs/WINDOWS_NATIVE.md. Not run here: real Windows PC.

## v10 (2026-11-15): tests, bug fixes, proposal alignment
tests/ (pytest, 421 cases at v10; `run.bat test`; conftest switches off python-dotenv, replaces Supabase with
tests/fakes.FakeSupabase and only allows loopback sockets; tests/ssh_server.py = real paramiko SSH server on
loopback). Fixed: failed/timed-out port scan no longer closes anything (HostScan.scan_ok, nmap XML timedout flag,
SCAN_HOST_TIMEOUT default 300 s; uplink + ticketing skip such hosts); SSH honeypot now subclasses
paramiko.ServerInterface (before: crashed on get_banner, recorded nothing); HTTP default-cred check (401 + Basic
challenge first); matcher (versionEndExcluding / StartExcluding flags in cpe_match, "4.7p1" = 4.7, letter patch
levels, unknown version = unconfirmed); PDF report MITRE mapping gets services, only open findings; ml reasons no
longer pile up. Added: risk_history + asset_changes tables (migration 004; writes are skipped quietly on an older
DB), change detection (new_asset / port_opened / port_closed / version_changed), CVE watchlist UI + alert + ticket,
common/notify.py + common/webpush.py (pywebpush, VAPID keys via `python -m common.webpush gen-keys`),
uplink.load_bundle / verify_stored_bundles (HMAC check of stored bundles; /audit/verify returns "bundles"),
/health returns model / intel / push status (Settings "Engine status"), TOTP re-enrol needs a current code +
`python -m soar.totp_2fa reset <email>`, intel.cli sync-lab / sync-new, ml.train --if-missing, launcher commands
test / train / totp-reset, .env.example. Honeypot: internal source = always alert, private IPs never sent to
reputation services, alert throttle 5 min per (source, service).
Not run here: PowerShell launchers, real nmap/Npcap, real Supabase, pywebpush with a real browser, torch training
(test skipped without torch). Live checks: docs/LAB_CHECKLIST.md.

## v12 (2026-11-18): real-data fixes
A: scanner/port_scan._application_cpes reads every <cpe> per port from nmap's XML and keeps the first cpe:/a:
(python-nmap keeps the LAST, usually the OS cpe:/o:linux:linux_kernel); intel.match.service_identity ignores
non-application CPEs; sync_nvd._store skips cpeMatch with vulnerable=false. Real Metasploitable data: 529 -> 517 CVEs
(13 wrong kernel matches on 22/23/512 removed, CVE-2023-48795 added on 22). C: watchlisted unconfirmed CVE ->
ticket titled "... [unconfirmed] (ip)". D: start-native.ps1 dev mode runs `node node_modules\next\dist\bin\next dev`
(PID = node) + Stop-StrayDashboard (node.exe whose command line contains the dashboard folder). E: audit/ in
.gitignore; user must `git rm -r --cached audit`. Tests: 436 (435 pass, 1 skip). Real-data flow script lived
outside the repo (sandbox); 57/57.

## v13 / v14 (2026-11-18 / 2026-11-20): proposal alignment
v13 added the dependency model (Jiang et al. 2024). v14 renamed it to Patch Prioritization + Fix Impact Preview
(no "digital twin"), removed the honeypot and attack-path ranking, added Nuclei + NetExec (non-intrusive / read-only),
one finding format, ML mapping for findings without a CVE, live Topology, API login check (common/auth.py), RLS fixes
(no self-promotion to admin, no browser writes to remediations), TOTP codes usable once, thread-local Supabase client +
paged selects (fixed the Topology 500s), rogue flag before scoring. Migration: supabase/migrations/006_proposal_alignment.sql.
Tests: 485 pass, 1 skip. Method + formulas: docs/PATCH_PRIORITIZATION.md. Not run here: real nuclei/nxc, PowerShell, Next build.

## TODO (v14)
1. Run migration 006 in Supabase, `run.bat update` (downloads Nuclei + NetExec), sign in again, `run.bat test`.
2. ONE clean scan of meta; check NetExec (SMBv1 / signing on 445) and Nuclei findings on the Vulnerabilities page.
3. Remediation demo with the Fix Impact Preview on the approval card; next scan -> prediction checked.
4. Windows 10 VM target: NetExec RDP/SMB/WinRM checks + the 3 Windows playbooks + rollback.
5. Panel evidence: test-case sheet + screenshots. `git rm -r --cached audit` (still tracked). Delete the old Supabase project.
