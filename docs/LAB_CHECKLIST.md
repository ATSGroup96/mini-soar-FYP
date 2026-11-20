# Mini-SOAR — Live lab checklist

The automated tests (`run.bat test`) prove the logic. This list proves the real lab:
real nmap + Npcap, real Metasploitable, real Supabase. Do it in order, tick each line,
and keep a screenshot of each result for the FYP file.

Lab used here: engine PC `192.168.56.1`, Metasploitable 2 `192.168.56.101`.

## 0. One-time setup

| # | Step | Expected result | OK? |
|---|---|---|---|
| 0.1 | Supabase → SQL Editor → run `supabase/migrations/004_trend_changes.sql` | "Success", tables `risk_history` and `asset_changes` exist | |
| 0.2 | `.\run.bat update` | packages installed; "KEV sync complete", "EPSS sync complete"; "Saved model"; a scan runs | |
| 0.3 | `.\run.bat test` | all tests pass, 0 failed (the ML training test also runs here) | |
| 0.4 | Dashboard → Settings → Engine status | "trained PyTorch model", CVE / KEV / EPSS counts above 0, cloud "connected" | |
| 0.5 | `.\run.bat stop`, wait, then open http://localhost:3000 | page does not load (the dashboard really stopped). Then `.\run.bat` again | |

## 1. Scan (proposal: discovery, ports, OS, shadow-IT, default credentials, TLS)

| # | Step | Expected result | OK? |
|---|---|---|---|
| 1.1 | `.\run.bat scan 192.168.56.101` | about 20+ services, OS "Linux 2.6.x", MAC shown, "1 default-cred" or more | |
| 1.2 | Assets page | host listed with a grade (D or F), marked rogue until you authorize it | |
| 1.3 | Vulnerabilities page | CVEs with CVSS, EPSS %, KEV badge; click "explain" → reasons | |
| 1.3b | Vulnerabilities page, filter port 22 / 23 / 512 | port 22 shows OpenSSH CVEs (e.g. CVE-2023-48795); ports 23 and 512 show **no** CVEs | |
| 1.4 | TLS Certs page | certificates of port 25 / 5432 shown (expired, self-signed) | |
| 1.5 | `.\run.bat scan 8.8.8.8` | nothing scanned ("0 hosts"); `scope.reject` in the Audit page | |

## 2. Failed scan safety (the 13 Nov problem)

| # | Step | Expected result | OK? |
|---|---|---|---|
| 2.1 | Note the number of open tickets. Pause the Metasploitable VM **during** a port scan (VirtualBox → Machine → Pause) and wait for the scan to finish | notification "Scan of a host did not finish"; scan output says "port scan FAILED / timed out" | |
| 2.2 | Tickets page | same open tickets as before; nothing auto-closed | |
| 2.3 | Resume the VM, scan again | normal result again | |

## 3. Change detection and risk trend

| # | Step | Expected result | OK? |
|---|---|---|---|
| 3.1 | On Metasploitable: `sudo nc -l -p 4444 &` then scan | notification "New open port"; Overview → Recent changes shows "port opened 4444" | |
| 3.2 | Stop it (`sudo pkill nc`), scan | "port closed 4444" | |
| 3.3 | Overview → Risk trend | one point per scan | |

## 4. CVE watchlist

| # | Step | Expected result | OK? |
|---|---|---|---|
| 4.1 | Vulnerabilities → CVE watchlist → add a CVE that the host has but that has no ticket (medium / low) | chip appears | |
| 4.2 | Scan again | notification "Watchlisted CVE found"; "watchlist" badge on the row; a ticket for it | |
| 4.3 | Add a CVE whose row says "unconfirmed", scan again | a ticket titled "... [unconfirmed] (192.168.56.101)" | |

## 5. Fix with approval, 2FA, verify, rollback

| # | Step | Expected result | OK? |
|---|---|---|---|
| 5.1 | If 2FA codes are refused: `.\run.bat totp-reset <your email>`, then Settings → Generate QR, scan it, delete the old entry in the app. Check the PC clock is correct | new codes are accepted | |
| 5.2 | `.\run.bat enroll 192.168.56.101 msfadmin` then Assets → Test | "ready" | |
| 5.3 | Tickets → telnet ticket → Fix | dry-run preview with the exact commands; nothing changed on the host yet | |
| 5.4 | Remediation → Approve with a **wrong** code | refused; `remediation.approve.totp_fail` in Audit | |
| 5.5 | Approve with the right code | status succeeded, "verified fixed"; `telnet 192.168.56.101` no longer connects; ticket resolved | |
| 5.6 | Rollback with a code | telnet works again; ticket back to in progress | |
| 5.7 | Try to fix port 22 (Tickets → custom action block_port 22) | refused: "would cut the engine's SSH access" | |
| 5.8 | Set `FORCE_DRY_RUN=true`, restart, approve a fix | "FORCE_DRY_RUN is on — not executed"; host unchanged. Set it back to false | |

## 6. Patch prioritization, Fix Impact Preview, live topology

| # | Step | Expected result | OK? |
|---|---|---|---|
| 6.1 | Supabase → SQL Editor → run `supabase/migrations/006_proposal_alignment.sql` | "Success"; the orange "Running with defaults" note on the Patch Prioritization page disappears after a refresh | |
| 6.2 | Patch Prioritization page | components listed (OS + every service of .101); the OS has the most "Depend on it"; "Block port 21 (ftp)" (vsftpd backdoor) near the top of the ranking | |
| 6.3 | Press **Preview** on "Block port 21" | Fix Impact Preview: host and network risk go down; "Risk removed" = the "Risk drop" of that row (same number); nothing changes on the host | |
| 6.4 | Preview `patch_cve` of a mild CVE on port 22 | "Risk goes UP" note with the reason (component average); that fix is not in the ranking | |
| 6.5 | Click "Compare with paper baseline" | a second list (CVSS-only formula); the four boxes show "dangerous fixes in top 5" for ours vs. baseline | |
| 6.6 | Assets → set 192.168.56.101 "Importance" to **low**, then back to **critical** | message "is now ..."; on Patch Prioritization (Refresh) every component's Importance changes and CRS numbers go down (low) / up (critical) | |
| 6.7 | Add dependency `192.168.56.101|21` → `192.168.56.101|3306`, rule data | appears in the list as "manual"; mysql:3306 "Depend on it" +1. Then **Remove** it | |
| 6.8 | Hide an automatic one (Hide next to `…|23 → …|os`) | it disappears from the list; telnet no longer counts towards the OS | |
| 6.9 | Tickets → request a fix (e.g. block port 23) → Remediation → Review | the approval card shows the dry-run commands **and** the Fix Impact Preview; approve with 2FA; wait for "succeeded / verified" | |
| 6.10 | Run a new scan | scan summary shows `fix_checks: 1`; Remediation → Details shows "Checked by the next scan: ✓ as predicted"; Patch Prioritization shows "Prediction accuracy" 100% (1/1). Then roll back the fix | |
| 6.11 | Topology page open, start a scan | the graph redraws by itself while the scan writes (hosts → OS + services → data/interaction/network lines) | |
| 6.12 | As a viewer account, change Importance | refused: "this needs the 'admin' role" | |

## 7. Nuclei + NetExec

| # | Step | Expected result | OK? |
|---|---|---|---|
| 7.1 | Settings → Engine status | "Scan tools: Nuclei ready · NetExec ready" (else `.\run.bat update`) | |
| 7.2 | Scan 192.168.56.101 | scan output: "… CVE, N Nuclei/NetExec"; Audit: `nuclei.start/finish`, `netexec.check` | |
| 7.3 | Vulnerabilities → filter NetExec | on Samba 445: "SMBv1 enabled" and "SMB signing not required" (evidence = NetExec banner) | |
| 7.4 | Vulnerabilities → filter Nuclei | default-login / panel / misconfiguration findings with the matched URL as evidence | |
| 7.5 | Tickets | tickets for the medium+ tool findings, e.g. "SMBv1 enabled on netbios-ssn:445 (…)", with a suggested fix | |
| 7.6 | Patch Prioritization → component `…|445` | its "findings" count includes the NetExec findings; "Block port 445" ranked | |
| 7.7 | Reports → PDF | "Open findings by tool: Nmap + CVE match …, NetExec …, Nuclei …"; MITRE shows T1557.001 / T1135 | |
| 7.8 | Audit log: search `netexec.check` | only `smb`, `rdp`, `winrm` with `--port`, `--shares`, `-u ""`, `-p ""` — no modules, no commands, no real logins | |

## 7b. API login (security)

| # | Step | Expected result | OK? |
|---|---|---|---|
| 7b.1 | From another PC: `curl -X POST http://<engine-ip>:8000/scan -H "Content-Type: application/json" -d "{}"` | 401 "not signed in"; no scan starts | |
| 7b.2 | Viewer account: press Run scan | 403 "needs the 'analyst' role" | |
| 7b.3 | Approve two fixes with the **same** 6-digit code | the second is refused: "already used" | |

## 8. Audit, encryption, report

| # | Step | Expected result | OK? |
|---|---|---|---|
| 8.1 | Audit page | "Hash chain intact" and "Stored scan results verified" | |
| 8.2 | Stop the engine, change one letter in `audit\audit_chain.jsonl`, start, open Audit | "Tampering detected" with the entry number. Undo the change | |
| 8.3 | Open a file in `data\offline_results\` in Notepad | unreadable (encrypted) | |
| 8.4 | `.venv\Scripts\python -m scanner.cli verify-bundles` | "N of N verified" | |
| 8.5 | Reports → download PDF | grade, assets table, findings, MITRE ATT&CK table with several techniques | |

## 9. Push notifications (optional)

| # | Step | Expected result | OK? |
|---|---|---|---|
| 9.1 | `.venv\Scripts\python -m common.webpush gen-keys`, paste the 3 lines into `.env`, `.\run.bat stop`, `.\run.bat` | Settings → Engine status → push "ready" | |
| 9.2 | Settings → Enable push on this device → allow | "Push enabled on this device." | |
| 9.3 | `.venv\Scripts\python -m common.webpush test` | a desktop notification "Mini-SOAR test" | |

## 10. Other modes (only if you want to show them)

| # | Step | Expected result | OK? |
|---|---|---|---|
| 10.1 | `.env`: `NETWORK_MODE=nat` + `ENGINE_HOST_IPS=192.168.56.1/24`, Docker Desktop running, `.\run.bat update` | scan works with connect scan; no MAC, OS "from service banners" | |
| 10.2 | Kali: `./start.sh update` | full scan as in native mode | |
