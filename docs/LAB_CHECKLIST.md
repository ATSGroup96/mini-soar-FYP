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

## 6. Digital twin and attack paths

| # | Step | Expected result | OK? |
|---|---|---|---|
| 6.1 | Topology page | attacker → 192.168.56.101 edge with reasons (KEV / default cred) | |
| 6.2 | What-if: block port 21 | before / after risk, exposure and counts; nothing changes on the host | |

## 7. Honeypot

| # | Step | Expected result | OK? |
|---|---|---|---|
| 7.1 | From Metasploitable or Kali: `ssh -p 2222 root@192.168.56.1` and type any password 3 times | "Permission denied" every time; Honeypot page shows 3 rows with the passwords, reputation "internal" | |
| 7.2 | Same machine: `curl -u admin:admin http://192.168.56.1:8081/admin` | login page HTML; a row with user admin / password admin | |
| 7.3 | `curl -d "username=root&password=toor" http://192.168.56.1:8081/login` | "Invalid credentials"; row recorded | |
| 7.4 | Notifications (bell) | one "Honeypot hit (ssh)" and one "Honeypot hit (http)" (not one per attempt) | |
| 7.5 | Windows Firewall | python.exe allowed on **Private** networks, otherwise the VMs cannot reach ports 2222 / 8081 | |

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
