# Mini-SOAR — Test results

Automated test suite in `tests/` (pytest). Run it on the project PC with:

```
.\run.bat test
```

(or `.venv\Scripts\python -m pip install -r requirements-dev.txt` once, then
`.venv\Scripts\python -m pytest`).

## Result of the last full run

| | |
|---|---|
| Date | 20 Nov 2026 (v14) |
| Where | Development sandbox (Linux, Python 3.13) with the project's own paramiko 3.4.0, FastAPI 0.111 and pyotp 2.9; not the project PC |
| Total test cases | 486 |
| Passed | 485 |
| Failed | 0 |
| Skipped | 1 (ML training: needs PyTorch, which the sandbox does not have) |

**What v14 changed in the tests:**
- 32 honeypot tests removed (feature removed)
- the what-if and attack-path tests were rewritten as Fix Impact Preview tests
- new: 25 Nuclei/NetExec tests (`tests/test_tools.py`)
- new: tests for the API login and roles, TOTP replay, the automatic network rule, the live
  topology, paged Supabase reads, one client per thread, and the rogue flag before scoring

**Still to do:** run `.\run.bat test` on the project PC after v14 and note the result here.
The real Nuclei / NetExec binaries are never run by the tests (they are switched off in
`tests/conftest.py`). Their live behaviour is checked with `docs/LAB_CHECKLIST.md` §7.

## How the tests are kept safe

* The real `.env` is never read (python-dotenv is switched off for the tests).
* The real Supabase project is never contacted: an in-memory stand-in is used.
* A network guard lets a test connect only to this machine (127.0.0.1).
* Every test runs in its own empty temporary folder.

## What is real and what is a stand-in

| Part | In the tests |
|---|---|
| Engine code (scanner, intel, ml, soar, api, reports, common) | the real code |
| SSH (fixes, verify, enroll, default-password check) | real SSH protocol over loopback (paramiko client <-> test server) |
| HTTP (API, HTTP default-password check) | real HTTP over loopback |
| TLS check | real TLS handshake with a generated certificate |
| nmap | stand-in that returns nmap-shaped results (incl. a timed-out host) |
| Supabase | in-memory stand-in with the same tables, defaults and unique keys |
| NVD / EPSS / KEV / web push | stand-ins returning feed-shaped data |
| Nuclei / NetExec binaries | `subprocess.run` replaced by output in the tools' documented formats |
| Dashboard login (Supabase JWT) | token `t-<user id>` accepted by a stand-in check; the real check is unit-tested with PyJWT |

So the tests prove the logic and the protocols. They do not prove the live lab
(real nmap + Npcap, real Metasploitable, real Supabase): see `docs/LAB_CHECKLIST.md`.

## Summary by area

| Area | File | What it covers | Cases | Pass | Fail | Skip |
|---|---|---|---|---|---|---|
| Report | `tests/test_analysis.py` | MITRE ATT&CK mapping, PDF report | 6 | 6 | 0 | 0 |
| API gateway | `tests/test_api.py` | Every endpoint over HTTP with login + roles, 2FA enrolment (self only), TOTP replay, audit verify | 24 | 24 | 0 | 0 |
| Core security | `tests/test_common_core.py` | AES-256-GCM, HMAC signing, audit hash chain, file lock, network modes, syslog, API login check, paged reads, one client per thread | 36 | 36 | 0 | 0 |
| Safety guard | `tests/test_common_scope.py` | Authorization gate, allowlist, never-touch list, dashboard scope rules | 32 | 32 | 0 | 0 |
| End to end | `tests/test_engine_e2e.py` | Scan -> tickets -> approve -> fix -> re-scan -> closed; CLI; rogue flag before scoring | 14 | 14 | 0 | 0 |
| CVE intelligence | `tests/test_intel.py` | NVD/EPSS/KEV sync, version matching, watchlist | 51 | 51 | 0 | 0 |
| ML risk scoring | `tests/test_ml.py` | Features, expert formula, explanations, grades, training | 33 | 32 | 0 | 1 |
| Notifications + hygiene | `tests/test_notify_push.py` | Notifications, web push, launcher helpers, no secrets in code | 19 | 19 | 0 | 0 |
| Patch prioritization | `tests/test_prioritization.py` | Components, dependency rules (incl. automatic network rule), CCS/CVS/CRS, ranking, paper baseline, Fix Impact Preview = ranking numbers, prediction check, API, live topology | 63 | 63 | 0 | 0 |
| Scanner | `tests/test_scanner.py` | Discovery, port scan per mode, failed/timed-out scans, default passwords, TLS | 38 | 38 | 0 | 0 |
| Tickets + approval | `tests/test_soar_flow.py` | Tickets, SLA, admin + 2FA gates (code used once), worker, verify, rollback | 38 | 38 | 0 | 0 |
| Fix plans | `tests/test_soar_plan.py` | Suggested fixes, Linux + Windows commands, safety refusals, dry-run, kill switch | 55 | 55 | 0 | 0 |
| Real SSH | `tests/test_ssh_live.py` | Engine SSH code against a real loopback SSH server: fixes, verify, enroll | 27 | 27 | 0 | 0 |
| Nuclei + NetExec | `tests/test_tools.py` | Non-intrusive Nuclei command + parsing, NetExec read-only allow-list + parsing, scope, one finding format, ML mapping, tickets, prioritization, re-scan | 25 | 25 | 0 | 0 |
| Upload + detection | `tests/test_uplink.py` | Encrypted bundles, rogue devices, change detection, re-scan verification, risk trend | 25 | 25 | 0 | 0 |

## Test cases

### Analysis + report (`tests/test_analysis.py`)

- [pass] entry weakness reasons
- [pass] unconfirmed kev is not an entry point
- [pass] graph has attacker initial access and lateral edges
- [pass] paths are ranked by target risk
- [pass] no weak host means no paths
- [pass] empty network
- [pass] what if never changes the real data
- [pass] blocking the worst port lowers risk
- [pass] fixing a minor finding explains why grade stays
- [pass] fix that matches nothing is reported
- [pass] stop service by name or port number
- [pass] disable account removes default credential
- [pass] several fixes together
- [pass] network what if
- [pass] mitre mapping from services and findings
- [pass] mitre clean host maps nothing
- [pass] mitre coverage is deduplicated
- [pass] report is built without cloud
- [pass] report contains findings grade and mitre
- [pass] report counts only open findings

### API gateway (`tests/test_api.py`)

- [pass] health offline
- [pass] health reports cloud
- [pass] get scope
- [pass] set scope needs dashboard mode
- [pass] set scope admin 2fa and validation
- [pass] scan endpoint runs engine
- [pass] scan busy gives 409 and errors give 400
- [pass] attack graph
- [pass] attack graph empty without cloud
- [pass] whatif single and many
- [pass] whatif errors
- [pass] whatif ignores closed ports and fixed findings
- [pass] full remediation flow
- [pass] request errors are 400
- [pass] reject and rollback guards
- [pass] totp enroll first time
- [pass] totp cannot be replaced without current code
- [pass] totp reset cli
- [pass] unknown profile is 404 and no cloud is 503
- [pass] actions need cloud
- [pass] audit verify includes bundles
- [pass] audit verify detects tampering
- [pass] report pdf download
- [pass] target check

### Core security (`tests/test_common_core.py`)

- [pass] encrypt decrypt roundtrip
- [pass] encrypt uses fresh nonce
- [pass] tampered ciphertext is rejected
- [pass] json roundtrip
- [pass] wrong key length is refused
- [pass] signature verifies
- [pass] signature fails when body changes
- [pass] signature fails with other key
- [pass] old signature is a replay
- [pass] signing needs a key
- [pass] chain links and verifies
- [pass] empty chain is ok
- [pass] edited entry is detected
- [pass] deleted entry is detected
- [pass] audit is mirrored to cloud
- [pass] audit survives cloud failure
- [pass] chain stays intact with parallel writers
- [pass] non blocking lock reports busy
- [pass] network mode names (9 cases)
- [pass] engine host interfaces parsing
- [pass] nmap scanner uses nmap path
- [pass] syslog sends udp packet
- [pass] syslog never raises when siem is down

### Safety guard (`tests/test_common_scope.py`)

- [pass] settings are read from env
- [pass] bad aes key becomes empty
- [pass] gate passes with lab switch and ranges
- [pass] gate refuses without master switch
- [pass] gate refuses without ranges
- [pass] is in scope (6 cases)
- [pass] assert in scope raises outside
- [pass] filter targets drops and audits
- [pass] filter targets needs authorization
- [pass] expand scope lists hosts without denied
- [pass] engine own ip is always denied
- [pass] engine host ips setting is denied
- [pass] validate accepts private 24
- [pass] validate rejects (6 cases)
- [pass] validate respects ceiling
- [pass] dashboard scope overrides env
- [pass] dashboard scope needs authorized flag
- [pass] dashboard cannot beat env master switch
- [pass] dashboard row with oversized range is ignored
- [pass] falls back to env when cloud is down
- [pass] save scope needs a note when authorizing
- [pass] windows adapter parsing skips virtual and loopback

### End to end (`tests/test_engine_e2e.py`)

- [pass] scan offline runs the whole pipeline
- [pass] scan refuses without authorization
- [pass] out of scope target is never scanned
- [pass] second scan is refused while one runs
- [pass] scan to fix to closed ticket
- [pass] timed out scan closes nothing end to end
- [pass] new port between scans is reported
- [pass] cli show scope
- [pass] cli show scope fails closed
- [pass] cli scan and verify commands
- [pass] cli discover
- [pass] cli scan refused without authorization

### CVE intelligence (`tests/test_intel.py`)

- [pass] init db is repeatable
- [pass] store parses nvd record
- [pass] store twice does not duplicate
- [pass] severity bands (8 cases)
- [pass] exact version match with epss and kev
- [pass] other exact version does not match
- [pass] version inside range
- [pass] version after fix is not matched
- [pass] older branch is only unconfirmed
- [pass] end excluding bound is respected
- [pass] portable suffix is same version
- [pass] letter suffix ordering
- [pass] unknown version gives unconfirmed candidates
- [pass] unknown product gives nothing
- [pass] product name normalisation
- [pass] watchlist hit is marked
- [pass] match host prefers cpe and sorts kev first
- [pass] match host reads cloud watchlist
- [pass] service identity (8 cases)
- [pass] os cpe does not turn a service into the kernel
- [pass] platform only rows are not stored
- [pass] match host without database rows is empty
- [pass] kev sync
- [pass] epss sync skips comment and header
- [pass] epss sync tries second source
- [pass] epss sync fails clearly when all sources down
- [pass] cpe to match string (6 cases)
- [pass] vendor alias candidates
- [pass] sync cpe uses alias when first name has no cves
- [pass] sync cpe reads cpes from scans
- [pass] sync cpe without scans does nothing
- [pass] cli stats and init

### ML risk scoring (`tests/test_ml.py`)

- [pass] feature vector layout
- [pass] features handle missing values
- [pass] exposure is capped
- [pass] service criticality (6 cases)
- [pass] oracle known value
- [pass] oracle is deterministic and bounded
- [pass] exploit signals raise the score
- [pass] unconfirmed version is discounted
- [pass] kev low cvss outranks high cvss no exploit
- [pass] training data is reproducible
- [pass] grades (10 cases)
- [pass] score vector falls back to formula without model
- [pass] score host sets host risk to worst finding
- [pass] score host keeps watchlist reason
- [pass] rescoring does not pile up reasons
- [pass] host with only default password still has risk
- [pass] clean host is grade a
- [skipped here] training learns the formula
- [pass] model status reports fallback

### Notifications + hygiene (`tests/test_notify_push.py`)

- [pass] notify stores a row
- [pass] notify never raises
- [pass] unknown level becomes info
- [pass] push is skipped when not configured
- [pass] push goes to every subscription
- [pass] low level notifications are not pushed
- [pass] dead subscription is removed and errors do not stop others
- [pass] generated vapid keys have the right shape
- [pass] gen keys command
- [pass] sync lab runs all feeds and survives one failure
- [pass] intel status counts
- [pass] train if missing skips existing model
- [pass] train without torch says so
- [pass] service runner writes log
- [pass] every python file compiles
- [pass] no secret is committed in source
- [pass] env example lists every setting without values
- [pass] schema and migration define the new tables
- [pass] requirements pin every package

### Scanner (`tests/test_scanner.py`)

- [pass] discovery only touches in scope targets
- [pass] discovery whole scope when no target
- [pass] discovery merges arp and nmap
- [pass] nat mode discovers with tcp ping and no arp
- [pass] host and native mode use plain ping scan
- [pass] discovery survives missing nmap
- [pass] port scan parses open services
- [pass] port scan refuses out of scope
- [pass] port scan flags per mode (3 cases)
- [pass] full ports flag
- [pass] failed scan is not reported as no open ports
- [pass] host timeout is a failed scan
- [pass] timeout of another host does not matter
- [pass] host timeout setting
- [pass] application cpe wins over operating system cpe
- [pass] cpe without raw xml falls back to python nmap
- [pass] broken xml is harmless
- [pass] host with really no open ports is ok
- [pass] cpe given as list
- [pass] os guess from banners (4 cases)
- [pass] banner os guess used when nmap has none
- [pass] http default password is found
- [pass] http strong password is not flagged
- [pass] http public page is not flagged
- [pass] http check closed port is quiet
- [pass] check host runs only known services
- [pass] check host refuses out of scope
- [pass] credential list is small and documented
- [pass] tls reads self signed certificate
- [pass] tls flags expired certificate
- [pass] tls returns none for plain port
- [pass] tls check host picks tls like services
- [pass] tls refuses out of scope

### Tickets + approval (`tests/test_soar_flow.py`)

- [pass] totp verify and sealed secret
- [pass] totp old code is rejected
- [pass] totp enrolment uri and qr
- [pass] tickets opened for priority findings
- [pass] ticket severity sla and suggested fix
- [pass] no duplicate tickets on rescan
- [pass] unconfirmed version does not open a ticket
- [pass] low risk cve gets no ticket but watchlisted one does
- [pass] watchlisted unconfirmed cve gets a marked ticket
- [pass] watchlisted confirmed ticket has no unconfirmed tag
- [pass] overdue tickets are escalated once
- [pass] resolved tickets are not escalated
- [pass] tickets close when rescan shows the fix
- [pass] failed scan closes no tickets
- [pass] partial scan only judges scanned hosts
- [pass] ticketing is a no op offline
- [pass] request creates dry run without touching the host
- [pass] request for unsafe or out of scope target is refused
- [pass] windows os is picked from the asset
- [pass] admin with valid code approves
- [pass] non admin cannot approve (2 cases)
- [pass] wrong code is refused and audited
- [pass] admin without 2fa cannot approve
- [pass] only a dry run can be approved
- [pass] reject sends ticket back to open
- [pass] worker applies verifies and resolves
- [pass] worker ignores everything that is not approved
- [pass] fix that does not verify is rolled back
- [pass] failed command is rolled back
- [pass] ssh login failure changes nothing and does not roll back
- [pass] refused plan fails once
- [pass] row approved without totp is not executed
- [pass] kill switch stops the worker from changing hosts
- [pass] row without target fails cleanly
- [pass] admin rollback with 2fa
- [pass] only an executed fix can be rolled back

### Fix plans (`tests/test_soar_plan.py`)

- [pass] default password locks the account
- [pass] anonymous ftp blocks the port
- [pass] cleartext services are stopped (4 cases)
- [pass] backdoor ports are blocked (5 cases)
- [pass] exposed admin services are blocked (6 cases)
- [pass] backdoored build is blocked
- [pass] any other cve blocks until patched
- [pass] ssh port is never suggested for blocking
- [pass] nothing to suggest without port or finding
- [pass] windows target gets windows params
- [pass] every suggestion builds a valid plan
- [pass] block port plan
- [pass] stop service plan covers systemd initd and inetd
- [pass] disable account plan
- [pass] dangerous or invalid plans are refused (14 cases)
- [pass] plan for out of scope host is refused
- [pass] windows block port plan
- [pass] windows stop service saves start type for rollback
- [pass] windows disable account plan and refusals
- [pass] os family (4 cases)
- [pass] dry run shows commands and runs nothing
- [pass] windows dry run is readable
- [pass] apply needs approval and totp
- [pass] force dry run is a kill switch
- [pass] apply and rollback run the planned commands
- [pass] ssh settings are required
- [pass] run remote refuses out of scope

### Real SSH (`tests/test_ssh_live.py`)

- [pass] ssh default password is found
- [pass] ssh strong password is not flagged
- [pass] ssh check on dead port is quiet
- [pass] run remote returns output and exit code
- [pass] run remote raises when a command fails and stops
- [pass] run remote without check keeps going
- [pass] wrong key cannot log in
- [pass] unreadable key file is reported
- [pass] apply and rollback over real ssh
- [pass] verify account lock reads passwd status (4 cases)
- [pass] verify port closed and open
- [pass] verify stop service uses known port
- [pass] verify stop service without port asks the host
- [pass] verify without anything to check is not fixed
- [pass] verify is not fixed when host unreachable
- [pass] check target ready
- [pass] check target not ready without sudo
- [pass] check target reports login failure
- [pass] enroll settings rules
- [pass] public key line is derived from private key
- [pass] enroll refuses out of scope and own account
- [pass] full enroll flow over ssh
- [pass] enroll wrong admin password
- [pass] enroll stops when iptables is missing

### Upload + detection (`tests/test_uplink.py`)

- [pass] offline mode stores encrypted signed bundle
- [pass] tampered bundle is rejected
- [pass] bundle signed with other key is rejected
- [pass] verify stored bundles reports bad files
- [pass] verify with no bundles
- [pass] first scan creates rows
- [pass] rogue alert only on first sight
- [pass] authorized device is not rogue
- [pass] rescan does not duplicate rows
- [pass] tls certificates are replaced not piled up
- [pass] no change events on first scan of a host
- [pass] closed port is detected and vuln marked fixed
- [pass] new port raises alert
- [pass] reopened port and regression are detected
- [pass] version change is detected
- [pass] missing version answer is not a change
- [pass] analyst decision survives rescan
- [pass] failed scan of a host changes nothing
- [pass] other hosts in the same scan are still processed
- [pass] risk history per host and network
- [pass] risk trend goes down after a fix
- [pass] network risk is average of all assets
- [pass] watchlist hit alerts once
- [pass] cve added to watchlist later alerts on next scan
- [pass] upload works when new tables are missing
