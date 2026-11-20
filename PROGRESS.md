# Build progress — Mini-SOAR / CAASM Platform

This project is being delivered in parts inside **one repo**. Each part is a
self-consistent checkpoint you can start testing.

| Part | Contents | Status |
|------|----------|--------|
| 1 | Folder structure, `.env.example`, `.gitignore`, `requirements.txt`, Dockerfiles, `docker-compose.yml`, Supabase SQL schema (tables + RLS + indexes), shared `common/` core (config, **allowlist guard**, AES-256-GCM + HMAC crypto, hash-chain audit, Supabase/SQLite access, syslog) | ✅ ready |
| 2 | Scanner engine: host discovery (ARP+nmap), port/service/OS detection, default-cred hygiene check, TLS checker, shadow-IT/rogue detection, encrypted+signed uplink, CLI | ✅ ready |
| 3 | Offline intel: NVD / EPSS / CISA KEV sync scripts + CVE matching; ML training script (PyTorch) + synthetic bootstrap + **explainable** scoring | ✅ ready |
| 4 | SOAR engine (SSH remediation, dry-run, approval, TOTP 2FA, rollback, patch-verify re-scan), (v14: attack paths, what-if and honeypot replaced by Patch Prioritization + Fix Impact Preview; Nuclei + NetExec added) | ✅ ready |
| 5 | FastAPI gateway + Next.js dashboard (11 pages: overview, assets, vulns, topology, patch prioritization, tickets, remediation, TLS, audit, reports, settings), dark mode, Cytoscape topology, PWA push | ✅ ready |
| 6 | SLA ticketing + escalation, Reporting (PDF + MITRE ATT&CK), `run.bat`/`run.sh`, full README + Metasploitable 2 testing guide, final single zip | ✅ ready |

## How to sanity-check Part 1 now (optional)

1. `copy .env.example .env` and fill in your Supabase values later.
2. Load the schema: in Supabase Studio → SQL Editor, paste
   `supabase/schema.sql` and Run. You should see the tables, RLS enabled,
   and indexes created with no errors.
3. (Optional) `docker compose build scanner` to confirm the image builds.

The full one-command `run.bat` and testing guide arrive in Part 6.

## Populating the offline intelligence DB (Part 3)

```
python -m intel.cli init
python -m intel.cli sync-all      # NVD + EPSS + KEV (needs internet once)
python -m intel.cli stats
```

## Training the ML risk model (Part 3)

```
pip install -r requirements.txt   # installs torch, scikit-learn
python -m ml.train                # ~seconds on CPU, saves data/model/risk_mlp.pt
```

Until a model is trained, risk scoring automatically falls back to a
transparent "oracle" risk function, so the platform still produces sensible,
explainable scores out of the box. Every score comes with its top contributing
factors (via feature ablation) — e.g. *"Listed on CISA KEV (+4.8)"*.

## Safety model (enforced in code from Part 1)

- `common/config.py` → `assert_authorized_to_run()` refuses to run unless
  `AUTHORIZED_LAB_ONLY=true` and `ALLOWED_RANGES` is set.
- `common/allowlist.py` → every network target is filtered through
  `filter_targets()` / `assert_in_scope()`; anything outside the allowlist or
  inside `DENY_HOSTS` is dropped before a packet is sent, and the rejection is
  written to the tamper-evident audit log.
