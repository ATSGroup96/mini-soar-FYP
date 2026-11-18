# Mini-SOAR digital twin — method, formulas and what it is based on

## 1. In one paragraph

The digital twin is a **model of the lab's security state**, not a copy of the machines.
After every scan it holds each host's **components** (the operating system and every open
service), the **dependencies** between them, and their findings (CVEs, default passwords).
Fixes are tried on the twin first ("virtual patching"), the twin ranks which fix lowers the
risk most, and after a real fix the next scan checks whether the twin's prediction was right.

**Base paper:** Y. Jiang, W. Wang, J. Ding, X. Lu, Y. Jing, "Leveraging Digital Twin
Technology for Enhanced Cybersecurity in Cyber–Physical Production Systems",
*Future Internet* 16(4):134, 2024. https://doi.org/10.3390/fi16040134

**Definition used:** a network digital twin is a digital representation of a data network.
It does not have to be a full replica and can model only the aspects a use case needs
(IETF IRTF NMRG, *Network Digital Twin: Concepts and Reference Architecture*, Internet-Draft).

## 2. The formulas

**Step 1 — finding risk (0–100).** Unchanged from the rest of Mini-SOAR: CVSS, EPSS, CISA KEV,
default password, service type, exposure, rogue device, version confidence (`ml/`).

**Step 2 — component vulnerability score (CVS).** A severity-weighted average of the finding
risks on the component:

    CVS = Σ w(s)·s / Σ w(s)        w = 4 (s ≥ 80), 3 (60–79), 2 (40–59), 1 (< 40)

A working default password counts as one finding of risk 65.

**Step 3 — criticality (CCS).**

    D   = (components that depend on this one) / (highest such count in the network)
    W   = admin's asset weight: critical 1.0, normal 0.8, low 0.5
    CCS = W × (0.5 + 0.5 × D)                                   range 0.25 … 1.0

**Step 4 — component risk.**

    CRS = CCS × CVS            host risk = highest CRS of its components
                               network risk = average host risk (also shown: sum of all CRS)

**Step 5 — patch priority.** Every candidate fix (block each risky port, lock each default
account, vendor-patch each very bad CVE) is applied to a copy of the twin. The fixes are
ranked by how much the network's total CRS drops, biggest drop first.

**Step 6 — twin accuracy (prediction check).** When a fix is requested, the twin stores what it
expects: the ports that close, the CVEs that disappear, the default passwords that stop
working, and the host's risk afterwards (plus a compact snapshot of the host). After the fix is
applied and verified, the next scan compares the prediction with reality:

    match = everything predicted to disappear did disappear
            AND |actual host CRS − predicted host CRS| ≤ 10

Fixes applied to the same host between two scans are checked together, because the scan sees
all of them at once. Twin accuracy = matched predictions / checked predictions.

**Baseline (the paper's own formulas), shown next to ours:**

    CVS_paper = Σ_i w_i · Sum(S_i) / Σ_i N_i   over CVSS bands critical / high / medium / low
    CCS_paper = number of dependency relations of the component (raw count)
    CRS_paper = CCS_paper × CVS_paper

**Comparison shown on the dashboard.** For each ranking, the dashboard shows how many of the
top 5 fixes remove a CISA-KEV CVE or a working default password, and at which rank the first
one appears. Both are proxies for "really exploited" that don't depend on either formula.

## 3. Dependency rules

"A depends on B" (edge A → B). The rule names come from the paper.

| Rule | Automatic (same host) | Example |
|---|---|---|
| embedding | every service runs on the OS | `ftp:21 → Linux OS` |
| data | web/app servers use a local database | `http:80 → mysql:3306` |
| interaction | RPC services register with the port mapper | `nfs:2049 → rpcbind:111` |
| network | none automatically; the admin adds them (e.g. across hosts) | `web host :80 → DB host :3306` |

The admin can add a missing dependency, or hide a wrong automatic one, on the Topology page.
Asset weights are set on the Assets page. Both are written to the audit log.

## 4. Kept, changed, added (for the report and viva)

| Paper element | Ours | Type | Reason / source |
|---|---|---|---|
| Model of components + dependency rules | Same idea; components = OS + services | Adaptation | IT network instead of a factory |
| CCS from dependencies | Normalised, with a 0.5 floor | Improvement | A component nobody depends on (e.g. a backdoored FTP server) would otherwise be ranked almost nothing |
| Stakeholder weighting (manual talks with the project team) | Asset weight in the dashboard | Improvement | Repeatable, audited |
| CVS from CVSS only | CVS from our finding risk (EPSS + KEV + default passwords) | Improvement | Jacobs et al. (2023, EPSS v3): CVSS alone is a poor predictor of real exploitation |
| CRS = CCS × CVS | Same | Kept | — |
| Virtual patch, ranking rule | Automatic ranking by biggest risk drop | Improvement | The paper's wording ("ascending order") is unclear; ours is explicit |
| Not connected to live data (paper's future work) | Twin rebuilt after every scan | Extension | Per scan, not truly real-time |
| Predictions never validated | Prediction vs. real re-scan, twin accuracy % | Extension | Our evaluation method |
| Stops at virtual patching | Real fix with approval, 2FA, verification, rollback | Extension | Rest of Mini-SOAR |
| securiCAD attack simulation (time-to-compromise) | Not used; own attack-path graph | Not adopted | Commercial tool; $0 budget |
| MongoDB + Shodan + CWE/CAPEC | Not used; NVD + EPSS + KEV in SQLite | Not adopted | Private lab; Shodan only sees the internet |
| Physical / control layers | Not applicable | Not adopted | No physical process in an IT lab |

## 5. Honest limitations

* The numbers 4/3/2/1, 0.5, 1.0/0.8/0.5, 65 and the tolerance 10 are **our choices**, because
  the paper doesn't publish its weights. They are in `soar/twin_model.py` and can be tuned.
* "Improvement" is only proven once the comparison on the lab shows it. The dashboard shows
  both rankings side by side.
* The finding-risk model is trained on synthetic data labelled by the expert formula
  (`ml/bootstrap_data.py`). The improvement rests on the EPSS/KEV/default-password inputs, not
  on the model having learned something new.
* Automatic dependencies are heuristics (e.g. "a web server uses the local database"). The
  admin can correct them.
* A prediction can miss because of changes the twin can't know about (a new CVE published
  between the two scans, a service restarted by hand). The check records the reason.

## 6. Where it is in the code

| What | File |
|---|---|
| Formulas, dependency rules, ranking, prediction check | `soar/twin_model.py` |
| Loading from Supabase, predictions stored with fixes, checks after a scan | `soar/twin_store.py` |
| Prediction stored when a fix is requested | `soar/approval.py` (`create_request`) |
| Check after every scan | `scanner/engine.py` (`run_scan`, summary `twin_checked`) |
| API: `GET /twin`, `POST /twin/criticality`, `POST /twin/dependency`, `POST /twin/dependency/remove`; `/whatif` now also returns `twin` | `api/main.py` |
| Dashboard | `dashboard/components/TwinPanel.tsx` (Topology page), Assets page "Importance" |
| Database | `supabase/migrations/005_digital_twin.sql` |
| Tests | `tests/test_twin.py` |
