# Mini-SOAR patch prioritization + Fix Impact Preview — method, formulas, sources

## 1. In one paragraph

Patch Prioritization ranks the possible fixes by **how much risk each one removes**, using
**component dependencies**, **asset importance** and the **exploit-aware finding score**. The
**Fix Impact Preview** shows the same before-and-after numbers for one fix before it is
approved. After every scan, each host is modelled as **components** (the operating system and
each open service) linked by **dependency rules**. Every candidate fix is applied to a copy of
this model in memory, never to the real host. When a fix is approved, its preview is stored,
and the next scan checks it against what really changed.

**Base paper [6]:** Y. Jiang, W. Wang, J. Ding, X. Lu, Y. Jing, "Leveraging Digital Twin
Technology for Enhanced Cybersecurity in Cyber–Physical Production Systems",
*Future Internet* 16(4):134, 2024. https://doi.org/10.3390/fi16040134

**What we take from it:** its *method* — dependency analysis, the criticality calculation and
virtual-patch risk analysis. **What we do not do:** build a digital twin. The paper uses a twin
of a factory. Mini-SOAR applies the method directly to scan data from an IT network. This is
the wording of the final proposal: "adapts the method of [6] … to IT networks without building
a digital twin."

## 2. The formulas

**Step 1 — finding risk (0–100).** This is the same score used everywhere else in Mini-SOAR.
It comes from CVSS, EPSS, CISA KEV, default passwords, service type, exposure, rogue device
and version confidence (`ml/`). Findings without a CVE (Nuclei, NetExec) are mapped to the same
inputs; see §5.

**Step 2 — component vulnerability score (CVS).** This is the severity-weighted average of the
finding risks on one component:

    CVS = Σ w(s)·s / Σ w(s)        w = 4 (s ≥ 80), 3 (60–79), 2 (40–59), 1 (< 40)

A working default password counts as one finding of risk 65.

**Step 3 — criticality (CCS).**

    D   = (components that depend on this one) / (highest such count in the network)
    W   = asset importance set by the admin: critical 1.0, normal 0.8, low 0.5
    CCS = W × (0.5 + 0.5 × D)                                   range 0.25 … 1.0

**Step 4 — component risk.**

    CRS = CCS × CVS            host risk = highest CRS of its components
                               network risk = sum of all CRS (also shown: average host risk)

**Step 5 — patch priority.** The candidate fixes are: block each risky port, lock each
default account, and vendor-patch each very bad CVE. Each one is applied to a copy of the
model. Fixes are ranked by how much the **network total CRS** drops, biggest drop first.
Fixes that do not lower the total are left out. Port 22 is never offered, because the engine
manages hosts over SSH.

**Step 6 — Fix Impact Preview.** For one fix (or several together) the preview shows:
- host CRS and grade, before → after
- network total and average, before → after
- open ports, findings, KEV findings and working default passwords, before → after
- what is expected to disappear
- the riskiest components left

It calls the **same functions** as the ranking, so a ranked fix and its preview always show
the same drop. A test (`test_preview_drop_equals_the_ranked_drop`) proves this.

**Step 7 — checking the prediction.** The preview is stored twice: when a fix is requested
(so the approver sees it) and again when the fix is approved (the one that counts). After the
fix runs and the post-fix check passes, the next scan compares the stored preview with reality:

    match = everything predicted to disappear did disappear
            AND |actual host CRS − predicted host CRS| ≤ 10

Fixes on the same host between two scans are checked together, because the scan sees all of
them at once. Prediction accuracy = matched / checked. [6] does not check its predictions.

**Baseline (the paper's own formulas), shown next to ours:**

    CVS_paper = Σ_i w_i · Sum(S_i) / Σ_i N_i   over CVSS bands critical / high / medium / low
    CCS_paper = number of dependency relations of the component (raw count)
    CRS_paper = CCS_paper × CVS_paper

**Comparison shown on the dashboard.** For each ranking (ours and the paper's), the dashboard
shows:
- how many of the top 5 fixes remove a CISA-KEV CVE or a working default password
- the rank at which the first such fix appears

Both are proxies for "really exploited" that do not depend on either formula.

## 3. Dependency rules ("A depends on B" = edge A → B)

We use 4 of the paper's 7 rules: embedding, interaction, data and network. Cascading-failure
propagation is not modelled.

| Rule | Added automatically | Example |
|---|---|---|
| embedding | every service runs on its host's OS | `ftp:21 → Linux OS` |
| data | a web/app server uses a database on the same host | `http:80 → mysql:3306` |
| interaction | RPC services register with the port mapper | `nfs:2049 → rpcbind:111` |
| network | every other host on the same /24 needs a directory server to log in (a host offering LDAP 389/636, Kerberos 88 or Global Catalog 3268/3269, e.g. an AD domain controller). Anything else is added by the admin | `PC OS → DC ldap:389` |

The admin can add a missing dependency, or hide a wrong automatic one, on the Patch
Prioritization page. Asset importance is set on the Assets page. Both actions are admin-only
and written to the audit log.

## 4. Kept, changed, added (for the report and viva)

| Paper element | Ours | Type | Reason / source |
|---|---|---|---|
| Digital twin of the production system | No twin. The method runs on scan data | Changed | Proposal wording; an IT lab does not need a full replica |
| Components + dependency rules | Same idea; components = OS + services; 4 of 7 rules | Adaptation | IT network instead of a factory |
| CCS from dependencies | Normalised, with a 0.5 floor | Improvement | Without the floor, a component nobody depends on (e.g. a backdoored FTP server) would rank almost nothing |
| Stakeholder weighting (interviews) | Asset importance in the dashboard | Improvement | Della Penna et al. [9]: asset-focused prioritisation beats CVSS; CISA SSVC [11] "mission prevalence" |
| CVS from CVSS only | CVS from our finding risk (EPSS + KEV + default passwords) | Improvement | Jacobs et al. [2]: CVSS alone is a poor predictor of exploitation |
| CRS = CCS × CVS | Same | Kept | — |
| Virtual patch + ranking rule | Automatic ranking by biggest drop in network risk | Improvement | The paper's ranking wording is unclear; ours is explicit |
| Not connected to real-time data | Rebuilt after every scan | Extension | Per scan, not live traffic (same limit as [6]) |
| Predictions never checked | Stored at approval, checked by the next scan | Extension | Our evaluation method |
| Stops at virtual patching | Real fix with approval, 2FA, post-fix check, rollback | Extension | Rest of Mini-SOAR |
| securiCAD attack simulation | Not used | Not adopted | Commercial tool; $0 budget |
| MongoDB + Shodan + CWE/CAPEC | Not used; NVD + EPSS + KEV in SQLite | Not adopted | Private lab; Shodan only sees the internet |

## 5. Findings without a CVE (Nuclei, NetExec)

Nuclei templates and NetExec checks often have no CVE, so they have no CVSS, EPSS or KEV
value. They are scored by the **same model** with the same 10 inputs, so no retraining is
needed (`ml/finding_map.py`):

| Input | Value |
|---|---|
| CVSS | the template's own CVSS when it has one; otherwise critical 9.5, high 8.0, medium 5.5, low 3.0, info 0 |
| EPSS / KEV | real values when the template names a CVE; otherwise 0 / not on KEV |
| version confirmed | yes (the tool saw the problem on the live service) |
| default password | a Nuclei `default-login` hit marks the service |

NetExec checks (CVSS-equivalent):

| Check | CVSS-equivalent |
|---|---|
| SMBv1 enabled | 8.1 |
| SMB signing not required | 6.5 |
| null-session login | 5.3 |
| anonymous readable share | 7.5 |
| anonymous writable share | 9.1 |
| RDP without NLA | 7.0 |
| WinRM on HTTP | 4.3 |

When Nuclei confirms a CVE that the version matcher had already found on the same port, no
second row is made. The existing row becomes "version-confirmed" and keeps the evidence.

## 6. Honest limitations

* **Our design choices, not the paper's.** The paper does not publish its weights, so these
  are ours: band weights 4/3/2/1, floor 0.5, importance 1.0/0.8/0.5, default-password score 65,
  tolerance 10, and the CVSS-equivalents above. They are all at the top of
  `soar/prioritization.py` and `ml/finding_map.py`.
* **CVS is an average, as in [6].** Removing only the milder finding of a component raises its
  average while the worse findings stay. The preview then says "Risk goes UP" and explains why.
  The ranking never suggests such a fix.
* **The improvement is not yet proven.** It is only shown once the comparison on the lab shows
  it. The dashboard shows both rankings side by side.
* **Synthetic training data.** The finding-risk model is trained on data labelled by the expert
  formula (`ml/bootstrap_data.py`). Any improvement comes from the EPSS, KEV and
  default-password inputs, not from the model learning something new.
* **Automatic dependencies are heuristics.** The admin can correct them.
* **Some prediction misses are expected.** The model cannot know about some changes, such as a
  new CVE published between two scans or a service restarted by hand. The check records the
  reason.

## 7. Where it is in the code

| What | File |
|---|---|
| Formulas, dependency rules, ranking, preview, prediction check, topology graph | `soar/prioritization.py` |
| Loading from Supabase (3 paged queries), previews stored with fixes, checks after a scan | `soar/prioritization_store.py` |
| Preview stored on request and refreshed on approval | `soar/approval.py` |
| Check after every scan | `scanner/engine.py` (summary `fix_checks`) |
| API: `GET /prioritization`, `GET /topology`, `POST /fix-preview`, `POST /prioritization/importance`, `POST /prioritization/dependency`, `POST /prioritization/dependency/remove` | `api/main.py` |
| Dashboard | Patch Prioritization page (`PrioritizationPanel.tsx`, `FixImpact.tsx`), Remediation approval card, live Topology page, Assets "Importance" |
| Database | `supabase/migrations/006_proposal_alignment.sql` (`assets.importance`, `component_dependencies`, `remediations.fix_prediction` / `fix_check`) |
| Tests | `tests/test_prioritization.py` |
