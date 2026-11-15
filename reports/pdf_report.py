"""
PDF security assessment report (reportlab).

Pulls the current state from Supabase (assets, vulns, tickets, remediations),
computes the security grade, lists prioritized findings, and appends a MITRE
ATT&CK technique mapping. Falls back to whatever data is available offline.

  python -m reports.pdf_report          # writes reports/out/mini-soar-report.pdf
"""
from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone

from common.db import get_service_client
from .mitre_mapping import map_all

OUT_DIR = Path("./reports/out")


def _grade(score: float) -> str:
    return "F" if score >= 80 else "D" if score >= 60 else "C" if score >= 40 else "B" if score >= 20 else "A"


def _gather() -> dict:
    """Current state from Supabase. Only OPEN findings and OPEN ports count."""
    client = get_service_client()
    if not client:
        return {"assets": [], "vulns": [], "services": [], "tickets": [], "remediations": []}
    services = client.table("services").select("*").execute().data
    return {
        "assets": client.table("assets").select("*").execute().data,
        "vulns": client.table("vulnerabilities").select("*").eq("status", "open")
                 .order("ml_risk_score", desc=True).limit(1000).execute().data,
        "services": [s for s in services if (s.get("state") or "open") == "open"],
        "tickets": client.table("tickets").select("*").execute().data,
        "remediations": client.table("remediations").select("*").execute().data,
    }


def _hosts_for_mitre(data: dict) -> list[dict]:
    """Rebuild each host (open services + open findings) for the ATT&CK mapping."""
    by_asset = {a["id"]: {"ip": a["ip"], "is_rogue": a.get("is_rogue"),
                          "services": [], "vulnerabilities": []} for a in data["assets"]}
    for s in data.get("services", []):
        h = by_asset.get(s["asset_id"])
        if h:
            h["services"].append({"service_name": s.get("service_name"),
                                  "has_default_cred": s.get("has_default_cred")})
    for v in data["vulns"]:
        h = by_asset.get(v["asset_id"])
        if h:
            h["vulnerabilities"].append({"in_kev": v.get("in_kev")})
    return list(by_asset.values())


def build_latest_report() -> str:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                    TableStyle)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "mini-soar-report.pdf"
    data = _gather()

    assets = data["assets"]
    net_score = (sum(a.get("risk_score") or 0 for a in assets) / len(assets)) if assets else 0
    grade = _grade(net_score)
    kev = [v for v in data["vulns"] if v.get("in_kev")]

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Title"], textColor=colors.HexColor("#1d4ed8"))
    story = []

    story.append(Paragraph("Mini-SOAR — Security Assessment Report", h1))
    story.append(Paragraph(
        f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} · "
        f"Lab environment · Authorized scope only", styles["Normal"]))
    story.append(Spacer(1, 8 * mm))

    # Summary
    story.append(Paragraph("Executive summary", styles["Heading2"]))
    summary = [
        ["Security grade", grade, "Avg risk", f"{net_score:.0f}/100"],
        ["Assets", str(len(assets)),
         "Rogue devices", str(sum(1 for a in assets if a.get("is_rogue")))],
        ["Open vulnerabilities", str(len(data["vulns"])),
         "On CISA KEV", str(len(kev))],
        ["Open tickets",
         str(sum(1 for t in data["tickets"] if t.get("status") not in ("resolved", "rejected"))),
         "Remediations", str(len(data["remediations"]))],
    ]
    t = Table(summary, colWidths=[35 * mm, 30 * mm, 35 * mm, 30 * mm])
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef2ff")),
        ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#eef2ff")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    story.append(t)
    story.append(Spacer(1, 6 * mm))

    # Assets with their grade
    story.append(Paragraph("Assets", styles["Heading2"]))
    arows = [["IP address", "Operating system", "Grade", "Risk", "Rogue"]]
    for a in sorted(assets, key=lambda x: x.get("risk_score") or 0, reverse=True)[:40]:
        arows.append([str(a.get("ip") or "-"), (a.get("os_guess") or "-")[:38],
                      a.get("risk_grade") or "-", f"{a.get('risk_score') or 0:.0f}",
                      "YES" if a.get("is_rogue") else "-"])
    if len(arows) == 1:
        arows.append(["(no assets yet)", "", "", "", ""])
    at = Table(arows, colWidths=[32 * mm, 62 * mm, 16 * mm, 16 * mm, 16 * mm])
    at.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f766e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
    ]))
    story.append(at)
    story.append(Spacer(1, 6 * mm))

    # Top findings
    story.append(Paragraph("Prioritized findings (KEV / EPSS / ML)", styles["Heading2"]))
    rows = [["CVE", "CVSS", "EPSS", "KEV", "ML risk"]]
    for v in data["vulns"][:20]:
        rows.append([
            v["cve_id"], str(v.get("cvss_score") or "-"),
            f"{(v.get('epss_score') or 0)*100:.1f}%",
            "YES" if v.get("in_kev") else "-",
            str(v.get("ml_risk_score") or "-"),
        ])
    if len(rows) == 1:
        rows.append(["(no findings yet)", "", "", "", ""])
    ft = Table(rows, colWidths=[45 * mm, 20 * mm, 25 * mm, 20 * mm, 25 * mm])
    ft.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1d4ed8")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
    ]))
    story.append(ft)
    story.append(Spacer(1, 6 * mm))

    # MITRE ATT&CK mapping
    story.append(Paragraph("MITRE ATT&CK coverage", styles["Heading2"]))
    mitre = map_all(_hosts_for_mitre(data))
    mrows = [["Technique", "Name", "Tactic"]]
    for tech in mitre["coverage"]:
        mrows.append([tech["technique_id"], tech["name"], tech["tactic"]])
    if len(mrows) == 1:
        mrows.append(["-", "No techniques mapped yet", "-"])
    mt = Table(mrows, colWidths=[25 * mm, 60 * mm, 55 * mm])
    mt.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#7c3aed")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
    ]))
    story.append(mt)
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph(
        "This report was produced by the Mini-SOAR platform against an authorized "
        "lab environment. All scanning and remediation were restricted to the "
        "configured allowlist.", styles["Italic"]))

    SimpleDocTemplate(str(out_path), pagesize=A4,
                      title="Mini-SOAR Security Report").build(story)
    return str(out_path)


if __name__ == "__main__":
    print("Report written to:", build_latest_report())
