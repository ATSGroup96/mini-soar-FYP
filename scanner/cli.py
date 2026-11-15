"""
Scanner CLI — the container entrypoint.

Usage:
  python -m scanner.cli scan [--scope env | --targets 192.168.56.101,...] [--full-ports]
  python -m scanner.cli discover
  python -m scanner.cli verify-audit
  python -m scanner.cli show-scope
"""
from __future__ import annotations

import argparse
import json
import sys

from common.config import get_settings, assert_authorized_to_run, AuthorizationError

try:
    from rich.console import Console
    from rich.table import Table
    console = Console()
    _HAVE_RICH = True
except Exception:  # rich is optional; fall back to plain output
    _HAVE_RICH = False

    class _Plain:
        @staticmethod
        def _strip(s):
            import re
            # strip only rich-style tags ([bold], [/green], [bold red]);
            # leave real bracketed content like list reprs untouched
            return re.sub(r"\[/?[a-zA-Z][a-zA-Z0-9 _#]*\]", "", str(s))

        def print(self, *a, **k):
            print(*[self._strip(x) for x in a])

        def print_json(self, data):
            print(data)

    class Table:  # minimal shim
        def __init__(self, title=""):
            self.title, self.cols, self.rows = title, [], []

        def add_column(self, name, **k):
            self.cols.append(name)

        def add_row(self, *vals):
            self.rows.append(vals)

    console = _Plain()


def _cmd_show_scope(_args) -> int:
    from common.scope_store import effective_scope
    s = get_settings()
    sc = effective_scope(force=True)
    console.print("[bold]Authorized scope[/bold]")
    console.print(f"  SOURCE              : {sc['source']}")
    console.print(f"  AUTHORIZED_LAB_ONLY : {s.authorized_lab_only} (.env master switch)")
    console.print(f"  NETWORK AUTHORIZED  : {sc['authorized']}  {sc['note']}")
    console.print(f"  ALLOWED_RANGES      : {[str(n) for n in sc['allowed_ranges']]}")
    console.print(f"  DENY_HOSTS          : {sc['deny_hosts']}")
    console.print(f"  FORCE_DRY_RUN       : {s.force_dry_run}")
    try:
        assert_authorized_to_run()
        console.print("[green]Authorization gate: PASS[/green]")
    except AuthorizationError as e:
        console.print(f"[red]Authorization gate: FAIL — {e}[/red]")
        return 1
    return 0


def _cmd_discover(_args) -> int:
    from . import discovery
    hosts = discovery.discover()
    table = Table(title="Live hosts")
    table.add_column("IP"); table.add_column("MAC"); table.add_column("Method")
    for h in hosts:
        table.add_row(h.ip, h.mac or "-", h.method)
    if _HAVE_RICH:
        console.print(table)
    else:
        print("IP\tMAC\tMethod")
        for h in hosts:
            print(f"{h.ip}\t{h.mac or '-'}\t{h.method}")
    return 0


def _cmd_scan(args) -> int:
    from . import engine
    targets = None
    if args.targets:
        targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    try:
        result = engine.run_scan(targets=targets, full_ports=args.full_ports)
    except engine.ScanBusy as e:
        console.print(f"[yellow]{e}[/yellow]")
        return 2
    console.print_json(json.dumps(result["meta"]))
    console.print(f"[bold]Uplink:[/bold] {result['uplink']}")
    for h in result["hosts"]:
        console.print(
            f"  [cyan]{h['ip']}[/cyan] {h.get('os_guess','?')} — "
            f"{len(h['services'])} services, "
            f"{len(h.get('default_creds', []))} default-cred, "
            f"{len(h.get('vulnerabilities', []))} CVE"
            + ("  [red](ROGUE)[/red]" if h.get("is_rogue") else "")
        )
    return 0


def _cmd_verify_audit(_args) -> int:
    from common.audit import verify_chain
    ok, n, msg = verify_chain()
    color = "green" if ok else "red"
    console.print(f"[{color}]{msg}[/{color}]")
    return 0 if ok else 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scanner", description="Mini-SOAR scanner")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="run a full scan")
    p_scan.add_argument("--scope", choices=["env"], default="env",
                        help="use ALLOWED_RANGES from .env (default)")
    p_scan.add_argument("--targets", help="comma-separated IPs (must be in scope)")
    p_scan.add_argument("--full-ports", action="store_true", help="scan all 65535 ports")
    p_scan.set_defaults(func=_cmd_scan)

    sub.add_parser("discover", help="host discovery only").set_defaults(func=_cmd_discover)
    sub.add_parser("show-scope", help="print scope + auth gate").set_defaults(func=_cmd_show_scope)
    sub.add_parser("verify-audit", help="verify audit hash chain").set_defaults(func=_cmd_verify_audit)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except AuthorizationError as e:
        console.print(f"[red]Refused: {e}[/red]")
        return 1


if __name__ == "__main__":
    sys.exit(main())
