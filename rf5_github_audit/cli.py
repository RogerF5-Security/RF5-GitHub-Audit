"""Command-line entry point; demo mode works without authentication."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

from . import __version__
from .audit import run_audit
from .client import ApiError, GitHubClient, redact, validate_owner, validate_repo
from .report import write_reports


def demo_report():
    return {"schema_version": 1, "tool": "RF5 GitHub Audit", "version": __version__, "generated_at": datetime.now(timezone.utc).isoformat(), "mode": "read-only", "simulated": True, "scope": {"include_private": False, "requested": 3}, "summary": {"checked": 1, "attention": 1, "partial": 1}, "repositories": [
        {"repository": "example-org/public-tool", "description": "Herramienta de ejemplo con controles comprobados", "status": "checked", "controls": {"secret_scanning": "enabled", "secret_scanning_push_protection": "enabled"}, "checks": {"dependency_alerts": {"status": "checked", "value": {}}}, "coverage": {"checked": 8, "unavailable": 0}, "findings": []},
        {"repository": "example-org/legacy-tool", "description": "Ejemplo de alertas y permisos de escritura", "status": "attention", "controls": {"secret_scanning": "enabled", "secret_scanning_push_protection": "disabled"}, "checks": {"dependency_alerts": {"status": "checked", "value": {"high": 2}}}, "coverage": {"checked": 7, "unavailable": 1}, "findings": [{"severity": "high", "code": "open_dependency_alerts", "message": "2 alertas de dependencias pendientes de revisión"}]},
        {"repository": "example-org/limited-access", "description": "Ejemplo de información no disponible por permisos", "status": "partial", "controls": {"secret_scanning": "unknown"}, "checks": {}, "coverage": {"checked": 2, "unavailable": 6}, "findings": []}]}


def main(argv=None):
    parser = argparse.ArgumentParser(description="RF5 GitHub Audit: GitHub API posture inventory, GET-only.")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--owner", help="GitHub account or organization; default: authenticated user")
    parser.add_argument("--repo", action="append", default=[], metavar="OWNER/REPO", help="Explicit repository; repeatable")
    parser.add_argument("--include-private", action="store_true", help="Explicitly include owned private repositories in local reports")
    parser.add_argument("--limit", type=int, default=50, help="Maximum repositories, 1-500 (default: 50)")
    parser.add_argument("--workers", type=int, choices=range(1, 9), default=4)
    parser.add_argument("--output", type=Path, default=Path("reports"))
    parser.add_argument("--demo", action="store_true", help="Use clearly labelled synthetic data without network or authentication")
    args = parser.parse_args(argv)
    if not 1 <= args.limit <= 500:
        parser.error("--limit must be between 1 and 500")
    if args.demo and (args.repo or args.owner or args.include_private):
        parser.error("--demo cannot be combined with live targets")
    try:
        if args.demo:
            report = demo_report()
        else:
            client = GitHubClient()
            owner = validate_owner(args.owner or client.get("user")["login"])
            targets = [validate_repo(name) for name in args.repo]
            if not targets:
                targets = client.owned_repositories(owner) if args.include_private else client.public_repositories(owner)
            if not targets:
                raise ValueError("No repositories matched the requested scope")
            if len(targets) > args.limit:
                print(f"Scope limited to {args.limit} of {len(targets)} repositories", file=sys.stderr)
            report = run_audit(client, targets[:args.limit], include_private=args.include_private, workers=args.workers)
            report["scope"].update(discovered=len(targets), limit=args.limit, truncated=len(targets) > args.limit)
        paths = write_reports(report, args.output)
        print(json.dumps({"mode": report["mode"], "simulated": report["simulated"], "repositories": len(report["repositories"]), "summary": report["summary"], "json": str(paths[0].resolve()), "html": str(paths[1].resolve())}, ensure_ascii=True))
        return 0
    except (ApiError, ValueError, OSError, json.JSONDecodeError) as exc:
        print("RF5 GitHub Audit: " + redact(str(exc)), file=sys.stderr)
        return 2
