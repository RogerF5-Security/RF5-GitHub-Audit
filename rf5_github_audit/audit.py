"""Collect posture evidence while keeping unavailable checks explicit."""

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import quote

from . import __version__
from .client import ApiError, validate_repo


def query(call):
    try:
        return {"status": "checked", "value": call()}
    except ApiError as exc:
        reason = {401: "authentication_required", 403: "permission_or_rate_limit", 404: "unavailable_or_not_authorized", 429: "rate_limited"}.get(exc.status, "request_failed")
        return {"status": "unavailable", "reason": reason, "http_status": exc.status}


def inspect_repository(client, full_name, include_private=False):
    validate_repo(full_name)
    data = client.get(f"repos/{full_name}")
    actual_name = validate_repo(data["full_name"])
    if actual_name.lower() != full_name.lower():
        raise ValueError("Repository redirect changed the requested target")
    if data.get("private") and not include_private:
        return {"repository": "[private repository skipped]", "status": "skipped", "reason": "private_repository_requires_opt_in"}
    base = f"repos/{actual_name}"
    security = data.get("security_and_analysis") or {}
    controls = {name: security.get(name, {}).get("status", "unknown") for name in ["secret_scanning", "secret_scanning_push_protection", "dependabot_security_updates"]}
    checks = {}
    checks["private_vulnerability_reporting"] = query(lambda: client.get(base + "/private-vulnerability-reporting"))
    checks["dependabot_alerts_enabled"] = query(lambda: client.get(base + "/vulnerability-alerts") is None)
    checks["workflow_permissions"] = query(lambda: client.get(base + "/actions/permissions/workflow"))
    branch = quote(data["default_branch"], safe="")
    checks["default_branch_rules"] = query(lambda: client.get(base + "/rules/branches/" + branch))
    def classic_protection():
        try:
            return client.get(base + "/branches/" + branch + "/protection")
        except ApiError as exc:
            if exc.status == 404 and "branch not protected" in str(exc).lower():
                return None
            raise
    checks["classic_branch_protection"] = query(classic_protection)
    projection = "group_by(.security_advisory.severity) | map({severity:.[0].security_advisory.severity,count:length})"
    def dependency_counts():
        counts = Counter()
        for page in client.pages(base + "/dependabot/alerts?state=open&per_page=100", projection):
            for group in page:
                severity, count = group["severity"], group["count"]
                if severity not in {"critical", "high", "medium", "low"} or type(count) is not int or count < 0:
                    raise ValueError("Invalid dependency-alert aggregate")
                counts[severity] += count
        return dict(counts)
    checks["dependency_alerts"] = query(dependency_counts)
    checks["secret_alerts"] = query(lambda: client.secret_count(base + "/secret-scanning/alerts?state=open&per_page=100"))
    findings = []
    for name in ["secret_scanning", "secret_scanning_push_protection"]:
        if controls[name] == "disabled":
            findings.append({"severity": "high", "code": name + "_disabled", "message": name + " is disabled"})
    reporting = checks["private_vulnerability_reporting"]
    if reporting["status"] == "checked" and reporting["value"].get("enabled") is False:
        findings.append({"severity": "low", "code": "private_reporting_disabled", "message": "Private vulnerability reporting is disabled"})
    rules, classic = checks["default_branch_rules"], checks["classic_branch_protection"]
    if rules["status"] == classic["status"] == "checked" and not rules["value"] and not classic["value"]:
        findings.append({"severity": "medium", "code": "default_branch_unprotected", "message": "No classic protection or active rules were returned for the default branch"})
    permissions = checks["workflow_permissions"]
    if permissions["status"] == "checked":
        if permissions["value"]["default_workflow_permissions"] == "write":
            findings.append({"severity": "medium", "code": "workflow_default_write", "message": "Default Actions token has write permissions"})
        if permissions["value"].get("can_approve_pull_request_reviews"):
            findings.append({"severity": "medium", "code": "workflow_review_approval", "message": "Actions may approve pull requests"})
    for check_name, severity in [("dependency_alerts", "high"), ("secret_alerts", "high")]:
        check = checks[check_name]
        count = sum(check["value"].values()) if check_name == "dependency_alerts" and check["status"] == "checked" else check.get("value", 0)
        if check["status"] == "checked" and count:
            if check_name == "dependency_alerts":
                severity = next(level for level in ["critical", "high", "medium", "low"] if check["value"].get(level))
            findings.append({"severity": severity, "code": "open_" + check_name, "message": f"{count} open GitHub {check_name.replace('_', ' ')}"})
    missing = sum(check["status"] != "checked" for check in checks.values())
    status = "attention" if findings else "partial" if missing or "unknown" in controls.values() else "checked"
    return {"repository": actual_name, "url": f"https://github.com/{actual_name}", "private": bool(data["private"]), "archived": bool(data["archived"]), "description": data.get("description") or "", "default_branch": data["default_branch"], "status": status, "controls": controls, "checks": checks, "findings": findings, "coverage": {"checked": len(checks) - missing, "unavailable": missing}}


def run_audit(client, repositories, *, include_private=False, workers=4):
    repositories = list(dict.fromkeys(validate_repo(name) for name in repositories))
    if not 1 <= workers <= 8:
        raise ValueError("workers must be between 1 and 8")
    def inspect(name):
        try:
            return inspect_repository(client, name, include_private)
        except ApiError as exc:
            return {"repository": name, "status": "unavailable", "http_status": exc.status}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(inspect, repositories))
    return {"schema_version": 1, "tool": "RF5 GitHub Audit", "version": __version__, "generated_at": datetime.now(timezone.utc).isoformat(), "mode": "read-only", "simulated": False, "scope": {"include_private": include_private, "requested": len(repositories)}, "repositories": results, "summary": dict(Counter(result["status"] for result in results))}
