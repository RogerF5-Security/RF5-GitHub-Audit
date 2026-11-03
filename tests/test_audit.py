import contextlib
from copy import deepcopy
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from rf5_github_audit.audit import inspect_repository, query, run_audit
from rf5_github_audit.cli import demo_report, main
from rf5_github_audit.client import ApiError, GitHubClient, parse_json_stream, redact, validate_owner, validate_repo
from rf5_github_audit.report import render_html, write_reports


class FakeClient:
    def __init__(self):
        self.data = {"full_name": "example-org/tool", "private": False, "archived": False, "description": "Example", "default_branch": "main", "security_and_analysis": {name: {"status": "enabled"} for name in ["secret_scanning", "secret_scanning_push_protection", "dependabot_security_updates"]}}
        self.permission_failure = False
        self.rules = [{"type": "non_fast_forward"}, {"type": "deletion"}]
        self.secrets = 0
        self.dependency_pages = [[], []]

    def get(self, endpoint):
        if endpoint == "repos/example-org/tool":
            return deepcopy(self.data)
        if self.permission_failure:
            raise ApiError(403, "Forbidden")
        if endpoint.endswith("/private-vulnerability-reporting"):
            return {"enabled": True}
        if endpoint.endswith("/vulnerability-alerts"):
            return None
        if endpoint.endswith("/actions/permissions/workflow"):
            return {"default_workflow_permissions": "read", "can_approve_pull_request_reviews": False}
        if "/rules/branches/" in endpoint:
            return self.rules
        if endpoint.endswith("/protection"):
            raise ApiError(404, "Branch not protected (HTTP 404)")
        raise AssertionError(endpoint)

    def pages(self, endpoint, projection):
        if self.permission_failure:
            raise ApiError(403, "Forbidden")
        return self.dependency_pages

    def secret_count(self, endpoint):
        if self.permission_failure:
            raise ApiError(403, "Forbidden")
        return self.secrets


class TransportTests(unittest.TestCase):
    def test_get_only_fixed_host_and_no_shell(self):
        calls = []
        def runner(args, **kwargs):
            calls.append((args, kwargs))
            return SimpleNamespace(returncode=0, stdout='{"ok":true}', stderr="")
        client = GitHubClient("gh", runner=runner)
        self.assertEqual(client.get("repos/example-org/tool"), {"ok": True})
        args, kwargs = calls[0]
        self.assertEqual(args[args.index("--method") + 1], "GET")
        self.assertEqual(args[args.index("--hostname") + 1], "github.com")
        self.assertNotIn("shell", kwargs)
        self.assertNotIn("--input", args)

    def test_reject_external_host_and_traversal(self):
        client = GitHubClient("gh")
        for value in ["https://evil.example/user", "//evil.example", "../user", "repos/../user", "-F"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                client.get(value)

    def test_secret_bodies_are_rejected_before_transport(self):
        client = GitHubClient("gh", runner=lambda *args, **kwargs: self.fail("transport should not run"))
        with self.assertRaises(ValueError):
            client.get("repos/example-org/tool/secret-scanning/alerts")

    def test_secret_pagination_receives_only_counts(self):
        def runner(args, **kwargs):
            self.assertEqual(args[args.index("--jq") + 1], "length")
            self.assertIn("--paginate", args)
            return SimpleNamespace(returncode=0, stdout="100\n2\n", stderr="")
        self.assertEqual(GitHubClient("gh", runner=runner).secret_count("repos/example-org/tool/secret-scanning/alerts"), 102)

    def test_invalid_secret_count_rejected(self):
        client = GitHubClient("gh", runner=lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout='{"secret":"excluded"}', stderr=""))
        with self.assertRaises(ApiError):
            client.secret_count("repos/example-org/tool/secret-scanning/alerts")

    def test_api_error_redacts_tokens(self):
        token = "ghp_" + "A" * 36
        client = GitHubClient("gh", runner=lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout="", stderr=f"HTTP 403 Authorization: Bearer {token}"))
        with self.assertRaises(ApiError) as raised:
            client.get("user")
        self.assertEqual(raised.exception.status, 403)
        self.assertNotIn(token, str(raised.exception))

    def test_timeout_reported_without_trace_data(self):
        def runner(*args, **kwargs):
            raise subprocess.TimeoutExpired("gh", 60)
        with self.assertRaisesRegex(ApiError, "timed out"):
            GitHubClient("gh", runner=runner).get("user")

    def test_json_pagination_stream(self):
        self.assertEqual(parse_json_stream('[{"a":1}]\n[{"a":2}]\n'), [[{"a": 1}], [{"a": 2}]])

    def test_scope_validation(self):
        self.assertEqual(validate_owner("example-org"), "example-org")
        self.assertEqual(validate_repo("example-org/project.v1"), "example-org/project.v1")
        for name in ["owner/../repo", "owner/repo?x=1", "owner/..", "-owner/repo", "owner/repo/extra"]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_repo(name)

    def test_redact_query_credentials(self):
        self.assertNotIn("sensitive", redact("access_token=sensitive&client_secret=sensitive"))


class AuditTests(unittest.TestCase):
    def test_checked_controls(self):
        result = inspect_repository(FakeClient(), "example-org/tool")
        self.assertEqual(result["status"], "checked")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["coverage"]["unavailable"], 0)

    def test_403_is_partial_not_clean(self):
        client = FakeClient()
        client.permission_failure = True
        result = inspect_repository(client, "example-org/tool")
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["checks"]["secret_alerts"]["status"], "unavailable")
        self.assertNotIn("value", result["checks"]["secret_alerts"])

    def test_private_requires_explicit_opt_in(self):
        client = FakeClient()
        client.data["private"] = True
        result = inspect_repository(client, "example-org/tool")
        self.assertEqual(result["status"], "skipped")
        self.assertNotIn("example-org/tool", json.dumps(result))
        self.assertNotEqual(inspect_repository(client, "example-org/tool", True)["status"], "skipped")

    def test_repository_rename_does_not_widen_scope(self):
        client = FakeClient()
        client.data["full_name"] = "other-owner/other-tool"
        with self.assertRaises(ValueError):
            inspect_repository(client, "example-org/tool")

    def test_alert_totals_cover_multiple_pages_and_keep_severity(self):
        client = FakeClient()
        client.dependency_pages = [[{"severity": "low", "count": 100}], [{"severity": "low", "count": 7}]]
        result = inspect_repository(client, "example-org/tool")
        finding = next(f for f in result["findings"] if f["code"] == "open_dependency_alerts")
        self.assertEqual(result["checks"]["dependency_alerts"]["value"], {"low": 107})
        self.assertEqual(finding["severity"], "low")

    def test_unprotected_default_branch_flagged(self):
        client = FakeClient()
        client.rules = []
        result = inspect_repository(client, "example-org/tool")
        self.assertIn("default_branch_unprotected", [f["code"] for f in result["findings"]])

    def test_disabled_control_flagged(self):
        client = FakeClient()
        client.data["security_and_analysis"]["secret_scanning"]["status"] = "disabled"
        self.assertEqual(inspect_repository(client, "example-org/tool")["status"], "attention")

    def test_unknown_metadata_is_partial(self):
        client = FakeClient()
        client.data["security_and_analysis"] = {}
        self.assertEqual(inspect_repository(client, "example-org/tool")["status"], "partial")

    def test_query_404_is_not_zero_alerts(self):
        result = query(lambda: (_ for _ in ()).throw(ApiError(404, "Not Found")))
        self.assertEqual(result["status"], "unavailable")
        self.assertNotIn("value", result)

    def test_unavailable_repository_keeps_scope(self):
        class Missing:
            def get(self, endpoint):
                raise ApiError(404, "Not Found")
        result = run_audit(Missing(), ["example-org/missing"])
        self.assertEqual(result["summary"], {"unavailable": 1})


class ReportTests(unittest.TestCase):
    def test_truncated_scope_is_visible(self):
        report = demo_report()
        report["scope"].update(truncated=True, discovered=10)
        self.assertIn("se revisaron 3 de 10 repositorios", render_html(report))

    def test_description_is_html_escaped(self):
        report = demo_report()
        report["repositories"][0]["description"] = '<img src=x onerror="alert(1)">'
        output = render_html(report)
        self.assertNotIn('<img src=x', output)
        self.assertIn('&lt;img src=x', output)
        self.assertIn("Content-Security-Policy", output)
        self.assertIn("nonce-", output)

    def test_demo_is_labelled_and_offline(self):
        output = render_html(demo_report())
        self.assertIn("DATOS SIMULADOS", output)
        self.assertNotIn('<script src=', output)
        self.assertNotIn('fetch(', output)

    def test_existing_reports_are_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = write_reports(demo_report(), tmp)
            second = write_reports(demo_report(), tmp)
            self.assertNotEqual(first, second)
            self.assertTrue(all(p.exists() for p in first + second))

    def test_demo_cli_does_not_construct_a_client(self):
        with tempfile.TemporaryDirectory() as tmp, patch("rf5_github_audit.cli.GitHubClient", side_effect=AssertionError), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["--demo", "--output", tmp]), 0)
            self.assertEqual(len(list(Path(tmp).glob("*.json"))), 1)


if __name__ == "__main__":
    unittest.main()
