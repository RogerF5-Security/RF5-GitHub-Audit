"""GitHub CLI transport: fixed host, GET-only requests, bounded execution."""

import json
import re
import shutil
import subprocess
from urllib.parse import urlsplit


class ApiError(RuntimeError):
    def __init__(self, status, message):
        self.status = status
        super().__init__(message)


def redact(text):
    text = re.sub(r"\b(?:gh[pousr]_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+)\b", "[REDACTED]", text)
    text = re.sub(r"(?i)(authorization\s*:\s*)[^\r\n]+", r"\1[REDACTED]", text)
    return re.sub(r"(?i)((?:access_token|client_secret|token)=)[^\s&]+", r"\1[REDACTED]", text)


def validate_owner(owner):
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", owner):
        raise ValueError("Invalid GitHub owner")
    return owner


def validate_repo(full_name):
    parts = full_name.split("/")
    if len(parts) != 2 or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", parts[1]) or parts[1] in {".", ".."}:
        raise ValueError("Repository must be OWNER/REPOSITORY")
    validate_owner(parts[0])
    return full_name


def parse_json_stream(text):
    """gh --paginate --jq emits one JSON value per page."""
    values, decoder, remaining = [], json.JSONDecoder(), text.lstrip()
    while remaining:
        value, offset = decoder.raw_decode(remaining)
        values.append(value)
        remaining = remaining[offset:].lstrip()
    return values


class GitHubClient:
    def __init__(self, executable=None, timeout=60, runner=subprocess.run):
        self.executable = executable or shutil.which("gh")
        if not self.executable:
            raise ApiError(None, "GitHub CLI is required: https://cli.github.com/")
        self.timeout, self.runner = timeout, runner

    def _request(self, endpoint, *, paginate=False, projection=None):
        parsed = urlsplit(endpoint)
        if parsed.scheme or parsed.netloc or endpoint.startswith(("/", "-")) or ".." in parsed.path.split("/"):
            raise ValueError("Only relative GitHub API paths are allowed")
        if "/secret-scanning/alerts" in parsed.path and projection != "length":
            raise ValueError("Secret alert bodies are excluded; use secret_count")
        command = [self.executable, "api", endpoint, "--hostname", "github.com", "--method", "GET"]
        if paginate:
            command.append("--paginate")
        if projection:
            command += ["--jq", projection]
        try:
            result = self.runner(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=self.timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise ApiError(None, "GitHub request timed out") from exc
        except OSError as exc:
            raise ApiError(None, "Unable to execute GitHub CLI") from exc
        if result.returncode:
            error = redact(result.stderr or "GitHub request failed")
            status = re.search(r"\b(?:HTTP\s+)?(401|403|404|429|5\d\d)\b", error)
            raise ApiError(int(status.group(1)) if status else None, error.strip()[:400])
        return result.stdout

    def get(self, endpoint):
        text = self._request(endpoint)
        return json.loads(text) if text.strip() else None

    def pages(self, endpoint, projection):
        return parse_json_stream(self._request(endpoint, paginate=True, projection=projection))

    def secret_count(self, endpoint):
        # The application receives only counts, never alert bodies or secret values.
        pages = self.pages(endpoint, "length")
        if any(type(value) is not int or value < 0 for value in pages):
            raise ApiError(None, "Invalid secret-count response")
        return sum(pages)

    def public_repositories(self, owner):
        validate_owner(owner)
        user = self.get(f"users/{owner}")
        endpoint = f"orgs/{owner}/repos?type=public&per_page=100" if user["type"] == "Organization" else f"users/{owner}/repos?type=owner&per_page=100"
        pages = self.pages(endpoint, "map({full_name,private})")
        return [validate_repo(repo["full_name"]) for page in pages for repo in page if repo.get("private") is False]

    def owned_repositories(self, owner):
        validate_owner(owner)
        user = self.get(f"users/{owner}")
        if user["type"] == "Organization":
            endpoint = f"orgs/{owner}/repos?type=all&per_page=100"
        else:
            if self.get("user")["login"].lower() != owner.lower():
                raise ValueError("Private personal repositories require the authenticated owner's account")
            endpoint = "user/repos?affiliation=owner&visibility=all&per_page=100"
        pages = self.pages(endpoint, "map({full_name,private,owner:{login:.owner.login}})")
        return [validate_repo(repo["full_name"]) for page in pages for repo in page if repo["owner"]["login"].lower() == owner.lower()]
