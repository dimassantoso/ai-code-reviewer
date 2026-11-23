#!/usr/bin/env python3
"""Install the AI reviewer on a repo: create its webhook, then prove it exists.

    python3 tools/add_repo.py pasarpolis/newservice
    python3 tools/add_repo.py https://gitlab.com/pasarpolis/newservice

Reads .env next to the Makefile. Idempotent: re-running updates the existing hook
instead of creating a duplicate.
"""
import json
import os
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GL_EVENTS = {"merge_requests_events": True, "note_events": True, "push_events": False,
             "tag_push_events": False, "issues_events": False, "wiki_page_events": False,
             "pipeline_events": False, "deployment_events": False, "releases_events": False,
             "enable_ssl_verification": True}
GH_EVENTS = ["pull_request", "pull_request_review_comment", "issue_comment"]


def env():
    values = {}
    path = os.path.join(ROOT, ".env")
    if not os.path.exists(path):
        sys.exit("no .env next to the Makefile; copy .env.example first")
    for line in open(path):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def call(url, token, method="GET", body=None, platform="gitlab"):
    """One API call; returns parsed JSON. Raises with the platform's error message."""
    data = json.dumps(body).encode() if body is not None else None
    request = Request(url, data=data, method=method)
    request.add_header("PRIVATE-TOKEN" if platform == "gitlab" else "Authorization",
                       token if platform == "gitlab" else "Bearer " + token)
    request.add_header("Content-Type", "application/json")
    request.add_header("Accept", "application/json")
    try:
        with urlopen(request, timeout=30) as response:
            raw = response.read()
            return json.loads(raw) if raw.strip() else {}
    except HTTPError as error:
        detail = error.read().decode(errors="replace")[:300]
        raise SystemExit("%s %s -> %s: %s" % (method, url, error.code, detail))
    except URLError as error:
        raise SystemExit("%s %s -> %s" % (method, url, error.reason))


def parse_repo(argument):
    """`group/project` or a git URL -> (platform, group/project)."""
    text = argument.strip()
    platform = "gitlab"
    if text.startswith("git@"):
        text = re.sub(r"^git@([^:]+):", r"https://\1/", text)
    if re.match(r"(?i)^[a-z0-9.-]+\.(com|net|org|io|dev|id)/[^/]+/[^/]+", text):
        text = "https://" + text  # bare host/path, no scheme
    if text.startswith(("http://", "https://")):
        host = urlsplit(text).netloc.lower()
        path = urlsplit(text).path
        if "github" in host:
            platform = "github"
        text = path
    text = re.sub(r"^/+", "", text)
    text = re.sub(r"\.git$", "", text)
    text = re.sub(r"/(-\/.*|tree/.*|blob/.*)$", "", text) or text
    parts = [p for p in text.split("/") if p]
    if len(parts) < 2:
        sys.exit("need group/project, got %r" % argument)
    return platform, "/".join(parts[:2])


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: python3 tools/add_repo.py <repo name or url>")
    config = env()
    platform, repo = parse_repo(sys.argv[1])
    public = config.get("PUBLIC_URL", "").rstrip("/")
    if not public:
        sys.exit("PUBLIC_URL is not set in .env — the public base URL the platform calls, "
                 "e.g. https://reviewer.example.com")
    path = "/gl-review" if platform == "gitlab" else "/gh-review"
    hook_url = public + path
    secret = (config.get("GITLAB_WEBHOOK_SECRET") or config.get("GITHUB_WEBHOOK_SECRET")
              or config.get("WEBHOOK_SECRET"))
    token = config.get("GITLAB_TOKEN" if platform == "gitlab" else "GITHUB_TOKEN")
    if not token:
        sys.exit("no %s_TOKEN in .env" % platform.upper())

    if platform == "gitlab":
        base = (config.get("GITLAB_URL") or "https://gitlab.com").rstrip("/") + "/api/v4"
        project = call("%s/projects/%s" % (base, quote(repo, safe="")), token)
        if not isinstance(project, dict) or "id" not in project:
            sys.exit("cannot read %s" % repo)
        hooks_url = "%s/projects/%s/hooks" % (base, project["id"])
        hooks = call(hooks_url, token)
        existing = next((h for h in hooks if str(h.get("url", "")).rstrip("/") == hook_url), None)
        body = dict(GL_EVENTS, url=hook_url, token=secret) if secret else dict(GL_EVENTS, url=hook_url)
        if existing:
            hook = call("%s/%s" % (hooks_url, existing["id"]), token, "PUT", body)
            action = "updated"
        else:
            hook = call(hooks_url, token, "POST", body)
            action = "created"
        # prove it exists and carries the events we need
        saved = call("%s/%s" % (hooks_url, hook["id"]), token)
        events = sorted(k for k in GL_EVENTS if saved.get(k))
        print("%s gitlab webhook %s on %s -> %s" % (action, saved["id"], repo, hook_url))
        print("events: %s" % ", ".join(events))
        if not saved.get("merge_requests_events"):
            sys.exit("merge_requests_events is off — reviews would never fire")
    else:
        base = (config.get("GITHUB_URL") or "https://api.github.com").rstrip("/")
        repo_info = call("%s/repos/%s" % (base, repo), token, platform="github")
        hooks_url = "%s/repos/%s/hooks" % (base, repo_info["full_name"])
        hooks = call(hooks_url, token, platform="github")
        existing = next((h for h in hooks
                         if str((h.get("config") or {}).get("url", "")).rstrip("/") == hook_url), None)
        body = {"name": "web", "active": True, "events": GH_EVENTS,
                "config": {"url": hook_url, "content_type": "json",
                           **({"secret": secret} if secret else {})}}
        if existing:
            hook = call("%s/%s" % (hooks_url, existing["id"]), token, "PATCH", body, platform="github")
            action = "updated"
        else:
            hook = call(hooks_url, token, "POST", body, platform="github")
            action = "created"
        saved = call("%s/%s" % (hooks_url, hook["id"]), token, platform="github")
        print("%s github webhook %s on %s -> %s" % (action, saved["id"], repo, hook_url))
        print("events: %s" % ", ".join(sorted(saved.get("events") or [])))
        if "pull_request" not in (saved.get("events") or []):
            sys.exit("pull_request event is off — reviews would never fire")

    # keep a REVIEW_REPOS allowlist in sync, but only if one is already in use
    allow = [r.strip() for r in (config.get("REVIEW_REPOS") or "").split(",") if r.strip()]
    if allow and repo.lower() not in [a.lower() for a in allow]:
        allow.append(repo)
        write_env({**config, "REVIEW_REPOS": ",".join(allow)})
        print("added to REVIEW_REPOS: %s" % ", ".join(allow))


def write_env(config):
    """Rewrite .env keeping order and comments; only the keys in `config` are touched."""
    path = os.path.join(ROOT, ".env")
    lines, seen = [], set()
    for line in open(path).read().splitlines():
        key = line.split("=", 1)[0].strip()
        if key in config and not line.lstrip().startswith("#") and "=" in line:
            lines.append("%s=%s" % (key, config[key]))
            seen.add(key)
        else:
            lines.append(line)
    for key, value in config.items():
        if key not in seen:
            lines.append("%s=%s" % (key, value))
    open(path, "w").write("\n".join(lines) + "\n")
    os.chmod(path, 0o600)


if __name__ == "__main__":
    main()
