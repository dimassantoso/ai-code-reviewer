#!/usr/bin/env python3
"""Setup wizard: ask for what the reviewer needs and write .env.

    make init                 # interactive
    python3 tools/init.py --env /path/.env
    python3 tools/init.py --yes   # no questions: current/environment/default values

Re-runnable: values already in .env (or exported in the environment) are the defaults,
so pressing Enter keeps them. Secrets are never echoed. An existing .env is backed up
before it is replaced. Stdlib only, like the server.
"""
import argparse
import getpass
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UNIT = "pasarpolis-ai-code-reviewer"

# (section, [(key, default, help)]) — the order .env is written in.
SECTIONS = [
    ("Platform credentials (configure at least one token + its webhook secret)", [
        ("GITLAB_URL", "https://gitlab.com", "GitLab base URL (HTTPS)"),
        ("GITLAB_TOKEN", "", "GitLab token with api scope"),
        ("GITLAB_WEBHOOK_SECRET", "", "GitLab webhook secret"),
        ("GITHUB_URL", "https://api.github.com", "GitHub API URL (Enterprise: https://host/api/v3)"),
        ("GITHUB_TOKEN", "", "GitHub token with pull request read/write"),
        ("GITHUB_WEBHOOK_SECRET", "", "GitHub webhook secret"),
    ]),
    ("Webhook server", [
        ("BIND_HOST", "0.0.0.0", "listen address"),
        ("BIND_PORT", "9877", "listen port(s), comma-separated"),
        ("PUBLIC_URL", "", "public base URL the platforms call (used by make add)"),
    ]),
    ("Bot identity and access", [
        ("BOT_USERNAME", "", "username that answers @mentions (blank disables replies)"),
        ("MIN_ACCESS_LEVEL", "30", "GitLab access to review/reply (30=Developer)"),
        ("APPROVE_ACCESS_LEVEL", "40", "GitLab access to auto-approve (40=Maintainer)"),
    ]),
    ("Model (Hermes Agent CLI)", [
        ("HERMES_BIN", "hermes", "hermes executable"),
        ("HERMES_PROFILE", "", "Hermes profile (blank = default home)"),
        ("HERMES_MODEL", "", "model override, e.g. anthropic/claude-sonnet-5-5 (blank = profile default)"),
        ("HERMES_SKILL", "ai-code-reviewer", "skill loaded into every review"),
        ("HERMES_TIMEOUT_S", "300", "seconds per model call"),
    ]),
    ("Review behaviour", [
        ("MAX_DIFF", "30000", "diff characters per model call before chunking"),
        ("REVIEW_BUDGET_S", "1200", "wall-clock budget for one chunked review"),
        ("MAX_INLINE", "20", "inline comments per review"),
        ("REVIEW_REPOS", "", "allowlist group/project,owner/repo (blank = every hooked repo)"),
        ("COOLDOWN_SECONDS", "30", "per-user per-thread reply cooldown"),
    ]),
    ("Capacity", [
        ("MAX_WORKERS", "4", "concurrent reviews"),
        ("QUEUE_SIZE", "100", "queued reviews before webhooks get 503"),
    ]),
    ("Dashboard and storage", [
        ("DASHBOARD_USER", "admin", "dashboard login"),
        ("DASHBOARD_PASSWORD", "", "dashboard password (blank = open; only behind a proxy/VPN)"),
        ("REVIEW_STORE", "./reviews.jsonl", "review history file"),
        ("MEMORY_DB", "./reviewer.db", "SQLite file of conceded mistakes (blank disables learning)"),
        ("LESSONS_IN_PROMPT", "10", "past mistakes fed into each review"),
    ]),
]
KNOWN = [key for _, fields in SECTIONS for key, _, _ in fields]
DEFAULTS = {key: default for _, fields in SECTIONS for key, default, _ in fields}
SECRET_KEYS = {"GITLAB_TOKEN", "GITHUB_TOKEN", "GITLAB_WEBHOOK_SECRET", "GITHUB_WEBHOOK_SECRET",
               "WEBHOOK_SECRET", "DASHBOARD_PASSWORD"}


def parse_env(text):
    """KEY=VALUE lines of a .env, comments and blanks ignored, surrounding quotes stripped."""
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[7:].strip()
        values[key] = value.strip().strip('"').strip("'")
    return values


def render_env(values):
    """The .env text: known keys grouped by section, any other existing keys kept at the end."""
    out = ["# Written by `make init` on %s. Re-run it to change values;" % time.strftime("%Y-%m-%d %H:%M"),
           "# Enter keeps the current one. Never commit this file.", ""]
    for title, fields in SECTIONS:
        out.append("# --- %s ---" % title)
        for key, _, help_text in fields:
            out.append("# %s" % help_text)
            out.append("%s=%s" % (key, values.get(key, "")))
        out.append("")
    extra = [k for k in values if k not in KNOWN]
    if extra:
        out.append("# --- Other settings (kept from the previous .env) ---")
        out += ["%s=%s" % (k, values[k]) for k in extra]
        out.append("")
    return "\n".join(out)


def mask(key, value):
    if key in SECRET_KEYS and value:
        return value[:4] + "…" + "*" * 6 if len(value) > 8 else "******"
    return value


def whoami(platform, url, token, opener=urlopen):
    """The token's username, proving the URL and token work. Raises ValueError otherwise."""
    api = url.rstrip("/") + ("/api/v4/user" if platform == "gitlab" else "/user")
    request = Request(api, headers={"Accept": "application/json", "User-Agent": "ai-code-reviewer-init",
                                    **({"PRIVATE-TOKEN": token} if platform == "gitlab"
                                       else {"Authorization": "Bearer " + token})})
    try:
        with opener(request, timeout=15) as response:
            data = json.loads(response.read() or b"{}")
    except HTTPError as error:
        raise ValueError("%s rejected the token (HTTP %s)" % (api, error.code)) from None
    except (URLError, OSError, ValueError) as error:
        raise ValueError("cannot reach %s: %s" % (api, getattr(error, "reason", error))) from None
    name = data.get("username") or data.get("login")
    if not name:
        raise ValueError("%s answered without a username" % api)
    return name


def smoke_test(values, run=subprocess.run):
    """One harmless review through the exact CLI options the service uses."""
    cmd = [values.get("HERMES_BIN") or "hermes"]
    if values.get("HERMES_PROFILE"):
        cmd += ["-p", values["HERMES_PROFILE"]]
    cmd += ["chat", "--query-file", "-", "-t", "", "-Q", "--max-turns", "5"]
    if values.get("HERMES_MODEL"):
        cmd += ["-m", values["HERMES_MODEL"]]
    if values.get("HERMES_SKILL"):
        cmd += ["-s", values["HERMES_SKILL"]]
    result = run(cmd, input="Review this harmless diff:\n+ return 1\n", capture_output=True, text=True,
                 timeout=int(values.get("HERMES_TIMEOUT_S") or 300))
    output = (result.stdout or "").strip()
    if result.returncode or not output:
        raise ValueError((result.stderr or output or "no output").strip()[-400:])
    return output


UNIT_TEMPLATE = """[Unit]
Description=AI Code Reviewer (Hermes Agent webhook service)
After=network-online.target

[Service]
Type=simple
WorkingDirectory={root}
EnvironmentFile={env}
Environment=PATH={path}
ExecStart={python} -u {root}/server.py
StandardOutput=append:{root}/server.log
StandardError=append:{root}/server.log
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
"""


class Wizard:
    def __init__(self, values, ask=input, secret=getpass.getpass, say=print, assume_yes=False):
        self.values, self.ask, self.secret, self.say, self.yes = values, ask, secret, say, assume_yes

    def text(self, key, label, required=False):
        current = self.values.get(key, "")
        if self.yes:
            return current
        while True:
            answer = self.ask("%s [%s]: " % (label, current) if current else "%s: " % label).strip()
            value = answer or current
            if value or not required:
                self.values[key] = value
                return value
            self.say("  required")

    def hidden(self, key, label, generate=False):
        current = self.values.get(key, "")
        if not current and generate:
            current = secrets.token_urlsafe(32)
            self.values[key] = current
            if self.yes:
                return current
            self.say("  generated a random %s (Enter keeps it)" % key)
        if self.yes:
            return current
        hint = "Enter keeps current" if current else "blank to skip"
        answer = self.secret("%s (%s): " % (label, hint)).strip()
        self.values[key] = answer or current
        return self.values[key]

    def confirm(self, label, default=False):
        if self.yes:
            return default
        answer = self.ask("%s [%s]: " % (label, "Y/n" if default else "y/N")).strip().lower()
        return default if not answer else answer in ("y", "yes")


def run_wizard(w, check=None, smoke=None, which=None):
    # Resolved at call time, not definition time, so tests can patch the module functions.
    check, smoke, which = check or whoami, smoke or smoke_test, which or shutil.which
    v, say = w.values, w.say
    say("\nAI Code Reviewer setup. Enter keeps the value in brackets.\n")

    has_gl, has_gh = bool(v.get("GITLAB_TOKEN")), bool(v.get("GITHUB_TOKEN"))
    default = "both" if has_gl and has_gh else "github" if has_gh else "gitlab"
    choice = default if w.yes else (w.ask("Platform: gitlab, github or both [%s]: " % default).strip().lower()
                                    or default)
    platforms = ["gitlab", "github"] if choice == "both" else [choice if choice in ("gitlab", "github") else "gitlab"]

    names = []
    for platform in platforms:
        p = platform.upper()
        say("\n== %s ==" % platform.capitalize())
        url = w.text(p + "_URL", "%s URL" % platform.capitalize(), required=True)
        token = w.hidden(p + "_TOKEN", "%s token" % platform.capitalize())
        if token:
            try:
                name = check(platform, url, token)
                names.append(name)
                say("  ok: token belongs to @%s" % name)
            except ValueError as error:
                say("  warning: %s" % error)
                if not w.confirm("  keep this token anyway?", default=w.yes):
                    v[p + "_TOKEN"] = ""
        w.hidden(p + "_WEBHOOK_SECRET", "%s webhook secret" % platform.capitalize(), generate=True)
    for platform in ("gitlab", "github"):
        if platform not in platforms and v.get(platform.upper() + "_TOKEN") and \
                w.confirm("Remove the %s settings?" % platform, default=False):
            for key in ("_TOKEN", "_WEBHOOK_SECRET"):
                v[platform.upper() + key] = ""
    if not any(v.get(p.upper() + "_TOKEN") for p in ("gitlab", "github")):
        say("  warning: no platform token set; the server will refuse to start until one is")

    say("\n== Webhook server ==")
    w.text("PUBLIC_URL", "Public URL the platforms call (e.g. https://reviewer.example.com)")
    w.text("BIND_HOST", "Listen address")
    w.text("BIND_PORT", "Listen port")
    if names and not v.get("BOT_USERNAME"):
        v["BOT_USERNAME"] = names[0]
    w.text("BOT_USERNAME", "Bot username for replies (blank disables replies)")

    say("\n== Model ==")
    if not v.get("HERMES_BIN") or v["HERMES_BIN"] == "hermes":
        v["HERMES_BIN"] = which("hermes") or v.get("HERMES_BIN") or "hermes"
    binary = w.text("HERMES_BIN", "Hermes executable")
    if not (os.path.isfile(binary) and os.access(binary, os.X_OK)) and not which(binary):
        say("  warning: %s not found. Install Hermes Agent: https://hermes-agent.nousresearch.com/docs/" % binary)
    w.text("HERMES_PROFILE", "Hermes profile (blank = default)")
    w.text("HERMES_MODEL", "Model (blank = profile default)")
    if w.confirm("Run one harmless review now to check the model?", default=False):
        try:
            say("  model answered: %s" % smoke(v)[:160].replace("\n", " "))
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            say("  warning: smoke test failed: %s" % error)
            say("  run `hermes setup` (with the same profile) to configure a provider")

    say("\n== Dashboard ==")
    w.text("DASHBOARD_USER", "Dashboard user")
    w.hidden("DASHBOARD_PASSWORD", "Dashboard password", generate=not v.get("DASHBOARD_PASSWORD"))
    w.text("MEMORY_DB", "Mistakes database (blank disables learning)")

    if w.confirm("\nAdjust advanced settings (workers, diff size, allowlist)?", default=False):
        for key in ("MAX_WORKERS", "QUEUE_SIZE", "MAX_DIFF", "REVIEW_BUDGET_S",
                    "HERMES_TIMEOUT_S", "MAX_INLINE", "REVIEW_REPOS", "MIN_ACCESS_LEVEL",
                    "APPROVE_ACCESS_LEVEL", "LESSONS_IN_PROMPT"):
            w.text(key, key)
    return v


def install_unit(env_path, say=print, run=subprocess.run):
    unit_dir = os.path.expanduser("~/.config/systemd/user")
    os.makedirs(unit_dir, exist_ok=True)
    path = os.path.join(unit_dir, UNIT + ".service")
    text = UNIT_TEMPLATE.format(root=ROOT, env=env_path, python=sys.executable,
                                path=os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"))
    if os.path.exists(path):
        shutil.copy2(path, path + ".bak")
    with open(path, "w") as fh:
        fh.write(text)
    run(["systemctl", "--user", "daemon-reload"], check=False)
    run(["systemctl", "--user", "enable", "--now", UNIT], check=False)
    say("  wrote %s and started it (make status / make logs)" % path)


def write_env(path, values):
    """Back up an existing file, then write atomically with owner-only permissions."""
    backup = None
    if os.path.exists(path):
        backup = "%s.%s.bak" % (path, time.strftime("%Y%m%d-%H%M%S"))
        shutil.copy2(path, backup)
        os.chmod(backup, 0o600)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(render_env(values))
    os.replace(tmp, path)
    os.chmod(path, 0o600)
    return backup


def main(argv=None, ask=input, secret=getpass.getpass, say=print):
    parser = argparse.ArgumentParser(description="Write .env for the AI code reviewer.")
    parser.add_argument("--env", default=os.path.join(ROOT, ".env"), help="file to write (default: ./.env)")
    parser.add_argument("--yes", action="store_true", help="no questions; keep current/env/default values")
    args = parser.parse_args(argv)

    values = dict(DEFAULTS)
    example = os.path.join(ROOT, ".env.example")
    if not os.path.exists(args.env) and os.path.exists(example):
        values.update({k: v for k, v in parse_env(open(example).read()).items() if v})
    if os.path.exists(args.env):
        values.update(parse_env(open(args.env).read()))
    values.update({k: os.environ[k] for k in KNOWN if os.environ.get(k)})  # exported values win

    wizard = Wizard(values, ask=ask, secret=secret, say=say, assume_yes=args.yes)
    try:
        run_wizard(wizard)
    except (KeyboardInterrupt, EOFError):
        say("\naborted; nothing written")
        return 1

    say("\n== Summary ==")
    for key in KNOWN:
        if values.get(key):
            say("  %-22s %s" % (key, mask(key, values[key])))
    if not wizard.confirm("\nWrite %s?" % args.env, default=True):
        say("nothing written")
        return 1
    backup = write_env(args.env, values)
    say("wrote %s (mode 600)%s" % (args.env, "; previous saved as %s" % backup if backup else ""))

    if not args.yes:
        if wizard.confirm("Install the review skill into the Hermes home now (make skill)?", default=True):
            subprocess.run(["make", "--no-print-directory", "-C", ROOT, "skill"], check=False)
        if shutil.which("systemctl") and wizard.confirm(
                "Install and start the systemd user service %s?" % UNIT, default=False):
            install_unit(args.env, say=say)

    public = values.get("PUBLIC_URL", "").rstrip("/") or "https://<your-host>"
    say("\nNext steps:")
    if values.get("GITLAB_TOKEN"):
        say("  GitLab webhook:  %s/gl-review   (make add REPO=group/project creates it)" % public)
    if values.get("GITHUB_TOKEN"):
        say("  GitHub webhook:  %s/gh-review   (make add REPO=owner/repo creates it)" % public)
    say("  Run directly:    set -a; . %s; set +a; python3 server.py" % args.env)
    say("  Or with Docker:  docker compose up -d --build")
    say("  Dashboard:       http://<host>:%s/dashboard" % (values.get("BIND_PORT") or "9877").split(",")[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
