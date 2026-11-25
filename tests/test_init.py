#!/usr/bin/env python3
"""Checks for tools/init.py, the setup wizard. Never touches the real .env or the network."""
import importlib.util
import os
import pathlib
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

TOOLS = pathlib.Path(__file__).resolve().parent.parent / "tools"
spec = importlib.util.spec_from_file_location("init_wizard", TOOLS / "init.py")
init = importlib.util.module_from_spec(spec)
sys.modules["init_wizard"] = init
spec.loader.exec_module(init)


def scripted(answers):
    """An input() replacement that replays answers in order (Enter = "")."""
    queue = list(answers)
    return lambda prompt="": queue.pop(0) if queue else ""


class EnvFileTests(unittest.TestCase):
    def test_parse_handles_comments_quotes_and_export(self):
        values = init.parse_env('# c\nA=1\nexport B="two"\nC=\'3\'\n\nnot a line\nD=x=y\n')
        self.assertEqual(values, {"A": "1", "B": "two", "C": "3", "D": "x=y"})

    def test_render_round_trips_and_keeps_unknown_keys(self):
        values = dict(init.DEFAULTS, GITLAB_TOKEN="glpat-x", HERMES_UID="1000")
        parsed = init.parse_env(init.render_env(values))
        self.assertEqual(parsed["GITLAB_TOKEN"], "glpat-x")
        self.assertEqual(parsed["HERMES_UID"], "1000")
        self.assertEqual(parsed["MAX_WORKERS"], "4")

    def test_mask_hides_secrets_only(self):
        self.assertNotIn("supersecretvalue", init.mask("GITLAB_TOKEN", "supersecretvalue"))
        self.assertEqual(init.mask("BIND_PORT", "9877"), "9877")

    def test_write_backs_up_and_is_owner_only(self):
        path = os.path.join(tempfile.mkdtemp(), ".env")
        with open(path, "w") as fh:
            fh.write("OLD=1\n")
        backup = init.write_env(path, {"GITLAB_TOKEN": "t"})
        self.assertTrue(os.path.exists(backup))
        self.assertEqual(open(backup).read(), "OLD=1\n")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(init.parse_env(open(path).read())["GITLAB_TOKEN"], "t")


class WizardTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.env = os.path.join(self.dir, ".env")
        self.out = []
        self.clean = patch.dict(os.environ, {k: "" for k in init.KNOWN})
        self.clean.start()
        self.addCleanup(self.clean.stop)

    def run_main(self, answers, secrets_, argv=(), check=None):
        check = check or (lambda platform, url, token: "reviewbot")
        with patch.object(init, "whoami", side_effect=check), \
                patch.object(init, "smoke_test", return_value="LGTM"), \
                patch.object(init.subprocess, "run") as run, \
                patch.object(init.shutil, "which", return_value="/usr/bin/hermes"):
            code = init.main(["--env", self.env, *argv], ask=scripted(answers),
                             secret=scripted(secrets_), say=self.out.append)
        return code, run

    def test_fresh_gitlab_setup(self):
        answers = ["gitlab", "",                      # platform, GitLab URL default
                   "https://rev.example.com", "", "", "",  # public URL, bind host/port, bot username
                   "", "codereview", "",               # hermes bin, profile, model
                   "n",                                # smoke test
                   "", "",                             # dashboard user, memory db
                   "n", "y", "n", "n"]                 # advanced, write, make skill, systemd
        code, run = self.run_main(answers, ["glpat-secret", "", ""])
        self.assertEqual(code, 0)
        values = init.parse_env(open(self.env).read())
        self.assertEqual(values["GITLAB_TOKEN"], "glpat-secret")
        self.assertGreaterEqual(len(values["GITLAB_WEBHOOK_SECRET"]), 32)  # generated
        self.assertGreaterEqual(len(values["DASHBOARD_PASSWORD"]), 32)     # generated
        self.assertEqual(values["BOT_USERNAME"], "reviewbot")              # from the token check
        self.assertEqual(values["HERMES_BIN"], "/usr/bin/hermes")
        self.assertEqual(values["HERMES_PROFILE"], "codereview")
        self.assertEqual(values["PUBLIC_URL"], "https://rev.example.com")
        self.assertEqual(values["MEMORY_DB"], "./reviewer.db")
        self.assertFalse(any("glpat-secret" in line for line in self.out), "secret echoed")
        self.assertTrue(any("/gl-review" in line for line in self.out))
        run.assert_not_called()  # skill install and systemd declined

    def test_rerun_keeps_existing_values(self):
        with open(self.env, "w") as fh:
            fh.write("GITLAB_TOKEN=glpat-old\nGITLAB_WEBHOOK_SECRET=keepme\nHERMES_MODEL=m1\nHERMES_UID=1000\n")
        code, _ = self.run_main([], [], argv=["--yes"])
        self.assertEqual(code, 0)
        values = init.parse_env(open(self.env).read())
        self.assertEqual((values["GITLAB_TOKEN"], values["GITLAB_WEBHOOK_SECRET"]), ("glpat-old", "keepme"))
        self.assertEqual((values["HERMES_MODEL"], values["HERMES_UID"]), ("m1", "1000"))
        self.assertTrue(any(name.startswith(".env.") and name.endswith(".bak") for name in os.listdir(self.dir)))

    def test_rejected_token_can_be_dropped(self):
        def bad(platform, url, token):
            raise ValueError("rejected the token (HTTP 401)")
        answers = ["gitlab", "", "n"] + [""] * 12 + ["y", "n", "n"]
        code, _ = self.run_main(answers, ["glpat-wrong", "", ""], check=bad)
        self.assertEqual(code, 0)
        self.assertEqual(init.parse_env(open(self.env).read())["GITLAB_TOKEN"], "")
        self.assertTrue(any("HTTP 401" in line for line in self.out))

    def test_declining_write_leaves_file_alone(self):
        with open(self.env, "w") as fh:
            fh.write("GITLAB_TOKEN=t\n")
        answers = [""] * 13 + ["n", "n"]  # ... advanced: n, write: n
        code, _ = self.run_main(answers, ["", "", ""])
        self.assertEqual(code, 1)
        self.assertEqual(open(self.env).read(), "GITLAB_TOKEN=t\n")

    def test_exported_environment_wins(self):
        with patch.dict(os.environ, {"GITHUB_TOKEN": "ghp-env"}):
            self.run_main([], [], argv=["--yes"])
        self.assertEqual(init.parse_env(open(self.env).read())["GITHUB_TOKEN"], "ghp-env")


class WhoamiTests(unittest.TestCase):
    def test_reads_username_and_reports_rejection(self):
        class Response:
            def __init__(self, body): self.body = body
            def read(self): return self.body
            def __enter__(self): return self
            def __exit__(self, *a): return False
        seen = []

        def opener(request, timeout=None):
            seen.append((request.full_url, request.get_header("Private-token")))
            return Response(b'{"username": "bot"}')
        self.assertEqual(init.whoami("gitlab", "https://gl.example/", "tok", opener=opener), "bot")
        self.assertEqual(seen, [("https://gl.example/api/v4/user", "tok")])

        def denied(request, timeout=None):
            raise init.HTTPError(request.full_url, 401, "no", {}, None)
        with self.assertRaises(ValueError):
            init.whoami("github", "https://api.github.com", "tok", opener=denied)


if __name__ == "__main__":
    unittest.main()
