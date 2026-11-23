#!/usr/bin/env python3
"""Tests for the webhook review server. Run: python3 -m unittest -v"""
import base64
import hashlib
import hmac
import json
import os
import queue
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Tests must never write to a real review store: the deployed service exports
# REVIEW_STORE, and inheriting it makes the suite append fixture rows to it.
os.environ["REVIEW_STORE"] = ""
import server  # noqa: E402

# Ambient env must not change results: these three are module-level constants.
server.BOT_USERNAME = ""
server._reviewed.clear()
server.MIN_ACCESS_LEVEL = 30
server.APPROVE_ACCESS_LEVEL = 40

SECRET = "s3cret"


def sign_github(raw, secret=SECRET):
    return "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()


def sign_standard(raw, secret="whsec_" + base64.b64encode(b"k" * 24).decode(), msg_id="msg-1", ts=None):
    ts = str(int(time.time())) if ts is None else str(ts)
    key = base64.b64decode(secret[6:])
    signature = "v1," + base64.b64encode(hmac.new(key, f"{msg_id}.{ts}.".encode() + raw, hashlib.sha256).digest()).decode()
    return {"webhook-id": msg_id, "webhook-timestamp": ts, "webhook-signature": signature}, secret


class VerificationTests(unittest.TestCase):
    def test_github_signature(self):
        raw = b'{"a":1}'
        self.assertTrue(server.verify("github", {"X-Hub-Signature-256": sign_github(raw)}, raw, SECRET))
        self.assertFalse(server.verify("github", {"X-Hub-Signature-256": sign_github(raw, "other")}, raw, SECRET))
        self.assertFalse(server.verify("github", {}, raw, SECRET))
        self.assertFalse(server.verify("github", {"X-Hub-Signature-256": sign_github(raw)}, raw, ""))

    def test_gitlab_token(self):
        raw = b'{"a":1}'
        self.assertTrue(server.verify("gitlab", {"X-Gitlab-Token": SECRET}, raw, SECRET))
        self.assertFalse(server.verify("gitlab", {"X-Gitlab-Token": "nope"}, raw, SECRET))

    def test_standard_webhooks(self):
        raw = b'{"a":1}'
        headers, secret = sign_standard(raw)
        self.assertTrue(server.verify("gitlab", headers, raw, secret))
        self.assertFalse(server.verify("gitlab", headers, b'{"a":2}', secret))

    def test_standard_webhooks_rejects_stale_timestamp(self):
        raw = b"{}"
        headers, secret = sign_standard(raw, ts=int(time.time()) - 3600)
        self.assertFalse(server.verify("gitlab", headers, raw, secret))

    def test_standard_webhooks_rejects_malformed_secret(self):
        raw = b"{}"
        headers, _ = sign_standard(raw)
        self.assertFalse(server.verify("gitlab", headers, raw, "whsec_!!!notbase64"))


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.saved = dict(os.environ)
        for key in ("GITLAB_TOKEN", "GITHUB_TOKEN", "GITLAB_WEBHOOK_SECRET", "GITHUB_WEBHOOK_SECRET", "WEBHOOK_SECRET"):
            os.environ.pop(key, None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.saved)

    def test_requires_token(self):
        with self.assertRaises(ValueError):
            server.load_config()

    def test_requires_secret(self):
        os.environ["GITLAB_TOKEN"] = "t"
        with self.assertRaises(ValueError):
            server.load_config()

    def test_rejects_plain_http_url(self):
        os.environ.update(GITLAB_TOKEN="t", GITLAB_WEBHOOK_SECRET=SECRET, GITLAB_URL="http://gitlab.internal")
        with self.assertRaises(ValueError):
            server.load_config()

    def test_accepts_both_platforms(self):
        os.environ.update(GITLAB_TOKEN="t", GITHUB_TOKEN="g", WEBHOOK_SECRET=SECRET)
        config = server.load_config()
        self.assertEqual(set(config), {"gitlab", "github"})
        self.assertEqual(config["github"]["url"], "https://api.github.com")


class HandlerTests(unittest.TestCase):
    def setUp(self):
        server._seen.clear()
        self.config = {"github": {"token": "t", "secret": SECRET, "url": "https://api.github.com"}}
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        self.httpd.config = self.config
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def post(self, path, raw, headers=None):
        request = Request(self.base + path, data=raw, headers=headers or {}, method="POST")
        try:
            with urlopen(request, timeout=10) as response:
                return response.status, response.read().decode()
        except Exception as error:  # HTTPError carries the status we assert on
            return error.code, error.read().decode()

    def test_health(self):
        with urlopen(self.base + "/health", timeout=10) as response:
            self.assertEqual(response.read(), b"ok")

    def test_unknown_route(self):
        self.assertEqual(self.post("/nope", b"{}")[0], 404)

    def test_rejects_missing_and_bad_signature(self):
        raw = json.dumps({"action": "opened"}).encode()
        with patch.object(server, "process") as process:
            self.assertEqual(self.post("/gh-review", raw)[0], 403)
            self.assertEqual(self.post("/gh-review", raw, {"X-Hub-Signature-256": "sha256=deadbeef"})[0], 403)
            process.assert_not_called()

    def test_dispatches_signed_github_event(self):
        raw = json.dumps({"action": "opened"}).encode()
        headers = {"X-Hub-Signature-256": sign_github(raw), "X-GitHub-Event": "pull_request"}
        done = threading.Event()

        def fake_process(platform, event, payload, config, track=None):
            done.set()
            return True

        with patch.object(server, "process", side_effect=fake_process) as process:
            status, body = self.post("/gh-review", raw, headers)
            self.assertTrue(done.wait(5))
        self.assertEqual((status, body), (202, "accepted"))
        self.assertEqual(process.call_args[0][:2], ("github", "pull_request"))

    def test_duplicate_delivery_is_not_reviewed_twice(self):
        raw = json.dumps({"action": "opened", "id": "dup-1"}).encode()
        headers = {"X-Hub-Signature-256": sign_github(raw), "X-GitHub-Event": "pull_request"}
        once = threading.Event()

        def fake_process(*args):
            once.set()
            return True

        with patch.object(server, "process", side_effect=fake_process) as process:
            self.assertEqual(self.post("/gh-review", raw, headers)[0], 202)
            self.assertTrue(once.wait(5))
            self.assertEqual(self.post("/gh-review", raw, headers), (200, "duplicate"))
        self.assertEqual(process.call_count, 1)

    def test_unconfigured_platform_is_404(self):
        raw = json.dumps({"action": "opened"}).encode()
        status, _ = self.post("/gl-review", raw, {"X-Gitlab-Token": SECRET})
        self.assertEqual(status, 404)

    def test_rejects_non_json_after_signature(self):
        raw = b"not json"
        status, _ = self.post("/gh-review", raw, {"X-Hub-Signature-256": sign_github(raw)})
        self.assertEqual(status, 400)

    def test_rejects_oversized_body(self):
        status, _ = self.post("/gh-review", b"x", {"Content-Length": str(server.MAX_BODY + 1)})
        self.assertEqual(status, 413)


class ApiStub(BaseHTTPRequestHandler):
    notes = []
    overflow = False
    diff = "--- a.py\n+print(1)\n"

    def do_GET(self):
        if self.path == "/api/v4/projects/1/merge_requests/2/changes?access_raw_diffs=true":
            payload = {"changes": [{"new_path": "a.py", "diff": "@@ -0,0 +1 @@\n+print(1)"}],
                       "overflow": ApiStub.overflow}
        elif self.path == "/api/v4/projects/1":
            payload = {"id": 1, "permissions": {"project_access": {"access_level": 40}}}
        elif self.path == "/api/v4/projects/1/merge_requests/2/notes?per_page=100&sort=desc":
            payload = []
        elif self.path == "/api/v4/projects/1/merge_requests/2/approvals":
            payload = {"user_has_approved": False, "user_can_approve": True, "state": "pending"}
        elif self.path == "/api/v4/projects/1/merge_requests/2/discussions?per_page=100":
            payload = []
        elif self.path == "/api/v4/projects/1/merge_requests/2":
            payload = {"iid": 2, "author": {"username": "alice"}, "diff_refs": {
                "base_sha": "b" * 40, "start_sha": "s" * 40, "head_sha": "h" * 40}}
        else:
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        ApiStub.notes.append((self.path, json.loads(body), self.headers.get("PRIVATE-TOKEN")))
        payload = b'{"id": 1}'
        self.send_response(201)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


class EndToEndTests(unittest.TestCase):
    """Real HTTP server + fake GitLab API + stub hermes binary. No external network."""

    @classmethod
    def setUpClass(cls):
        cls.api = ThreadingHTTPServer(("127.0.0.1", 0), ApiStub)
        threading.Thread(target=cls.api.serve_forever, daemon=True).start()
        cls.bin_dir = tempfile.mkdtemp()
        cls.hermes = os.path.join(cls.bin_dir, "hermes")
        with open(cls.hermes, "w") as handle:
            handle.write("#!/bin/sh\ncat > \"$0.stdin\"\nprintf '## Review\\n\\nDiff looks fine.\\nVERDICT: APPROVE\\n'\n")
        os.chmod(cls.hermes, 0o755)
        cls.config = {
            "gitlab": {"token": "gl-token", "secret": SECRET, "url": f"http://127.0.0.1:{cls.api.server_address[1]}"}
        }
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.httpd.config = cls.config
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        for httpd in (cls.httpd, cls.api):
            httpd.shutdown()
            httpd.server_close()

    def setUp(self):
        server._seen.clear()

    def post(self, raw, headers):
        request = Request(self.base + "/gl-review", data=raw, headers=headers, method="POST")
        try:
            with urlopen(request, timeout=30) as response:
                return response.status, response.read().decode()
        except Exception as error:
            return error.code, error.read().decode()

    def wait_for_notes(self, count=1, timeout=15):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if len(ApiStub.notes) >= count:
                return True
            time.sleep(0.05)
        return False

    def test_review_end_to_end(self):
        ApiStub.notes.clear()
        payload = {
            "object_kind": "merge_request",
            "project": {"id": 1},
            "object_attributes": {"iid": 2, "action": "open"},
        }
        raw = json.dumps(payload).encode()
        with patch.dict(os.environ, {"HERMES_BIN": self.hermes, "GITLAB_TOKEN": "gl-token", "WEBHOOK_SECRET": "leak"}):
            status, body = self.post(raw, {"X-Gitlab-Token": SECRET, "X-Gitlab-Event": "Merge Request Hook"})
            self.assertEqual((status, body), (202, "accepted"))
            self.assertTrue(self.wait_for_notes())
        self.assertEqual(len(ApiStub.notes), 1)
        path, posted, token = ApiStub.notes[0]
        self.assertEqual(path, "/api/v4/projects/1/merge_requests/2/notes")
        self.assertEqual(token, "gl-token")
        self.assertIn("<!-- ai-review -->", posted["body"])
        self.assertIn("Approved", posted["body"])
        self.assertNotIn("VERDICT:", posted["body"])
        with open(self.hermes + ".stdin") as handle:
            prompt = handle.read()
        self.assertIn("+print(1)", prompt)
        self.assertIn("untrusted", prompt)

    def test_ignores_unrelated_event(self):
        ApiStub.notes.clear()
        raw = json.dumps({"object_kind": "push", "project": {"id": 1}}).encode()
        status, body = self.post(raw, {"X-Gitlab-Token": SECRET, "X-Gitlab-Event": "Push Hook"})
        self.assertEqual((status, body), (202, "accepted"))
        self.assertFalse(self.wait_for_notes(timeout=1))
        self.assertEqual(ApiStub.notes, [])

    def test_rejects_oversized_diff(self):
        ApiStub.notes.clear()
        raw = json.dumps({"object_kind": "merge_request", "project": {"id": 1},
                          "object_attributes": {"iid": 2, "action": "open"}}).encode()
        with patch.object(server, "MAX_DIFF", 5), patch.dict(os.environ, {"HERMES_BIN": self.hermes}):
            self.assertEqual(self.post(raw, {"X-Gitlab-Token": SECRET, "X-Gitlab-Event": "Merge Request Hook"})[0], 202)
            self.assertFalse(self.wait_for_notes(timeout=1))
        self.assertEqual(ApiStub.notes, [])


class IsolatedCase(unittest.TestCase):
    """Every test starts with an empty dedupe/head memory."""

    def setUp(self):
        server._seen.clear()
        server._reviewed.clear()
        server._targets.clear()


class GitHubFlowTests(IsolatedCase):
    CONFIG = {"token": "gh", "secret": SECRET, "url": "https://api.github.com"}

    def payload(self, action="opened"):
        return {"action": action, "number": 5, "repository": {"full_name": "acme/widgets"}}

    DIFF = (b"diff --git a/src/auth.py b/src/auth.py\n--- a/src/auth.py\n+++ b/src/auth.py\n"
            b"@@ -0,0 +1,2 @@\n+print(1)\n+print(2)\n")
    REVIEW = ("## Review\n\n### Inline Comments\n"
              "- `src/auth.py:2` WARNING: Off-by-one check. Fix: use <.\n\n"
              "VERDICT: APPROVE")

    def fake_api(self, posts, bodies=None):
        def call(base, token, platform, path, body=None, accept="application/json"):
            if accept.endswith("diff"):
                return self.DIFF
            if body is None:
                return json.dumps({"title": "Add auth", "body": "why", "user": {"login": "alice"},
                                   "head": {"ref": "feat"}, "base": {"ref": "main"}}).encode()
            (posts if posts is not None else bodies).append((path, body))
            return b"{}"
        return call

    def test_review_posts_comment_review(self):
        posts = []
        with patch.object(server, "api", side_effect=self.fake_api(posts)), \
                patch.object(server, "run_hermes", return_value=self.REVIEW) as hermes:
            self.assertTrue(server.process("github", "pull_request", self.payload(), self.CONFIG))
        prompt = hermes.call_args[0][0]
        self.assertIn("print(1)", prompt)
        self.assertIn("PR #5: Add auth", prompt)
        self.assertIn("Author: @alice", prompt)
        self.assertIn("### Inline Comments", prompt)
        self.assertEqual(len(posts), 1)
        inline_path, inline_body = posts[0]
        self.assertEqual(inline_path, "/repos/acme/widgets/pulls/5/reviews")
        self.assertEqual(inline_body["comments"],
                         [{"path": "src/auth.py", "line": 2, "side": "RIGHT",
                           "body": "**WARNING** Off-by-one check.\n\n*Fix:* use <"}])
        self.assertEqual(inline_body["event"], "COMMENT")
        self.assertIn("Approved", inline_body["body"])
        self.assertIn("@alice", inline_body["body"])
        self.assertNotIn("VERDICT:", inline_body["body"])
        self.assertNotIn("### Inline Comments", inline_body["body"])

    def test_inline_offsets_use_diff_line_numbers(self):
        posts = []
        review = "### Inline Comments\n- `src/auth.py:1` CRITICAL: only line 1 exists.\n\nVERDICT: APPROVE"
        with patch.object(server, "api", side_effect=self.fake_api(posts)), \
                patch.object(server, "run_hermes", return_value=review):
            self.assertTrue(server.process("github", "pull_request", self.payload(), self.CONFIG))
        self.assertEqual(posts[0][1]["comments"][0]["line"], 1)

    def test_approves_when_token_can_push(self):
        posts = []

        def fake_api(base, token, platform, path, body=None, accept="application/json"):
            if accept.endswith("diff"):
                return self.DIFF
            if body is None:
                if path == "/repos/acme/widgets":
                    return json.dumps({"permissions": {"push": True}}).encode()
                return json.dumps({"title": "t", "user": {"login": "alice"},
                                   "head": {"ref": "f"}, "base": {"ref": "main"}}).encode()
            posts.append((path, body))
            return b"{}"

        with patch.object(server, "api", side_effect=fake_api), \
                patch.object(server, "run_hermes", return_value="ok\nVERDICT: APPROVE"):
            self.assertTrue(server.process("github", "pull_request", self.payload(), self.CONFIG))
        self.assertEqual(posts[0][1]["event"], "APPROVE")

    def test_draft_pr_not_approved(self):
        posts = []

        def fake_api(base, token, platform, path, body=None, accept="application/json"):
            if accept.endswith("diff"):
                return self.DIFF
            if body is None:
                if path == "/repos/acme/widgets":
                    return json.dumps({"permissions": {"push": True}}).encode()
                return json.dumps({"title": "t", "draft": True, "user": {"login": "alice"},
                                   "head": {"ref": "f"}, "base": {"ref": "main"}}).encode()
            posts.append((path, body))
            return b"{}"

        with patch.object(server, "api", side_effect=fake_api), \
                patch.object(server, "run_hermes", return_value="ok\nVERDICT: APPROVE"):
            self.assertTrue(server.process("github", "pull_request", self.payload(), self.CONFIG))
        self.assertEqual(posts[0][1]["event"], "COMMENT")

    def test_inline_cap_respected(self):
        posts = []
        lines = "".join(f"- `src/auth.py:{n}` WARNING: issue {n}.\n" for n in (1, 2))
        with patch.object(server, "MAX_INLINE", 1), \
                patch.object(server, "api", side_effect=self.fake_api(posts)), \
                patch.object(server, "run_hermes", return_value="### Inline Comments\n" + lines + "\nVERDICT: APPROVE"):
            self.assertTrue(server.process("github", "pull_request", self.payload(), self.CONFIG))
        self.assertEqual(len(posts[0][1]["comments"]), 1)

    def test_no_inline_section_still_posts_summary(self):
        posts = []
        with patch.object(server, "api", side_effect=self.fake_api(posts)), \
                patch.object(server, "run_hermes", return_value="LGTM\nVERDICT: APPROVE"):
            self.assertTrue(server.process("github", "pull_request", self.payload(), self.CONFIG))
        self.assertEqual(len(posts), 1)
        self.assertNotIn("comments", posts[0][1])

    def test_ignores_other_actions_and_events(self):
        with patch.object(server, "api") as api:
            self.assertFalse(server.process("github", "pull_request", self.payload("closed"), self.CONFIG))
            self.assertFalse(server.process("github", "issue_comment", self.payload(), self.CONFIG))
        api.assert_not_called()

    def test_rejects_bad_destination(self):
        bad_names = ("../secrets", "a/b/c", "acme/widgets/../../x", "")
        for name in bad_names:
            with self.subTest(name=name), self.assertRaises(ValueError):
                server.process("github", "pull_request",
                               {"action": "opened", "number": 1, "repository": {"full_name": name}}, self.CONFIG)
        with patch.object(server, "api") as api, self.assertRaises(ValueError):
            server.process("github", "pull_request", {"action": "opened", "repository": {"full_name": "a/b"}}, self.CONFIG)
        api.assert_not_called()

    def test_empty_diff_skips_review(self):
        with patch.object(server, "api", return_value=b"  \n"), patch.object(server, "run_hermes") as hermes:
            self.assertFalse(server.process("github", "pull_request", self.payload(), self.CONFIG))
        hermes.assert_not_called()


class GitLabFlowTests(unittest.TestCase):
    CONFIG = {"token": "gl", "secret": SECRET, "url": "https://gitlab.example.com"}

    def test_overflow_blocks_review(self):
        def fake_api(base, token, platform, path, body=None, accept="application/json"):
            if path == "/projects/1":
                return json.dumps({"permissions": {"project_access": {"access_level": 40}}}).encode()
            return b'{"changes": [], "overflow": true}'

        with patch.object(server, "api", side_effect=fake_api), patch.object(server, "run_hermes") as hermes:
            with self.assertRaises(ValueError):
                server.process("gitlab", "Merge Request Hook", {
                    "object_kind": "merge_request", "project": {"id": 1},
                    "object_attributes": {"iid": 2, "action": "update"}}, self.CONFIG)
        hermes.assert_not_called()

    def test_low_access_level_skips_review(self):
        def fake_api(base, token, platform, path, body=None, accept="application/json"):
            return b'{"permissions": {"project_access": {"access_level": 20}}}'

        with patch.object(server, "api", side_effect=fake_api), patch.object(server, "run_hermes") as hermes:
            self.assertFalse(server.process("gitlab", "Merge Request Hook", {
                "object_kind": "merge_request", "project": {"id": 1},
                "object_attributes": {"iid": 2, "action": "update"}}, self.CONFIG))
        hermes.assert_not_called()


class InlineTests(unittest.TestCase):
    REVIEW = ("Summary here.\n\n### Inline Comments\n"
              "- `src/auth.py:31` WARNING: Off-by-one expiry check. Fix: use <.\n"
              "- `src/db.py:12` SUGGESTION: Reuse the connection pool.\n"
              "- not a comment line\n\nVERDICT: REQUEST_CHANGES")

    def test_parses_comments(self):
        parsed = server.parse_inline_comments(self.REVIEW)
        self.assertEqual([(c["file"], c["line"], c["level"]) for c in parsed],
                         [("src/auth.py", 31, "WARNING"), ("src/db.py", 12, "SUGGESTION")])
        self.assertEqual(parsed[0]["fix"], "use <")

    def test_new_lines_match_diff_hunks(self):
        diff = "@@ -1,2 +1,3 @@\n context\n+added\n-removed\n+another\n"
        self.assertEqual(server.new_lines_of(diff), {2, 3})

    def test_verdict_parsing(self):
        self.assertEqual(server.verdict_of("looks fine\nVERDICT: APPROVE"), "APPROVE")
        self.assertEqual(server.verdict_of("nol\nVERDICT: REQUEST_CHANGES"), "REQUEST_CHANGES")
        self.assertEqual(server.verdict_of("VERDICT: APPROVE but REQUEST_CHANGES"), "REQUEST_CHANGES")
        self.assertEqual(server.verdict_of("no verdict at all"), "REQUEST_CHANGES")

    def test_review_body_strips_inline_and_verdict(self):
        body = server.review_body(self.REVIEW, "alice", "REQUEST_CHANGES")
        self.assertIn("<!-- ai-review -->", body)
        self.assertIn("@alice", body)
        self.assertIn("Summary here.", body)
        self.assertNotIn("### Inline Comments", body)
        self.assertNotIn("Off-by-one", body)
        self.assertNotIn("VERDICT:", body)

    def test_inline_posted_only_for_real_lines(self):
        calls = []

        def fake_api(base, token, platform, path, body=None, accept="application/json"):
            calls.append((path, body))
            return b'{"id": 9}'

        changes = [{"new_path": "src/auth.py", "diff": "@@ -28,4 +30,4 @@\n a\n+b\n"}]
        with patch.object(server, "api", side_effect=fake_api):
            posted = server.gl_post_inline("https://gl/api/v4", "t", "/projects/1/merge_requests/2",
                                           self.REVIEW, changes, {"base_sha": "b", "head_sha": "h"})
        self.assertEqual(posted, {("src/auth.py", 31)})
        self.assertEqual(calls[0][0], "/projects/1/merge_requests/2/discussions")
        self.assertEqual(calls[0][1]["position"]["new_line"], 31)
        self.assertEqual(calls[0][1]["position"]["position_type"], "text")


REAL_MODEL_REVIEW = """**Verdict:** \U0001f534 REQUEST_CHANGES

### Criteria Checklist
- [x] Security \u2014 fails, token unused

### \U0001f534 Critical
- `auth.py:2` \u2014 `time` used without import; function cannot execute. *Fix:* add `import time`.
- `auth.py:1` \u2014 `token` never validated. *Fix:* validate it.

### \u26a0\ufe0f Warning
- `auth.py:2` \u2014 unvalidated `expiry`. *Fix:* normalize to epoch float.

### \u2705 Looks Good
- Nothing to commend.

---
\U0001f916 *Reviewed by AI Code Reviewer*
"""


class SummaryCoverageTests(unittest.TestCase):
    """Nothing may be lost when the inline cap or a bad line number drops a finding."""

    def test_findings_skipped_inline_stay_in_summary(self):
        review = ("### Critical\n- `a.py:1` kept inline.\n- `a.py:99` not in diff.\n"
                  "### Warning\n- `b.py:2` also skipped.\n\nVERDICT: REQUEST_CHANGES")
        posted = {("a.py", 1)}
        body = server.review_body(review, "alice", "REQUEST_CHANGES", posted=posted)
        self.assertNotIn("kept inline", body)
        self.assertIn("a.py:99", body)
        self.assertIn("b.py:2", body)

    def test_all_posted_findings_removed_from_summary(self):
        review = "### Critical\n- `a.py:1` one.\n\n### Notes\n- keep me\n\nVERDICT: APPROVE"
        body = server.review_body(review, "alice", "APPROVE", posted={("a.py", 1)})
        self.assertNotIn("a.py:1", body)
        self.assertIn("keep me", body)


class RemarkTests(unittest.TestCase):
    """A skipped row must say why, not just "skipped"."""

    def process(self, payload, event="Merge Request Hook"):
        with patch.object(server, "api", return_value=json.dumps(
                {"permissions": {"project_access": {"access_level": 40}}}).encode()), \
                patch.object(server, "run_hermes") as hermes:
            result = server.process("gitlab", event, payload, GL_CONFIG)
        return result, hermes

    def test_wrong_event_says_so(self):
        seen = {}
        payload = {"object_kind": "push"}
        with patch.object(server, "api"), patch.object(server, "run_hermes") as hermes:
            self.assertFalse(server.process("gitlab", "Push Hook", payload, GL_CONFIG,
                                            lambda stage, **kw: seen.update(kw)))
        hermes.assert_not_called()
        self.assertIn("not a merge request event", seen["remark"])

    def test_ignored_action_says_so(self):
        seen = {}
        payload = {"object_kind": "merge_request", "project": {"id": 1},
                   "object_attributes": {"iid": 2, "action": "close"}}
        with patch.object(server, "api"), patch.object(server, "run_hermes"):
            self.assertFalse(server.process("gitlab", "Merge Request Hook", payload, GL_CONFIG,
                                            lambda stage, **kw: seen.update(kw)))
        self.assertIn("close", seen["remark"])

    def test_low_access_reason_is_returned(self):
        payload = {"object_kind": "merge_request", "project": {"id": 1},
                   "object_attributes": {"iid": 2, "action": "update"}}
        seen = {}
        with patch.object(server, "api", return_value=json.dumps(
                {"permissions": {"project_access": {"access_level": 10}}}).encode()), \
                patch.object(server, "run_hermes") as hermes:
            self.assertFalse(server.process("gitlab", "Merge Request Hook", payload, GL_CONFIG,
                                            lambda stage, **kw: seen.update(kw)))
        hermes.assert_not_called()
        self.assertIn("MIN_ACCESS_LEVEL", seen["remark"])

    def test_unchanged_head_reason_is_returned(self):
        server._reviewed.clear()
        payload = {"object_kind": "merge_request", "project": {"id": 1},
                   "object_attributes": {"iid": 2, "action": "update"}}
        def fake_api(base, token, platform, path, body=None, accept="application/json"):
            if path == "/projects/1":
                return json.dumps({"permissions": {"project_access": {"access_level": 40}}}).encode()
            if path.endswith("/changes?access_raw_diffs=true"):
                return json.dumps({"changes": [{"new_path": "a.py", "diff": "@@ -0,0 +1 @@\n+x"}],
                                   "overflow": False}).encode()
            return json.dumps({"author": {"username": "dimas"},
                               "diff_refs": {"head_sha": "deadbeef"}}).encode()
        seen = {}
        with patch.object(server, "api", side_effect=fake_api), \
                patch.object(server, "run_hermes", return_value="VERDICT: APPROVE"):
            self.assertTrue(server.process("gitlab", "Merge Request Hook", payload, GL_CONFIG))
            self.assertFalse(server.process("gitlab", "Merge Request Hook", payload, GL_CONFIG,
                                            lambda stage, **kw: seen.update(kw)))
        self.assertIn("unchanged", seen["remark"])

    def test_skip_reason_lands_in_the_history_record(self):
        tracker = server.Tracker(os.path.join(tempfile.mkdtemp(), "r.jsonl"))
        rec = tracker.begin("gitlab", "g/p!1")
        tracker.finish(rec, "skipped", remark="MR action 'close' does not trigger a review")
        self.assertEqual(tracker.snapshot()["history"][0]["remark"],
                         "MR action 'close' does not trigger a review")


class ApiRetryTests(unittest.TestCase):
    """A dropped connection must not fail the review; a bad response must."""

    def test_connection_reset_is_retried(self):
        ok = b'{"id": 1}'
        with patch.object(server, "api_once", side_effect=[ConnectionResetError(104, "reset"), ok]) as once, \
                patch.object(server.time, "sleep"):
            self.assertEqual(server.api("https://x", "t", "gitlab", "/p"), ok)
        self.assertEqual(once.call_count, 2)

    def test_urlerror_wrapping_reset_is_retried(self):
        ok = b"[]"
        reset = URLError(ConnectionResetError(104, "reset"))
        with patch.object(server, "api_once", side_effect=[reset, ok]), patch.object(server.time, "sleep"):
            self.assertEqual(server.api("https://x", "t", "github", "/p"), ok)

    def test_gives_up_after_last_attempt(self):
        with patch.object(server, "api_once", side_effect=ConnectionResetError(104, "reset")) as once, \
                patch.object(server.time, "sleep"):
            with self.assertRaises(ConnectionResetError):
                server.api("https://x", "t", "gitlab", "/p")
        self.assertEqual(once.call_count, server.API_ATTEMPTS)

    def test_http_error_is_not_retried(self):
        error = HTTPError("https://x/p", 401, "Unauthorized", {}, None)
        with patch.object(server, "api_once", side_effect=error) as once, patch.object(server.time, "sleep"):
            with self.assertRaises(HTTPError):
                server.api("https://x", "t", "github", "/p")
        self.assertEqual(once.call_count, 1)

    def test_bad_http_status_inside_urlopen_is_not_retried(self):
        error = URLError(HTTPError("https://x/p", 404, "Not Found", {}, None))
        with patch.object(server, "api_once", side_effect=error) as once, patch.object(server.time, "sleep"):
            with self.assertRaises(URLError):
                server.api("https://x", "t", "gitlab", "/p")
        self.assertEqual(once.call_count, 1)


class StoreIsolationTests(unittest.TestCase):
    """A test run must not touch the deployed review store."""

    def test_suite_uses_no_store_path(self):
        self.assertEqual(os.environ.get("REVIEW_STORE"), "")
        self.assertEqual(server._tracker.path, "")


class TrackerTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "reviews.jsonl")
        self.t = server.Tracker(self.path, limit=5, est=10)

    def test_live_job_reports_progress_then_lands_in_history(self):
        rec = self.t.begin("gitlab", "g/p!1", "alice", files=2)
        self.assertEqual(self.t.snapshot()["stats"]["running"], 1)
        self.t.stage(rec, "reviewing")
        live = self.t.snapshot()["live"][0]
        self.assertEqual(live["stage"], "reviewing")
        self.assertGreaterEqual(live["pct"], 25)
        self.assertLessEqual(live["pct"], 85)
        self.t.finish(rec, verdict="APPROVE", inline=3)
        snap = self.t.snapshot()
        self.assertEqual(snap["live"], [])
        self.assertEqual(snap["history"][0]["verdict"], "APPROVE")
        self.assertEqual(snap["stats"]["running"], 0)
        self.assertEqual(snap["stats"]["verdicts"], {"APPROVE": 1})

    def test_history_survives_restart(self):
        rec = self.t.begin("github", "a/b#2")
        self.t.finish(rec, verdict="REQUEST_CHANGES")
        again = server.Tracker(self.path)
        self.assertEqual(len(again.snapshot()["history"]), 1)
        self.assertEqual(again.snapshot()["stats"]["total"], 1)
        self.assertEqual(again.seq, rec["id"])

    def test_duration_is_measured_not_zero(self):
        rec = self.t.begin("gitlab", "g/p!9")
        time.sleep(0.2)
        self.t.finish(rec)
        self.assertGreater(self.t.snapshot()["history"][0]["duration"], 0)

    def test_explicit_duration_is_kept(self):
        rec = self.t.begin("gitlab", "g/p!10")
        self.t.finish(rec, duration=42.0)
        self.assertEqual(self.t.snapshot()["history"][0]["duration"], 42.0)

    def test_failure_is_recorded_with_reason(self):
        rec = self.t.begin("gitlab", "g/p!3")
        self.t.finish(rec, "failed", error="diff too large for one review")
        snap = self.t.snapshot()
        self.assertEqual(snap["stats"]["failed"], 1)
        self.assertEqual(snap["history"][0]["error"], "diff too large for one review")

    def test_history_is_newest_first(self):
        for i in range(3):
            self.t.finish(self.t.begin("gitlab", "g/p!%d" % i))
        hist = self.t.snapshot()["history"]
        self.assertEqual([r["target"] for r in hist], ["g/p!2", "g/p!1", "g/p!0"])

    def test_history_is_bounded(self):
        for i in range(8):
            self.t.finish(self.t.begin("gitlab", "g/p!%d" % i))
        self.assertEqual(len(self.t.snapshot()["history"]), 5)

    def test_corrupt_store_line_is_ignored(self):
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write('{"id": 2, "target": "ok"}\nnot json\n')
        snap = server.Tracker(self.path).snapshot()
        self.assertEqual([r["target"] for r in snap["history"]], ["ok"])


class LabelTests(unittest.TestCase):
    """Every real event shape must produce a readable target, never `?`."""

    def test_gitlab_merge_request(self):
        payload = {"object_kind": "merge_request", "project": {"path_with_namespace": "g/p"},
                   "object_attributes": {"iid": 12}}
        self.assertEqual(server.label_of("gitlab", payload), "g/p!12")

    def test_gitlab_note_event_uses_merge_request(self):
        payload = {"object_kind": "note", "project": {"path_with_namespace": "pasarpolis/integrationservice"},
                   "merge_request": {"iid": 4895}}
        self.assertEqual(server.label_of("gitlab", payload), "pasarpolis/integrationservice!4895")

    def test_github_pull_request_event(self):
        payload = {"repository": {"full_name": "a/b"}, "number": 7,
                   "pull_request": {"number": 7}}
        self.assertEqual(server.label_of("github", payload), "a/b#7")

    def test_github_comment_event(self):
        payload = {"repository": {"full_name": "a/b"}, "issue": {"number": 9},
                   "comment": {"id": 1}}
        self.assertEqual(server.label_of("github", payload), "a/b#9")

    def test_unparseable_payload_still_returns_a_label(self):
        self.assertEqual(server.label_of("gitlab", {}), "?")
        self.assertEqual(server.label_of("github", {"repository": {}}), "?#?")


class LinkTests(unittest.TestCase):
    def test_gitlab_url_prefers_payload_url(self):
        payload = {"project": {"web_url": "https://gitlab.com/g/p"},
                   "object_attributes": {"iid": 7, "url": "https://gitlab.com/g/p/-/merge_requests/7"}}
        self.assertEqual(server.url_of("gitlab", payload), "https://gitlab.com/g/p/-/merge_requests/7")

    def test_gitlab_url_built_when_absent(self):
        payload = {"project": {"web_url": "https://gitlab.com/g/p"},
                   "object_attributes": {"iid": 7}}
        self.assertEqual(server.url_of("gitlab", payload), "https://gitlab.com/g/p/-/merge_requests/7")

    def test_gitlab_note_event_builds_url(self):
        payload = {"project": {"web_url": "https://gitlab.com/g/p"},
                   "object_kind": "note", "merge_request": {"iid": 3}}
        self.assertEqual(server.url_of("gitlab", payload), "https://gitlab.com/g/p/-/merge_requests/3")

    def test_github_url_from_pull_request(self):
        payload = {"pull_request": {"html_url": "https://github.com/a/b/pull/12"}}
        self.assertEqual(server.url_of("github", payload), "https://github.com/a/b/pull/12")

    def test_missing_or_non_https_url_is_blank(self):
        self.assertEqual(server.url_of("gitlab", {}), "")
        self.assertEqual(server.url_of("github", {"pull_request": {"html_url": "javascript:alert(1)"}}), "")

    def test_note_url_is_trimmed_to_the_mr(self):
        payload = {"object_attributes": {"url": "https://gitlab.com/g/p/-/merge_requests/5#note_99"}}
        self.assertEqual(server.url_of("gitlab", payload), "https://gitlab.com/g/p/-/merge_requests/5")

    def test_label_from_url(self):
        self.assertEqual(server.label_from_url("https://gitlab.com/g/p/-/merge_requests/12"), "g/p!12")
        self.assertEqual(server.label_from_url("https://github.com/a/b/pull/7"), "a/b#7")
        self.assertEqual(server.label_from_url("https://example.com/nope"), "")

    def test_old_note_url_loses_its_anchor_on_load(self):
        path = os.path.join(tempfile.mkdtemp(), "r.jsonl")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"id": 4, "target": "?", "status": "done",
                                 "url": "https://gitlab.com/g/p/-/merge_requests/9#note_77"}) + "\n")
        row = server.Tracker(path).snapshot()["history"][0]
        self.assertEqual(row["url"], "https://gitlab.com/g/p/-/merge_requests/9")
        self.assertEqual(row["target"], "g/p!9")

    def test_old_record_without_target_is_repaired_on_load(self):
        path = os.path.join(tempfile.mkdtemp(), "r.jsonl")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"id": 3, "target": "?", "status": "done",
                                 "url": "https://gitlab.com/g/p/-/merge_requests/12"}) + "\n")
        self.assertEqual(server.Tracker(path).snapshot()["history"][0]["target"], "g/p!12")

    def test_record_carries_url(self):
        tracker = server.Tracker(os.path.join(tempfile.mkdtemp(), "r.jsonl"))
        rec = tracker.begin("github", "a/b#1", url="https://github.com/a/b/pull/1")
        tracker.finish(rec)
        self.assertEqual(tracker.snapshot()["history"][0]["url"], "https://github.com/a/b/pull/1")


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.old = server._tracker
        server._tracker = server.Tracker(os.path.join(self.tmp, "r.jsonl"))
        server.DASHBOARD_USER, server.DASHBOARD_PASSWORD = "admin", ""
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d" % self.httpd.server_address[1]

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        server._tracker = self.old
        server.DASHBOARD_USER, server.DASHBOARD_PASSWORD = "admin", ""

    def get(self, path, creds=None):
        request = Request(self.base + path)
        if creds:
            request.add_header("Authorization", "Basic " + base64.b64encode(creds.encode()).decode())
        try:
            with urlopen(request, timeout=5) as r:
                return r.status, r.read().decode()
        except HTTPError as error:
            return error.code, error.read().decode()

    def test_dashboard_page_and_json(self):
        status, page = self.get("/dashboard")
        self.assertEqual(status, 200)
        self.assertIn("AI Code Reviewer", page)
        self.assertIn("/api/reviews", page)
        status, body = self.get("/api/reviews")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(set(data), {"live", "history", "stats"})
        self.assertEqual(data["stats"]["workers"], server.MAX_WORKERS)

    def test_basic_auth_gate_when_configured(self):
        server.DASHBOARD_USER, server.DASHBOARD_PASSWORD = "admin", "s3cret"
        self.assertEqual(self.get("/api/reviews")[0], 401)
        self.assertEqual(self.get("/dashboard")[0], 401)
        self.assertEqual(self.get("/api/reviews", "admin:wrong")[0], 401)
        self.assertEqual(self.get("/api/reviews", "bob:s3cret")[0], 401)
        self.assertEqual(self.get("/api/reviews", "admin:s3cret")[0], 200)
        self.assertEqual(self.get("/dashboard", "admin:s3cret")[0], 200)

    def test_401_advertises_basic_realm(self):
        server.DASHBOARD_PASSWORD = "s3cret"
        try:
            urlopen(self.base + "/dashboard", timeout=5)
        except HTTPError as error:
            self.assertEqual(error.code, 401)
            self.assertIn("Basic realm=", error.headers["WWW-Authenticate"])
        else:
            self.fail("expected 401")

    def test_health_needs_no_login(self):
        server.DASHBOARD_PASSWORD = "s3cret"
        self.assertEqual(self.get("/health")[0], 200)


class RealModelOutputTests(unittest.TestCase):
    """Parsers must handle the layouts models actually emit, not only the prompted one."""

    def test_sectioned_bullets_parsed_with_severity(self):
        parsed = server.parse_inline_comments(REAL_MODEL_REVIEW)
        # auth.py:2 appears in Critical and Warning; one comment survives, the worse wording wins.
        self.assertEqual([(c["file"], c["line"], c["level"]) for c in parsed],
                         [("auth.py", 2, "CRITICAL"), ("auth.py", 1, "CRITICAL")])
        self.assertIn("time", parsed[0]["message"])
        self.assertTrue(parsed[0]["fix"])

    def test_duplicate_findings_deduped(self):
        review = ("### Critical\n- `a.py:3` boom\n### Warning\n- `a.py:3` boom\n")
        self.assertEqual(len(server.parse_inline_comments(review)), 1)

    def test_bullets_without_severity_heading_ignored(self):
        review = "### Notes\n- `a.py:3` just prose here\n### Critical\n- `a.py:4` real bug\n"
        self.assertEqual([(c["line"], c["level"]) for c in server.parse_inline_comments(review)], [(4, "CRITICAL")])

    def test_bold_verdict_line(self):
        self.assertEqual(server.verdict_of(REAL_MODEL_REVIEW), "REQUEST_CHANGES")
        self.assertEqual(server.verdict_of("**Verdict:** \u2705 APPROVE"), "APPROVE")
        self.assertEqual(server.verdict_of("VERDICT: APPROVE"), "APPROVE")

    def test_review_body_strips_sectioned_inline_blocks(self):
        body = server.review_body(REAL_MODEL_REVIEW, "alice", "REQUEST_CHANGES")
        self.assertIn("Changes Requested", body)
        self.assertIn("@alice", body)
        self.assertIn("Criteria Checklist", body)
        self.assertNotIn("auth.py:2", body)
        self.assertNotIn("Verdict:**", body)


class DebateTests(unittest.TestCase):
    def setUp(self):
        self.saved = dict(os.environ)
        server._replied.clear()
        server._cooldown.clear()
        self.saved_bot = server.BOT_USERNAME
        self.saved_min = server.MIN_ACCESS_LEVEL
        server.BOT_USERNAME = "santosodb"
        server.MIN_ACCESS_LEVEL = 30
        self.config = {"token": "gl", "secret": SECRET, "url": "https://gitlab.example.com"}

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.saved)
        server.BOT_USERNAME = self.saved_bot
        server.MIN_ACCESS_LEVEL = self.saved_min
        with server._replied_lock:
            server._replied.clear()
        with server._cooldown_lock:
            server._cooldown.clear()

    def payload(self, note="@santosodb is this a real bug?", discussion_id="d1", note_id=7,
                username="alice", marker=False):
        return {"object_kind": "note", "project_id": 1,
                "user": {"username": username},
                "object_attributes": {"note": ("<!-- ai-review -->" if marker else "") + note,
                                      "noteable_type": "MergeRequest", "noteable_iid": 2,
                                      "discussion_id": discussion_id, "id": note_id}}

    def fake_api(self, posts, level=40):
        def call(base, token, platform, path, body=None, accept="application/json"):
            if body is None:
                if path == "/projects/1":
                    return json.dumps({"permissions": {"project_access": {"access_level": level}}}).encode()
                if path.startswith("/projects/1/merge_requests/2/discussions"):
                    return json.dumps([{"id": "d1", "notes": [
                        {"author": {"username": "santosodb"}, "body": "That expiry check is wrong."},
                        {"author": {"username": "alice"}, "body": "Why?"}]}]).encode()
                return b"{}"
            posts.append((path, body))
            return b'{"id": 5}'
        return call

    def test_mention_triggers_threaded_reply(self):
        posts = []
        with patch.object(server, "api", side_effect=self.fake_api(posts)), \
             patch.object(server, "run_hermes", return_value="You're right \u2014 the check should be <."):
            self.assertTrue(server.debate("gitlab", self.payload(), self.config))
        self.assertEqual(posts[0][0], "/projects/1/merge_requests/2/discussions/d1/notes")
        self.assertIn("<!-- ai-review -->", posts[0][1]["body"])
        self.assertIn("Reply to @alice", posts[0][1]["body"])

    def test_own_marker_and_non_mention_ignored(self):
        with patch.object(server, "run_hermes") as hermes:
            self.assertFalse(server.debate("gitlab", self.payload(marker=True), self.config))
            self.assertFalse(server.debate("gitlab", self.payload(note="no mention here"), self.config))
            self.assertFalse(server.debate("gitlab", self.payload(username="santosodb"), self.config))
        hermes.assert_not_called()

    def test_substring_mention_rejected(self):
        with patch.object(server, "run_hermes") as hermes:
            self.assertFalse(server.debate("gitlab", self.payload(note="@santosodbot ping"), self.config))
        hermes.assert_not_called()

    def test_same_note_replied_once(self):
        posts = []
        with patch.object(server, "api", side_effect=self.fake_api(posts)), \
             patch.object(server, "run_hermes", return_value="ok"):
            self.assertTrue(server.debate("gitlab", self.payload(), self.config))
            self.assertFalse(server.debate("gitlab", self.payload(), self.config))
        self.assertEqual(len(posts), 1)

    def test_cooldown_blocks_second_note_same_thread(self):
        posts = []
        with patch.object(server, "api", side_effect=self.fake_api(posts)), \
             patch.object(server, "run_hermes", return_value="ok"):
            self.assertTrue(server.debate("gitlab", self.payload(note_id=7), self.config))
            self.assertFalse(server.debate("gitlab", self.payload(note_id=8), self.config))
        self.assertEqual(len(posts), 1)

    def test_github_debate_uses_thread_and_replies(self):
        posts = []

        def fake_api(base, token, platform, path, body=None, accept="application/json"):
            if body is None:
                if "/comments" in path:
                    return json.dumps([{"user": {"login": "alice"}, "body": "the check is wrong"},
                                       {"user": {"login": "santosodb"}, "body": "no it is not"}]).encode()
                return b"{}"
            posts.append((path, body))
            return b'{"id": 1}'

        payload = {"action": "created", "repository": {"full_name": "acme/widgets"},
                   "issue": {"number": 3},
                   "comment": {"id": 11, "body": "@santosodb why?", "user": {"login": "bob"}}}
        with patch.object(server, "api", side_effect=fake_api), \
                patch.object(server, "run_hermes", return_value="Because of x.") as hermes:
            self.assertTrue(server.debate("github", payload,
                                          {"token": "gh", "secret": SECRET, "url": "https://api.github.com"}))
        query = hermes.call_args[0][0]
        self.assertIn("Thread so far:", query)
        self.assertIn("@alice: the check is wrong", query)
        self.assertEqual(posts[0][0], "/repos/acme/widgets/issues/3/comments")
        self.assertIn("Reply to @bob", posts[0][1]["body"])

    def test_debate_query_includes_diff_context(self):
        posts = []

        def fake_api(base, token, platform, path, body=None, accept="application/json"):
            if body is not None:
                posts.append((path, body))
                return b'{"id": 1}'
            if "/changes" in path:
                return json.dumps({"changes": [{"new_path": "auth.py",
                                                "diff": "@@ -0,0 +1 @@\n+return age < limit"}]}).encode()
            if "/discussions" in path:
                return json.dumps([{"id": "d1", "notes": [{"author": {"username": "santosodb"},
                                                           "body": "off by one"}]}]).encode()
            return json.dumps({"permissions": {"project_access": {"access_level": 40}}}).encode()

        with patch.object(server, "api", side_effect=fake_api), \
                patch.object(server, "run_hermes", return_value="checked") as hermes:
            self.assertTrue(server.debate("gitlab", self.payload(), self.config))
        query = hermes.call_args[0][0]
        self.assertIn("Diff under discussion:", query)
        self.assertIn("return age < limit", query)
        self.assertIn("Thread so far:", query)

    def test_debate_survives_missing_diff(self):
        def fake_api(base, token, platform, path, body=None, accept="application/json"):
            if body is not None:
                return b'{"id": 1}'
            if "/changes" in path:
                raise OSError("boom")
            if "/discussions" in path:
                return b"[]"
            return json.dumps({"permissions": {"project_access": {"access_level": 40}}}).encode()

        with patch.object(server, "api", side_effect=fake_api), \
                patch.object(server, "run_hermes", return_value="ok"):
            self.assertTrue(server.debate("gitlab", self.payload(), self.config))

    def test_low_access_blocks_debate(self):
        with patch.object(server, "api", side_effect=self.fake_api([], level=20)), \
             patch.object(server, "run_hermes") as hermes:
            self.assertFalse(server.debate("gitlab", self.payload(), self.config))
        hermes.assert_not_called()

    def test_no_bot_username_disables_debate(self):
        server.BOT_USERNAME = ""
        with patch.object(server, "run_hermes") as hermes:
            self.assertFalse(server.debate("gitlab", self.payload(), self.config))
        hermes.assert_not_called()


class StaleReviewTests(unittest.TestCase):
    CONFIG = {"token": "gl", "secret": SECRET, "url": "https://gitlab.example.com"}

    def test_moved_head_discards_result(self):
        posted = []
        heads = iter(["sha-old", "sha-new"])

        def fake_api(base, token, platform, path, body=None, accept="application/json"):
            if path == "/projects/1":
                return json.dumps({"permissions": {"project_access": {"access_level": 40}}}).encode()
            if "/changes" in path:
                return json.dumps({"changes": [{"new_path": "a.py", "diff": "@@ -0,0 +1 @@\n+x"}],
                                   "overflow": False}).encode()
            if body is not None:
                posted.append((path, body))
                return b'{"id": 1}'
            return json.dumps({"author": {"username": "alice"},
                               "diff_refs": {"head_sha": next(heads)}}).encode()

        with patch.object(server, "api", side_effect=fake_api), \
                patch.object(server, "run_hermes", return_value="ok\nVERDICT: APPROVE"):
            self.assertFalse(server.process("gitlab", "Merge Request Hook", {
                "object_kind": "merge_request", "project": {"id": 1},
                "object_attributes": {"iid": 2, "action": "update"}}, self.CONFIG))
        self.assertEqual(posted, [])

    def test_superseded_helper_edge_cases(self):
        job = {"base": "b", "token": "t", "path": "/p", "head": ""}
        self.assertFalse(server.superseded("gitlab", job, self.CONFIG))  # unknown head: post anyway
        job["head"] = "sha"
        with patch.object(server, "api_json", return_value={}):
            self.assertFalse(server.superseded("gitlab", job, self.CONFIG))  # head gone: post anyway


class DraftTests(unittest.TestCase):
    HARMLESS_GL = {"token": "gl", "secret": SECRET, "url": "https://gitlab.example.com"}

    def test_draft_mr_is_reviewed_but_not_approved(self):
        def fake_api(base, token, platform, path, body=None, accept="application/json"):
            if path == "/projects/1":
                return json.dumps({"permissions": {"project_access": {"access_level": 40}}}).encode()
            if "/changes" in path:
                return json.dumps({"changes": [{"new_path": "a.py", "diff": "@@ -0,0 +1 @@\n+x"}],
                                   "overflow": False}).encode()
            if path.endswith("/approvals"):
                raise AssertionError("must not approve a draft")
            if body is not None:
                return b'{"id": 1}'
            return json.dumps({"author": {"username": "alice"}, "diff_refs": {}}).encode()

        with patch.object(server, "api", side_effect=fake_api), \
                patch.object(server, "run_hermes", return_value="fine\nVERDICT: APPROVE"):
            self.assertTrue(server.process("gitlab", "Merge Request Hook", {
                "object_kind": "merge_request", "project": {"id": 1},
                "object_attributes": {"iid": 2, "action": "update", "title": "Draft: wip"}},
                self.HARMLESS_GL))

    def test_non_draft_approves(self):
        calls = []

        def fake_api(base, token, platform, path, body=None, accept="application/json"):
            calls.append(path)
            if path == "/projects/1":
                return json.dumps({"permissions": {"project_access": {"access_level": 40}}}).encode()
            if "/changes" in path:
                return json.dumps({"changes": [{"new_path": "a.py", "diff": "@@ -0,0 +1 @@\n+x"}],
                                   "overflow": False}).encode()
            if path.endswith("/approvals") and body is None:
                return b'{"user_has_approved": false, "user_can_approve": true}'
            return b'{"id": 1}'

        with patch.object(server, "api", side_effect=fake_api), \
                patch.object(server, "run_hermes", return_value="fine\nVERDICT: APPROVE"):
            self.assertTrue(server.process("gitlab", "Merge Request Hook", {
                "object_kind": "merge_request", "project": {"id": 1},
                "object_attributes": {"iid": 2, "action": "update", "title": "Add auth"}},
                self.HARMLESS_GL))
        self.assertIn("/projects/1/merge_requests/2/approve", calls)


class GuardTests(unittest.TestCase):
    GL = {"token": "gl", "secret": SECRET, "url": "https://gitlab.example.com"}
    GH = {"token": "gh", "secret": SECRET, "url": "https://api.github.com"}

    def tearDown(self):
        server.BOT_USERNAME = ""

    def test_split_diff_paths(self):
        raw = ("diff --git a/src/a.py b/src/a.py\n--- a/src/a.py\n+++ b/src/a.py\n@@ -1 +1 @@\n+x\n"
               "diff --git a/b.py b/b.py\n--- a/b.py\n+++ b/b.py\n@@ -1 +1 @@\n+y\n")
        self.assertEqual([f["new_path"] for f in server.split_diff(raw)], ["src/a.py", "b.py"])
        self.assertEqual(server.split_diff(""), [])

    def test_verdict_uses_last_verdict_line(self):
        self.assertEqual(server.verdict_of("VERDICT: REQUEST_CHANGES\nok now\nVERDICT: APPROVE"), "APPROVE")
        self.assertEqual(server.verdict_of("VERDICT: APPROVE"), "APPROVE")
        self.assertEqual(server.verdict_of("VERDICT: APPROVE\nVERDICT: REQUEST_CHANGES"), "REQUEST_CHANGES")

    def test_bot_authored_mr_is_reviewed(self):
        """The bot's own MRs are reviewed: BOT_USERNAME is the webhook user, not a skip list."""
        server.BOT_USERNAME = "santosodb"
        def fake_api(base, token, platform, path, body=None, accept="application/json"):
            if path == "/projects/1":
                return json.dumps({"permissions": {"project_access": {"access_level": 40}}}).encode()
            if path.endswith("/changes?access_raw_diffs=true"):
                return json.dumps({"changes": [{"new_path": "a.py", "diff": "@@ -0,0 +1 @@\n+x"}], "overflow": False}).encode()
            return json.dumps({"author": {"username": "santosodb"}, "diff_refs": {}}).encode()
        with patch.object(server, "api", side_effect=fake_api), \
                patch.object(server, "run_hermes", return_value="VERDICT: APPROVE") as hermes:
            self.assertTrue(server.process("gitlab", "Merge Request Hook", {
                "object_kind": "merge_request", "project": {"id": 1},
                "object_attributes": {"iid": 2, "action": "update"}}, self.GL))
        hermes.assert_called_once()

    def test_same_head_is_not_reviewed_twice(self):
        """Our own approval triggers another MR event; the head did not move, so skip."""
        server._reviewed.clear()
        calls = {"n": 0}
        def fake_api(base, token, platform, path, body=None, accept="application/json"):
            if path == "/projects/1":
                return json.dumps({"permissions": {"project_access": {"access_level": 40}}}).encode()
            if path.endswith("/changes?access_raw_diffs=true"):
                return json.dumps({"changes": [{"new_path": "a.py", "diff": "@@ -0,0 +1 @@\n+x"}],
                                   "overflow": False}).encode()
            return json.dumps({"author": {"username": "dimas"},
                               "diff_refs": {"head_sha": "abc123"}}).encode()
        payload = {"object_kind": "merge_request", "project": {"id": 1},
                   "object_attributes": {"iid": 2, "action": "update"}}
        with patch.object(server, "api", side_effect=fake_api), \
                patch.object(server, "run_hermes", return_value="VERDICT: APPROVE") as hermes:
            self.assertTrue(server.process("gitlab", "Merge Request Hook", payload, self.GL))
            self.assertFalse(server.process("gitlab", "Merge Request Hook", payload, self.GL))
            calls["n"] = hermes.call_count
        self.assertEqual(calls["n"], 1)

    def test_new_head_is_reviewed_again(self):
        server._reviewed.clear()
        heads = {"sha": "aaa"}
        def fake_api(base, token, platform, path, body=None, accept="application/json"):
            if path == "/projects/1":
                return json.dumps({"permissions": {"project_access": {"access_level": 40}}}).encode()
            if path.endswith("/changes?access_raw_diffs=true"):
                return json.dumps({"changes": [{"new_path": "a.py", "diff": "@@ -0,0 +1 @@\n+x"}],
                                   "overflow": False}).encode()
            return json.dumps({"author": {"username": "dimas"},
                               "diff_refs": {"head_sha": heads["sha"]}}).encode()
        payload = {"object_kind": "merge_request", "project": {"id": 1},
                   "object_attributes": {"iid": 2, "action": "update"}}
        with patch.object(server, "api", side_effect=fake_api), \
                patch.object(server, "run_hermes", return_value="VERDICT: APPROVE") as hermes:
            self.assertTrue(server.process("gitlab", "Merge Request Hook", payload, self.GL))
            heads["sha"] = "bbb"
            self.assertTrue(server.process("gitlab", "Merge Request Hook", payload, self.GL))
            self.assertEqual(hermes.call_count, 2)

    def test_already_reviewed_open_mr_skipped(self):
        def fake_api(base, token, platform, path, body=None, accept="application/json"):
            if path == "/projects/1":
                return json.dumps({"permissions": {"project_access": {"access_level": 40}}}).encode()
            if "/notes" in path:
                return json.dumps([{"body": "<!-- ai-review -->\nold review"}]).encode()
            return b"{}"
        with patch.object(server, "api", side_effect=fake_api), patch.object(server, "run_hermes") as hermes:
            self.assertFalse(server.process("gitlab", "Merge Request Hook", {
                "object_kind": "merge_request", "project": {"id": 1},
                "object_attributes": {"iid": 2, "action": "open"}}, self.GL))
        hermes.assert_not_called()

    def test_github_debate_rejects_bad_repo(self):
        payload = {"action": "created", "repository": {"full_name": "../../x"},
                   "issue": {"number": 3}, "comment": {"id": 1, "body": "@santosodb hi",
                                                       "user": {"login": "alice"}}}
        with patch.object(server, "api") as api, patch.object(server, "run_hermes") as hermes:
            self.assertFalse(server.debate("github", payload, self.GH))
        api.assert_not_called()
        hermes.assert_not_called()

    def test_repo_name_validator(self):
        for good in ("acme/widgets", "a/b", "org/repo.js"):
            self.assertTrue(server.is_repo_name(good), good)
        for bad in ("acme", "a/b/c", "../x", "", None, "a/.."):
            self.assertFalse(server.is_repo_name(bad), bad)


class ClaimTests(unittest.TestCase):
    def setUp(self):
        server._seen.clear()

    def test_duplicate_detected_and_released(self):
        raw = b'{"x":1}'
        self.assertTrue(server.claim("gitlab", raw))
        self.assertFalse(server.claim("gitlab", raw))
        self.assertTrue(server.claim("github", raw))  # platform-scoped
        server.release("gitlab", raw)
        self.assertTrue(server.claim("gitlab", raw))

    def test_queue_bound_rejects_new_work(self):
        for index in range(1000):
            server.claim("gitlab", str(index).encode())
        with self.assertRaises(OverflowError):
            server.claim("gitlab", b"one-too-many")

    def test_stale_entries_expire(self):
        server._seen[("gitlab", b"old")] = time.monotonic() - 301
        self.assertTrue(server.claim("gitlab", b"new"))
        self.assertNotIn(("gitlab", b"old"), server._seen)


class HermesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.bin = os.path.join(self.tmp, "hermes")
        self.saved = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.saved)

    def script(self, body):
        with open(self.bin, "w") as handle:
            handle.write("#!/bin/sh\n" + body)
        os.chmod(self.bin, 0o755)
        os.environ["HERMES_BIN"] = self.bin

    def test_returns_stdout_and_scrubs_secrets(self):
        self.script('cat >/dev/null\nprintf "%s|%s" "$GITLAB_TOKEN" "$HERMES_MODEL"\n')
        os.environ.update(GITLAB_TOKEN="leak", HERMES_MODEL="m1")
        self.assertEqual(server.run_hermes("diff"), "|m1")

    def test_profile_flag_precedes_chat(self):
        self.script('cat >/dev/null\nprintf "%s" "$*"\n')
        os.environ["HERMES_PROFILE"] = "codereview"
        server.run_hermes("diff")
        # the stub cannot see argv, so assert the builder through a recorded run
        recorded = []
        with patch.object(server.subprocess, "run", side_effect=lambda cmd, **kw: recorded.append(cmd) or type("R", (), {"stdout": "ok"})()):
            server.run_hermes("diff")
        self.assertEqual(recorded[0][1:3], ["-p", "codereview"])
        self.assertEqual(recorded[0][3], "chat")

    def test_strips_session_id_trailer(self):
        self.script('cat >/dev/null\nprintf "review text\\n\\nsession_id: local-abc\\n"\n')
        self.assertEqual(server.run_hermes("diff"), "review text")

    def test_empty_output_is_error(self):
        self.script("cat >/dev/null\n")
        with self.assertRaises(ValueError):
            server.run_hermes("diff")

    def test_nonzero_exit_is_error(self):
        self.script("exit 3\n")
        with self.assertRaises(Exception):
            server.run_hermes("diff")

    def test_timeout_is_error(self):
        self.script("sleep 5\n")
        os.environ["HERMES_TIMEOUT_S"] = "1"
        with self.assertRaises(Exception):
            server.run_hermes("diff")


class ConcurrencyTests(unittest.TestCase):
    """Race conditions: dedupe under parallel delivery, per-MR ordering, queue bounds."""

    def setUp(self):
        server._seen.clear()
        server._targets.clear()
        server._jobs = queue.Queue(maxsize=100)
        server._workers_started = False
        self.config = {"github": {"token": "t", "secret": SECRET, "url": "https://api.github.com"}}
        self.httpd = server.Server(("127.0.0.1", 0), server.Handler)
        self.httpd.config = self.config
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        server._workers_started = False

    def post(self, raw):
        headers = {"X-Hub-Signature-256": sign_github(raw), "X-GitHub-Event": "pull_request"}
        request = Request(self.base + "/gh-review", data=raw, headers=headers, method="POST")
        try:
            with urlopen(request, timeout=10) as response:
                return response.status
        except HTTPError as error:
            return error.code

    def payload(self, number=1, head="a"):
        return json.dumps({"action": "opened", "number": number,
                           "repository": {"full_name": "o/r"}, "after": head}).encode()

    def test_parallel_duplicate_delivery_reviews_once(self):
        raw = self.payload(head="dup")
        calls = []
        gate = threading.Event()

        def fake_process(*args):
            calls.append(args[0])
            gate.wait(5)
            return True

        with patch.object(server, "process", side_effect=fake_process):
            results = []
            threads = [threading.Thread(target=lambda: results.append(self.post(raw))) for _ in range(16)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(10)
            gate.set()
            deadline = time.time() + 5
            while len(calls) < 1 and time.time() < deadline:
                time.sleep(0.02)
            time.sleep(0.3)

        self.assertEqual(len(calls), 1, "identical payload reviewed more than once")
        self.assertEqual(results.count(202), 1)
        self.assertEqual(results.count(200), 15)

    def test_same_mr_reviews_are_serialized(self):
        active = []
        peak = []
        done = []

        def fake_process(*args):
            active.append(1)
            peak.append(len(active))
            time.sleep(0.2)
            active.pop()
            done.append(1)
            return True

        with patch.object(server, "process", side_effect=fake_process):
            for i in range(3):
                self.assertEqual(self.post(self.payload(head="h%d" % i)), 202)
            deadline = time.time() + 10
            while time.time() < deadline and len(done) < 3:
                time.sleep(0.02)

        self.assertEqual(len(done), 3)
        self.assertEqual(max(peak), 1, "two reviews of one MR ran concurrently")

    def test_full_queue_returns_503_then_retry_succeeds(self):
        server._jobs = queue.Queue(maxsize=1)
        self.addCleanup(setattr, server, "MAX_WORKERS", server.MAX_WORKERS)
        server.MAX_WORKERS = 1
        gate = threading.Event()

        def fake_process(*args):
            gate.wait(10)
            return True

        with patch.object(server, "process", side_effect=fake_process):
            self.assertEqual(self.post(self.payload(number=1)), 202)   # worker picks it up
            self.assertEqual(self.post(self.payload(number=2)), 202)   # fills the queue
            self.assertEqual(self.post(self.payload(number=3)), 503)   # queue full
            gate.set()
            time.sleep(0.4)
            with patch.object(server, "process", return_value=True):
                self.assertEqual(self.post(self.payload(number=3)), 202)

    def test_worker_start_failure_releases_claim(self):
        raw = self.payload(number=9)
        with patch.object(server, "spawn", side_effect=RuntimeError("no threads")):
            self.assertEqual(self.post(raw), 503)
        with patch.object(server, "process", return_value=True):
            self.assertEqual(self.post(raw), 202)

    def test_failed_review_releases_claim_for_platform_retry(self):
        raw = self.payload(number=7)
        with patch.object(server, "process", side_effect=OSError("api down")):
            self.assertEqual(self.post(raw), 202)
            key = ("github", hashlib.sha256(raw).digest())
            deadline = time.time() + 5
            while time.time() < deadline and key in server._seen:
                time.sleep(0.02)
            self.assertNotIn(key, server._seen, "failed review kept the dedupe claim")


if __name__ == "__main__":
    unittest.main()
