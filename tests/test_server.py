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
os.environ["MEMORY_DB"] = ""  # same for the mistakes database
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
        server._reviewed.clear()
        server._whoami_cache.clear()

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
        ApiStub.overflow = False
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
        notes = [n for n in ApiStub.notes if n[0].endswith("/notes")]
        self.assertEqual(len(notes), 1)
        path, posted, token = notes[0]
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
        self.assertEqual((status, body), (200, "ignored"))
        self.assertFalse(self.wait_for_notes(timeout=1))
        self.assertEqual(ApiStub.notes, [])

    def test_oversized_diff_is_reviewed_in_chunks(self):
        ApiStub.notes.clear()
        server._reviewed.clear()
        server._whoami_cache.clear()
        raw = json.dumps({"object_kind": "merge_request", "project": {"id": 1},
                          "object_attributes": {"iid": 2, "action": "open"}}).encode()
        with patch.object(server, "MAX_DIFF", 5), patch.dict(os.environ, {"HERMES_BIN": self.hermes}):
            self.assertEqual(self.post(raw, {"X-Gitlab-Token": SECRET, "X-Gitlab-Event": "Merge Request Hook"})[0], 202)
            self.assertTrue(self.wait_for_notes(timeout=15))
            # wait for the terminal approve POST, so the job cannot leak into the next test
            deadline = time.time() + 15
            while time.time() < deadline and not any(n[0].endswith("/approve") for n in ApiStub.notes):
                time.sleep(0.05)
        body = [n for n in ApiStub.notes if n[0].endswith("/notes")][0][1]["body"]
        self.assertIn("<!-- ai-review -->", body)
        self.assertIn("MR author: @alice", body)
        with open(self.hermes + ".stdin") as handle:
            self.assertIn("part 1 of", handle.read())


class AllowlistTests(unittest.TestCase):

    def setUp(self):
        server._reviewed.clear()
        server._seen.clear()
    """REVIEW_REPOS restricts which repos get reviewed."""

    GL = {"object_kind": "merge_request", "project": {"id": 1, "path_with_namespace": "acme/widgets"},
          "object_attributes": {"iid": 2, "action": "open"}}

    def test_empty_allowlist_reviews_everything(self):
        self.assertTrue(server.repo_enabled("gitlab", self.GL))

    def test_listed_repo_is_enabled_case_insensitively(self):
        with patch.object(server, "REVIEW_REPOS", {"acme/widgets"}):
            self.assertTrue(server.repo_enabled("gitlab", self.GL))
            self.assertTrue(server.repo_enabled("gitlab", {"project": {"path_with_namespace": "ACME/Widgets"}}))

    def test_unlisted_repo_is_refused_with_a_remark(self):
        seen = {}
        with patch.object(server, "REVIEW_REPOS", {"acme/other"}), patch.object(server, "run_hermes") as hermes:
            self.assertFalse(server.process("gitlab", "Merge Request Hook", self.GL,
                                            {"token": "t", "secret": "s"},
                                            lambda stage, **kw: seen.update(kw)))
        hermes.assert_not_called()
        self.assertIn("not in REVIEW_REPOS", seen["remark"])
        self.assertIn("acme/widgets", seen["remark"])

    def test_github_repo_name(self):
        payload = {"repository": {"full_name": "acme/widgets"}}
        with patch.object(server, "REVIEW_REPOS", {"acme/widgets"}):
            self.assertEqual(server.repo_of("github", payload), "acme/widgets")
            self.assertTrue(server.repo_enabled("github", payload))


class ReviewOnlyOpenTests(unittest.TestCase):
    """Only open, non-draft MRs are reviewed. Draft -> ready triggers a review."""

    GL_CONFIG = {"token": "gl", "secret": SECRET, "url": "https://gl.example"}

    def setUp(self):
        server._reviewed.clear()
        server._seen.clear()

    def payload(self, action="open", state="opened", draft=False, title="feat: x"):
        return {"object_kind": "merge_request", "project": {"id": 1, "path_with_namespace": "acme/w"},
                "object_attributes": {"iid": 2, "action": action, "state": state,
                                      "draft": draft, "title": title}}

    def run_with(self, payload, event="Merge Request Hook", job=None):
        seen = {}
        job = job or {"base": "b", "token": "t", "path": "/p", "pid": 1, "iid": 2,
                      "files": [{"new_path": "a.py", "diff": "@@ -0,0 +1 @@\n+x"}],
                      "author": "alice", "header": "h", "level": 40, "draft": False,
                      "refs": {}, "head": "sha1", "diff": "@@ -0,0 +1 @@\n+x"}
        job["draft"] = bool(payload["object_attributes"].get("draft")) or job["draft"]  # as collected
        with patch.object(server, "collect_gitlab", return_value=job), \
                patch.object(server, "run_hermes", return_value="ok\nVERDICT: APPROVE") as hermes, \
                patch.object(server, "api"), patch.object(server, "reviewer_of", return_value="bot"), \
                patch.object(server, "gl_post_inline", return_value=set()), \
                patch.object(server, "gl_resolve_fixed", return_value=0), \
                patch.object(server, "superseded", return_value=False), \
                patch.object(server, "gl_approve", return_value=True):
            result = server.process("gitlab", event, payload, self.GL_CONFIG,
                                    lambda stage, **kw: seen.update(kw))
        return result, seen, hermes

    def test_open_mr_is_reviewed(self):
        result, _, hermes = self.run_with(self.payload(action="open"))
        self.assertTrue(result)
        hermes.assert_called_once()

    def test_closed_mr_is_skipped(self):
        result, seen, hermes = self.run_with(self.payload(action="close", state="closed"))
        self.assertFalse(result)
        hermes.assert_not_called()
        self.assertIn("does not trigger a review", seen["remark"])

    def test_merged_mr_is_skipped(self):
        result, seen, hermes = self.run_with(self.payload(action="merge", state="merged"))
        self.assertFalse(result)
        hermes.assert_not_called()
        self.assertIn("does not trigger a review", seen["remark"])

    def test_update_on_closed_mr_is_skipped(self):
        result, seen, hermes = self.run_with(self.payload(action="update", state="closed"))
        self.assertFalse(result)
        hermes.assert_not_called()
        self.assertIn("does not trigger a review", seen["remark"])

    def test_update_on_merged_mr_is_skipped(self):
        result, seen, hermes = self.run_with(self.payload(action="update", state="merged"))
        self.assertFalse(result)
        hermes.assert_not_called()
        self.assertIn("does not trigger a review", seen["remark"])

    def test_draft_mr_is_skipped(self):
        result, seen, hermes = self.run_with(self.payload(action="open", draft=True))
        self.assertFalse(result)
        hermes.assert_not_called()
        self.assertIn("draft", seen["remark"])

    def test_wip_title_counts_as_draft(self):
        job = {"base": "b", "token": "t", "path": "/p", "pid": 1, "iid": 2,
               "files": [{"new_path": "a.py", "diff": "@@ -0,0 +1 @@\n+x"}],
               "author": "alice", "header": "h", "level": 40, "draft": True,
               "refs": {}, "head": "sha1", "diff": "@@ -0,0 +1 @@\n+x"}
        result, seen, hermes = self.run_with(self.payload(action="open"), job=job)
        self.assertFalse(result)
        hermes.assert_not_called()
        self.assertIn("draft", seen["remark"])

    def test_marking_ready_is_an_update_and_triggers_a_review(self):
        """A draft opened as draft is skipped, so un-drafting is its first real review."""
        payload = self.payload(action="update", state="opened", draft=False)
        payload["object_attributes"]["changes"] = {"draft": {"previous": True, "current": False}}
        self.assertTrue(server.triggers_review("gitlab", "Merge Request Hook", payload))
        result, _, hermes = self.run_with(payload)
        self.assertTrue(result)
        hermes.assert_called_once()

    def test_a_plain_update_is_not_reviewed(self):
        """Pushes and edits on an existing MR must not re-trigger a review."""
        payload = self.payload(action="update", state="opened", draft=False)
        self.assertFalse(server.triggers_review("gitlab", "Merge Request Hook", payload))
        result, seen, hermes = self.run_with(payload)
        self.assertFalse(result)
        hermes.assert_not_called()
        self.assertIn("only a new MR", seen["remark"])

    def test_github_ready_for_review_triggers(self):
        self.assertTrue(server.triggers_review("github", "pull_request", {"action": "ready_for_review"}))

    def test_github_merged_pr_is_skipped(self):
        job = {"base": "b", "token": "t", "repo": "acme/w", "number": 1,
               "files": [{"new_path": "a.py", "diff": "@@ -0,0 +1 @@\n+x"}], "author": "alice",
               "header": "h", "draft": False, "state": "closed", "merged": True,
               "head": "sha1", "diff": "@@ -0,0 +1 @@\n+x"}
        seen = {}
        with patch.object(server, "collect_github", return_value=job), \
                patch.object(server, "run_hermes") as hermes:
            result = server.process("github", "pull_request", {"action": "opened", "number": 1},
                                    {"token": "gh", "secret": SECRET, "url": "https://api.github.com"},
                                    lambda stage, **kw: seen.update(kw))
        self.assertFalse(result)
        hermes.assert_not_called()
        self.assertIn("merged", seen["remark"])


class TriggerFilterTests(unittest.TestCase):
    """Non-review webhooks are acknowledged and dropped: no dashboard row."""

    def test_push_hook_is_filtered_out(self):
        self.assertFalse(server.triggers_review("gitlab", "Push Hook", {"object_kind": "push"}))

    def test_only_a_new_merge_request_triggers(self):
        for action in ("open",):
            payload = {"object_kind": "merge_request", "object_attributes": {"action": action, "iid": 1}}
            self.assertTrue(server.triggers_review("gitlab", "Merge Request Hook", payload), action)

    def test_edits_to_an_existing_mr_do_not_trigger(self):
        """`update`/`reopen` fire on every push, label, and title edit. Not new work."""
        for action in ("update", "reopen"):
            payload = {"object_kind": "merge_request",
                       "object_attributes": {"action": action, "state": "opened", "iid": 1}}
            self.assertFalse(server.triggers_review("gitlab", "Merge Request Hook", payload), action)

    def test_undrafting_triggers_a_review(self):
        """A draft opened as draft is skipped, so the ready transition is its first look."""
        payload = {"object_kind": "merge_request",
                   "object_attributes": {"action": "update", "state": "opened", "iid": 1,
                                         "changes": {"draft": {"previous": True, "current": False}}}}
        self.assertTrue(server.triggers_review("gitlab", "Merge Request Hook", payload))

    def test_a_title_edit_that_is_not_an_undraft_does_not_trigger(self):
        payload = {"object_kind": "merge_request",
                   "object_attributes": {"action": "update", "state": "opened", "iid": 1,
                                         "changes": {"title": {"previous": "Add auth", "current": "Add auth v2"}}}}
        self.assertFalse(server.triggers_review("gitlab", "Merge Request Hook", payload))

    def test_update_on_a_closed_or_merged_mr_creates_no_row(self):
        for state in ("closed", "merged"):
            with self.subTest(state=state):
                payload = {"object_kind": "merge_request",
                           "object_attributes": {"action": "update", "state": state, "iid": 1}}
                self.assertFalse(server.triggers_review("gitlab", "Merge Request Hook", payload))

    def test_update_on_an_open_mr_creates_no_row(self):
        payload = {"object_kind": "merge_request",
                   "object_attributes": {"action": "update", "state": "opened", "iid": 1}}
        self.assertFalse(server.triggers_review("gitlab", "Merge Request Hook", payload))

    def test_closed_merge_request_is_filtered_out(self):
        payload = {"object_kind": "merge_request", "object_attributes": {"action": "close", "iid": 1}}
        self.assertFalse(server.triggers_review("gitlab", "Merge Request Hook", payload))

    def test_note_event_still_triggers_debate(self):
        payload = {"object_kind": "note", "object_attributes": {"noteable_type": "MergeRequest", "note": "@bot hi"}}
        self.assertTrue(server.triggers_review("gitlab", "Note Hook", payload))

    def test_github_pr_actions(self):
        for action in ("opened", "ready_for_review"):
            self.assertTrue(server.triggers_review("github", "pull_request", {"action": action}))
        for action in ("synchronize", "reopened", "closed", "edited", "converted_to_draft", "review_requested"):
            self.assertFalse(server.triggers_review("github", "pull_request", {"action": action}), action)
        self.assertFalse(server.triggers_review("github", "push", {"action": "opened"}))

    def test_garbage_payload_is_filtered_out(self):
        self.assertFalse(server.triggers_review("gitlab", "Merge Request Hook", {"object_kind": "merge_request"}))
        self.assertFalse(server.triggers_review("gitlab", "Merge Request Hook", {}))


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
        self.assertIn("### Critical", prompt)
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
                patch.object(server, "run_hermes", return_value="ok\nVERDICT: APPROVE") as hermes:
            self.assertFalse(server.process("github", "pull_request", self.payload(), self.CONFIG))
        hermes.assert_not_called()
        self.assertEqual(posts, [])

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
        original = self.payload()

        def fake_api(base, token, platform, path, body=None, accept="application/json"):
            if accept.endswith("diff"):
                return b"  \n"
            return json.dumps({"title": "t", "state": "open", "merged": False, "user": {"login": "alice"},
                               "head": {"ref": "f"}, "base": {"ref": "main"}}).encode()

        with patch.object(server, "api", side_effect=fake_api), patch.object(server, "run_hermes") as hermes:
            self.assertFalse(server.process("github", "pull_request", original, self.CONFIG))
        hermes.assert_not_called()


class GitLabFlowTests(unittest.TestCase):
    CONFIG = {"token": "gl", "secret": SECRET, "url": "https://gitlab.example.com"}

    def test_overflow_blocks_review(self):
        def fake_api(base, token, platform, path, body=None, accept="application/json"):
            if path == "/user":
                return json.dumps({"username": "santosodb"}).encode()
            if path == "/projects/1":
                return json.dumps({"permissions": {"project_access": {"access_level": 40}}}).encode()
            return b'{"changes": [], "overflow": true}'

        with patch.object(server, "api", side_effect=fake_api), patch.object(server, "run_hermes") as hermes:
            with self.assertRaises(ValueError):
                server.process("gitlab", "Merge Request Hook", {
                    "object_kind": "merge_request", "project": {"id": 1},
                    "object_attributes": {"iid": 2, "action": "open"}}, self.CONFIG)
        hermes.assert_not_called()

    def test_low_access_level_skips_review(self):
        def fake_api(base, token, platform, path, body=None, accept="application/json"):
            return b'{"permissions": {"project_access": {"access_level": 20}}}'

        with patch.object(server, "api", side_effect=fake_api), patch.object(server, "run_hermes") as hermes:
            self.assertFalse(server.process("gitlab", "Merge Request Hook", {
                "object_kind": "merge_request", "project": {"id": 1},
                "object_attributes": {"iid": 2, "action": "open"}}, self.CONFIG))
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

    CHANGES = [{"new_path": "src/auth.py", "diff": "@@ -28,4 +30,4 @@\n a\n+b\n"}]
    PATH = "/projects/1/merge_requests/2"

    def test_review_published_as_one_batch_of_drafts(self):
        calls = []

        def fake_api(base, token, platform, path, body=None, accept="application/json", method=None):
            calls.append((path, body, method))
            if path.endswith("/draft_notes") and body is None:
                return b'[{"id": 5, "note": "<!-- ai-review -->\\nstale"}, {"id": 6, "note": "human"}]'
            return b'{"id": 9}'

        with patch.object(server, "api", side_effect=fake_api):
            posted = server.gl_publish_review("https://gl/api/v4", "t", self.PATH, self.REVIEW,
                                              self.CHANGES, {"base_sha": "b", "head_sha": "h"},
                                              lambda done: "summary %d" % len(done))
        self.assertEqual(posted, {("src/auth.py", 31)})
        paths = [c[0] for c in calls]
        self.assertEqual(paths, [self.PATH + "/draft_notes", self.PATH + "/draft_notes/5",
                                 self.PATH + "/draft_notes", self.PATH + "/draft_notes",
                                 self.PATH + "/draft_notes/bulk_publish"])
        self.assertEqual(calls[1][2], "DELETE")  # only our own stale draft is discarded
        self.assertEqual(calls[2][1]["position"]["new_line"], 31)
        self.assertEqual(calls[3][1], {"note": "summary 1"})
        self.assertFalse(any(p.endswith("/discussions") or p.endswith("/notes") for p in paths))

    def test_falls_back_to_discussions_without_draft_notes_api(self):
        calls = []

        def fake_api(base, token, platform, path, body=None, accept="application/json", method=None):
            calls.append(path)
            if "/draft_notes" in path:
                raise server.HTTPError(path, 404, "Not Found", {}, None)
            return b'{"id": 9}'

        with patch.object(server, "api", side_effect=fake_api):
            posted = server.gl_publish_review("https://gl/api/v4", "t", self.PATH, self.REVIEW,
                                              self.CHANGES, {"base_sha": "b", "head_sha": "h"},
                                              lambda done: "summary")
        self.assertEqual(posted, {("src/auth.py", 31)})
        self.assertIn(self.PATH + "/discussions", calls)
        self.assertEqual(calls[-1], self.PATH + "/notes")

    def test_no_inline_posts_only_the_summary_note(self):
        calls = []

        def fake_api(base, token, platform, path, body=None, accept="application/json", method=None):
            calls.append(path)
            return b'{"id": 9}'

        with patch.object(server, "api", side_effect=fake_api):
            posted = server.gl_publish_review("https://gl/api/v4", "t", self.PATH,
                                              "Fine.\nVERDICT: APPROVE", self.CHANGES, {}, lambda done: "s")
        self.assertEqual((posted, calls), (set(), [self.PATH + "/notes"]))


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


GL_CONFIG = {"token": "t", "secret": "s", "url": "https://gitlab.com"}


class RunJobRemarkTests(unittest.TestCase):
    """Regression: a skip must stay a skip, never become a failed row."""

    def run_one(self, payload, event):
        tracker = server.Tracker(os.path.join(tempfile.mkdtemp(), "r.jsonl"))
        old = server._tracker
        server._tracker = tracker
        try:
            server.run_job("gitlab", event, payload, GL_CONFIG, b"raw", None)
        finally:
            server._tracker = old
        return tracker.snapshot()["history"][0]

    def test_ignored_event_is_skipped_with_a_remark(self):
        row = self.run_one({"object_kind": "push"}, "Push Hook")
        self.assertEqual(row["status"], "skipped")
        self.assertIn("not a merge request event", row["remark"])
        self.assertEqual(row["error"], "")

    def test_failure_reports_its_error_without_a_remark_collision(self):
        payload = {"object_kind": "merge_request", "project": {"id": 1},
                   "object_attributes": {"iid": 2, "action": "open"}}

        def boom(*a, **kw):
            raise ValueError("diff too large for one review")

        with patch.object(server, "collect_gitlab", side_effect=boom):
            row = self.run_one(payload, "Merge Request Hook")
        self.assertEqual(row["status"], "failed")
        self.assertEqual(row["error"], "diff too large for one review")
        self.assertNotIn("multiple values", row["error"])


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
                   "object_attributes": {"iid": 2, "action": "open"}}
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
                   "object_attributes": {"iid": 2, "action": "open"}}
        def fake_api(base, token, platform, path, body=None, accept="application/json"):
            if path == "/user":
                return json.dumps({"username": "santosodb"}).encode()
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


class DebateRemarkTests(unittest.TestCase):
    """A debate reply that does not happen must say why."""

    def setUp(self):
        # Both maps are module globals keyed by the note, and every fixture reuses
        # note id 9 — without a reset the first test answers for all the others.
        server._replied.clear()
        server._cooldown.clear()

    def run_debate(self, payload, bot="santosodb"):
        seen = {}
        old = server.BOT_USERNAME
        server.BOT_USERNAME = bot
        try:
            with patch.object(server, "api"), patch.object(server, "run_hermes") as hermes, \
                    patch.object(server, "api_json", return_value=[]):
                result = server.debate("gitlab", payload, GL_CONFIG, lambda stage, **kw: seen.update(kw))
        finally:
            server.BOT_USERNAME = old
        return result, seen, hermes

    def note(self, text, commenter="alice", kind="MergeRequest"):
        return {"object_kind": "note", "user": {"username": commenter}, "project_id": 1,
                "merge_request": {"iid": 2, "author": {"username": "dimas"}},
                "object_attributes": {"noteable_type": kind, "note": text, "noteable_iid": 2,
                                      "id": 9, "discussion_id": "d1"}}

    def test_no_bot_username(self):
        _, seen, _ = self.run_debate(self.note("@santosodb hi"), bot="")
        self.assertIn("BOT_USERNAME", seen["remark"])

    def test_no_mention(self):
        _, seen, _ = self.run_debate(self.note("looks good"))
        self.assertIn("does not mention", seen["remark"])

    def test_reply_in_our_thread_needs_no_mention(self):
        """A human answering our inline finding is already addressing us."""
        seen = {}
        old = server.BOT_USERNAME
        server.BOT_USERNAME = "santosodb"
        ours = [{"id": "d1", "notes": [
            {"author": {"username": "santosodb"}, "body": "<!-- ai-review -->\nfinding"},
            {"author": {"username": "alice"}, "body": "good catch, fixed"}]}]
        try:
            server._replied.clear()
            with patch.object(server, "api_json", return_value=ours), \
                    patch.object(server, "api"), \
                    patch.object(server, "run_hermes", return_value="thanks"), \
                    patch.object(server, "gl_access_level", return_value=40), \
                    patch.object(server, "gl_thread", return_value=""), \
                    patch.object(server, "bounded_diff", return_value=""):
                posted = server.debate("gitlab", self.note("good catch, fixed"), GL_CONFIG,
                                       lambda stage, **kw: seen.update(kw))
        finally:
            server.BOT_USERNAME = old
        self.assertTrue(posted)
        self.assertEqual(seen.get("remark"), "answered")  # reached the reply, not a skip

    def test_no_mention_outside_our_thread_still_skips(self):
        """Someone else's discussion is not an address; the mention stays required."""
        seen = {}
        old = server.BOT_USERNAME
        server.BOT_USERNAME = "santosodb"
        theirs = [{"id": "d1", "notes": [
            {"author": {"username": "bob"}, "body": "unrelated thread"}]}]
        try:
            server._replied.clear()
            with patch.object(server, "api_json", return_value=theirs):
                posted = server.debate("gitlab", self.note("looks good"), GL_CONFIG,
                                       lambda stage, **kw: seen.update(kw))
        finally:
            server.BOT_USERNAME = old
        self.assertFalse(posted)
        self.assertIn("does not mention", seen["remark"])

    def test_our_thread_lookup_failing_falls_back_to_requiring_the_mention(self):
        seen = {}
        old = server.BOT_USERNAME
        server.BOT_USERNAME = "santosodb"
        try:
            with patch.object(server, "api_json", side_effect=URLError("down")):
                posted = server.debate("gitlab", self.note("looks good"), GL_CONFIG,
                                       lambda stage, **kw: seen.update(kw))
        finally:
            server.BOT_USERNAME = old
        self.assertFalse(posted)
        self.assertIn("does not mention", seen["remark"])

    def test_own_reply(self):
        _, seen, _ = self.run_debate(self.note("<!-- ai-review -->\n@santosodb answer"))
        self.assertIn("our own replies", seen["remark"])

    def test_bot_commenter(self):
        _, seen, _ = self.run_debate(self.note("@santosodb hi", commenter="dependabot[bot]"))
        self.assertIn("written by a bot", seen["remark"])

    def test_not_a_merge_request_note(self):
        _, seen, _ = self.run_debate(self.note("@santosodb hi", kind="Commit"))
        self.assertIn("not on a merge request", seen["remark"])

    def test_low_access(self):
        payload = self.note("@santosodb hi")
        seen = {}
        old = server.BOT_USERNAME
        server.BOT_USERNAME = "santosodb"
        try:
            with patch.object(server, "gl_access_level", return_value=10), \
                    patch.object(server, "api"), patch.object(server, "run_hermes") as hermes:
                self.assertFalse(server.debate("gitlab", payload, GL_CONFIG,
                                               lambda stage, **kw: seen.update(kw)))
        finally:
            server.BOT_USERNAME = old
        hermes.assert_not_called()
        self.assertIn("MIN_ACCESS_LEVEL", seen["remark"])


class ChunkedReviewTests(unittest.TestCase):
    """Diffs over MAX_DIFF are reviewed in parts, never rejected."""

    def files(self, count, size):
        return [{"new_path": "f%d.py" % i, "diff": "\n".join(
            ["@@ -1,%d +1,%d @@" % (size, size)] + ["+line %d of file %d" % (n, i) for n in range(size)])}
            for i in range(count)]

    def test_small_diff_is_one_call(self):
        calls = []
        with patch.object(server, "run_hermes", side_effect=lambda q: calls.append(q) or "ok\nVERDICT: APPROVE"):
            out = server.review_diff("HDR", "+x" * 100, self.files(1, 3))
        self.assertEqual(len(calls), 1)
        self.assertIn("APPROVE", out)

    def test_oversized_diff_is_chunked_and_never_rejected(self):
        files = self.files(120, 60)
        total = sum(len(f["diff"]) for f in files)
        self.assertGreater(total, server.MAX_DIFF)
        calls = []
        with patch.object(server, "run_hermes",
                          side_effect=lambda q, **kw: calls.append(q) or "finding\nVERDICT: APPROVE"):
            out = server.review_diff("HDR", "\n".join(f["diff"] for f in files), files)
        self.assertGreater(len(calls), 1)
        for i, chunk in enumerate(calls, 1):
            self.assertIn("part %d of %d" % (i, len(calls)), chunk)
            self.assertLessEqual(len(chunk), server.MAX_DIFF + len("HDR") + 200)
        self.assertIn("APPROVE", out)

    def test_chunks_cover_every_file(self):
        files = self.files(30, 40)
        joined = "\n".join(server.chunks_of(files, limit=2000))
        for i in range(30):
            self.assertIn("f%d.py" % i, joined)

    def test_single_file_bigger_than_limit_splits_at_hunks(self):
        big = {"new_path": "big.py", "diff": "\n".join(
            ["@@ -%d,2 +%d,2 @@" % (n, n) for n in range(1, 400)] + ["+padding line %d" % n for n in range(300)])}
        chunks = server.chunks_of([big], limit=1000)
        self.assertGreater(len(chunks), 1)
        for c in chunks:
            self.assertIn("big.py", c)
            self.assertLessEqual(len(c), 1200)

    def test_merged_verdict_keeps_the_strictest(self):
        merged = server.merge_reviews(["looks fine\nVERDICT: APPROVE",
                                       "bug here\nVERDICT: REQUEST_CHANGES"])
        self.assertIn("REQUEST_CHANGES", merged)
        self.assertIn("bug here", merged)
        self.assertNotIn("VERDICT: APPROVE", merged)


class ReviewBudgetTests(unittest.TestCase):
    """A huge diff must degrade to a partial, labelled review — never a bare timeout."""

    def files(self, count, size):
        return [{"new_path": "f%d.py" % i, "diff": "\n".join(
            ["@@ -1,%d +1,%d @@" % (size, size)] + ["+line %d of %d" % (n, i) for n in range(size)])}
            for i in range(count)]

    def test_budget_skips_the_tail_and_says_so(self):
        files = self.files(40, 40)
        calls = []
        clock = iter([0, 0, 9999])  # first part starts, then the budget is gone

        def fake_run(prompt, timeout=None):
            calls.append(prompt)
            return "finding\nVERDICT: REQUEST_CHANGES"

        with patch.object(server, "run_hermes", side_effect=fake_run), \
                patch.object(server, "MAX_DIFF", 400), patch.object(server, "time") as fake_time:
            fake_time.monotonic = lambda: next(clock, 9999)
            out = server.review_diff("HDR", "x" * 5000, files, budget=100)
        self.assertEqual(len(calls), 1)
        self.assertIn("did not fit the 100s budget", out)
        self.assertIn("REQUEST_CHANGES", out)

    def test_partial_review_still_posts_a_verdict(self):
        files = self.files(30, 40)
        with patch.object(server, "MAX_DIFF", 400), \
                patch.object(server, "run_hermes", return_value="ok\nVERDICT: APPROVE"):
            out = server.review_diff("HDR", "x" * 5000, files, budget=10_000)
        self.assertEqual(server.verdict_of(out), "APPROVE")
        self.assertNotIn("did not fit", out)

    def test_zero_budget_is_an_error_not_silence(self):
        with patch.object(server, "MAX_DIFF", 400), \
                patch.object(server, "run_hermes") as hermes, \
                patch.object(server, "time") as fake_time:
            fake_time.monotonic = lambda: 0
            with self.assertRaises(ValueError):
                server.review_diff("HDR", "x" * 5000, self.files(20, 40), budget=5)
        hermes.assert_not_called()


class ResolveThreadTests(unittest.TestCase):
    """The bot resolves its own threads whose finding is gone, and nothing else."""

    REVIEW = "### Inline Comments\n- `a.py:10` WARNING: still broken.\n\nVERDICT: REQUEST_CHANGES"

    def discussion(self, did="d1", author="santosodb", resolved=False,
                   path="a.py", line=5, extra=None):
        notes = [{"system": False, "author": {"username": author},
                  "resolvable": True, "resolved": resolved,
                  "position": {"new_path": path, "new_line": line}}]
        if extra:
            notes.append({"system": False, "author": {"username": extra}})
        return {"id": did, "notes": notes}

    def resolve(self, discussions):
        calls = []

        def fake_api_json(base, token, platform, path, body=None, accept="application/json", method=None):
            if body is not None:
                calls.append((path, body, method))
                return {}
            return discussions

        with patch.object(server, "api_json", side_effect=fake_api_json):
            closed = server.gl_resolve_fixed("b", "t", 1, 2, self.REVIEW, "santosodb")
        return closed, calls

    def test_fixed_finding_is_resolved(self):
        closed, calls = self.resolve([self.discussion(line=5)])
        self.assertEqual(closed, 1)
        # GitLab resolves only via PUT; the old POST was a 404 in production.
        self.assertEqual(calls, [("/projects/1/merge_requests/2/discussions/d1?resolved=true", {}, "PUT")])

    def test_resolve_really_sends_put(self):
        """Below the api_json mock: the request method reaches urllib."""
        seen = []

        class Opener:
            def open(self, request, timeout=None):
                seen.append((request.get_method(), request.full_url))
                raise server.URLError("stop")

        with patch.object(server, "build_opener", return_value=Opener()), \
                patch.object(server, "API_ATTEMPTS", 1):
            with self.assertRaises(server.URLError):
                server.gl_resolve("https://gl/api/v4", "t", 1, 2, "d1")
        self.assertEqual(seen, [("PUT", "https://gl/api/v4/projects/1/merge_requests/2/discussions/d1?resolved=true")])

    def test_still_flagged_finding_stays_open(self):
        closed, calls = self.resolve([self.discussion(line=10)])
        self.assertEqual((closed, calls), (0, []))

    def test_already_resolved_thread_is_left_alone(self):
        closed, calls = self.resolve([self.discussion(resolved=True)])
        self.assertEqual((closed, calls), (0, []))

    def test_human_thread_is_not_touched(self):
        closed, calls = self.resolve([self.discussion(author="alice")])
        self.assertEqual((closed, calls), (0, []))

    def test_thread_a_human_joined_is_left_open(self):
        closed, calls = self.resolve([self.discussion(extra="alice")])
        self.assertEqual((closed, calls), (0, []))

    def test_only_our_threads_are_closed(self):
        closed, calls = self.resolve([self.discussion(did="d1"), self.discussion(did="d2", author="alice")])
        self.assertEqual(closed, 1)
        self.assertEqual(len(calls), 1)

    def test_unknown_position_is_not_guessed(self):
        d = self.discussion()
        d["notes"][0]["position"] = {}
        closed, calls = self.resolve([d])
        self.assertEqual((closed, calls), (0, []))

    def test_api_failure_does_not_abort_the_review(self):
        def fake_api_json(base, token, platform, path, body=None, accept="application/json", method=None):
            if body is not None:
                raise server.URLError("down")
            return [self.discussion(line=5)]

        with patch.object(server, "api_json", side_effect=fake_api_json):
            self.assertEqual(server.gl_resolve_fixed("b", "t", 1, 2, self.REVIEW, "santosodb"), 0)

    def test_no_reviewer_identity_resolves_nothing(self):
        with patch.object(server, "api_json") as api_json:
            self.assertEqual(server.gl_resolve_fixed("b", "t", 1, 2, self.REVIEW, ""), 0)
        api_json.assert_not_called()


class OwnCommentFilterTests(unittest.TestCase):
    """Our own review comments echo back as note hooks; they must not create rows."""

    def setUp(self):
        self.saved = server.BOT_USERNAME
        server.BOT_USERNAME = "santosodb"

    def tearDown(self):
        server.BOT_USERNAME = self.saved

    def note(self, body, author="santosodb"):
        return {"object_kind": "note", "user": {"username": author},
                "object_attributes": {"note": body, "noteable_type": "MergeRequest",
                                      "noteable_iid": 1, "id": 9}}

    def test_our_review_comment_is_dropped(self):
        payload = self.note(server.REVIEW_MARKER + "\n### Summary\nlooks fine")
        self.assertFalse(server.triggers_review("gitlab", "Note Hook", payload))

    def test_human_mention_still_triggers(self):
        payload = self.note("hey @santosodb why is this slow?", author="alice")
        self.assertTrue(server.triggers_review("gitlab", "Note Hook", payload))

    def test_a_human_quoting_our_comment_still_triggers(self):
        """The marker alone is not proof: the author decides."""
        payload = self.note("> " + server.REVIEW_MARKER + "\nwhat does this mean @santosodb?",
                            author="alice")
        self.assertTrue(server.triggers_review("gitlab", "Note Hook", payload))

    def test_github_bot_comment_is_dropped(self):
        payload = {"action": "created",
                   "comment": {"body": server.REVIEW_MARKER + "\nsummary",
                               "user": {"login": "santosodb"}},
                   "issue": {"number": 3}}
        self.assertFalse(server.triggers_review("github", "issue_comment", payload))

    def test_github_human_comment_triggers(self):
        payload = {"action": "created",
                   "comment": {"body": "@santosodb take a look", "user": {"login": "alice"}},
                   "issue": {"number": 3}}
        self.assertTrue(server.triggers_review("github", "issue_comment", payload))


class EventStreamTests(unittest.TestCase):
    """SSE endpoint: pushes a snapshot on change instead of being polled."""

    def setUp(self):
        self.tracker = server.Tracker(path=None)
        self.saved = server._tracker
        self.saved_password = server.DASHBOARD_PASSWORD
        server._tracker = self.tracker
        server.DASHBOARD_PASSWORD = ""  # the stream is behind the same Basic auth

    def tearDown(self):
        server._tracker = self.saved
        server.DASHBOARD_PASSWORD = self.saved_password

    def test_bump_wakes_a_waiting_subscriber(self):
        woke = []

        def wait():
            with self.tracker.changed:
                before = self.tracker.version
                self.tracker.changed.wait_for(lambda: self.tracker.version != before, timeout=2)
                woke.append(self.tracker.version)

        thread = threading.Thread(target=wait, daemon=True)
        thread.start()
        time.sleep(0.05)
        self.tracker.begin("gitlab", "g/p!1", "dimas")
        thread.join(2)
        self.assertEqual(len(woke), 1)
        self.assertGreater(woke[0], 0)

    def test_stage_change_bumps_but_a_repeat_does_not(self):
        rec = self.tracker.begin("gitlab", "g/p!1")
        version = self.tracker.version
        self.tracker.stage(rec, "reviewing")
        self.assertEqual(self.tracker.version, version + 1)
        self.tracker.stage(rec, "reviewing")
        self.assertEqual(self.tracker.version, version + 1)

    def test_finish_bumps(self):
        rec = self.tracker.begin("gitlab", "g/p!1")
        version = self.tracker.version
        self.tracker.finish(rec, "done")
        self.assertEqual(self.tracker.version, version + 1)

    def test_stream_pushes_a_snapshot_without_being_polled(self):
        """Open /api/events, change nothing, and a frame still arrives immediately."""
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        httpd.config = {}
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            response = urlopen(f"http://127.0.0.1:{httpd.server_address[1]}/api/events", timeout=5)
            self.assertEqual(response.headers["Content-Type"], "text/event-stream; charset=utf-8")
            line = response.readline()
            self.assertTrue(line.startswith(b"data: "), line)
            self.assertEqual(response.readline(), b"\n")  # blank line ends the frame
            data = json.loads(line[len(b"data: "):])
            self.assertIn("stats", data)
            self.assertEqual(data["stats"]["workers"], server.MAX_WORKERS)
            response.close()
        finally:
            httpd.shutdown()
            httpd.server_close()


class AuthorColumnTests(unittest.TestCase):
    """The dashboard's MR-author column must actually fill in."""

    CONFIG = {"token": "gl", "secret": SECRET, "url": "https://gl.example"}

    def setUp(self):
        server._reviewed.clear()

    def test_gitlab_mr_hook_author(self):
        payload = {"object_kind": "merge_request",
                   "object_attributes": {"author_id": 7, "author": {"username": "dimas"}}}
        self.assertEqual(server.author_of(payload), "dimas")

    def test_gitlab_mr_hook_without_author_object_falls_back(self):
        payload = {"object_kind": "merge_request", "object_attributes": {"author_id": 7},
                   "merge_request": {"author": {"username": "dimas"}}}
        self.assertEqual(server.author_of(payload), "dimas")

    def test_gitlab_mr_hook_with_only_author_id_is_blank(self):
        self.assertEqual(server.author_of({"object_attributes": {"author_id": 7}}), "")

    def test_note_hook_author_is_the_mr_author(self):
        payload = {"object_kind": "note",
                   "merge_request": {"author": {"username": "dimas"}},
                   "user": {"username": "someone-else"}}
        self.assertEqual(server.author_of(payload), "dimas")

    def test_github_pr_author(self):
        self.assertEqual(server.author_of({"pull_request": {"user": {"login": "dimas"}}}), "dimas")

    def test_author_resolved_from_the_api_reaches_the_record(self):
        """A payload with no author still gets one once the API tells us who opened it."""
        payload = {"object_kind": "merge_request", "project": {"id": 1, "path_with_namespace": "g/p"},
                   "object_attributes": {"iid": 2, "action": "open", "state": "opened",
                                         "author_id": 7, "title": "feat: x"}}
        self.assertEqual(server.author_of(payload), "")  # what GitLab actually sends
        job = {"base": "b", "token": "t", "path": "/p", "pid": 1, "iid": 2, "author": "dimas",
               "files": [{"new_path": "a.py", "diff": "@@ -0,0 +1 @@\n+x"}],
               "header": "h", "level": 40, "draft": False, "refs": {},
               "head": "sha1", "diff": "@@ -0,0 +1 @@\n+x"}
        tracker = server.Tracker(path=None)
        rec = tracker.begin("gitlab", "g/p!2", server.author_of(payload))

        def track(stage, **fields):
            rec.update(fields)

        with patch.object(server, "collect_gitlab", return_value=job), \
                patch.object(server, "run_hermes", return_value="ok\nVERDICT: APPROVE"), \
                patch.object(server, "api"), patch.object(server, "reviewer_of", return_value="bot"), \
                patch.object(server, "gl_post_inline", return_value=set()), \
                patch.object(server, "gl_resolve_fixed", return_value=0), \
                patch.object(server, "gl_approve"), patch.object(server, "superseded", return_value=False):
            server.process("gitlab", "Merge Request Hook", payload, self.CONFIG, track)
        tracker.finish(rec, "done")
        self.assertEqual(tracker.snapshot()["history"][0]["author"], "dimas")


class AuthorCarryOverTests(unittest.TestCase):
    """A note hook knows only `author_id`, so the row reuses what we learned earlier.

    Reproduces pasarpolis/integrationservice!4895: the review row carried the author,
    the own-comment row right after it did not.
    """

    TARGET = "pasarpolis/integrationservice!4895"

    def setUp(self):
        server._reviewed.clear()

    def test_note_row_reuses_the_author_of_the_mr_row(self):
        """Drives run_job, so it proves the carry-over is wired in — not just that it exists."""
        tracker = server.Tracker(path=None)
        tracker.begin("gitlab", self.TARGET, "alvian.r.hanif")  # the review row, earlier
        payload = {"object_kind": "note", "user": {"username": "alvian.r.hanif"},
                   "project": {"id": 1, "path_with_namespace": "pasarpolis/integrationservice"},
                   "merge_request": {"iid": 4895},
                   "object_attributes": {"note": "@santosodb is this safe?",
                                         "noteable_type": "MergeRequest",
                                         "noteable_iid": 4895, "discussion_id": "d"}}
        self.assertEqual(server.author_of(payload), "")  # what GitLab actually sends
        old = server.BOT_USERNAME
        server.BOT_USERNAME = "santosodb"
        try:
            with patch.object(server, "_tracker", tracker), \
                    patch.object(server, "debate", return_value=False):
                server.run_job("gitlab", "Note Hook", payload,
                               {"token": "t", "url": "https://gl.example"}, b"{}", "k1")
        finally:
            server.BOT_USERNAME = old
        skipped = tracker.snapshot()["history"][0]
        self.assertEqual(skipped["target"], self.TARGET)
        self.assertEqual(skipped["author"], "alvian.r.hanif")

    def test_rows_loaded_from_the_store_get_their_author_backfilled(self):
        """History written before the carry-over existed still renders an author."""
        path = os.path.join(tempfile.mkdtemp(), "reviews.jsonl")
        base = {"platform": "gitlab", "target": self.TARGET, "url": "https://gitlab.com/g/p/-/merge_requests/4895"}
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(dict(base, id=1, author="alvian.r.hanif", status="done",
                                     stage="done", started=1.0, duration=247.9,
                                     verdict="", inline=0, files=0, error="", remark="")) + "\n")
            fh.write(json.dumps(dict(base, id=2, author="", status="skipped",
                                     stage="skipped", started=2.0, duration=0.0,
                                     verdict="", inline=0, files=0, error="",
                                     remark="comment is one of our own replies")) + "\n")
        history = server.Tracker(path=path).snapshot()["history"]
        self.assertEqual([r["author"] for r in history], ["alvian.r.hanif", "alvian.r.hanif"])

    def test_unknown_target_stays_blank_instead_of_inventing_one(self):
        tracker = server.Tracker(path=None)
        self.assertEqual(tracker.author_of_target("nobody/here!1"), "")
        self.assertEqual(tracker.author_of_target(""), "")


class ReviewerFlagTests(unittest.TestCase):
    """Comments distinguish the MR author from the reviewing bot."""

    def test_footer_names_author_and_reviewer(self):
        body = server.review_body("ok\nVERDICT: APPROVE", "dimas", "APPROVE", reviewer="santosodb")
        self.assertIn("MR author: @dimas", body)
        self.assertIn("Reviewer: @santosodb (bot)", body)

    def test_footer_without_a_known_reviewer(self):
        body = server.review_body("ok\nVERDICT: APPROVE", "dimas", "APPROVE")
        self.assertIn("MR author: @dimas", body)
        self.assertIn("Reviewer: Hermes Agent (bot)", body)

    def test_author_is_not_listed_as_reviewer(self):
        body = server.review_body("ok", "dimas", "APPROVE", reviewer="santosodb")
        self.assertNotIn("Reviewer: @dimas", body)

    def test_reviewer_is_looked_up_and_cached(self):
        server._whoami_cache.clear()
        with patch.object(server, "api_json", return_value={"username": "santosodb"}) as a:
            self.assertEqual(server.reviewer_of("gitlab", "https://gl", "t"), "santosodb")
            self.assertEqual(server.reviewer_of("gitlab", "https://gl", "t"), "santosodb")
        self.assertEqual(a.call_count, 1)

    def test_lookup_failure_does_not_break_the_review(self):
        server._whoami_cache.clear()
        with patch.object(server, "api_json", side_effect=server.URLError("down")):
            self.assertEqual(server.reviewer_of("gitlab", "https://gl2", "t"), "")


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


class AuthorTests(unittest.TestCase):
    """The Author column is the MR/PR creator, never the commenter."""

    def test_gitlab_mr_author(self):
        payload = {"object_attributes": {"author": {"username": "dimas"}}}
        self.assertEqual(server.author_of(payload), "dimas")

    def test_gitlab_note_reports_the_mr_author(self):
        payload = {"object_kind": "note", "user": {"username": "reviewer"},
                   "merge_request": {"iid": 1, "author": {"username": "dimas"}}}
        self.assertEqual(server.author_of(payload), "dimas")

    def test_github_pr_author(self):
        payload = {"pull_request": {"user": {"login": "alice"}}}
        self.assertEqual(server.author_of(payload), "alice")

    def test_github_comment_reports_the_pr_author(self):
        payload = {"action": "created", "comment": {"user": {"login": "reviewer"}},
                   "issue": {"number": 1, "user": {"login": "alice"}}}
        self.assertEqual(server.author_of(payload), "alice")

    def test_missing_author_is_blank(self):
        self.assertEqual(server.author_of({}), "")


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
        self.assertIn("/api/events", page)  # streams; the poll endpoint is the fallback
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
        """The head moves between collection and posting, so the verdict is dropped."""
        posted = []
        heads = iter(["sha-old", "sha-new"])

        def fake_api(base, token, platform, path, body=None, accept="application/json"):
            if path == "/user":
                return json.dumps({"username": "santosodb"}).encode()
            if path == "/projects/1":
                return json.dumps({"permissions": {"project_access": {"access_level": 40}}}).encode()
            if "/changes" in path:
                return json.dumps({"changes": [{"new_path": "a.py", "diff": "@@ -0,0 +1 @@\n+x"}],
                                   "overflow": False}).encode()
            if body is not None:
                posted.append((path, body))
                return b'{"id": 1}'
            if path.endswith("/merge_requests/2"):
                # Only the MR endpoint carries the head; consume one sha per read so
                # collection and the staleness check disagree on purpose.
                return json.dumps({"author": {"username": "alice"},
                                   "diff_refs": {"head_sha": next(heads)}}).encode()
            return b"[]"  # notes/discussions listings

        with patch.object(server, "api", side_effect=fake_api), \
                patch.object(server, "run_hermes", return_value="ok\nVERDICT: APPROVE"):
            self.assertFalse(server.process("gitlab", "Merge Request Hook", {
                "object_kind": "merge_request", "project": {"id": 1},
                "object_attributes": {"iid": 2, "action": "open"}}, self.CONFIG))
        self.assertEqual(posted, [])

    def test_superseded_helper_edge_cases(self):
        job = {"base": "b", "token": "t", "path": "/p", "pid": 1, "iid": 2, "head": ""}
        self.assertFalse(server.superseded("gitlab", job, self.CONFIG))  # unknown head: post anyway
        job["head"] = "sha"
        with patch.object(server, "api_json", return_value={}):
            self.assertFalse(server.superseded("gitlab", job, self.CONFIG))  # head gone: post anyway


class DraftTests(unittest.TestCase):
    HARMLESS_GL = {"token": "gl", "secret": SECRET, "url": "https://gitlab.example.com"}

    def test_draft_mr_is_not_reviewed(self):
        def fake_api(base, token, platform, path, body=None, accept="application/json"):
            if path == "/user":
                return json.dumps({"username": "santosodb"}).encode()
            if path == "/projects/1":
                return json.dumps({"permissions": {"project_access": {"access_level": 40}}}).encode()
            if "/changes" in path:
                return json.dumps({"changes": [{"new_path": "a.py", "diff": "@@ -0,0 +1 @@\n+x"}],
                                   "overflow": False}).encode()
            if path.endswith("/approvals"):
                raise AssertionError("a draft must not be reviewed at all")
            if body is not None:
                return b'{"id": 1}'
            return json.dumps({"author": {"username": "alice"}, "diff_refs": {}}).encode()

        with patch.object(server, "api", side_effect=fake_api), \
                patch.object(server, "run_hermes", return_value="fine\nVERDICT: APPROVE"):
            self.assertFalse(server.process("gitlab", "Merge Request Hook", {
                "object_kind": "merge_request", "project": {"id": 1},
                "object_attributes": {"iid": 2, "action": "open", "title": "Draft: wip"}},
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
                "object_attributes": {"iid": 2, "action": "open", "title": "Add auth"}},
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
            if path == "/user":
                return json.dumps({"username": "santosodb"}).encode()
            if path == "/projects/1":
                return json.dumps({"permissions": {"project_access": {"access_level": 40}}}).encode()
            if path.endswith("/changes?access_raw_diffs=true"):
                return json.dumps({"changes": [{"new_path": "a.py", "diff": "@@ -0,0 +1 @@\n+x"}], "overflow": False}).encode()
            return json.dumps({"author": {"username": "santosodb"}, "diff_refs": {}}).encode()
        with patch.object(server, "api", side_effect=fake_api), \
                patch.object(server, "run_hermes", return_value="VERDICT: APPROVE") as hermes:
            self.assertTrue(server.process("gitlab", "Merge Request Hook", {
                "object_kind": "merge_request", "project": {"id": 1},
                "object_attributes": {"iid": 2, "action": "open"}}, self.GL))
        hermes.assert_called_once()

    def test_same_head_is_not_reviewed_twice(self):
        """Our own approval triggers another MR event; the head did not move, so skip."""
        server._reviewed.clear()
        calls = {"n": 0}
        def fake_api(base, token, platform, path, body=None, accept="application/json"):
            if path == "/user":
                return json.dumps({"username": "santosodb"}).encode()
            if path == "/projects/1":
                return json.dumps({"permissions": {"project_access": {"access_level": 40}}}).encode()
            if path.endswith("/changes?access_raw_diffs=true"):
                return json.dumps({"changes": [{"new_path": "a.py", "diff": "@@ -0,0 +1 @@\n+x"}],
                                   "overflow": False}).encode()
            return json.dumps({"author": {"username": "dimas"},
                               "diff_refs": {"head_sha": "abc123"}}).encode()
        payload = {"object_kind": "merge_request", "project": {"id": 1},
                   "object_attributes": {"iid": 2, "action": "open"}}
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
            if path == "/user":
                return json.dumps({"username": "santosodb"}).encode()
            if path == "/projects/1":
                return json.dumps({"permissions": {"project_access": {"access_level": 40}}}).encode()
            if path.endswith("/changes?access_raw_diffs=true"):
                return json.dumps({"changes": [{"new_path": "a.py", "diff": "@@ -0,0 +1 @@\n+x"}],
                                   "overflow": False}).encode()
            return json.dumps({"author": {"username": "dimas"},
                               "diff_refs": {"head_sha": heads["sha"]}}).encode()
        payload = {"object_kind": "merge_request", "project": {"id": 1},
                   "object_attributes": {"iid": 2, "action": "open"}}
        with patch.object(server, "api", side_effect=fake_api), \
                patch.object(server, "run_hermes", return_value="VERDICT: APPROVE") as hermes:
            self.assertTrue(server.process("gitlab", "Merge Request Hook", payload, self.GL))
            heads["sha"] = "bbb"
            self.assertTrue(server.process("gitlab", "Merge Request Hook", payload, self.GL))
            self.assertEqual(hermes.call_count, 2)

    def test_already_reviewed_open_mr_skipped(self):
        def fake_api(base, token, platform, path, body=None, accept="application/json"):
            if path == "/user":
                return json.dumps({"username": "santosodb"}).encode()
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
        cmd = server.hermes_command()
        self.assertEqual(cmd[1:3], ["-p", "codereview"])
        self.assertEqual(cmd[3], "chat")

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


class ReviewRequestTests(unittest.TestCase):
    """Reviews run on creation, ready, reviewer assignment or `@bot review`; never on a push."""

    def setUp(self):
        self.saved = server.BOT_USERNAME
        server.BOT_USERNAME = "bot"

    def tearDown(self):
        server.BOT_USERNAME = self.saved

    def gl(self, changes=None, **attrs):
        base = {"action": "update", "state": "opened", "iid": 1, "title": "feat"}
        base.update(attrs)
        payload = {"object_kind": "merge_request", "project": {"id": 1}, "object_attributes": base}
        if changes is not None:
            payload["changes"] = changes  # GitLab sends `changes` at the top level
        return payload

    def test_push_does_not_trigger(self):
        self.assertFalse(server.triggers_review("gitlab", "Merge Request Hook", self.gl(oldrev="abc")))
        self.assertFalse(server.triggers_review("github", "pull_request", {"action": "synchronize"}))

    def test_draft_to_ready_reads_top_level_changes(self):
        ready = self.gl({"draft": {"previous": True, "current": False}})
        self.assertTrue(server.triggers_review("gitlab", "Merge Request Hook", ready))

    def test_bot_added_as_reviewer_triggers(self):
        added = self.gl({"reviewers": {"previous": [{"username": "alice"}],
                                       "current": [{"username": "alice"}, {"username": "Bot"}]}})
        self.assertTrue(server.triggers_review("gitlab", "Merge Request Hook", added))
        self.assertTrue(server.is_rereview("gitlab", added))

    def test_other_reviewer_or_removal_does_not(self):
        other = self.gl({"reviewers": {"previous": [], "current": [{"username": "alice"}]}})
        removed = self.gl({"reviewers": {"previous": [{"username": "bot"}], "current": []}})
        for payload in (other, removed):
            self.assertFalse(server.triggers_review("gitlab", "Merge Request Hook", payload))

    def test_reviewer_request_on_a_draft_is_held(self):
        added = self.gl({"reviewers": {"previous": [], "current": [{"username": "bot"}]}}, title="Draft: wip")
        self.assertFalse(server.triggers_review("gitlab", "Merge Request Hook", added))

    def test_github_review_requested_from_the_bot_only(self):
        ask = lambda login: {"action": "review_requested", "requested_reviewer": {"login": login}}
        self.assertTrue(server.triggers_review("github", "pull_request", ask("bot")))
        self.assertFalse(server.triggers_review("github", "pull_request", ask("alice")))
        self.assertFalse(server.triggers_review("github", "pull_request",
                                                dict(ask("bot"), pull_request={"draft": True})))

    def test_review_command_parsing(self):
        note = lambda text: {"object_kind": "note", "object_attributes": {"note": text}}
        for text in ("@bot review", "@bot re-review please", "@Bot, rereview", "@bot please recheck",
                     "@bot can you review this?", "thanks! @bot review again"):
            with self.subTest(text=text):
                self.assertTrue(server.review_command("gitlab", note(text)))
        for text in ("@bot your review is wrong here", "@bot why?", "please review @bot", "@botty review", "review"):
            with self.subTest(text=text):
                self.assertFalse(server.review_command("gitlab", note(text)))

    def test_review_request_of_gitlab_note(self):
        payload = {"object_kind": "note", "project_id": 1, "project": {"id": 1, "path_with_namespace": "acme/w"},
                   "merge_request": {"iid": 2, "state": "opened", "title": "feat"},
                   "object_attributes": {"note": "@bot review", "noteable_type": "MergeRequest", "noteable_iid": 2}}
        event, mr = server.review_request_of("gitlab", payload)
        self.assertEqual(event, "Merge Request Hook")
        self.assertTrue(mr["_force"])
        self.assertEqual(mr["object_attributes"]["iid"], 2)
        commit = dict(payload, object_attributes={"note": "@bot review", "noteable_type": "Commit"})
        self.assertIsNone(server.review_request_of("gitlab", commit))

    def test_review_request_of_github_needs_a_pr(self):
        pr = {"action": "created", "comment": {"body": "@bot review"}, "repository": {"full_name": "acme/w"},
              "issue": {"number": 7, "pull_request": {"url": "x"}}}
        self.assertEqual(server.review_request_of("github", pr)[1]["number"], 7)
        issue = dict(pr, issue={"number": 7})
        self.assertIsNone(server.review_request_of("github", issue))

    def test_command_comment_runs_a_review_not_a_debate(self):
        payload = {"object_kind": "note", "project_id": 1, "project": {"id": 1, "path_with_namespace": "acme/w"},
                   "user": {"username": "alice"}, "merge_request": {"iid": 2, "state": "opened"},
                   "object_attributes": {"note": "@bot re-review", "noteable_type": "MergeRequest",
                                         "noteable_iid": 2, "discussion_id": "d", "id": 9}}
        tracker = server.Tracker(os.path.join(tempfile.mkdtemp(), "r.jsonl"))
        saved = server._tracker
        server._tracker = tracker
        try:
            with patch.object(server, "process", return_value=True) as process, \
                    patch.object(server, "debate") as debate, \
                    patch.object(server, "api") as api:
                server.run_job("gitlab", "Note Hook", payload, GL_CONFIG, b"raw", None)
        finally:
            server._tracker = saved
        debate.assert_not_called()
        event, mr = process.call_args[0][1], process.call_args[0][2]
        self.assertEqual((event, mr["_force"], mr["object_attributes"]["iid"]), ("Merge Request Hook", True, 2))
        self.assertIn("/notes/9/award_emoji", api.call_args[0][3])  # eyes reaction
        row = tracker.snapshot()["history"][0]
        self.assertEqual((row["status"], row["remark"]), ("done", "review requested by @alice"))


class RereviewFlowTests(unittest.TestCase):
    """A re-review carries our open findings and withdraws a stale approval."""

    JOB = {"base": "b", "token": "t", "path": "/projects/1/merge_requests/2", "pid": 1, "iid": 2,
           "files": [{"new_path": "a.py", "diff": "@@ -0,0 +1 @@\n+x"}], "author": "alice",
           "header": "h", "level": 40, "draft": False, "refs": {}, "head": "sha2",
           "diff": "@@ -0,0 +1 @@\n+x"}
    FINDING = {"id": "d1", "notes": [{"author": {"username": "bot"}, "resolvable": True, "resolved": False,
                                      "body": "<!-- ai-review -->\n### WARNING\nNull deref.\n\n*Fix:* guard it",
                                      "position": {"new_path": "a.py", "new_line": 1}}]}

    def setUp(self):
        server._reviewed.clear()

    def run_push(self, review, approved=True):
        calls = []

        def fake_api_json(base, token, platform, path, body=None, accept="application/json", method=None):
            calls.append((path, method or ("POST" if body is not None else "GET")))
            if path.endswith("/discussions?per_page=100"):
                return [self.FINDING]
            if path.endswith("/approvals"):
                return {"user_has_approved": approved}
            return {}
        payload = {"object_kind": "merge_request", "project": {"id": 1, "path_with_namespace": "acme/w"},
                   "object_attributes": {"iid": 2, "action": "open", "state": "opened"}, "_force": True}
        with patch.object(server, "collect_gitlab", return_value=dict(self.JOB)), \
                patch.object(server, "api_json", side_effect=fake_api_json), \
                patch.object(server, "api"), patch.object(server, "reviewer_of", return_value="bot"), \
                patch.object(server, "gl_post_inline", return_value=set()), \
                patch.object(server, "gl_resolve_fixed", return_value=0), \
                patch.object(server, "superseded", return_value=False), \
                patch.object(server, "gl_approve", return_value=True), \
                patch.object(server, "run_hermes", return_value=review) as hermes:
            self.assertTrue(server.process("gitlab", "Merge Request Hook", payload, GL_CONFIG))
        return hermes.call_args[0][0], calls

    def test_prompt_lists_open_findings(self):
        prompt, _ = self.run_push("ok\nVERDICT: APPROVE")
        self.assertIn("requested re-review", prompt)
        self.assertIn("`a.py:1` WARNING: Null deref.", prompt)

    def test_request_changes_withdraws_our_approval(self):
        _, calls = self.run_push("bad\nVERDICT: REQUEST_CHANGES")
        self.assertIn(("/projects/1/merge_requests/2/unapprove", "POST"), calls)

    def test_nothing_to_withdraw_when_we_never_approved(self):
        _, calls = self.run_push("bad\nVERDICT: REQUEST_CHANGES", approved=False)
        self.assertNotIn(("/projects/1/merge_requests/2/unapprove", "POST"), calls)

    def test_github_dismisses_our_approval(self):
        calls = []

        def fake_api_json(base, token, platform, path, body=None, accept="application/json", method=None):
            calls.append((path, method, body))
            return [{"id": 9, "user": {"login": "bot"}, "state": "APPROVED"},
                    {"id": 8, "user": {"login": "alice"}, "state": "APPROVED"}]
        with patch.object(server, "api_json", side_effect=fake_api_json):
            self.assertEqual(server.gh_dismiss_approvals("b", "t", "acme/w", 5, "bot"), 1)
        self.assertEqual(calls[1][:2], ("/repos/acme/w/pulls/5/reviews/9/dismissals", "PUT"))

    def test_github_open_findings_skip_outdated(self):
        comments = [{"user": {"login": "bot"}, "path": "a.py", "line": 3, "body": "**CRITICAL** SQL injection."},
                    {"user": {"login": "bot"}, "path": "a.py", "line": None, "body": "**WARNING** old."},
                    {"user": {"login": "alice"}, "path": "a.py", "line": 4, "body": "**WARNING** human."}]
        with patch.object(server, "api_json", return_value=comments):
            self.assertEqual(server.gh_open_findings("b", "t", "acme/w", 5, "bot"),
                             ["- `a.py:3` CRITICAL: SQL injection."])


class StanceTests(unittest.TestCase):
    def test_parse(self):
        cases = {
            "STANCE: CONCEDE\nYou're right — x.": ("CONCEDE", "You're right — x."),
            "**STANCE: DEFEND**\nStill holds: a.py:3.": ("DEFEND", "Still holds: a.py:3."),
            "STANCE: NO_REPLY": ("NO_REPLY", ""),
            "STANCE: no reply": ("NO_REPLY", ""),
            "NO_REPLY": ("NO_REPLY", ""),
            "Just an answer.": ("ANSWER", "Just an answer."),
            "STANCE: BANANA\nhi": ("ANSWER", "hi"),
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(server.stance_of(text), expected)


class DecisionFlowTests(unittest.TestCase):
    """No reply for acknowledgements; a concession resolves the thread and is remembered."""

    def setUp(self):
        server._replied.clear()
        server._cooldown.clear()
        self.saved = server.BOT_USERNAME, server._memory
        server.BOT_USERNAME = "bot"
        server._memory = server.Memory(os.path.join(tempfile.mkdtemp(), "m.db"))
        self.config = {"token": "gl", "secret": SECRET, "url": "https://gl"}

    def tearDown(self):
        server._memory.close()
        server.BOT_USERNAME, server._memory = self.saved
        server._replied.clear()
        server._cooldown.clear()

    def payload(self, note="That check is fine, the value is validated upstream."):
        return {"object_kind": "note", "project_id": 1, "project": {"id": 1, "path_with_namespace": "acme/w"},
                "user": {"username": "alice"}, "merge_request": {"iid": 2},
                "object_attributes": {"note": note, "noteable_type": "MergeRequest", "noteable_iid": 2,
                                      "discussion_id": "d1", "id": 7}}

    def run_debate(self, answer):
        posts, seen = [], {}
        thread = {"id": "d1", "notes": [
            {"author": {"username": "bot"}, "resolvable": True, "resolved": False,
             "body": "<!-- ai-review -->\n### WARNING\nUnvalidated input.\n\n*Fix:* validate it",
             "position": {"new_path": "a.py", "new_line": 4}},
            {"author": {"username": "alice"}, "body": "It is validated upstream."}]}

        def fake_api(base, token, platform, path, body=None, accept="application/json", method=None):
            if body is not None:
                posts.append((path, method or "POST"))
                return b'{"id": 5}'
            if path == "/projects/1":
                return json.dumps({"permissions": {"project_access": {"access_level": 40}}}).encode()
            if "/discussions" in path:
                return json.dumps([thread]).encode()
            return b"{}"
        with patch.object(server, "api", side_effect=fake_api), \
                patch.object(server, "run_hermes", return_value=answer):
            result = server.debate("gitlab", self.payload(), self.config,
                                   lambda stage, **kw: seen.update(kw))
        return result, posts, seen

    def test_no_reply_posts_nothing(self):
        result, posts, seen = self.run_debate("STANCE: NO_REPLY")
        self.assertFalse(result)
        self.assertEqual(posts, [])
        self.assertIn("no reply needed", seen["remark"])

    def test_concede_resolves_thread_and_records_mistake(self):
        result, posts, seen = self.run_debate(
            "STANCE: CONCEDE\nYou're right — the input is validated by the serializer.")
        self.assertTrue(result)
        self.assertEqual(posts[0], ("/projects/1/merge_requests/2/discussions/d1/notes", "POST"))
        self.assertIn(("/projects/1/merge_requests/2/discussions/d1?resolved=true", "PUT"), posts)
        self.assertIn("thread resolved", seen["remark"])
        self.assertIn("mistake #1 recorded", seen["remark"])
        lessons = server._memory.lessons("acme/w")
        self.assertEqual(len(lessons), 1)
        self.assertEqual(lessons[0]["file"], "a.py")
        self.assertIn("Unvalidated input", lessons[0]["finding"])
        self.assertIn("validated by the serializer", lessons[0]["lesson"])

    def test_defend_keeps_thread_open_and_records_nothing(self):
        result, posts, seen = self.run_debate("STANCE: DEFEND\nStill holds: a.py:4 reads raw query params.")
        self.assertTrue(result)
        self.assertEqual(len(posts), 1)
        self.assertEqual(seen["remark"], "defended")
        self.assertEqual(server._memory.count(), 0)

    def test_reply_body_never_shows_the_stance_line(self):
        with patch.object(server, "api") as api, \
                patch.object(server, "api_json", return_value={}), \
                patch.object(server, "gl_access_level", return_value=40), \
                patch.object(server, "gl_thread", return_value=""), \
                patch.object(server, "bounded_diff", return_value=""), \
                patch.object(server, "reviewer_of", return_value="bot"), \
                patch.object(server, "run_hermes", return_value="STANCE: ANSWER\nIt runs once per request."):
            self.assertTrue(server.debate("gitlab", self.payload(note="@bot when does it run?"), self.config))
        body = api.call_args[0][4]["body"]
        self.assertIn("It runs once per request.", body)
        self.assertNotIn("STANCE", body)


class MemoryTests(unittest.TestCase):
    def setUp(self):
        self.memory = server.Memory(os.path.join(tempfile.mkdtemp(), "m.db"))
        self.addCleanup(self.memory.close)

    def test_disabled_without_path(self):
        memory = server.Memory("")
        self.assertIsNone(memory.record_mistake("gitlab", "acme/w", "x"))
        self.assertEqual((memory.lessons("acme/w"), memory.count()), ([], 0))

    def test_same_mistake_is_stored_once(self):
        args = ("gitlab", "acme/w", "Unvalidated input.")
        self.assertEqual(self.memory.record_mistake(*args, file="a.py", line=4), 1)
        self.assertIsNone(self.memory.record_mistake(*args, file="a.py", line=4))
        self.assertEqual(self.memory.count(), 1)

    def test_lessons_are_per_repo_newest_first_and_capped(self):
        for n in range(5):
            self.memory.record_mistake("gitlab", "acme/w", "finding %d" % n)
            time.sleep(0.001)
        self.memory.record_mistake("gitlab", "other/r", "elsewhere")
        lessons = self.memory.lessons("acme/w", limit=3)
        self.assertEqual([l["finding"] for l in lessons], ["finding 4", "finding 3", "finding 2"])

    def test_survives_reopen(self):
        path = os.path.join(tempfile.mkdtemp(), "m.db")
        first = server.Memory(path)
        first.record_mistake("gitlab", "acme/w", "kept")
        first.close()
        again = server.Memory(path)
        self.addCleanup(again.close)
        self.assertEqual(again.count(), 1)

    def test_lessons_reach_the_review_prompt(self):
        saved = server._memory
        server._memory = self.memory
        try:
            self.memory.record_mistake("gitlab", "acme/w", "Flagged Decimal rounding.", file="m.py",
                                       level="WARNING", lesson="You're right — ROUND_HALF_UP is required.")
            block = server.lessons_block("acme/w")
            self.assertIn("Lessons from earlier reviews", block)
            self.assertIn("[WARNING] in m.py Flagged Decimal rounding.", block)
            self.assertIn("ROUND_HALF_UP", block)
            self.assertEqual(server.lessons_block("other/r"), "")
        finally:
            server._memory = saved


class DashboardActionTests(unittest.TestCase):
    """Stop, re-review and delete from the dashboard."""

    MR = {"object_kind": "merge_request", "project": {"id": 1, "path_with_namespace": "acme/w"},
          "object_attributes": {"iid": 2, "action": "open", "state": "opened",
                                "url": "https://gitlab.com/acme/w/-/merge_requests/2"}}

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.saved = server._tracker
        server._tracker = server.Tracker(os.path.join(self.dir, "r.jsonl"))
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        self.httpd.config = {"gitlab": {"token": "t", "secret": SECRET, "url": "https://gitlab.com"}}
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        server._tracker = self.saved

    def post(self, path, headers=None):
        request = Request(self.base + path, data=b"", method="POST",
                          headers={"X-Dashboard": "1"} if headers is None else headers)
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read() or b"{}")
        except HTTPError as error:
            body = error.read()
            try:
                return error.code, json.loads(body)
            except ValueError:
                return error.code, body.decode()

    def finished(self, url="https://gitlab.com/acme/w/-/merge_requests/2"):
        rec = server._tracker.begin("gitlab", "acme/w!2", "alice", url=url)
        server._tracker.finish(rec, "done", verdict="APPROVE")
        return rec["id"]

    def test_delete_removes_row_and_store_line(self):
        keep, drop = self.finished(), self.finished()
        self.assertEqual(self.post(f"/api/reviews/{drop}/delete")[0], 200)
        self.assertEqual([r["id"] for r in server._tracker.snapshot()["history"]], [keep])
        with open(server._tracker.path) as fh:
            self.assertEqual([json.loads(l)["id"] for l in fh], [keep])
        self.assertEqual(server.Tracker(server._tracker.path).snapshot()["history"][0]["id"], keep)
        self.assertEqual(self.post(f"/api/reviews/{drop}/delete")[0], 404)

    def test_running_review_cannot_be_deleted(self):
        rec = server._tracker.begin("gitlab", "acme/w!2", "alice")
        status, body = self.post(f"/api/reviews/{rec['id']}/delete")
        self.assertEqual(status, 409)
        self.assertIn("stop it first", body["message"])

    def test_rereview_rebuilds_the_target_and_forces(self):
        rid = self.finished()
        with patch.object(server, "enqueue") as enqueue:
            self.assertEqual(self.post(f"/api/reviews/{rid}/rereview")[0], 202)
        platform, event, payload, cfg, raw, key = enqueue.call_args[0][0]
        self.assertEqual((platform, event), ("gitlab", "Merge Request Hook"))
        self.assertTrue(payload["_force"])
        self.assertEqual(payload["project"]["id"], "acme%2Fw")
        self.assertEqual(payload["object_attributes"]["iid"], 2)
        self.assertTrue(server.is_rereview("gitlab", payload))

    def test_rereview_refuses_foreign_host_or_missing_url(self):
        for url in ("https://evil.example/acme/w/-/merge_requests/2", ""):
            with self.subTest(url=url), patch.object(server, "enqueue") as enqueue:
                self.assertEqual(self.post(f"/api/reviews/{self.finished(url)}/rereview")[0], 409)
                enqueue.assert_not_called()

    def test_github_replay(self):
        payload = server.replay_of("https://api.github.com",
                                   {"platform": "github", "url": "https://github.com/acme/w/pull/7"})
        self.assertEqual((payload["number"], payload["repository"]["full_name"]), (7, "acme/w"))

    def test_forced_replay_resolves_project_path_and_skips_guards(self):
        server._reviewed.clear()

        def fake_api_json(base, token, platform, path, body=None, accept="application/json", method=None):
            if path == "/projects/acme%2Fw":
                return {"id": 1, "permissions": {"project_access": {"access_level": 40}}}
            if path == "/projects/1":
                return {"permissions": {"project_access": {"access_level": 40}}}
            if "/notes" in path:
                return [{"body": "<!-- ai-review -->"}]  # reviewed before: a plain open would skip
            if "/changes" in path:
                return {"changes": [{"new_path": "a.py", "diff": "@@ -0,0 +1 @@\n+x"}], "overflow": False}
            return {"author": {"username": "alice"}, "state": "opened", "title": "feat",
                    "diff_refs": {"head_sha": "s"}}
        payload = server.replay_of("https://gitlab.com", {"platform": "gitlab",
                                   "url": "https://gitlab.com/acme/w/-/merge_requests/2"})
        with patch.object(server, "api_json", side_effect=fake_api_json):
            job = server.collect_gitlab(payload, GL_CONFIG)
        self.assertIsInstance(job, dict)
        self.assertEqual(job["pid"], 1)

    def test_replay_of_merged_mr_is_refused(self):
        def fake_api_json(base, token, platform, path, body=None, accept="application/json", method=None):
            if path in ("/projects/acme%2Fw", "/projects/1"):
                return {"id": 1, "permissions": {"project_access": {"access_level": 40}}}
            if "/changes" in path:
                return {"changes": [{"new_path": "a.py", "diff": "@@ -0,0 +1 @@\n+x"}], "overflow": False}
            return [] if "/notes" in path else {"state": "merged"}
        payload = server.replay_of("https://gitlab.com", {"platform": "gitlab",
                                   "url": "https://gitlab.com/acme/w/-/merge_requests/2"})
        with patch.object(server, "api_json", side_effect=fake_api_json):
            self.assertIn("merged", server.collect_gitlab(payload, GL_CONFIG))

    def test_stop_kills_the_running_model_call(self):
        stub = os.path.join(self.dir, "hermes")
        with open(stub, "w") as fh:
            fh.write("#!/bin/sh\nsleep 30\n")
        os.chmod(stub, 0o755)

        def slow_process(platform, event, payload, cfg, track=None):
            track("reviewing")
            server.run_hermes("diff")
            raise AssertionError("not reached")
        started = time.time()
        with patch.dict(os.environ, {"HERMES_BIN": stub}), patch.object(server, "process", side_effect=slow_process):
            worker = threading.Thread(target=server.run_job,
                                      args=("gitlab", "Merge Request Hook", self.MR, {}, b"raw", None))
            worker.start()
            deadline = time.time() + 5
            while not server._procs and time.time() < deadline:
                time.sleep(0.02)
            rid = next(iter(server._tracker.live))
            self.assertEqual(self.post(f"/api/reviews/{rid}/stop")[0], 202)
            worker.join(10)
        self.assertLess(time.time() - started, 10)
        row = server._tracker.snapshot()["history"][0]
        self.assertEqual((row["status"], row["remark"]), ("stopped", "stopped from the dashboard"))
        self.assertEqual(server._procs, {})
        self.assertEqual(self.post(f"/api/reviews/{rid}/stop")[0], 409)  # no longer running

    def test_stop_between_steps_posts_nothing(self):
        posted = []

        def process(platform, event, payload, cfg, track=None):
            server.stop_review(next(iter(server._tracker.live)))
            track("posting")  # the next step notices the stop
            posted.append(1)
        with patch.object(server, "process", side_effect=process):
            server.run_job("gitlab", "Merge Request Hook", self.MR, {}, b"raw", None)
        self.assertEqual(posted, [])
        self.assertEqual(server._tracker.snapshot()["history"][0]["status"], "stopped")

    def test_cross_site_requests_are_refused(self):
        rid = self.finished()
        self.assertEqual(self.post(f"/api/reviews/{rid}/delete", headers={})[0], 403)  # no X-Dashboard
        self.assertEqual(self.post(f"/api/reviews/{rid}/delete",
                                   headers={"X-Dashboard": "1", "Origin": "https://evil.example"})[0], 403)
        self.assertEqual(self.post(f"/api/reviews/{rid}/delete",
                                   headers={"X-Dashboard": "1", "Sec-Fetch-Site": "cross-site"})[0], 403)
        self.assertEqual(len(server._tracker.snapshot()["history"]), 1)

    def test_actions_need_the_dashboard_login(self):
        rid = self.finished()
        with patch.object(server, "DASHBOARD_PASSWORD", "pw"):
            self.assertEqual(self.post(f"/api/reviews/{rid}/delete")[0], 401)
            auth = "Basic " + base64.b64encode(b"admin:pw").decode()
            self.assertEqual(self.post(f"/api/reviews/{rid}/delete",
                                       headers={"X-Dashboard": "1", "Authorization": auth})[0], 200)

    def test_unknown_action_is_404(self):
        self.assertEqual(self.post("/api/reviews/1/explode")[0], 404)


if __name__ == "__main__":
    unittest.main()
