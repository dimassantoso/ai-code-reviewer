#!/usr/bin/env python3
"""Unit checks for tools/add_repo.py — parsing and .env rewriting.

    python3 -m unittest discover -s tests
"""
import importlib.util
import os
import pathlib
import shutil
import sys
import tempfile
import unittest

TOOLS = pathlib.Path(__file__).resolve().parent.parent / "tools"
spec = importlib.util.spec_from_file_location("add_repo", TOOLS / "add_repo.py")
add_repo = importlib.util.module_from_spec(spec)
sys.modules["add_repo"] = add_repo
spec.loader.exec_module(add_repo)


class ParseRepoTests(unittest.TestCase):
    def test_plain_slug(self):
        self.assertEqual(add_repo.parse_repo("acme/widgets"), ("gitlab", "acme/widgets"))

    def test_gitlab_https_url(self):
        self.assertEqual(add_repo.parse_repo("https://gitlab.com/acme/widgets"),
                         ("gitlab", "acme/widgets"))

    def test_ssh_url(self):
        self.assertEqual(add_repo.parse_repo("git@gitlab.com:acme/widgets.git"),
                         ("gitlab", "acme/widgets"))

    def test_github_url_detected(self):
        self.assertEqual(add_repo.parse_repo("https://github.com/acme/widgets"),
                         ("github", "acme/widgets"))

    def test_bare_host_detected_as_github(self):
        self.assertEqual(add_repo.parse_repo("github.com/acme/widgets"),
                         ("github", "acme/widgets"))

    def test_mr_url_is_trimmed_to_the_repo(self):
        self.assertEqual(add_repo.parse_repo("https://gitlab.com/acme/widgets/-/merge_requests/9"),
                         ("gitlab", "acme/widgets"))

    def test_trailing_git_is_stripped(self):
        self.assertEqual(add_repo.parse_repo("https://github.com/acme/widgets.git"),
                         ("github", "acme/widgets"))

    def test_single_segment_is_rejected(self):
        with self.assertRaises(SystemExit):
            add_repo.parse_repo("widgets")


class WriteEnvTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, ".env")
        with open(self.path, "w") as handle:
            handle.write("# comment survives\nA=1\nB=2\n")
        self.original = add_repo.ROOT
        add_repo.ROOT = self.dir

    def tearDown(self):
        add_repo.ROOT = self.original
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_rewrites_existing_key_and_keeps_comments(self):
        add_repo.write_env({"B": "99", "C": "3"})
        text = open(self.path).read()
        self.assertIn("# comment survives", text)
        self.assertIn("A=1", text)
        self.assertIn("B=99", text)
        self.assertIn("C=3", text)

    def test_file_is_private(self):
        add_repo.write_env({"B": "99"})
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    def test_env_reader_ignores_comments_and_quotes(self):
        with open(self.path, "w") as handle:
            handle.write('# x\nA="quoted"\nB=plain\n')
        self.assertEqual(add_repo.env(), {"A": "quoted", "B": "plain"})


if __name__ == "__main__":
    unittest.main()
