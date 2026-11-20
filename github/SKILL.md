---
name: ai-code-reviewer-github
description: Use when reviewing GitHub pull requests via the webhook service.
tags: [code-review, github, quality, security]
related_skills: [ai-code-reviewer]
---

# ai-code-reviewer — GitHub adapter

Generic core: see `../SKILL.md`.

Status: review-only. `server.py` fetches the PR diff and posts one `COMMENT` review. Thread debate, permission gating, inline per-line comments and per-comment dedupe are **not implemented**; sections below describe the API surface if you add them.

## Webhook

- Route: `POST /gh-review`
- Events: `pull_request` (opened, synchronize, reopened)
- Signature: `X-Hub-Signature-256: sha256=<hex hmac>` over raw body, keyed with `GITHUB_WEBHOOK_SECRET` (or `WEBHOOK_SECRET`).

## API

- Diff: `GET /repos/:owner/:repo/pulls/:number` with `Accept: application/vnd.github.v3.diff`
- PR meta: `GET /repos/:owner/:repo/pulls/:number`
- Review comments: `GET /repos/:owner/:repo/pulls/:number/comments`
- Post review: `POST /repos/:owner/:repo/pulls/:number/reviews` (body: `event`, `body`) ← what `server.py` uses, `event=COMMENT`
- Reply to comment: `POST /repos/:owner/:repo/pulls/:number/comments/:comment_id/replies`
- PR note: `POST /repos/:owner/:repo/issues/:number/comments`

## Mention matching (design)

`@BOT_USERNAME` whole-username match. Ignore `BOT_USERNAME`, `[bot]`-suffixed logins, and comments containing `REVIEW_MARKER`.

## Access control (design)

`GITHUB_MIN_PERMISSION` (`read`, `write`, `admin`). Check via `GET /repos/:owner/:repo/collaborators/:username/permission`. Below → skip.

## Dedupe / cooldown

Same as GitLab: payload-level dedupe only (5 min, in memory). Per-comment reply dedupe and cooldown belong to a debate implementation this repo does not ship.

## Notes

GitHub review comments are anchored to diff lines (`path`, `line`, `side`). For general debate use `issue_comment` replies; for inline debate use the `replies` endpoint.
