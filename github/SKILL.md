---
name: ai-code-reviewer-github
description: Use when reviewing GitHub pull requests. Fetches diff via GitHub API, posts review comments, handles thread debate on @mention.
tags: [code-review, github, quality, security]
related_skills: [ai-code-reviewer]
---

# ai-code-reviewer — GitHub adapter

Generic core: see `../SKILL.md`. This file covers GitHub-specific wiring.

## Webhook

- Route: `POST /gh-review`
- Events: `pull_request` (opened, synchronize, reopened), `pull_request_review_comment`, `issue_comment` (PR body)
- Signature: `X-Hub-Signature-256: sha256=<hex hmac>` — verify against `WEBHOOK_SECRET` raw bytes.

## API

- Diff: `GET /repos/:owner/:repo/pulls/:number/files` (paginate)
- PR meta: `GET /repos/:owner/:repo/pulls/:number`
- Review comments: `GET /repos/:owner/:repo/pulls/:number/comments`
- Post review: `POST /repos/:owner/:repo/pulls/:number/reviews` (body: `event`, `comments[]`)
- Reply to comment: `POST /repos/:owner/:repo/pulls/:number/comments/:comment_id/replies`
- PR note: `POST /repos/:owner/:repo/issues/:number/comments`

## Mention matching

`@BOT_USERNAME` whole-username match. Ignore `BOT_USERNAME`, `[bot]`-suffixed logins, and comments containing `REVIEW_MARKER`.

## Access control

`GITHUB_MIN_PERMISSION` (`read`, `write`, `admin`). Check via `GET /repos/:owner/:repo/collaborators/:username/permission`. Below → skip.

## Dedupe / cooldown

- `_replied_cache: set[(pr_number, comment_id)]`
- `_cooldown: dict[(pr_number, commenter)] -> ts`, `COOLDOWN_SECONDS=30`

## Notes

GitHub review comments are anchored to diff lines (`path`, `line`, `side`). For general debate use `issue_comment` replies; for inline debate use `replies` endpoint.
