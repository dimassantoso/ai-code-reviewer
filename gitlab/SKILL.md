---
name: ai-code-reviewer-gitlab
description: Use when reviewing GitLab merge requests via the webhook service.
tags: [code-review, gitlab, quality, security]
related_skills: [ai-code-reviewer]
---

# ai-code-reviewer — GitLab adapter

Generic core: see `../SKILL.md`.

Status: review-only. `server.py` fetches the MR diff and posts one MR note. Thread debate, access-level gating, inline positions and per-note dedupe are **not implemented**; the sections below describe the API surface if you add them.

## Webhook

- Route: `POST /gl-review`
- Events: `Merge Request Hook` (open, update, reopen)
- Secret: `GITLAB_WEBHOOK_SECRET`, or `WEBHOOK_SECRET` as fallback (Standard Webhooks `whsec_*` or raw string)

## API

- Diff: `GET /projects/:id/merge_requests/:iid/changes`
- MR meta: `GET /projects/:id/merge_requests/:iid`
- Discussions: `GET /projects/:id/merge_requests/:iid/discussions`
- Inline note: `POST /projects/:id/merge_requests/:iid/discussions` (body: `body`, `position`)
- Thread reply: `POST /projects/:id/merge_requests/:iid/discussions/:discussion_id/notes`
- MR note: `POST /projects/:id/merge_requests/:iid/notes` ← what `server.py` uses

## Mention matching (design)

`@BOT_USERNAME` whole-username match, not substring. Ignore `BOT_USERNAME` and notes containing `REVIEW_MARKER`.

## Access control (design)

`MIN_ACCESS_LEVEL` (GitLab access level: 30=Developer, 40=Maintainer). Below → skip.

## Dedupe / cooldown

`server.py` dedupes identical webhook payloads in memory for 5 minutes. Per-note reply dedupe and cooldown apply only to a thread-debate implementation, which this repo does not ship.

Design if you add debate: `_replied_cache: set[(discussion_id, note_id)]`, `_cooldown: dict[(discussion_id, commenter)] -> ts`, `COOLDOWN_SECONDS=30`.
