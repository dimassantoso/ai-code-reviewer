---
name: ai-code-reviewer-gitlab
description: Use when reviewing GitLab merge requests. Fetches diff via GitLab API, posts inline notes, handles thread debate on @mention.
tags: [code-review, gitlab, quality, security]
related_skills: [ai-code-reviewer]
---

# ai-code-reviewer — GitLab adapter

Generic core: see `../SKILL.md`. This file covers GitLab-specific wiring.

## Webhook

- Route: `POST /gl-review`
- Events: `Merge Request Hook` (open, update, reopen), `Note Hook` (comment on MR)
- Secret: `WEBHOOK_SECRET` (Standard Webhooks `whsec_*` or raw string)

## API

- Diff: `GET /projects/:id/merge_requests/:iid/changes`
- MR meta: `GET /projects/:id/merge_requests/:iid`
- Discussions: `GET /projects/:id/merge_requests/:iid/discussions`
- Inline note: `POST /projects/:id/merge_requests/:iid/discussions` (body: `body`, `position`)
- Thread reply: `POST /projects/:id/merge_requests/:iid/discussions/:discussion_id/notes`
- MR note: `POST /projects/:id/merge_requests/:iid/notes`

## Mention matching

`@BOT_USERNAME` whole-username match, not substring. Ignore `BOT_USERNAME` and notes containing `REVIEW_MARKER`.

## Access control

`MIN_ACCESS_LEVEL` (GitLab access level: 30=Developer, 40=Maintainer). Below → skip.

## Dedupe / cooldown

- `_replied_cache: set[(discussion_id, note_id)]`
- `_cooldown: dict[(discussion_id, commenter)] -> ts`, `COOLDOWN_SECONDS=30`
