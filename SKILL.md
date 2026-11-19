---
name: ai-code-reviewer
category: software-development
description: Use when reviewing MRs/PRs on GitLab or GitHub. Handles diff analysis, thread debate, dedupe, cooldown. LLM-agnostic via Hermes Agent.
---

# ai-code-reviewer (GitLab + GitHub)

Unified Hermes Agent skill for AI code review on **GitLab Merge Requests** and **GitHub Pull Requests**.

## Trigger

| Platform | Event | Webhook endpoint |
|----------|-------|------------------|
| GitLab   | `Merge Request Hook` (opened, updated, reopened) | `POST /gl-review` |
| GitLab   | `Note Hook` (comment on MR) | `POST /gl-review` |
| GitHub   | `Pull Request` (opened, synchronize, reopened) | `POST /gh-review` |
| GitHub   | `Pull Request Review Comment` / `Issue Comment` | `POST /gh-review` |

## Configuration (env)

```bash
# Required
GITLAB_TOKEN=glpat-xxx          # for GitLab
GITHUB_TOKEN=ghp_xxx            # for GitHub
GITLAB_GROUP=123456             # GitLab group ID (optional, filters)
GITHUB_ORG=my-org               # GitHub org (optional, filters)

# Hermes
HERMES_BIN=/path/to/hermes
HERMES_MODEL=hms/deepseek-v4.1-flash-free
HERMES_SKILL=ai-code-reviewer
HERMES_TIMEOUT_S=180

# Server
BIND_HOST=0.0.0.0
BIND_PORT=9877,9876,9878        # comma-separated, any ports
WEBHOOK_SECRET=whsec_xxx        # Standard Webhooks secret (both platforms)

# Access control
MIN_ACCESS_LEVEL=30             # GitLab: 30=Developer, 40=Maintainer
GITHUB_MIN_PERMISSION=write     # GitHub: read, write, admin

# Bot identity
BOT_USERNAME=santosodb          # must match @mention trigger
```

## Webhook Signature Verification

Both platforms use **Standard Webhooks** format:
- Header: `webhook-signature: v1,<base64_hmac_sha256>`
- Header: `webhook-id: <msg_id>`
- Header: `webhook-timestamp: <unix_ts>`
- Secret format: `whsec_<base64_key>` → raw key = `base64_decode(secret[6:])`
- Signed payload: `msg_id.timestamp.body`

## Review Flow (MR/PR opened/updated)

1. Fetch diff (`/projects/:id/merge_requests/:iid/changes` or `/repos/:owner/:repo/pulls/:number/files`)
2. Build review prompt with diff + language conventions
3. Call Hermes Agent (`HERMES_BIN run -m HERMES_MODEL -s HERMES_SKILL`)
4. Parse response for `VERDICT: PASS|CHANGES_REQUESTED|COMMENT`
5. Post as **review** (GitLab: `/merge_requests/:iid/notes` with `review` type; GitHub: `/pulls/:number/reviews`)
6. Skip if verdict = PASS and no findings

## Thread Debate Mode (when @mentioned)

**Trigger:** Human @mentions `BOT_USERNAME` in a comment/review comment.

**Context:** Current discussion thread only (bounded).

**Protocol:**
1. **Concede first** if commenter is right. First line: `You're right — <point>.` Drop the claim.
2. **If your point holds**, restate ONCE with concrete evidence (file:line, failing test, runtime scenario).
3. **Trade-offs** when multiple approaches valid: state preference + why, leave room for author constraints.
4. **Uncertain**? Say known vs unknown, what evidence would settle it (test, doc, benchmark). Ask one focused question.
5. **No verdict token**, no new findings, max ~120 words unless code needed.
6. Post as **thread reply** (GitLab: `/discussions/:discussion_id/notes`; GitHub: reply to comment `/comments/:comment_id/replies`).

**Safety:**
- Match `@BOT_USERNAME` as whole username, not substring.
- Ignore bot-authored events and system notes → no reply loops.
- Dedupe: skip if already replied to same `(discussion_id, note_id)`.
- Cooldown: 30s per user per discussion.

## Dedupe & Cooldown

```python
_replied_cache: set[tuple[str, int]] = set()    # (discussion_id, note_id)
_cooldown: dict[tuple[str, str], float] = {}    # (discussion_id, commenter) -> timestamp
COOLDOWN_SECONDS = 30
```

## Language Conventions

Loaded from `references/language-conventions.md` (per-repo override supported via `.hermes/code-review-conventions.md` in target repo).

## Templates

- `templates/review-prompt.md` — review system prompt
- `templates/debate-prompt.md` — thread debate system prompt

## Implementation Notes

- Single server handles both platforms via separate routes (`/gl-review`, `/gh-review`).
- Platform detected from webhook headers (`X-Gitlab-Event` vs `X-GitHub-Event`).
- GitLab: `discussion_id` + `note_id`; GitHub: `comment_id` (for replies) + `pull_request_review_id` (for review comments).
- Hermes Agent invoked via CLI; timeout enforced by `HERMES_TIMEOUT_S`.
- Health: `GET /health` on all bound ports.