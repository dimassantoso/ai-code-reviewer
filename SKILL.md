---
name: ai-code-reviewer
category: software-development
description: Use when reviewing MRs/PRs on GitLab or GitHub via a webhook service.
---

# ai-code-reviewer (GitLab + GitHub)

Webhook service in this repo (`server.py`, Python stdlib) posts AI reviews of GitLab merge requests and GitHub pull requests. Reviews are produced by the Hermes Agent CLI.

## Endpoints

| Platform | Event | Route |
|---|---|---|
| GitLab | `Merge Request Hook` (open, update, reopen) | `POST /gl-review` |
| GitHub | `pull_request` (opened, synchronize, reopened) | `POST /gh-review` |
| both | health | `GET /health` |

A platform without a configured token returns `404`. Bad signature → `403`. Accepted job → `202` before the review runs in a background thread.

## Config (env)

```bash
GITLAB_TOKEN=glpat-...            # scope: api
GITHUB_TOKEN=ghp_...              # repo / pull-request write
GITLAB_WEBHOOK_SECRET=...         # required per platform
GITHUB_WEBHOOK_SECRET=...
WEBHOOK_SECRET=...                # shared fallback for either platform
GITLAB_URL=https://gitlab.com     # optional, HTTPS only
GITHUB_URL=https://api.github.com # optional, HTTPS only
BIND_HOST=0.0.0.0
BIND_PORT=9877                    # comma-separated to bind several
HERMES_BIN=hermes
HERMES_MODEL=                     # optional, else profile default
HERMES_SKILL=ai-code-reviewer
HERMES_TIMEOUT_S=300
```

Secrets are mandatory — no dev bypass.

## Verification

- GitHub: `X-Hub-Signature-256: sha256=<hex hmac>` over the raw body.
- GitLab: constant-time match on `X-Gitlab-Token`, or Standard Webhooks `webhook-id` / `webhook-timestamp` / `webhook-signature` (5-minute skew, `whsec_` secrets base64-decoded).

## Review flow

1. Verify signature, dedupe identical raw payloads in memory (5 min), reply `202`.
2. Fetch the diff (GitLab: `/projects/:id/merge_requests/:iid/changes`; GitHub: `Accept: application/vnd.github.v3.diff`).
3. Cap diff at 100 KB — larger is rejected, never silently truncated.
4. Shell out to `hermes chat --query-file - -t "" -Q --max-turns 5`, with platform tokens stripped from the child env.
5. Post the result: GitLab MR note, GitHub `COMMENT` review.

No approval, merge, or code change. No thread-debate replies, access-level gating, or persistent queue — see "Not implemented".

## Not implemented

- Reply to `@mention` debates.
- Access-level / permission checks (`MIN_ACCESS_LEVEL`, `GITHUB_MIN_PERMISSION`).
- Inline diff-line comments; review text is posted as one note.
- Durable dedupe or retry: an accepted job is lost if the process dies.

Add these when a real user asks; each is a separate feature, listed so behaviour is not over-claimed.

## Deploy

Python direct and Docker both documented in `README.md`. The Docker image extends the official `nousresearch/hermes-agent` digest, so the container ships a real `hermes` CLI plus this skill; model credentials are never baked in.

## Pitfalls

- Webhook ack must precede the review (10 s platform timeout).
- `health` proves the listener only; smoke-test one harmless diff through the exact CLI command before trusting a deployment.
- Hermes CLI errors can land on stdout in `-Q` mode; log both streams.
- GitLab needs a legacy PAT with `api` scope; fine-grained tokens miss diff/notes rights.
- Do not mount a personal Hermes home into the container — it may contain messaging gateway credentials.
