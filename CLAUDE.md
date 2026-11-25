# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A webhook service (`server.py`, **Python stdlib only — no third-party packages, keep it that way**) that reviews GitLab merge requests and GitHub pull requests. It fetches the diff, sends it to the **Hermes Agent CLI** (`hermes chat ...`) as a subprocess, parses the model output, and posts inline comments, a summary and optionally an approval. `dashboard.html` is a single-file live dashboard served by the same process. `tools/add_repo.py` installs the webhook on a repo.

`tools/init.py` (`make init`) is the setup wizard that writes `.env`. Its `SECTIONS` list is the catalogue of settings, so add any new env var there and in `.env.example`.

`SKILL.md` is the **Hermes skill**: the review rubric and output contract that is loaded into every model call (`hermes chat -s $HERMES_SKILL`). It is prompt material for the reviewing model, not docs for this codebase. Reviews run with empty toolsets, so the model sees only the prompt and SKILL.md. Keep the skill as one self-contained file, because the model can't open files next to it.
- Its "Output format" section, `REVIEW_FORMAT` in `server.py`, and the parsers (`parse_inline_comments`, `verdict_of`, `strip_inline`) form one contract. Change all three together.
- The live copy lives in the Hermes home (with `HERMES_PROFILE` set: `$HERMES_HOME/profiles/<profile>/skills/.../ai-code-reviewer/`). `make skill` installs the repo version and keeps a `.bak` of the old one, and `make deploy` runs it. Never edit the installed copy directly. Installing changes live review behavior immediately, with no restart, so confirm with the user before running `make skill` or `make deploy`.

## Commands

```bash
python3 -m unittest discover -s tests -v                    # full suite (also: make test)
python3 -m unittest tests.test_server.ChunkedReviewTests -v  # one class
python3 -m unittest tests.test_server.ChunkedReviewTests.test_name  # one test
python3 tests/loadtest.py --requests 200 --concurrency 32 --workers 4
make init                                                   # setup wizard -> .env (tests: tests/test_init.py)
set -a; . ./.env; set +a; python3 server.py                 # run locally (server reads env, not .env)
```

No linter or build step is configured.

On this box the service runs as the systemd **user** unit `pasarpolis-ai-code-reviewer`. It uses `.env` as its EnvironmentFile and appends to `server.log`. Use `make` for operations: `make restart`, `make status`, `make health`, `make log`, `make add REPO=group/project`, `make reset`.
- **`make deploy` runs `git reset --hard origin/master`**. It throws away uncommitted work in this checkout, which is also the live deployment. Never run it while the tree has local changes.
- `dashboard.html` is read once at import (`DASHBOARD_HTML`), so you must restart before dashboard edits show up.
- `reviews.jsonl` is the live review history (`REVIEW_STORE`). Don't edit or truncate it by hand; `make reset` makes a backup first.

## Architecture (server.py)

Request path: `Handler.do_POST` checks Content-Length and body size, then `verify()` (GitHub HMAC; GitLab token or Standard Webhooks). Next, `triggers_review()` drops anything that can't produce a review with `200 ignored`, and **creates no dashboard row**. `claim()` dedupes the raw payload. The job then goes onto the bounded `_jobs` queue (`503` when full) and the handler acks `202` right away, since platforms time webhooks out at 10s.

Worker path: a fixed pool (`MAX_WORKERS`, started lazily by `start_workers`) runs `run_job()`. That function:
1. For note/comment events, calls `comment_decision()` first. If no reply is owed it returns *without* opening a tracker row.
2. Opens a `Tracker` row and takes `target_lock(key)` so that events for the same MR/PR run one at a time.
3. Sends the job to `process()` (review) or `debate()` (an `@BOT_USERNAME` reply in a thread).
4. On failure it calls `release()` on the dedupe claim, so the platform's retry can still run.

`process()` handles the review. The checks run in this order: repo allowlist (`REVIEW_REPOS`), event/action/state gates, collector (`collect_gitlab` / `collect_github`, which returns a *string* reason to refuse), head-SHA memory (`_reviewed`, which stops the approve → update-event → re-review loop), draft skip. Then `review_diff()` runs, followed by a `superseded()` check that discards the result if the head moved during the review. Last comes posting: GitLab gets discussions plus a summary note, and `gl_resolve_fixed` closes the bot's own stale threads. GitHub gets one batched review. Auto-approve happens only if the token user may approve.

What triggers a review (`gl_triggers`, `PR_ACTIONS`): only explicit requests. GitLab: `open`, or an `update` that `became_ready()` or `gl_reviewer_added()`. GitLab sends `changes` at the **top level** of the hook; read it with `hook_changes()`. GitHub: `opened`, `ready_for_review`, or `review_requested` for `BOT_USERNAME` (`requested()`). Pushes never trigger a review. A comment matching `review_command()` (`@bot review` / `re-review` / `recheck`) is turned by `run_job` into an MR-shaped payload (`review_request_of`, `_force: True`) and sent to `process()` instead of `debate()`, with a 👀 reaction (`acknowledge`). `is_rereview()` (an explicit request or `_force`) skips the head memory. For a re-review, `process()` adds the bot's open findings (`prior_findings_block`) to the prompt, and withdraws an earlier approval (`gl_unapprove` / `gh_dismiss_approvals`) when the verdict becomes REQUEST_CHANGES.

Replies (`debate()`): `comment_decision()` runs the cheap gates without a model call. The model's output must then start with `STANCE: CONCEDE|DEFEND|ANSWER|NO_REPLY` (`DEBATE_RULES`, parsed by `stance_of`). `NO_REPLY` posts nothing. `CONCEDE` calls `concede()`, which resolves the bot's GitLab thread and writes the finding to `Memory` (SQLite at `MEMORY_DB`, table `mistakes`, deduplicated by a UNIQUE key). `lessons_block()` puts recent mistakes for the repo into every review prompt. GitHub has no REST call for resolving a thread, so on GitHub a concession is recorded but the thread stays open.

Model I/O:
- `run_hermes()` builds the prompt and strips platform tokens/secrets from the child env.
- `REVIEW_FORMAT` (and SKILL.md's "Output format") ask for severity sections (`### Critical` / `### Warning` / `### Suggestion`) holding `` - `path:line` — msg. Fix: … `` bullets, ending with `VERDICT: APPROVE|REQUEST_CHANGES`. `parse_inline_comments()` also still accepts the older `### Inline Comments` block with `LEVEL:` bullets. `parse_inline_comments()`, `verdict_of()`, `strip_inline()` and `new_lines_of()` depend on this contract.
- Diffs larger than `MAX_DIFF` (env, default 30000 chars) are split by `split_diff` → `hunks_of` → `chunks_of`. Each chunk gets its own model call. The calls are capped by `REVIEW_BUDGET_S`, and parts that weren't reached are labelled as skipped. `merge_reviews` keeps the strictest verdict.
- Everything the bot posts carries `REVIEW_MARKER` (`<!-- ai-review -->`). `is_own_comment()` uses it to drop the bot's own comments when they echo back as note hooks, and thread resolution uses it to tell bot threads from human ones.

`api()` wraps `api_once()` and retries only transient connection errors (`API_ATTEMPTS`). It never retries HTTP errors, and it refuses redirects. A request with a body defaults to POST. Pass `method="PUT"` where the API requires it: GitLab resolves a discussion only with PUT (the old POST was a 404 in production), and GitHub dismisses a review with PUT. Test fakes of `api` often don't take `method`, so `api_json` passes it only when it is set.

Dashboard actions: `POST /api/reviews/<id>/{stop,rereview,delete}` (`Handler.action`). They require `authorized()` plus `same_origin()` (an `X-Dashboard: 1` header, and Origin / Sec-Fetch-Site must match). Stop: `run_job` binds the tracker id to the worker thread (`_current.job`). `run_hermes` runs the CLI with `Popen(start_new_session=True)`, registered in `_procs`, so `stop_review` can kill the whole process group. `track()` raises `Stopped` on the next stage change, and the row ends as `stopped`. Re-review: `replay_of()` rebuilds a payload from the record URL with `_force: True`, which bypasses trigger gates, the head memory and the "already reviewed on open" check, and counts as a re-review. `collect_gitlab` resolves the project path to its numeric id and refuses MRs whose API state isn't `opened`. Delete: `Tracker.delete` filters the JSONL file (not just the in-memory window) and replaces it atomically.

Dashboard: `Tracker` keeps live jobs in memory plus an append-only JSONL history, and fixes up old rows on `_load`. It notifies waiters through a `Condition`. `/api/events` is SSE, capped at 16 concurrent streams by the `STREAMS` semaphore. `/api/reviews` returns the full JSON snapshot. Both use HTTP Basic auth when `DASHBOARD_PASSWORD` is set.

All of the following live only in process memory and are lost on restart: dedupe (`_seen`), reviewed heads (`_reviewed`), debate dedupe and cooldown, pending debounce timers, and queued jobs. Only review history (`REVIEW_STORE`) and mistakes (`MEMORY_DB`) persist.

## Tests

`tests/test_server.py` imports `server` directly. It blanks `REVIEW_STORE` and `MEMORY_DB` before the import so the suite can't write to the live history or mistakes DB (tests that need memory swap in `server.Memory(<tmp path>)` and close it), and it resets module globals (`BOT_USERNAME`, access levels, `_reviewed`). Many config values are **module-level constants read at import**. Tests change them with `patch.object(server, "NAME", ...)`, not env vars. Reset `_seen`, `_reviewed` and `_whoami_cache` in `setUp` when a test goes through the handler. The end-to-end tests run the real HTTP server against `ApiStub` (a fake GitLab) and a stub `hermes` shell script set through `HERMES_BIN`. Other tests patch `server.run_hermes`.
