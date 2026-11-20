# ai-code-reviewer

Python stdlib webhook service for GitLab merge requests and GitHub pull requests. It fetches diffs, calls the Hermes Agent CLI, and posts review feedback. Hermes and a configured model provider are required; the server has no Python package dependencies.

Choose **Python direct** to use an existing host Hermes installation, or **Docker** to run the server with Hermes included in the image. Neither mode includes model credentials.

## Two ways to run

Docker — one command, no Python or Hermes install needed:

```bash
git clone https://github.com/dimassantoso/ai-code-reviewer && cd ai-code-reviewer
cp .env.example .env      # fill one token + its webhook secret
mkdir -p hermes-home && printf 'HERMES_UID=%s\nHERMES_GID=%s\n' "$(id -u)" "$(id -g)" >> .env
docker compose up -d --build
docker compose exec reviewer hermes setup   # provider login, once
curl -fsS http://127.0.0.1:9877/health
```

Python direct — requires Hermes already installed and authenticated:

```bash
git clone https://github.com/dimassantoso/ai-code-reviewer && cd ai-code-reviewer
cp .env.example .env      # fill one token + its webhook secret
set -a; . ./.env; set +a
python3 server.py
```

Point the platform webhook at `https://<host>/gl-review` or `https://<host>/gh-review`. Details for each mode below.


## Configuration

Copy `.env.example` to `.env` and fill in at least one platform token and its webhook secret. Protect this file and never commit it. Set up a dedicated Hermes home with a working provider and model; see the [Hermes documentation](https://hermes-agent.nousresearch.com/docs/).

| Variable | Meaning |
| --- | --- |
| `GITLAB_TOKEN`, `GITHUB_TOKEN` | API credentials; configure at least one. GitLab needs API access; GitHub needs repository pull request read/write access. |
| `GITLAB_WEBHOOK_SECRET`, `GITHUB_WEBHOOK_SECRET` | Required for each configured platform; `WEBHOOK_SECRET` is a shared fallback. Use separate random secrets. |
| `GITLAB_URL`, `GITHUB_URL` | HTTPS API base URLs; defaults are `https://gitlab.com` and `https://api.github.com`. For GitHub Enterprise include `/api/v3`. |
| `BIND_HOST`, `BIND_PORT` | Listen address and comma-separated ports; defaults `0.0.0.0` and `9877`. |
| `HERMES_BIN` | CLI executable; default `hermes` on PATH. |
| `HERMES_MODEL` | Optional model override; otherwise use Hermes configuration. |
| `HERMES_SKILL` | Optional skill name; example sets `ai-code-reviewer`. |
| `HERMES_TIMEOUT_S` | CLI timeout in seconds; default `300`. |

The server reads environment variables, not `.env` itself. Docker Compose loads `.env` via `env_file`; direct Python users must export it. Use shell-compatible values if sourcing the file.

## Python direct

Install and configure [Hermes Agent](https://hermes-agent.nousresearch.com/docs/), including provider authentication. Install this checkout as a local skill in the dedicated Hermes home:

```bash
export HERMES_HOME="$HOME/.hermes-reviewer"
mkdir -p "$HERMES_HOME/skills/ai-code-reviewer"
cp SKILL.md "$HERMES_HOME/skills/ai-code-reviewer/"
cp -R github gitlab references templates "$HERMES_HOME/skills/ai-code-reviewer/"
hermes setup
hermes skills list
cp .env.example .env
# Edit .env privately.
set -a; . ./.env; set +a
python3 server.py
```

Keep `HERMES_HOME` set for both Hermes setup and server execution. Verify the provider and skill using the same CLI options as the service:

```bash
printf 'Review this harmless diff: + return 1' | hermes chat --query-file - -t "" -Q --max-turns 5 -s ai-code-reviewer
curl -fsS http://127.0.0.1:9877/health
```

## Docker Compose

The Dockerfile extends the official Hermes Agent image pinned by digest. It includes the real Hermes CLI and bundles this skill; the upstream startup hook syncs bundled skills into the persistent Hermes home. Keep the image entrypoint: it initializes the home and drops privileges.

```bash
cp .env.example .env
# Edit .env privately: platform token, webhook secret, HERMES_UID and HERMES_GID.
mkdir -p hermes-home
# Set HERMES_UID and HERMES_GID in .env to the output of id -u and id -g.
docker compose up -d --build
docker compose exec reviewer hermes setup
# Configure provider authentication for this dedicated Hermes home.
curl -fsS http://127.0.0.1:9877/health
docker compose logs -f reviewer
```

`./hermes-home` persists Hermes config, credentials, sessions and logs at `/opt/data`. Treat it as sensitive. Do **not** mount an active personal Hermes home: it can contain messaging credentials and gateway configuration that starts other services. A fresh home has no configured provider. Run a harmless diff through the exact CLI command above using `docker compose exec -T reviewer sh -c '...'` before enabling webhooks. `health` only proves the HTTP listener works.

Compose publishes only `127.0.0.1:9877` and forces the container listener to `0.0.0.0:9877`. Change the host side of `ports` if 9877 is occupied. For other container ports, update the port mapping and Docker healthcheck too. Use an HTTPS reverse proxy or tunnel to receive external webhooks; restrict access and retain signature verification.

## Webhooks and behavior

- GitLab: configure `https://<host>/gl-review` for merge request events. The server accepts `X-Gitlab-Token` or Standard Webhooks signing headers; `whsec_` secrets must contain valid base64.
- GitHub: configure `https://<host>/gh-review` for pull request events and JSON payloads. The server verifies `X-Hub-Signature-256`.
- `GET /health` returns `200 ok`. A disabled platform returns `404`; an invalid signature returns `403`.
- Valid requests are acknowledged with `202 accepted` before background processing. This is not proof a review was posted; inspect logs and the MR/PR. Duplicate payloads are suppressed in memory for five minutes, not durably across restarts.
- GitLab open/update/reopen and GitHub opened/synchronize/reopened events trigger review. GitLab gets a note; GitHub gets a comment review. No automatic approval or merge is performed. Thread debate, access-level filtering and persistent deduplication are not implemented.
- Diffs over 100,000 characters are rejected rather than silently truncated. API and Hermes errors are logged; retries and persistence are not guaranteed after acknowledgement.

Review input is untrusted. The service requests empty Hermes toolsets and strips platform credentials from the CLI child environment, but use a dedicated least-privilege account and review model output before acting on it.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Tests use mocks and do not prove platform credentials, network access or model readiness.
