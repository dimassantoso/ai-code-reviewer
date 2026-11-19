# ai-code-reviewer

Unified Hermes Agent skill for AI code review on **GitLab** and **GitHub**.

## Quick Start

```bash
# Clone
git clone https://github.com/penawarlawas/ai-code-reviewer.git
cd ai-code-reviewer

# Configure
cp .env.example .env
# edit .env with your tokens

# Run (requires Hermes Agent installed)
hermes run -m hms/deepseek-v4.1-flash-free -s ai-code-reviewer
```

Or run the webhook server directly:

```bash
python server.py  # BIND_PORT=9877,9876,9878
```

## Platforms

| Platform | Webhook Route | Skill File |
|----------|---------------|------------|
| GitLab   | `/gl-review`  | `gitlab/SKILL.md` |
| GitHub   | `/gh-review`  | `github/SKILL.md` |

Both share core logic in `SKILL.md`.

## Features

- **Diff review**: security, correctness, performance, testing, conventions
- **Thread debate**: @mention the bot in a comment → contextual reply with evidence
- **Dedupe**: never reply twice to same note/comment
- **Cooldown**: 30s per user per thread
- **Standard Webhooks** signature verification
- **Language conventions**: per-repo override via `.hermes/code-review-conventions.md`

## Config (env)

```bash
GITLAB_TOKEN=glpat-xxx
GITHUB_TOKEN=ghp_xxx
GITLAB_GROUP=123456
GITHUB_ORG=my-org
HERMES_BIN=/usr/local/bin/hermes
HERMES_MODEL=hms/deepseek-v4.1-flash-free
HERMES_SKILL=ai-code-reviewer
BIND_PORT=9877,9876,9878
WEBHOOK_SECRET=whsec_<base64_key>
MIN_ACCESS_LEVEL=30
GITHUB_MIN_PERMISSION=write
BOT_USERNAME=santosodb
```

## Structure

```
.
├── SKILL.md                # Generic core
├── gitlab/SKILL.md         # GitLab adapter
├── github/SKILL.md         # GitHub adapter
├── references/
│   └── language-conventions.md
└── templates/
    └── review-prompt.md
```

## License

MIT — use freely.