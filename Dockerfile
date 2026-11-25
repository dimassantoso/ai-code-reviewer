# Hermes Agent base image: CLI + runtime are baked in, so the container
# really provides `hermes` (no pip install, no vendored wrapper).
#
# Tag alone would drift under us; the digest pins the exact image that was
# built and smoke-tested here (linux/arm64 + linux/amd64 multi-arch index).
FROM nousresearch/hermes-agent@sha256:3e9fe4c6ef36490f43aa0d0d80f9df64e9c92a576eee3042f1a97c8813c05355

WORKDIR /app
COPY server.py /app/server.py
COPY dashboard.html /app/dashboard.html
# Bundled-skills dir: the image's stage2 hook syncs /opt/hermes/skills into
# $HERMES_HOME/skills on every boot, which is how `hermes -s ai-code-reviewer`
# resolves the skill inside the container.
# The skill is one self-contained file: reviews run with no toolsets, so the model
# cannot open anything beside it.
COPY SKILL.md /opt/hermes/skills/ai-code-reviewer/SKILL.md

ENV PYTHONUNBUFFERED=1
ENV HERMES_SKILL=ai-code-reviewer

EXPOSE 9877

# Keep the image ENTRYPOINT (s6 /init -> stage2 boot -> main-wrapper). s6 needs
# PID 1 to seed $HERMES_HOME, sync skills and drop privileges; overriding the
# entrypoint skips all of that and the skill is never installed. main-wrapper
# execs a leading executable directly, so CMD stays a plain command.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python3 -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:9877/health',timeout=3)"

CMD ["python3", "/app/server.py"]
