# Operations for the deployed reviewer. `make` or `make help` lists targets.
# Works with the systemd user unit; falls back to a direct run without it.
SHELL := /bin/bash
UNIT  := pasarpolis-ai-code-reviewer
DIR   := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
ENV   := $(DIR)/.env
LOG   := $(DIR)/server.log
PORT  := $(or $(shell grep -m1 '^BIND_PORT=' $(ENV) 2>/dev/null | cut -d= -f2 | cut -d, -f1),9877)
IP    := $(or $(shell tailscale ip -4 2>/dev/null | head -1),127.0.0.1)
SC    := systemctl --user
export XDG_RUNTIME_DIR ?= /run/user/$(shell id -u)

.DEFAULT_GOAL := help
.PHONY: help start stop restart status health dash log logs password test deploy

help:  ## list targets
	@grep -E '^[a-z]+:.*## ' $(MAKEFILE_LIST) | sed 's/:.*## /\t/' | column -t -s "$$(printf '\t')"

start:  ## start the service
	$(SC) start $(UNIT) && sleep 2 && $(SC) is-active $(UNIT)

stop:  ## stop the service
	$(SC) stop $(UNIT) && $(SC) is-active $(UNIT) || true

restart:  ## restart after editing .env or pulling code
	$(SC) restart $(UNIT) && sleep 3 && $(SC) is-active $(UNIT) && $(MAKE) --no-print-directory health

status:  ## unit state plus listeners
	$(SC) status $(UNIT) --no-pager -l | head -12
	@ss -ltnp 2>/dev/null | grep -E ':($(PORT)|9876)\b' || echo "not listening"

health:  ## HTTP check on the tailnet address
	@curl -fsS -o /dev/null -w 'health=%{http_code}  $(IP):$(PORT)\n' http://$(IP):$(PORT)/health

dash:  ## print the dashboard URL
	@echo "http://$(IP):$(PORT)/dashboard"
	@echo "login: $$(grep -m1 '^DASHBOARD_USER=' $(ENV) | cut -d= -f2) / see DASHBOARD_PASSWORD in $(ENV)"

log:  ## last 100 log lines
	@tail -n 100 $(LOG)

logs:  ## stream the log (ctrl-c to stop)
	@tail -f -n 50 $(LOG)

password:  ## set the dashboard password: make password NEW=secret
	@test -n "$(NEW)" || { echo 'usage: make password NEW=secret'; exit 1; }
	@python3 - "$(ENV)" "$(NEW)" <<-'PY'
	import pathlib, sys
	path, value = pathlib.Path(sys.argv[1]), sys.argv[2]
	lines = [l for l in path.read_text().splitlines() if not l.startswith("DASHBOARD_PASSWORD=")]
	lines.append("DASHBOARD_PASSWORD=" + value)
	path.write_text("\n".join(lines) + "\n")
	path.chmod(0o600)
	PY
	@$(MAKE) --no-print-directory restart

test:  ## run the test suite
	cd $(DIR) && python3 -m unittest discover -s tests

deploy:  ## pull origin/master, restart, health check
	cd $(DIR) && git fetch -q origin && git reset --hard -q origin/master && git log --oneline -1
	@$(MAKE) --no-print-directory restart
