# Operations for the deployed reviewer. `make` or `make help` lists targets.
# Works with the systemd user unit; falls back to a direct run without it.
SHELL := /bin/bash
UNIT  := pasarpolis-ai-code-reviewer
DIR   := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
ENV   := $(DIR)/.env
LOG   := $(DIR)/server.log
# REVIEW_STORE may be relative to DIR (./reviews.jsonl) or absolute.
STORE_RAW := $(or $(shell grep -m1 '^REVIEW_STORE=' $(ENV) 2>/dev/null | cut -d= -f2),reviews.jsonl)
STORE := $(if $(filter /%,$(STORE_RAW)),$(STORE_RAW),$(DIR)/$(patsubst ./%,%,$(STORE_RAW)))
PORT  := $(or $(shell grep -m1 '^BIND_PORT=' $(ENV) 2>/dev/null | cut -d= -f2 | cut -d, -f1),9877)
# Prefer the MagicDNS name (survives IP changes), fall back to the tailnet IP.
HOST  := $(or $(shell tailscale status --json 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin)["Self"]["DNSName"].rstrip("."))' 2>/dev/null),$(or $(shell tailscale ip -4 2>/dev/null | head -1),127.0.0.1))
SC    := systemctl --user
export XDG_RUNTIME_DIR ?= /run/user/$(shell id -u)

.DEFAULT_GOAL := help
.PHONY: help start stop restart status health dash url log logs password test deploy reset add skill mistakes init

help:  ## list targets
	@grep -E '^[a-z]+:.*## ' $(MAKEFILE_LIST) | sed 's/:.*## /\t/' | column -t -s "$$(printf '\t')"

init:  ## setup wizard: platforms, tokens, model, dashboard -> .env (re-runnable)
	@python3 $(DIR)/tools/init.py

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
	@curl -fsS -o /dev/null -w 'health=%{http_code}  $(HOST):$(PORT)\n' http://$(HOST):$(PORT)/health

dash:  ## print the dashboard URL and login
	@echo "http://$(HOST):$(PORT)/dashboard"
	@echo "login: $$(grep -m1 '^DASHBOARD_USER=' $(ENV) | cut -d= -f2) / password: grep '^DASHBOARD_PASSWORD=' $(ENV)"

url:  ## just the dashboard URL (for copy-paste)
	@echo "http://$(HOST):$(PORT)/dashboard"

log:  ## last 100 log lines
	@tail -n 100 $(LOG)

logs:  ## stream the log (ctrl-c to stop)
	@tail -f -n 50 $(LOG)

reset:  ## wipe review history (asks first; keeps a backup)
	@test -f $(STORE) || { echo "no store at $(STORE)"; exit 1; }
	@printf 'Delete all %s review records and restart? [y/N] ' "$$(wc -l < $(STORE))"; read ans; \
	 case "$$ans" in y|Y) cp $(STORE) $(STORE).$$(date +%Y%m%d-%H%M%S).bak && : > $(STORE) && echo "cleared $(STORE)";; *) echo aborted; exit 1;; esac
	@$(MAKE) --no-print-directory restart

add:  ## install the reviewer on a repo: make add REPO=group/project
	@test -n "$(REPO)" || { echo 'usage: make add REPO=group/project'; exit 1; }
	@cd $(DIR) && python3 tools/add_repo.py "$(REPO)"

password:  ## set the dashboard password: make password NEW=secret
	@test -n "$(NEW)" || { echo 'usage: make password NEW=secret'; exit 1; }
	@python3 -c 'import pathlib,sys; p=pathlib.Path(sys.argv[1]); ls=[l for l in p.read_text().splitlines() if not l.startswith("DASHBOARD_PASSWORD=")]; p.write_text("\n".join(ls+["DASHBOARD_PASSWORD="+sys.argv[2]])+"\n"); p.chmod(0o600)' "$(ENV)" "$(NEW)"
	@$(MAKE) --no-print-directory restart

# Hermes home the service uses: HERMES_HOME from .env, else ~/.hermes; with
# HERMES_PROFILE set, skills live under profiles/<name>/.
HHOME   := $(or $(shell grep -m1 '^HERMES_HOME=' $(ENV) 2>/dev/null | cut -d= -f2),$(HOME)/.hermes)
HPROF   := $(shell grep -m1 '^HERMES_PROFILE=' $(ENV) 2>/dev/null | cut -d= -f2)
HSKILLS := $(HHOME)$(if $(HPROF),/profiles/$(HPROF))/skills
HSKILL  := $(or $(shell grep -m1 '^HERMES_SKILL=' $(ENV) 2>/dev/null | cut -d= -f2),ai-code-reviewer)

skill:  ## install SKILL.md into the Hermes home the service uses (backs up the old one)
	@dest=$$(find $(HSKILLS) -mindepth 1 -maxdepth 3 -type d -name '$(HSKILL)' 2>/dev/null | head -1); \
	 dest=$${dest:-$(HSKILLS)/$(HSKILL)}; mkdir -p "$$dest"; \
	 if [ -f "$$dest/SKILL.md" ] && ! cmp -s $(DIR)/SKILL.md "$$dest/SKILL.md"; then \
	   cp "$$dest/SKILL.md" "$$dest/SKILL.md.$$(date +%Y%m%d-%H%M%S).bak"; fi; \
	 cp $(DIR)/SKILL.md "$$dest/SKILL.md" && echo "skill installed: $$dest/SKILL.md"

MEM_RAW := $(shell grep -m1 '^MEMORY_DB=' $(ENV) 2>/dev/null | cut -d= -f2)
MEM     := $(if $(filter /%,$(MEM_RAW)),$(MEM_RAW),$(DIR)/$(patsubst ./%,%,$(MEM_RAW)))

mistakes:  ## findings the bot conceded were wrong (newest first): make mistakes [N=20]
	@test -n "$(MEM_RAW)" || { echo "MEMORY_DB is not set in .env"; exit 1; }
	@python3 -c 'import sqlite3,sys,time; db=sqlite3.connect(sys.argv[1]); rows=db.execute("SELECT created,repo,target,file,line,level,finding,commenter,lesson FROM mistakes ORDER BY created DESC LIMIT ?",(int(sys.argv[2]),)).fetchall(); print("%d total" % db.execute("SELECT COUNT(*) FROM mistakes").fetchone()[0]); [print("\n%s  %s %s  %s:%s [%s] by @%s\n  finding: %s\n  lesson:  %s" % (time.strftime("%Y-%m-%d %H:%M",time.localtime(r[0])),r[1],r[2],r[3] or "-",r[4] or "-",r[5] or "-",r[7],r[6][:200],r[8][:200])) for r in rows]' "$(MEM)" "$(or $(N),20)"

test:  ## run the test suite
	cd $(DIR) && python3 -m unittest discover -s tests

deploy:  ## pull origin/master, restart, health check
	cd $(DIR) && git fetch -q origin && git reset --hard -q origin/master && git log --oneline -1
	@$(MAKE) --no-print-directory skill
	@$(MAKE) --no-print-directory restart
