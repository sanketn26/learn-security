DOCS_MKDOCS ?= .venv/bin/mkdocs

.PHONY: docs docs-build lab-up lab-down lab-reset simulate ingest alerts

docs:
	@test -x "$(DOCS_MKDOCS)" || (echo "Missing $(DOCS_MKDOCS). Run: python3 -m venv .venv && .venv/bin/python -m pip install -r requirements-docs.txt" && exit 1)
	$(DOCS_MKDOCS) serve

docs-build:
	@test -x "$(DOCS_MKDOCS)" || (echo "Missing $(DOCS_MKDOCS). Run: python3 -m venv .venv && .venv/bin/python -m pip install -r requirements-docs.txt" && exit 1)
	$(DOCS_MKDOCS) build --strict

lab-up:
	chmod +x labs/scripts/*.sh
	./labs/scripts/lab-up.sh

lab-down:
	./labs/scripts/lab-down.sh

lab-reset:
	./labs/scripts/lab-reset.sh

simulate:
	python3 labs/attack-sim/simulate.py --scenario all

ingest:
	curl -s -X POST http://127.0.0.1:8090/ingest | python3 -m json.tool

alerts:
	curl -s http://127.0.0.1:8090/alerts | python3 -m json.tool
