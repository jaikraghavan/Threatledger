# Local development helpers. Requires uv (https://docs.astral.sh/uv/).
UV ?= uv
TAILWIND_VERSION ?= 4.1.11
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_S),Darwin)
  TW_OS := macos
else
  TW_OS := linux
endif
ifeq ($(UNAME_M),arm64)
  TW_ARCH := arm64
else ifeq ($(UNAME_M),aarch64)
  TW_ARCH := arm64
else
  TW_ARCH := x64
endif
TAILWIND := .bin/tailwindcss-$(TAILWIND_VERSION)

.PHONY: install env css css-watch run worker migrate seed test cov lint fmt typecheck security check docker-up docker-down

install:            ## install Python 3.12 + all dependencies into .venv
	$(UV) sync

env:                ## create .env with a random secret key (never committed)
	@$(UV) run python scripts/make_env.py

$(TAILWIND):        ## download the Tailwind standalone CLI and verify its checksum
	@mkdir -p .bin
	curl -fsSL -o $@ https://github.com/tailwindlabs/tailwindcss/releases/download/v$(TAILWIND_VERSION)/tailwindcss-$(TW_OS)-$(TW_ARCH)
	curl -fsSL https://github.com/tailwindlabs/tailwindcss/releases/download/v$(TAILWIND_VERSION)/sha256sums.txt \
	  | grep "tailwindcss-$(TW_OS)-$(TW_ARCH)$$" | awk '{print $$1"  $@"}' | shasum -a 256 -c -
	chmod +x $@

css: $(TAILWIND)    ## build static/css/app.css
	$(TAILWIND) -i assets/tailwind/app.css -o static/css/app.css --minify

css-watch: $(TAILWIND)
	$(TAILWIND) -i assets/tailwind/app.css -o static/css/app.css --watch

migrate:
	$(UV) run python manage.py migrate

seed:
	$(UV) run python manage.py seed

run: css migrate    ## dev server on http://127.0.0.1:8000
	$(UV) run python manage.py runserver

worker:
	$(UV) run python manage.py qcluster

test:
	$(UV) run pytest

cov:
	$(UV) run pytest --cov --cov-report=term-missing --cov-fail-under=80

lint:
	$(UV) run ruff check .
	$(UV) run ruff format --check .

fmt:
	$(UV) run ruff format .
	$(UV) run ruff check --fix .

typecheck:
	$(UV) run mypy .

security:
	@mkdir -p .bin
	$(UV) run bandit -c pyproject.toml -r threatledger config
	$(UV) export --frozen --no-dev --no-hashes --format requirements-txt -o .bin/requirements-audit.txt >/dev/null
	$(UV) run pip-audit -r .bin/requirements-audit.txt --progress-spinner off

check: lint typecheck cov security   ## everything CI runs except the Docker build

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down
