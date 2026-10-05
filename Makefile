# hardening-lab — flujo completo: make lab-up audit harden audit report
# En Windows ejecútalo desde Git Bash (necesita bash y docker en el PATH).

SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help
.ONESHELL:

# Git Bash convierte rutas tipo /workspace en rutas de Windows al llamar a docker.exe: se desactiva.
export MSYS_NO_PATHCONV := 1

UNAME := $(shell uname -s 2>/dev/null || echo unknown)
ifeq ($(UNAME),Linux)
export LAB_UID ?= $(shell id -u)
export LAB_GID ?= $(shell id -g)
endif

STATE_DIR := .lab
PHASE_FILE := $(STATE_DIR)/phase
LAB_STATE = $(shell cat $(PHASE_FILE) 2>/dev/null || echo baseline)

COMPOSE_BASE := docker compose -f lab/compose.yaml
COMPOSE_HARD := docker compose -f lab/compose.yaml -f lab/compose.hardened.yaml
COMPOSE = $(if $(filter hardened,$(LAB_STATE)),$(COMPOSE_HARD),$(COMPOSE_BASE))
CONTROLLER = $(COMPOSE) --profile tools run --rm -T controller

# Fase de la auditoría: por defecto, el estado actual del laboratorio (baseline | hardened).
PHASE ?= $(LAB_STATE)
# Fase de las re-auditorías de deriva: drift (manual) o scheduled (GitHub Actions).
DRIFT_PHASE ?= drift
# Run endurecido a aprobar como línea base (por defecto, el más reciente).
BASELINE_RUN ?=
RUN_ID := $(shell date -u +%Y%m%dT%H%M%SZ)-$(PHASE)
RUN_DIR := reports/runs/$(RUN_ID)

export HLAB_GIT_SHA := $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
export HLAB_GIT_DIRTY := $(shell test -n "$$(git status --porcelain 2>/dev/null)" && echo true || echo false)

.PHONY: help
help: ## Lista los objetivos disponibles
	@grep -hE '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Construye las imágenes (nodos, controlador y docker-bench)
	$(COMPOSE_BASE) --profile tools --profile audit build

.PHONY: lab-up
lab-up: build ## Levanta el laboratorio en estado baseline
	mkdir -p $(STATE_DIR)
	$(COMPOSE_BASE) up -d --wait --remove-orphans
	echo baseline > $(PHASE_FILE)
	$(MAKE) --no-print-directory ping

.PHONY: ping
ping: ## Verifica que Ansible llega a los tres nodos a través del bastión
	HLAB_LAB_STATE=$(LAB_STATE) $(CONTROLLER) bash lab/scripts/wait-ssh.sh

.PHONY: audit
audit: ## Audita el laboratorio (Lynis, OpenSCAP, docker-bench, Trivy, sondas) y normaliza resultados
	mkdir -p $(RUN_DIR)/raw/compose $(RUN_DIR)/raw/docker-bench
	$(COMPOSE) config --no-path-resolution > $(RUN_DIR)/raw/compose/effective.yaml
	HLAB_RUN_ID=$(RUN_ID) $(COMPOSE) --profile audit run --rm docker-bench > $(RUN_DIR)/raw/docker-bench/console.log
	HLAB_RUN_ID=$(RUN_ID) HLAB_PHASE=$(PHASE) HLAB_LAB_STATE=$(LAB_STATE) \
	HLAB_STARTED_AT=$$(date -u +%Y-%m-%dT%H:%M:%SZ) \
	  $(CONTROLLER) bash lab/scripts/audit.sh
	@echo "Auditoría guardada en $(RUN_DIR)"

.PHONY: harden
harden: ## Aplica el endurecimiento: runtime de contenedores (Compose) y sistema operativo (Ansible)
	mkdir -p $(STATE_DIR)
	$(COMPOSE_HARD) up -d --wait --remove-orphans
	echo hardened > $(PHASE_FILE)
	$(MAKE) --no-print-directory ping
	HLAB_LAB_STATE=hardened $(COMPOSE_HARD) --profile tools run --rm -T controller \
	  bash -c 'cd ansible && ansible-playbook playbooks/harden.yml'

.PHONY: idempotence
idempotence: ## Re-ejecuta el endurecimiento y falla si algo cambia (debe dar changed=0)
	HLAB_LAB_STATE=$(LAB_STATE) $(CONTROLLER) bash lab/scripts/idempotence.sh

.PHONY: report
report: ## Genera el informe HTML y los gráficos antes/después
	$(CONTROLLER) hlab report --reports reports --out reports/site --images docs/img

.PHONY: approve-baseline
approve-baseline: ## Aprueba la última auditoría endurecida como línea base para la deriva
	$(CONTROLLER) hlab baseline approve --reports reports $(if $(BASELINE_RUN),--run-id $(BASELINE_RUN))

.PHONY: drift
drift: ## Re-audita y compara contra la línea base aprobada (sale con código 3 si hay deriva)
	$(MAKE) --no-print-directory audit PHASE=$(DRIFT_PHASE)
	$(CONTROLLER) hlab drift --reports reports

.PHONY: drift-demo
drift-demo: ## Introduce una deriva controlada y demuestra que se detecta
	HLAB_LAB_STATE=$(LAB_STATE) $(CONTROLLER) bash -c 'cd ansible && ansible-playbook playbooks/drift-demo.yml'
	$(MAKE) --no-print-directory drift || echo "Deriva detectada (esperado en la demostración)."

.PHONY: lab-down
lab-down: ## Destruye el laboratorio, sus redes y las claves efímeras
	$(COMPOSE_HARD) --profile tools --profile audit down -v --remove-orphans
	rm -rf $(STATE_DIR)

.PHONY: all
all: ## Flujo completo: lab-up, audit (baseline), harden, audit (endurecido), report
	$(MAKE) --no-print-directory lab-up
	$(MAKE) --no-print-directory audit
	$(MAKE) --no-print-directory harden
	$(MAKE) --no-print-directory audit
	$(MAKE) --no-print-directory report

.PHONY: test
test: ## Tests de Python con cobertura
	uv run pytest --cov --cov-report=term-missing --cov-report=xml

.PHONY: lint
lint: ## Lint y tipos (ruff, mypy)
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy src
