# osint-veil — atajos de desarrollo y despliegue.
# `make` o `make help` lista los objetivos.

PY ?= python
TOOLS_USER ?= osinttools
PORT ?= 8000

.DEFAULT_GOAL := help

.PHONY: help bootstrap install test lint keygen run up down logs ps secure-up lockdown serve \
        ensure-tools-user audit openosint clean

# Usa el python del venv si existe; si no, el del sistema.
VENV_PY := $(shell [ -x .venv/bin/python ] && echo .venv/bin/python || echo $(PY))

# Detecta el comando de Compose: plugin v2 ('docker compose') o standalone v1
# ('docker-compose'). Antepone sudo si el usuario no está en el grupo 'docker'.
SUDO := $(shell docker info >/dev/null 2>&1 || echo sudo)
COMPOSE := $(shell docker compose version >/dev/null 2>&1 && echo "docker compose" || echo "docker-compose")

help:  ## Muestra esta ayuda
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# ── Instalación de un tirón (Kali/Debian) ─────────────────────────────
bootstrap:  ## Instala TODO con setup.sh. Pasa flags con ARGS="--all"
	./setup.sh $(ARGS)

# ── Desarrollo ────────────────────────────────────────────────────────
install:  ## Instala el paquete + dependencias de desarrollo
	$(PY) -m pip install -e ".[dev]"

test:  ## Ejecuta la batería de tests
	$(PY) -m pytest -q

lint:  ## Linter (ruff)
	$(PY) -m ruff check proxy tests

keygen:  ## Genera una clave de cifrado para PROXY_ENCRYPTION_KEY
	@$(PY) -m proxy.keygen

# ── Arranque local sin Docker (rápido, sin root) ──────────────────────
run:  ## Arranca el proxy en local sin Docker (modo warn). No necesita root.
	@echo "→ http://127.0.0.1:$(PORT)   (Ctrl+C para parar)"
	$(VENV_PY) -m uvicorn proxy.app:app --host 127.0.0.1 --port $(PORT)

# ── Despliegue Docker (lockdown automático) ───────────────────────────
up:  ## Construye y arranca en Docker con egress lockdown (de un tirón)
	$(SUDO) $(COMPOSE) up --build -d
	@echo "→ http://127.0.0.1:$(PORT)   (health: curl -s 127.0.0.1:$(PORT)/health)"

down:  ## Para y elimina los contenedores
	$(SUDO) $(COMPOSE) down

logs:  ## Sigue los logs del contenedor
	$(SUDO) $(COMPOSE) logs -f

ps:  ## Estado de los contenedores
	$(SUDO) $(COMPOSE) ps

# ── Despliegue bare-metal (sin Docker) ────────────────────────────────
secure-up: ensure-tools-user lockdown serve  ## Bare-metal de un tirón: usuario + lockdown + arranque

ensure-tools-user:  ## Crea el usuario sin salida a la IA (idempotente)
	@id $(TOOLS_USER) >/dev/null 2>&1 || sudo useradd -r -s /usr/sbin/nologin $(TOOLS_USER)
	@echo "usuario de herramientas: $(TOOLS_USER) (sin salida a Anthropic tras lockdown)"
	@sudo grep -q "ALL=($(TOOLS_USER))" /etc/sudoers.d/osint-veil 2>/dev/null || { \
	  echo "$$(id -un) ALL=($(TOOLS_USER)) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/osint-veil >/dev/null && \
	  sudo chmod 0440 /etc/sudoers.d/osint-veil; }

lockdown:  ## Aplica el bloqueo de egress a nivel de red (iptables)
	sudo PROXY_USER=$$(id -un) TOOLS_USER=$(TOOLS_USER) deploy/egress_lockdown.sh

serve:  ## Arranca el proxy en local (enforce + lockdown confirmado)
	PROXY_EGRESS=enforce PROXY_EGRESS_LOCKED=1 PROXY_TOOLS_USER=$(TOOLS_USER) \
	  $(PY) -m uvicorn proxy.app:app --host 127.0.0.1 --port $(PORT)

# ── CLI / utilidades ──────────────────────────────────────────────────
audit:  ## OSINT por CLI (usa Claude + summarizer Ollama). Uso: make audit CASE=.. TARGET=..
	@test -n "$(CASE)" -a -n "$(TARGET)" || { echo "Uso: make audit CASE=.. TARGET=.."; exit 2; }
	PROXY_TOOLS_USER=$(TOOLS_USER) $(VENV_PY) -m proxy.cli audit --case $(CASE) --target $(TARGET)

openosint:  ## Lanza OpenOSINT enrutado por el proxy (carga openosint.env). ARGS=".."
	@test -f openosint.env || { echo "Falta openosint.env. Ejecuta: ./setup.sh --openosint"; exit 2; }
	@command -v openosint >/dev/null 2>&1 || { echo "OpenOSINT no instalado. Ejecuta: ./setup.sh --openosint"; exit 2; }
	@echo "→ OpenOSINT vía proxy (http://127.0.0.1:$(PORT)). Asegúrate de que el proxy está arrancado (make up)."
	set -a; . ./openosint.env; set +a; openosint $(ARGS)

clean:  ## Limpia cachés y artefactos locales (NO toca el vault)
	rm -rf .pytest_cache .ruff_cache **/__pycache__ informe_*.md
