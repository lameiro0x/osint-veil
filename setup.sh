#!/usr/bin/env bash
#
# setup.sh — instalador de un tirón para osint-veil (Kali / Debian / Ubuntu).
#
# Uso típico:
#   git clone https://github.com/lameiro0x/osint-veil && cd osint-veil
#   ./setup.sh                 # base: deps de sistema + venv + paquete + .env con claves
#   ./setup.sh --tools --ner   # + binarios OSINT + NER de personas
#   ./setup.sh --ollama        # + summarizer local (Ollama + modelo)
#   ./setup.sh --lockdown      # + usuario sin-salida-IA + iptables egress lockdown (root)
#   ./setup.sh --all           # todo lo de arriba
#
# Es IDEMPOTENTE: puedes volver a ejecutarlo. No sobrescribe claves ya puestas
# en .env. No envía nada a ningún sitio (salvo descargar paquetes que pidas).
set -euo pipefail

# ── Localizar la raíz del repo y situarnos en ella ───────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Colores / log ────────────────────────────────────────────────────────
if [ -t 1 ]; then C_G="\033[32m"; C_Y="\033[33m"; C_R="\033[31m"; C_B="\033[36m"; C_0="\033[0m"
else C_G=""; C_Y=""; C_R=""; C_B=""; C_0=""; fi
info() { printf "${C_B}[*]${C_0} %s\n" "$*"; }
ok()   { printf "${C_G}[✓]${C_0} %s\n" "$*"; }
warn() { printf "${C_Y}[!]${C_0} %s\n" "$*"; }
err()  { printf "${C_R}[x]${C_0} %s\n" "$*" >&2; }

# ── Flags ────────────────────────────────────────────────────────────────
WITH_TOOLS=0; WITH_NER=0; WITH_OLLAMA=0; WITH_OPENOSINT=0; WITH_LOCKDOWN=0; RUN_TESTS=1; USE_VENV=1
TOOLS_USER="${TOOLS_USER:-osinttools}"

usage() {
  cat <<EOF
setup.sh — instalador de osint-veil

Opciones:
  --tools       Instala binarios OSINT (whois, dnsutils, nmap, amass, subfinder)
  --ner         Instala NER de personas (spaCy + modelo es_core_news_sm)
  --ollama      Instala Ollama + modelo local para el summarizer opcional
  --openosint   Instala OpenOSINT (aislado con pipx) y genera openosint.env
  --lockdown    Crea usuario '$TOOLS_USER' y aplica el egress lockdown (requiere root/sudo)
  --all         Equivale a --tools --ner --ollama --openosint --lockdown
  --no-venv     No crear venv; instala en el Python actual
  --no-test     No ejecutar la batería de tests al final
  -h, --help    Esta ayuda
EOF
}

for arg in "$@"; do
  case "$arg" in
    --tools) WITH_TOOLS=1 ;;
    --ner) WITH_NER=1 ;;
    --ollama) WITH_OLLAMA=1 ;;
    --openosint) WITH_OPENOSINT=1 ;;
    --lockdown) WITH_LOCKDOWN=1 ;;
    --all) WITH_TOOLS=1; WITH_NER=1; WITH_OLLAMA=1; WITH_OPENOSINT=1; WITH_LOCKDOWN=1 ;;
    --no-venv) USE_VENV=0 ;;
    --no-test) RUN_TESTS=0 ;;
    -h|--help) usage; exit 0 ;;
    *) err "Opción desconocida: $arg"; usage; exit 2 ;;
  esac
done

# ── sudo helper (no exige root si ya lo eres) ────────────────────────────
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"
  else warn "No eres root y no hay sudo: omitiré pasos que requieran privilegios."; fi
fi

# ── 1. Dependencias de sistema (apt) ─────────────────────────────────────
APT=""
if command -v apt-get >/dev/null 2>&1; then APT="apt-get"; fi

install_apt() {  # install_apt pkg1 pkg2 ...  (nunca aborta: fail -> warn)
  [ -n "$APT" ] || { warn "Sin apt-get; instala manualmente: $*"; return 0; }
  [ -n "$SUDO" ] || [ "$(id -u)" -eq 0 ] || { warn "Sin privilegios para apt; omito: $*"; return 0; }
  $SUDO $APT install -y --no-install-recommends "$@" || warn "apt no pudo instalar: $*"
  return 0
}

info "Instalando dependencias base de sistema…"
if [ -n "$APT" ]; then
  $SUDO $APT update -y || warn "apt update falló (sigo)."
  install_apt python3 python3-venv python3-pip git ca-certificates curl iptables
else
  warn "Distro sin apt. Asegúrate de tener: python3 (3.10+), python3-venv, pip, git, curl."
fi

# ── 2. Entorno Python ────────────────────────────────────────────────────
PYBASE="$(command -v python3 || command -v python)"
[ -n "$PYBASE" ] || { err "No encuentro python3."; exit 1; }

# Comprobar 3.10+
"$PYBASE" - <<'PY' || { err "Se requiere Python 3.10+."; exit 1; }
import sys
raise SystemExit(0 if sys.version_info >= (3, 10) else 1)
PY

if [ "$USE_VENV" -eq 1 ]; then
  if [ ! -d .venv ]; then
    info "Creando entorno virtual en ./.venv …"
    "$PYBASE" -m venv .venv
  fi
  # shellcheck disable=SC1091
  source .venv/bin/activate
  PY="python"
else
  PY="$PYBASE"
fi

info "Actualizando pip e instalando osint-veil…"
"$PY" -m pip install --upgrade pip >/dev/null
EXTRAS="dev"
[ "$WITH_NER" -eq 1 ] && EXTRAS="dev,ner"
"$PY" -m pip install -e ".[${EXTRAS}]"
ok "Paquete instalado (extras: ${EXTRAS})."

if [ "$WITH_NER" -eq 1 ]; then
  info "Descargando modelo de NER en español (es_core_news_sm)…"
  "$PY" -m spacy download es_core_news_sm || warn "No se pudo bajar el modelo spaCy (NER quedará limitado)."
fi

# ── 3. Configuración (.env) con claves autogeneradas ─────────────────────
if [ ! -f .env ]; then
  info "Creando .env desde .env.example…"
  cp .env.example .env
fi

# Rellena una clave SOLO si está vacía o con placeholder. Nunca pisa lo tuyo.
set_env_if_empty() {  # set_env_if_empty KEY VALUE
  KEY="$1" VALUE="$2" "$PY" - <<'PY'
import os, re, pathlib
key, value = os.environ["KEY"], os.environ["VALUE"]
p = pathlib.Path(".env"); txt = p.read_text()
cur = ""
m = re.search(rf"^{re.escape(key)}=(.*)$", txt, re.M)
if m: cur = m.group(1).strip()
placeholders = {"", "change-me", "changeme"}
if cur in placeholders:
    line = f"{key}={value}"
    # lambda en el reemplazo: evita que '\1', '\g<>' o backslashes del VALOR
    # se interpreten como backreferences de re.sub.
    txt = re.sub(rf"^{re.escape(key)}=.*$", lambda _m: line, txt, flags=re.M) if m else txt + f"\n{line}\n"
    p.write_text(txt)
    print(f"  set {key}")
else:
    print(f"  keep {key} (ya configurada)")
PY
}

info "Generando claves locales en .env…"
LOCAL_KEY="$("$PY" - <<'PY'
import secrets; print(secrets.token_hex(24))
PY
)"
FERNET_KEY="$("$PY" -m proxy.keygen)"
set_env_if_empty PROXY_LOCAL_API_KEY "$LOCAL_KEY"
set_env_if_empty PROXY_ENCRYPTION_KEY "$FERNET_KEY"

# API key de Anthropic: usa la del entorno si está; si no, deja hueco.
if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
  set_env_if_empty ANTHROPIC_API_KEY "$ANTHROPIC_API_KEY"
fi

# ── 4. Toolkit OSINT/recon del agente (opcional) ─────────────────────────
# Solo importan las herramientas que el agente sabe invocar (ver
# proxy/tools_external.py): subfinder, amass, assetfinder, whois, dig, dnsrecon,
# theHarvester (pasivas) y nmap, whatweb, wafw00f, nuclei (activas, tras --allow-active).
if [ "$WITH_TOOLS" -eq 1 ]; then
  info "Instalando toolkit OSINT/recon del agente…"
  # Vía apt (Kali trae casi todo): DNS, WHOIS, escaneo, fingerprint, WAF.
  install_apt whois dnsutils nmap dnsrecon theharvester whatweb wafw00f
  install_apt amass || warn "amass no disponible vía apt; instálalo manualmente si lo necesitas."

  # Vía Go (projectdiscovery / tomnomnom): subfinder, assetfinder, nuclei.
  if command -v go >/dev/null 2>&1; then
    mkdir -p "$HOME/.local/bin"
    go_install() {  # go_install <import_path> <bin>
      command -v "$2" >/dev/null 2>&1 && { ok "$2 ya instalado."; return 0; }
      info "Instalando $2 vía Go…"
      GOBIN="$HOME/.local/bin" go install "$1" || warn "No se pudo instalar $2 vía Go."
    }
    go_install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest subfinder
    go_install github.com/tomnomnom/assetfinder@latest assetfinder
    go_install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest nuclei
    command -v nuclei >/dev/null 2>&1 && { info "Actualizando plantillas de nuclei…"; nuclei -update-templates -silent || true; }
    case ":$PATH:" in
      *":$HOME/.local/bin:"*) ;;
      *) warn "Añade \$HOME/.local/bin al PATH (export PATH=\$HOME/.local/bin:\$PATH) para los binarios de Go.";;
    esac
  else
    warn "Go no instalado: subfinder/assetfinder/nuclei omitidos. Instala 'golang-go' y reejecuta --tools."
  fi
  info "Herramientas del agente detectadas:"
  "$PY" -c "import proxy.tools_external as te; print('  pasivas:', ', '.join(te.available()) or '(ninguna)'); print('  activas:', ', '.join(te.available(allow_active=True)))" || true
fi

# ── 5. Ollama opcional (summarizer local) ────────────────────────────────
if [ "$WITH_OLLAMA" -eq 1 ]; then
  if command -v ollama >/dev/null 2>&1; then
    ok "Ollama ya instalado."
  else
    info "Instalando Ollama (script oficial)…"
    curl -fsSL https://ollama.com/install.sh | sh || warn "Instalación de Ollama falló."
  fi
  if command -v ollama >/dev/null 2>&1; then
    info "Descargando modelo llama3.2…"
    ollama pull llama3.2 || warn "No se pudo descargar el modelo (hazlo luego: ollama pull llama3.2)."
    set_env_if_empty PROXY_SUMMARIZER "ollama"  # solo si seguía en 'off'/placeholder
    warn "Summarizer: revisa PROXY_SUMMARIZER=ollama en .env si lo quieres activo."
  fi
fi

# ── 5b. OpenOSINT (opcional) cableado contra el proxy ────────────────────
# OpenOSINT es el agente OSINT (18 herramientas). Se instala AISLADO con pipx
# para no chocar con las dependencias del proxy. Se configura como cliente
# OpenAI-compatible apuntando a osint-veil: así TODO lo que mande a la IA pasa
# por el sanitizador. NUNCA se le da una ANTHROPIC_API_KEY directa (saltaría el
# proxy y filtraría datos reales).
if [ "$WITH_OPENOSINT" -eq 1 ]; then
  info "Instalando OpenOSINT (aislado con pipx)…"
  if ! command -v pipx >/dev/null 2>&1; then
    install_apt pipx || "$PY" -m pip install --user pipx || warn "No pude instalar pipx."
    command -v pipx >/dev/null 2>&1 && pipx ensurepath >/dev/null 2>&1 || true
  fi
  if command -v pipx >/dev/null 2>&1; then
    pipx install openosint || pipx upgrade openosint || warn "No pude instalar OpenOSINT con pipx."
  else
    warn "Sin pipx: instala OpenOSINT a mano con 'pipx install openosint' o 'pip install openosint'."
  fi

  # Genera openosint.env: apunta OpenOSINT al proxy (OpenAI-compatible).
  PROXY_KEY="$(grep -E '^PROXY_LOCAL_API_KEY=' .env | cut -d= -f2- || true)"
  PROXY_MODEL="$(grep -E '^ANTHROPIC_MODEL=' .env | cut -d= -f2- || true)"; PROXY_MODEL="${PROXY_MODEL:-claude-sonnet-4-6}"
  if [ ! -f openosint.env ]; then
    {
      echo "# Carga esto antes de lanzar OpenOSINT:  set -a; . ./openosint.env; set +a"
      echo "# Enruta OpenOSINT por osint-veil (OpenAI-compatible). NO pongas aquí una"
      echo "# ANTHROPIC_API_KEY: saltaría el proxy y filtraría datos reales a la IA."
      echo "OPENAI_BASE_URL=http://127.0.0.1:8000/v1"
      echo "OPENAI_API_KEY=${PROXY_KEY}"
      echo "OPENAI_MODEL=${PROXY_MODEL}"
    } > openosint.env
    chmod 600 openosint.env
    ok "Generado openosint.env (apunta OpenOSINT al proxy)."
  else
    ok "openosint.env ya existe (no lo sobrescribo)."
  fi
  warn "Privacidad: con el proxy arrancado, lanza OpenOSINT con OPENAI_BASE_URL al proxy."
  warn "Bajo lockdown, ejecuta OpenOSINT como un usuario SIN salida directa a api.anthropic.com."
fi

# ── 6. Egress lockdown opcional (requiere privilegios) ───────────────────
if [ "$WITH_LOCKDOWN" -eq 1 ]; then
  if [ -z "$SUDO" ] && [ "$(id -u)" -ne 0 ]; then
    warn "Lockdown omitido: requiere root/sudo. Ejecuta luego: make secure-up"
  else
    info "Creando usuario '$TOOLS_USER' (sin salida a la IA) y sudoers…"
    id "$TOOLS_USER" >/dev/null 2>&1 || $SUDO useradd -r -s /usr/sbin/nologin "$TOOLS_USER"
    if ! $SUDO grep -q "ALL=($TOOLS_USER)" /etc/sudoers.d/osint-veil 2>/dev/null; then
      echo "$(id -un) ALL=($TOOLS_USER) NOPASSWD: ALL" | $SUDO tee /etc/sudoers.d/osint-veil >/dev/null
      $SUDO chmod 0440 /etc/sudoers.d/osint-veil
    fi
    info "Aplicando egress lockdown (iptables)…"
    $SUDO PROXY_USER="$(id -un)" TOOLS_USER="$TOOLS_USER" deploy/egress_lockdown.sh \
      && set_env_if_empty PROXY_TOOLS_USER "$TOOLS_USER" \
      || warn "Lockdown no aplicado del todo; revisa iptables."
    warn "Para arrancar en modo enforce: PROXY_EGRESS=enforce PROXY_EGRESS_LOCKED=1 en .env"
  fi
fi

# ── 7. Verificación ──────────────────────────────────────────────────────
if [ "$RUN_TESTS" -eq 1 ]; then
  info "Ejecutando tests de verificación…"
  "$PY" -m pytest -q || { err "Tests fallaron. Revisa el output."; exit 1; }
  ok "Tests OK."
fi

# ── Resumen final ────────────────────────────────────────────────────────
echo
ok "osint-veil instalado."
echo
HAS_KEY=0
grep -Eq '^ANTHROPIC_API_KEY=.+' .env && HAS_KEY=1
if [ "$HAS_KEY" -eq 0 ]; then
  warn "FALTA tu API key de Anthropic. Edita .env y pon ANTHROPIC_API_KEY=..."
  warn "(Para no-retención real, pide el acuerdo ZDR a Anthropic en tu cuenta.)"
fi
echo "Siguiente:"
[ "$USE_VENV" -eq 1 ] && echo "  source .venv/bin/activate"
echo "  # arrancar API:        make up           (Docker, lockdown auto)"
echo "  # o bare-metal seguro: make secure-up"
echo "  # OSINT por CLI:       make audit CASE=prueba_2026 TARGET=ejemplo.com"
echo "  # health:              curl -s 127.0.0.1:8000/health"
if [ "$WITH_OPENOSINT" -eq 1 ]; then
  echo "  # OpenOSINT vía proxy: set -a; . ./openosint.env; set +a; openosint"
fi
