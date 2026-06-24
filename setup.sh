#!/usr/bin/env bash
#
# setup.sh — instalador GUIADO de osint-veil (Kali / Debian / Ubuntu).
#
# Uso típico:
#   git clone https://github.com/lameiro0x/osint-veil && cd osint-veil
#   ./setup.sh --all      # instala TODO, preguntando antes de cada pieza pesada (recomendado)
#   ./setup.sh --all -y   # instala TODO sin preguntar (desatendido)
#   ./setup.sh            # solo lo básico (deps + venv + paquete + .env con claves)
#
# Instala: deps + venv + paquete + .env con claves. Extras (preguntados o por
# flag): toolkit OSINT, NER, Ollama+modelo, OpenOSINT, Docker, lockdown de red.
# Es IDEMPOTENTE: re-ejecutable. No pisa claves ya puestas en .env. Solo descarga
# lo que aceptes; nada de tus datos sale a ningún sitio.
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
WITH_TOOLS=0; WITH_NER=0; WITH_OLLAMA=0; WITH_OPENOSINT=0; WITH_LOCKDOWN=0; WITH_DOCKER=0
RUN_TESTS=1; USE_VENV=1; ASSUME_YES=0
SUMM_MODEL="${SUMM_MODEL:-llama3.2}"
TOOLS_USER="${TOOLS_USER:-osinttools}"

usage() {
  cat <<EOF
setup.sh — instalador guiado de osint-veil

Sin flags: instala SOLO lo básico (deps + venv + paquete + .env con claves).
Usa --all para los extras: te pregunta (con alternativas) antes de cada pieza pesada.

Opciones:
  --all         Lo instala TODO, preguntando antes de cada pieza pesada
                (toolkit + NER + Ollama+modelo + OpenOSINT + Docker + lockdown).
  --yes, -y     Responde "sí" a todas las preguntas (desatendido).
  --tools       Toolkit OSINT (whois, dns, nmap, subfinder, nuclei, whatweb…).
  --ner         NER de personas (spaCy + modelo es_core_news_sm).
  --ollama      Summarizer local (Ollama + modelo '$SUMM_MODEL').
  --openosint   OpenOSINT (pipx) + openosint.env apuntando al proxy.
  --docker      Docker + Compose (para 'make up').
  --lockdown    Usuario sin-salida-IA + egress lockdown (iptables, root).
  --no-venv     No crear venv; usa el Python actual.
  --no-test     No ejecutar los tests al final.
  -h, --help    Esta ayuda.
EOF
}

for arg in "$@"; do
  case "$arg" in
    --tools) WITH_TOOLS=1 ;;
    --ner) WITH_NER=1 ;;
    --ollama) WITH_OLLAMA=1 ;;
    --openosint) WITH_OPENOSINT=1 ;;
    --docker) WITH_DOCKER=1 ;;
    --lockdown) WITH_LOCKDOWN=1 ;;
    --all) WITH_TOOLS=1; WITH_NER=1; WITH_OLLAMA=1; WITH_OPENOSINT=1; WITH_DOCKER=1; WITH_LOCKDOWN=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    --no-venv) USE_VENV=0 ;;
    --no-test) RUN_TESTS=0 ;;
    -h|--help) usage; exit 0 ;;
    *) err "Opción desconocida: $arg"; usage; exit 2 ;;
  esac
done

# ── Pregunta sí/no (respeta --yes y entornos sin terminal) ───────────────
# ask "pregunta" [default Y|N]  -> 0 si sí, 1 si no
ask() {
  local q="$1" def="${2:-Y}" ans hint="[Y/n]"
  [ "$def" = "N" ] && hint="[y/N]"
  if [ "$ASSUME_YES" -eq 1 ]; then return 0; fi
  if [ ! -t 0 ]; then [ "$def" = "Y" ] && return 0 || return 1; fi
  printf "%b%s %s%b " "$C_B" "$q" "$hint" "$C_0"
  read -r ans || ans=""
  ans="${ans:-$def}"
  case "$ans" in [yYsS]*) return 0 ;; *) return 1 ;; esac
}

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

# Fija una clave SIEMPRE (crea o sobrescribe). Para banderas que controlamos
# nosotros (p.ej. PROXY_SUMMARIZER on/off según si hay Ollama).
set_env_force() {  # set_env_force KEY VALUE
  KEY="$1" VALUE="$2" "$PY" - <<'PY'
import os, re, pathlib
key, value = os.environ["KEY"], os.environ["VALUE"]
p = pathlib.Path(".env"); txt = p.read_text()
line = f"{key}={value}"
if re.search(rf"^{re.escape(key)}=.*$", txt, re.M):
    txt = re.sub(rf"^{re.escape(key)}=.*$", lambda _m: line, txt, flags=re.M)
else:
    txt = txt + f"\n{line}\n"
p.write_text(txt)
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

# API key de Anthropic: del entorno si está; si no, ofrece pegarla ahora.
if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
  set_env_if_empty ANTHROPIC_API_KEY "$ANTHROPIC_API_KEY"
elif ! grep -Eq '^ANTHROPIC_API_KEY=.+' .env && [ -t 0 ] && [ "$ASSUME_YES" -eq 0 ]; then
  echo
  info "API key de Anthropic (de console.anthropic.com → API keys, empieza por sk-ant-)."
  info "El cerebro Claude la necesita. Pulsa Enter para saltar y ponerla luego en .env."
  printf "%bPega tu ANTHROPIC_API_KEY (no se mostrará):%b " "$C_B" "$C_0"
  read -rs _apikey || _apikey=""; echo
  if [ -n "$_apikey" ]; then
    set_env_force ANTHROPIC_API_KEY "$_apikey"
    ok "API key guardada en .env."
  else
    info "Sin API key por ahora (la pones luego en .env)."
  fi
  unset _apikey
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

  # Go es necesario para subfinder/assetfinder/nuclei: lo instalamos si falta.
  if ! command -v go >/dev/null 2>&1; then
    info "Go no encontrado: instalando golang…"
    install_apt golang-go || install_apt golang
    # apt deja el binario en /usr/lib/go-*/bin o /usr/bin; refresca PATH por si acaso.
    command -v go >/dev/null 2>&1 || export PATH="/usr/lib/go/bin:/usr/local/go/bin:$PATH"
  fi

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
    warn "No pude instalar Go: subfinder/assetfinder/nuclei omitidos. Instala 'golang-go' y reejecuta --tools."
  fi
  info "Herramientas del agente detectadas:"
  "$PY" -c "import proxy.tools_external as te; print('  pasivas:', ', '.join(te.available()) or '(ninguna)'); print('  activas:', ', '.join(te.available(allow_active=True)))" || true
fi

# ── 5. Ollama (OPCIONAL) — summarizer local ──────────────────────────────
ollama_ready() { curl -fsS 127.0.0.1:11434/api/tags >/dev/null 2>&1; }

install_ollama_stack() {
    # 1) binario
    if ! command -v ollama >/dev/null 2>&1; then
        info "Instalando Ollama (script oficial)…"
        curl -fsSL https://ollama.com/install.sh | sh || warn "Instalación de Ollama falló."
    fi
    if ! command -v ollama >/dev/null 2>&1; then
        warn "Ollama no disponible → summarizer OFF."
        set_env_force PROXY_SUMMARIZER off
        return 0
    fi
    # 2) daemon arriba (servicio o en segundo plano)
    if ! ollama_ready; then
        info "Arrancando el servicio de Ollama…"
        $SUDO systemctl enable --now ollama 2>/dev/null || (ollama serve >/dev/null 2>&1 &)
        info "Esperando a Ollama…"
        for _ in $(seq 1 30); do ollama_ready && break; sleep 1; done
    fi
    if ! ollama_ready; then
        warn "El servicio de Ollama no respondió → summarizer OFF (arráncalo con 'ollama serve')."
        set_env_force PROXY_SUMMARIZER off
        return 0
    fi
    # 3) modelo (con reintento) + verificación
    if ! ollama list 2>/dev/null | grep -q "$SUMM_MODEL"; then
        info "Descargando modelo '$SUMM_MODEL' (~2 GB)…"
        ollama pull "$SUMM_MODEL" || { warn "Reintento del pull…"; ollama pull "$SUMM_MODEL" || true; }
    fi
    if ollama list 2>/dev/null | grep -q "$SUMM_MODEL"; then
        ok "Ollama + modelo '$SUMM_MODEL' listos."
        set_env_force PROXY_SUMMARIZER ollama
    else
        warn "No se pudo dejar el modelo → summarizer OFF (luego: ollama pull $SUMM_MODEL)."
        set_env_force PROXY_SUMMARIZER off
    fi
}

if [ "$WITH_OLLAMA" -eq 1 ]; then
    echo
    info "Summarizer local con Ollama — OPCIONAL:"
    echo "    · Resume EN LOCAL las salidas de las herramientas antes de mandarlas a Claude."
    echo "    · Ventaja: gastas MENOS tokens (más barato) y refuerzas la privacidad."
    echo "    · Alternativa: sin él, el proxy funciona IGUAL, solo manda más texto a Claude."
    echo "    · Coste: instala Ollama + un modelo (~2 GB de descarga)."
    if ask "¿Instalar Ollama + modelo para el summarizer?" Y; then
        install_ollama_stack
    else
        info "Ok, sin Ollama → summarizer OFF en .env."
        set_env_force PROXY_SUMMARIZER off
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
      echo "# Streaming: nada que configurar — OpenOSINT llama sin stream por esta vía."
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

# ── 5c. Docker (OPCIONAL) para 'make up' ─────────────────────────────────
# Bare-metal ('make run') NO necesita Docker. Solo se instala si lo pides
# (--docker) o si lo confirmas en el prompt. Nunca va dentro de --all.
install_docker() {
    info "Instalando Docker…"
    # En Debian/Kali el plugin Compose v2 es 'docker-compose-v2' (NO el
    # 'docker-compose-plugin' del repo oficial). Fallback al standalone v1.
    install_apt docker.io docker-compose-v2
    if ! docker compose version >/dev/null 2>&1; then
        warn "Compose v2 no disponible; instalo el standalone 'docker-compose' (v1)."
        install_apt docker-compose
    fi
    if command -v systemctl >/dev/null 2>&1; then
        $SUDO systemctl enable --now docker 2>/dev/null \
            || warn "No pude habilitar el servicio docker (arráncalo a mano)."
    fi
    if $SUDO usermod -aG docker "$(id -un)" 2>/dev/null; then
        warn "Te añadí al grupo 'docker': cierra sesión y entra de nuevo (o 'newgrp docker')."
    fi
    command -v docker >/dev/null 2>&1 && ok "Docker instalado ('make up' disponible)." \
        || warn "Docker no quedó disponible."
}

if command -v docker >/dev/null 2>&1; then
    ok "Docker ya instalado ('make up' disponible)."
elif [ "$WITH_DOCKER" -eq 1 ]; then
    echo
    info "Docker — OPCIONAL (forma de arrancar el proxy):"
    echo "    · Con Docker: 'make up' arranca con el egress lockdown automático."
    echo "    · Alternativa: 'make run' arranca SIN Docker ni root (igual de válido para probar)."
    if ask "¿Instalar Docker + Compose?" Y; then
        install_docker
    else
        info "Sin Docker. Arranca con 'make run' (bare-metal, sin root)."
    fi
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

# ── 7b. Aviso de API keys de servicios OSINT que faltan ──────────────────
# Muchas tools (subfinder, nuclei) y OpenOSINT rinden mucho más con keys de
# terceros. No las pedimos ni guardamos: solo avisamos de cuáles no detectamos
# en el entorno / .env / openosint.env, con dónde sacarlas (gratis casi todas).
if [ "$WITH_TOOLS" -eq 1 ] || [ "$WITH_OPENOSINT" -eq 1 ]; then
  info "Revisando API keys de servicios OSINT (opcionales pero recomendadas)…"
  _have_key() {  # _have_key VAR  -> 0 si está en el entorno o en un .env con valor
    local v="$1"
    [ -n "$(printenv "$v" 2>/dev/null)" ] && return 0
    grep -Eqs "^${v}=.+" .env openosint.env 2>/dev/null && return 0
    return 1
  }
  # VAR  servicio (dónde obtenerla)
  _KEYS="SHODAN_API_KEY|Shodan (account.shodan.io)
VIRUSTOTAL_API_KEY|VirusTotal (virustotal.com/gui/my-apikey)
CENSYS_API_ID|Censys (search.censys.io/account/api)
HIBP_API_KEY|HaveIBeenPwned (haveibeenpwned.com/API/Key)
ABUSEIPDB_API_KEY|AbuseIPDB (abuseipdb.com/account/api)
SECURITYTRAILS_API_KEY|SecurityTrails (securitytrails.com — subfinder/amass)
GITHUB_TOKEN|GitHub (github.com/settings/tokens — dorks/code search)"
  MISSING=0
  while IFS='|' read -r var desc; do
    [ -n "$var" ] || continue
    if _have_key "$var"; then ok "  $var detectada."
    else warn "  falta $var → $desc"; MISSING=$((MISSING + 1)); fi
  done <<EOF
$_KEYS
EOF
  if [ "$MISSING" -gt 0 ]; then
    warn "Faltan $MISSING keys OSINT. Sin ellas el escaneo es más pobre (no es bloqueante)."
    warn "Ponlas en tu entorno o en openosint.env. subfinder/amass usan además su"
    warn "propio config (p.ej. ~/.config/subfinder/provider-config.yaml)."
  fi
fi

# ── Guía final: próximos pasos (adaptada a lo instalado) ─────────────────
HAS_KEY=0; grep -Eq '^ANTHROPIC_API_KEY=.+' .env && HAS_KEY=1
HAS_DOCKER=0; command -v docker >/dev/null 2>&1 && HAS_DOCKER=1
LOCAL_KEY_VAL="$(grep -E '^PROXY_LOCAL_API_KEY=' .env | cut -d= -f2- || true)"

echo
ok "osint-veil instalado."
echo
printf "%b═══ PRÓXIMOS PASOS ═══%b\n" "$C_G" "$C_0"

N=1
if [ "$HAS_KEY" -eq 0 ]; then
  echo "  $N) Pon tu API key de Anthropic en .env:  ANTHROPIC_API_KEY=sk-ant-..."
  echo "     (console.anthropic.com → mete 5\$ de saldo + spend limit → API keys)"
  N=$((N + 1))
else
  ok "API key de Anthropic ya configurada."
fi

if [ "$HAS_DOCKER" -eq 1 ]; then
  echo "  $N) Arranca el proxy:   make up        (Docker, lockdown automático)"
else
  echo "  $N) Arranca el proxy:   make run       (sin Docker ni root)"
fi
N=$((N + 1))
echo "  $N) Comprueba salud:    curl -s 127.0.0.1:8000/health"
N=$((N + 1))
echo "  $N) Prueba la privacidad SIN gastar (dry-run, 0\$):"
echo "       curl -s -X POST 127.0.0.1:8000/v1/chat/completions \\"
echo "         -H 'Authorization: Bearer ${LOCAL_KEY_VAL:-<PROXY_LOCAL_API_KEY>}' \\"
echo "         -H 'Content-Type: application/json' \\"
echo "         -d '{\"case_id\":\"prueba\",\"dry_run\":true,\"messages\":[{\"role\":\"user\",\"content\":\"admin@x.com 10.0.0.5\"}]}'"
N=$((N + 1))
echo "  $N) OSINT real (Claude + summarizer):  make audit CASE=prueba1 TARGET=vulnweb.com"
if [ "$WITH_OPENOSINT" -eq 1 ]; then
  N=$((N + 1))
  echo "  $N) O con OpenOSINT:     make openosint"
fi

echo
[ "$HAS_KEY" -eq 0 ] && warn "Recuerda: sin ANTHROPIC_API_KEY el paso real (audit/openosint) no funciona; el dry-run sí."
info "Para no-retención de datos, pide el acuerdo ZDR a Anthropic en tu cuenta."
