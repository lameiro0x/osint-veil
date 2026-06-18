# Despliegue

Guía para poner `osint-veil` en producción **sin fugas** y de forma fluida.

## 1. Requisitos previos

- Python 3.10+ (o Docker).
- `ANTHROPIC_API_KEY` con acceso a la API.
- **Recomendado: acuerdo ZDR (Zero Data Retention) con Anthropic** para que no se
  retenga nada de lo poco que sale anonimizado. ZDR es un acuerdo comercial, no un
  flag. Usa un modelo compatible (Sonnet/Opus; Fable 5 **no** admite ZDR).

## 2. Configuración mínima segura (`.env`)

```env
ANTHROPIC_API_KEY=sk-ant-...
PROXY_LOCAL_API_KEY=<clave larga y aleatoria>     # NO dejar 'change-me'
PROXY_ENCRYPTION_KEY=<python -m proxy.keygen>     # cifra el vault en reposo
PROXY_MODE=strict
PROXY_EGRESS=enforce                              # exige lockdown de red
```

Con `PROXY_LOCAL_API_KEY=change-me` el proxy **rechaza** toda petición (503).
Con `PROXY_EGRESS=enforce` el OSINT autónomo **no arranca** sin lockdown de red.

## 3. Docker (recomendado)

El `Dockerfile` + `docker-compose.yml` montan el modelo de dos usuarios y aplican
el lockdown de egress en el arranque (requiere `CAP_NET_ADMIN`):

```bash
cp .env.example .env      # rellena las claves
make up                   # = docker compose up --build -d (lockdown automático)
# proxy en http://127.0.0.1:8000  (solo localhost)
```

Qué hace el contenedor:
- Corre el proxy como `proxyuser` (puede hablar con Anthropic).
- `PROXY_APPLY_LOCKDOWN=1` ejecuta `deploy/egress_lockdown.sh` sobre `osinttools`
  y marca `PROXY_EGRESS_LOCKED=1`.
- Las herramientas **externas** (binarios) se ejecutan como `osinttools`
  (`PROXY_TOOLS_USER`, vía sudo) → el lockdown de red las corta de verdad.
- El puerto se publica **solo en localhost**.

> Sin `CAP_NET_ADMIN` el lockdown no se puede aplicar y, en modo `enforce`, el
> OSINT autónomo se niega a arrancar (comportamiento correcto y seguro).

## 4. Bare-metal / systemd

De un tirón (crea el usuario, aplica lockdown y arranca):

```bash
make install
make secure-up        # ensure-tools-user + lockdown + serve (pide sudo)
```

Manual, equivalente:

```bash
pip install -e .                 # instala el CLI 'osint-veil'
sudo useradd -r -s /usr/sbin/nologin osinttools
echo "$(id -un) ALL=(osinttools) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/osint-veil
sudo PROXY_USER=$(id -un) TOOLS_USER=osinttools deploy/egress_lockdown.sh
PROXY_EGRESS=enforce PROXY_EGRESS_LOCKED=1 PROXY_TOOLS_USER=osinttools \
  uvicorn proxy.app:app --host 127.0.0.1 --port 8000
```

Para autónomo por CLI:

```bash
osint-veil audit --case cliente_a_2026 --target cliente.com
```

## 5. Herramientas OSINT externas (opcional)

Las pasivas se activan solas si el binario está instalado: `subfinder`, `amass`,
`whois`. Las **activas/intrusivas** (`nmap`, `amass -active`) solo con
`--allow-active` (CLI) o `allow_active: true` (API) — úsalas solo con
autorización explícita del objetivo.

```bash
osint-veil audit --case c --target cliente.com --allow-active
```

## 6. NER de nombres (opcional)

```bash
pip install ".[ner]"
python -m spacy download es_core_news_sm   # o en_core_web_sm
```

Sin esto, los nombres de persona se tokenizan solo si están en `sensitive_names`.

## 7. Checklist de "sin fugas"

- [ ] `PROXY_LOCAL_API_KEY` cambiada (no `change-me`).
- [ ] `PROXY_ENCRYPTION_KEY` configurada (vault cifrado).
- [ ] `PROXY_EGRESS=enforce` + lockdown de red aplicado (`PROXY_EGRESS_LOCKED=1`).
- [ ] Puerto publicado solo en `127.0.0.1` (o detrás de VPN/mTLS).
- [ ] ZDR acordado con Anthropic + modelo compatible.
- [ ] `proxy_data/` con permisos restringidos y backups cifrados.
- [ ] Revisado el audit log: solo tipos/conteos, cero valores reales.
