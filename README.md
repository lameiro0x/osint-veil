# osint-veil

> Un **velo de privacidad** entre tus herramientas OSINT y la IA: deja que Claude
> haga OSINT y auditorías casi solas **sin que los datos reales salgan de tu máquina**.

Privacy gateway local que se interpone entre tus herramientas OSINT/CTI y la API
de Claude. Recibe prompts o resultados de herramientas, **detecta información
sensible, anonimiza/tokeniza los identificadores, elimina los secretos**, guarda
las equivalencias en local (cifradas) y envía a Claude **solo una versión segura**.

<p align="left">
  <img alt="Python" src="https://img.shields.io/badge/python-3.10%2B-blue">
  <img alt="Tests" src="https://img.shields.io/badge/tests-97%20passing-brightgreen">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-lightgrey">
  <img alt="Status" src="https://img.shields.io/badge/status-MVP-orange">
</p>

> **Regla de oro:** nada llega a Claude si antes no pasa por el velo.

**Empieza por aquí:** [`docs/VISION.md`](docs/VISION.md) (qué es y por qué aporta,
con ejemplos) · [`docs/DESIGN.md`](docs/DESIGN.md) (arquitectura e invariantes).

> **Evolución (gateway autónomo).** Además del proxy manual, ahora incluye un
> **orquestador OSINT client-side** que ejecuta herramientas en local, mete los
> hallazgos reales en un **vault cifrado**, elimina secretos, **tokeniza con
> pistas de relevancia** (tokens anotados) y solo envía a Claude la versión
> segura. Lee la visión y el diseño en [`docs/VISION.md`](docs/VISION.md) y
> [`docs/DESIGN.md`](docs/DESIGN.md). Las **3 invariantes innegociables** (loop
> client-side, egress bloqueado a nivel red, tool output tratado como hostil)
> están en `docs/DESIGN.md`.

## 1. Qué es

Pensado para pentesting / OSINT con Claude (p. ej. usándolo desde OpenOSINT u
otra herramienta que soporte un endpoint compatible con OpenAI). El objetivo es
la **máxima privacidad**: que no se filtre nada del cliente, del host ni del
pentester — ni a la API ni a ningún otro sitio.

Sobre el entrenamiento del modelo: **la API de Anthropic no entrena con los datos
enviados por API** (retención estándar; existe retención cero bajo petición a
Anthropic). Aun así, este proxy va un paso más allá y solo envía texto ya
anonimizado, sin metadatos del usuario.

## 2. Arquitectura

```
  herramienta OSINT / script
            │  (formato OpenAI chat completions)
            ▼
  ┌───────────────────────────────────────────┐
  │  Privacy Proxy  (FastAPI, 127.0.0.1:8000)  │
  │                                            │
  │  1. auth local (Bearer)                    │
  │  2. sanitizer:                             │
  │       - elimina secretos  → SECRET_REMOVED │
  │       - tokeniza ids      → EMAIL_001 ...  │
  │  3. storage cifrado por case_id (Fernet)   │
  │  4. convierte OpenAI → Anthropic Messages  │
  └───────────────┬────────────────────────────┘
                  │  solo texto anonimizado
                  ▼
            api.anthropic.com  (Claude)
```

Módulos (`proxy/`):

| Archivo            | Responsabilidad                                        |
| ------------------ | ------------------------------------------------------ |
| `config.py`        | Settings de `.env` y config por caso (YAML/JSON).      |
| `sanitizer.py`     | Eliminación de secretos + tokenización determinista.   |
| `storage.py`       | Mappings y audit log por `case_id`, cifrado opcional.  |
| `claude_client.py` | OpenAI → Anthropic Messages API, sin metadatos.        |
| `app.py`           | Endpoints FastAPI.                                     |
| `keygen.py`        | `python -m proxy.keygen` genera la clave de cifrado.   |

## 3. Instalación

### Un tirón (Kali / Debian / Ubuntu) — recomendado

```bash
git clone https://github.com/lameiro0x/osint-veil && cd osint-veil
./setup.sh --all        # deps + venv + paquete + .env con claves + toolkit + Ollama + lockdown
```

`setup.sh` es idempotente y NO pisa claves ya puestas en `.env`. Flags:
`--tools` (toolkit OSINT del agente; instala Go automáticamente si falta),
`--ner` (NER de personas), `--ollama` (summarizer local),
`--openosint` (OpenOSINT vía pipx, enrutado al proxy), `--lockdown`
(usuario sin-salida-IA + iptables, requiere root), `--all`, `--no-venv`, `--no-test`.
También `make bootstrap ARGS="--all"`. Al final avisa de qué **API keys OSINT**
(Shodan, VirusTotal, Censys, HIBP, AbuseIPDB, SecurityTrails, GitHub) faltan —
opcionales pero mejoran mucho el escaneo. Solo falta poner tu `ANTHROPIC_API_KEY` en `.env`.

### Manual

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## 4. Configuración `.env`

```bash
cp .env.example .env
# genera una clave de cifrado y pégala en PROXY_ENCRYPTION_KEY
python -m proxy.keygen
```

> **Modo ahorro (por defecto).** `.env.example` viene con `ANTHROPIC_MODEL=claude-haiku-4-5-20251001`
> (≈5× más barato) y `PROXY_SUMMARIZER=ollama` (resume las salidas de tools en local
> antes de enviarlas a Claude → menos tokens). Con esto, ~5 USD de créditos API dan
> para decenas de escaneos de prueba. Sube a `claude-sonnet-4-6`/`claude-opus-4-8`
> cuando quieras máxima calidad. Pon un **spend limit** en la consola de Anthropic para
> no pasarte, y usa `"dry_run": true` para validar la privacidad **sin gastar API**.

| Variable               | Para qué                                                       |
| ---------------------- | -------------------------------------------------------------- |
| `ANTHROPIC_API_KEY`    | Tu clave de Anthropic (solo se usa al llamar a Claude).        |
| `ANTHROPIC_BASE_URL`   | `https://api.anthropic.com`.                                   |
| `ANTHROPIC_MODEL`      | Modelo por defecto. Ahorro: Haiku; calidad: sonnet/opus.       |
| `PROXY_LOCAL_API_KEY`  | Clave que exige el proxy en `Authorization: Bearer ...`.       |
| `PROXY_CASE_ID`        | Caso por defecto si la petición no envía `case_id`.            |
| `PROXY_STORAGE_PATH`   | Carpeta de mappings/logs (gitignored).                         |
| `PROXY_ENCRYPTION_KEY` | Clave Fernet para cifrar el almacenamiento local.             |
| `PROXY_MODE`           | `strict` (por defecto), `balanced` o `reporting`.             |
| `PROXY_CASES_PATH`     | Carpeta con los YAML/JSON de cada caso.                        |

### Configuración por caso

Crea `cases/<case_id>.yaml` (ver `cases/cliente_a_2026.yaml`):

```yaml
case_id: cliente_a_2026
provider: claude
model: claude-sonnet-4-6
mode: strict
rehydrate_output: false
sensitive_domains:
  - cliente.com
  - cliente.local
sensitive_keywords:
  - vpn
  - intranet
  - payroll
```

## 5. Cómo arrancarlo

```bash
make run          # sin Docker, sin root (modo warn) — lo más rápido para probar
# o con Docker (lockdown automático):
make up
# o bare-metal con lockdown de red (enforce, requiere root):
make secure-up
```

Docker es opcional: `make run` no lo necesita. `setup.sh` pregunta si quieres
instalar Docker (o fuérzalo con `./setup.sh --docker`).

## 6. Probar `/health`

```bash
curl http://127.0.0.1:8000/health
# {"status":"ok"}
```

## 7. Probar `/privacy/sanitize`

```bash
curl -X POST http://127.0.0.1:8000/privacy/sanitize \
  -H "Authorization: Bearer change-me" \
  -H "Content-Type: application/json" \
  -d '{
    "case_id": "cliente_a_2026",
    "text": "El email juan.perez@cliente.com aparece en vpn.cliente.com con token ghp_xxxxxxxxx"
  }'
```

Respuesta:

```json
{
  "sanitized_text": "El email EMAIL_001 aparece en SUBDOMAIN_001 con token SECRET_REMOVED",
  "findings": [
    {"type": "GITHUB_TOKEN", "replacement": "SECRET_REMOVED"},
    {"type": "EMAIL", "token": "EMAIL_001"},
    {"type": "SUBDOMAIN", "token": "SUBDOMAIN_001"}
  ]
}
```

## 8. Usarlo como endpoint compatible con OpenAI

Apunta tu herramienta a `http://127.0.0.1:8000/v1` y usa `PROXY_LOCAL_API_KEY`
como API key.

```bash
export OPENAI_BASE_URL=http://127.0.0.1:8000/v1
export OPENAI_API_KEY=change-me
```

Llamada directa:

```bash
curl -X POST http://127.0.0.1:8000/v1/chat/completions \
  -H "Authorization: Bearer change-me" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-sonnet-4-6",
    "case_id": "cliente_a_2026",
    "messages": [
      {"role": "system", "content": "Eres un analista de seguridad"},
      {"role": "user", "content": "Analiza estos hallazgos: admin@cliente.com en 10.0.0.5"}
    ],
    "max_tokens": 2000
  }'
```

El proxy sanitiza los mensajes, llama a Claude solo con tokens, y devuelve una
respuesta en formato OpenAI (`choices[].message.content`).

### Con OpenOSINT (recomendado)

[OpenOSINT](https://github.com/OpenOSINT/OpenOSINT) es un agente OSINT con 18
herramientas que habla OpenAI-compatible. Ponlo **detrás de osint-veil** para que
todo lo que envíe a la IA pase por el sanitizador (cada mensaje, incluida la salida
de sus herramientas, se tokeniza y se le quitan los secretos antes de llegar a Claude).

```bash
./setup.sh --openosint          # instala OpenOSINT (pipx) y genera openosint.env
make up                         # arranca el proxy (lockdown auto)
make openosint                  # carga openosint.env y abre la REPL enrutada
```

El proxy implementa un **puente de function calling OpenAI↔Anthropic**: traduce las
`tools`/`tool_calls` de OpenOSINT a la API de Anthropic, **sanitiza cada resultado de
herramienta** (ahí están los hallazgos sensibles) antes de mandarlo a Claude, y
**rehidrata los argumentos** de los `tool_calls` de vuelta para que OpenOSINT ejecute
contra los objetivos reales (un token no sirve para ejecutar).

`openosint.env` apunta `OPENAI_BASE_URL` al proxy y `OPENAI_API_KEY` a tu
`PROXY_LOCAL_API_KEY`. Notas:

- **Streaming: nada que configurar.** OpenOSINT, en modo OpenAI-compatible, llama sin
  `stream=True` (respuesta completa), justo lo que el proxy espera. (El proxy rechaza
  `stream=true` como salvaguarda, pero OpenOSINT no lo usa por esa vía.)
- **No** des a OpenOSINT una `ANTHROPIC_API_KEY` directa: saltaría el proxy y filtraría
  datos reales (usa solo `OPENAI_BASE_URL`/`OPENAI_API_KEY` hacia el proxy).
- Bajo lockdown, ejecútalo como un usuario sin salida directa a `api.anthropic.com`
  (solo el proxy debe alcanzar la IA).

### Modo `dry-run` (no llama a Claude)

Añade `"dry_run": true` para ver qué se censuraría sin gastar la API:

```bash
curl -X POST http://127.0.0.1:8000/v1/chat/completions \
  -H "Authorization: Bearer change-me" -H "Content-Type: application/json" \
  -d '{"case_id":"cliente_a_2026","dry_run":true,
       "messages":[{"role":"user","content":"admin@cliente.com en 10.0.0.5"}]}'
```

### Otros endpoints

| Endpoint                              | Uso                                                  |
| ------------------------------------- | ---------------------------------------------------- |
| `POST /privacy/sanitize`              | Anonimiza un texto y devuelve findings + anotaciones.|
| `POST /privacy/rehydrate`             | Revierte tokens → valores (solo si está permitido).  |
| `GET /privacy/mappings/{case_id}`     | Mappings del caso (solo en local).                   |
| `GET /privacy/audit-log/{case_id}`    | Qué tipos se censuraron y cuántas veces.             |
| `GET /privacy/review-queue/{case_id}` | Hallazgos de alta relevancia (revisión no bloqueante).|
| `GET /privacy/secrets/{case_id}`      | Secretos hallados — **solo vista previa** (valores completos solo en local). |
| `POST /osint/run`                     | OSINT autónomo y seguro, **síncrono** (loop client-side). |
| `POST /osint/jobs`                    | OSINT en **background**; devuelve `job_id` (no bloquea). |
| `GET /osint/jobs/{job_id}`            | Estado + eventos + resultado del job.                |
| `GET /osint/jobs/{job_id}/events`     | **Progreso en vivo** vía SSE.                        |
| `GET /osint/report/{case_id}`         | Informe en Markdown (`?rehydrate=true` solo local).  |

## CLI (uso recomendado para auditorías)

```bash
# OSINT autónomo y seguro de un objetivo; escribe informe rehidratado en LOCAL
python -m proxy.cli audit --case cliente_a_2026 --target cliente.com

# Regenerar el informe de un caso (--anon para mantener tokens)
python -m proxy.cli report --case cliente_a_2026

# Ver la cola de revisión (hallazgos de alta relevancia)
python -m proxy.cli review --case cliente_a_2026

# Listar herramientas OSINT disponibles
python -m proxy.cli tools [--allow-active]

# Ver secretos hallados (guardados en local, opt-in). --reveal = valores completos
python -m proxy.cli secrets --case cliente_a_2026 [--reveal]
```

La CLI usa [rich](https://github.com/Textualize/rich): paneles, progreso del loop
en vivo, tablas de hallazgos/cola de revisión/censura y el análisis renderizado en
Markdown. Tras `pip install -e .` el comando es `osint-veil`.

Herramientas integradas sin dependencias (`dns_resolve`, `http_headers`). Además,
**wrappers opcionales de binarios** se activan solos si están instalados:

- **Pasivas** (siempre disponibles si el binario está): `subfinder`, `amass -passive`,
  `assetfinder`, `whois`, `dig` (registros DNS), `dnsrecon`, `theHarvester` (crt.sh).
- **Activas / intrusivas** (solo con `--allow-active` y autorización del objetivo):
  `nmap`, `amass -active`, `whatweb`, `wafw00f`, `nuclei`.

Instálalas de golpe con `./setup.sh --tools` (apt + Go). El agente solo puede
invocar las que estén cableadas aquí; añadir más implica registrar su wrapper en
`proxy/tools_external.py` (sin shell, target validado).

```bash
osint-veil audit --case c --target cliente.com --allow-active   # incluye nmap si está
```

**Summarizer local (opcional):** si activas `PROXY_SUMMARIZER=ollama` (requiere
[Ollama](https://ollama.com) + un modelo), las salidas grandes de herramientas se
**condensan en local** antes de ir a Claude (menos tokens, mejor señal). Opera solo
sobre texto ya anonimizado y es **opt-in** — sin él no necesitas instalar nada y el
proxy funciona igual.

**Despliegue (Docker, egress real, ZDR):** ver [`docs/DEPLOY.md`](docs/DEPLOY.md).

```bash
make up                     # Docker, de un tirón (lockdown de red automático)
# o bare-metal:  make install && make secure-up
# o desarrollo:  pip install -e . && osint-veil ...
```

`make help` lista todos los atajos (install, test, lint, up/down, secure-up, audit).

## Egress control (obligatorio en producción)

La capa de software (`proxy/egress.py`) impide que las herramientas alcancen a
Anthropic, pero la **garantía real es a nivel de red**: ejecuta
`deploy/egress_lockdown.sh` para que solo el proceso del proxy pueda hablar con
la API. Sin esto, un binario externo podría abrir su propio socket.

Modos (`PROXY_EGRESS`):

| Modo      | Comportamiento del OSINT autónomo                                        |
| --------- | ------------------------------------------------------------------------ |
| `off`     | No comprueba nada.                                                       |
| `warn`    | Avisa en el log de que el egress no está forzado (por defecto).          |
| `enforce` | **Se niega a arrancar** salvo que el lockdown de red esté confirmado (`PROXY_EGRESS_LOCKED=1`, lo pone el script de despliegue / Docker). |

En producción: `PROXY_EGRESS=enforce` + `deploy/egress_lockdown.sh`.

## 9. Modos

| Modo        | Comportamiento                                                         |
| ----------- | ---------------------------------------------------------------------- |
| `strict`    | Tokeniza **todo** lo identificativo (dominios e IPs públicas incluidos). Por defecto. Ideal para auditoría real. |
| `balanced`  | Elimina secretos y tokeniza emails/IPs internas, pero deja pasar dominios e IPs públicas **no** marcados como sensibles. |
| `reporting` | Como `balanced`, y permite rehidratar la salida si `rehydrate_output: true`. |

## 10. Qué se detecta

**Secretos (se eliminan, nunca se almacenan):** GitHub (`ghp_`, `github_pat_`,
`gho_/ghs_/ghu_`), OpenAI (`sk-`), AWS (`AKIA…`), Slack (`xoxb-…`), Google
(`AIza…`), Stripe (`sk_live_…`), SendGrid (`SG.…`), GitLab (`glpat-…`), npm
(`npm_…`), Twilio (`SK…`), Azure (`AccountKey=…`), JWT (`eyJ…`),
`Authorization: Bearer …`, `Cookie:` / `Set-Cookie:`, asignaciones
`client_secret=` / `password=` / `api_key=` / `secret_key=` / `access_token=` /
`refresh_token=`, y claves privadas PEM/PGP (`BEGIN … PRIVATE KEY`).

Por defecto los secretos **se destruyen** (nunca se guardan ni se envían). Para
auditorías, un caso puede activar `store_secrets: true`: los secretos hallados se
guardan **en local, cifrados** (requiere `PROXY_ENCRYPTION_KEY`) para poder
reportarlos — **siguen sin enviarse jamás a Claude**, y su valor completo solo se
ve en local (`osint-veil secrets --reveal` / informe en archivo), nunca por la API.

**Identificadores (se tokenizan, con pista de relevancia):** email → `EMAIL_001`,
dominio → `DOMAIN_001`, subdominio → `SUBDOMAIN_001`, IP interna →
`INTERNAL_IP_001`, IP pública → `PUBLIC_IP_001`, repositorio → `REPO_001`, URL
privada → `URL_001`, GUID → `APP_ID_001`/`TENANT_ID_001` (según contexto), cuenta
de servicio → `SERVICE_ACCOUNT_001`, persona → `PERSON_001`, ruta interna →
`PATH_001`, tarjeta de crédito (validada Luhn) → `CREDIT_CARD_001`, dirección MAC
→ `MAC_001`, dirección cripto (ETH/BTC) → `CRYPTO_ADDR_001`, palabra clave del
caso → `KEYWORD_001`.

## 11. Tests

```bash
pytest -q
```

Cubre: tokenización de emails, dominios sensibles e IPs internas; eliminación de
GitHub tokens, JWTs y Bearer; que **no** se guardan secretos en los mappings; que
el mismo email mantiene el mismo token dentro de un caso; que casos distintos
tienen mappings separados; que `/privacy/sanitize` funciona; cifrado en reposo.

## 12. Limitaciones

- **Nombres de persona**: detección parcial. Se tokenizan los nombres listados en
  `sensitive_names` (config del caso) y, si instalas spaCy + un modelo
  (`pip install spacy && python -m spacy download es_core_news_sm`), también vía
  NER automático (dependencia **opcional**, se activa sola si está). Sin spaCy,
  solo los nombres conocidos. **Cuentas de servicio** sí se detectan
  (`svc_*`, `DOMINIO\\usuario`, `*$`, etc.) → `SERVICE_ACCOUNT_001`.
- **Tenant ID vs App ID**: ambos son GUIDs. Se distinguen por **contexto**
  (palabras como `app`/`client_id` cerca → `APP_ID`, si no `TENANT_ID`). Heurística,
  no infalible.
- **`DOMAIN` vs `SUBDOMAIN`** se decide por número de etiquetas (≥3 = subdominio),
  no por TLDs compuestos (`co.uk`), así que algún `ejemplo.co.uk` se marcará como
  subdominio.
- La sanitización es por **regex**, no semántica: datos sensibles en formatos no
  contemplados pueden escapar. Revisa siempre en modo `dry-run` antes de auditar.
- La conversión OpenAI→Anthropic cubre `system`/`user`/`assistant` con contenido
  de texto. No soporta tool-calls ni imágenes (**TODO**).

## 13. Riesgos residuales

- **Falsos negativos del regex**: un identificador con formato inusual puede
  llegar a Claude. Usa `dry-run` y amplía `sensitive_keywords`/`sensitive_domains`.
- **Mappings = datos sensibles**: `proxy_data/` contiene los valores reales
  (cifrados si configuras `PROXY_ENCRYPTION_KEY`). Protégelo y no lo subas a git
  (ya está en `.gitignore`). Sin clave de cifrado, se guarda en claro.
- **Rehidratación**: revierte tokens a valores reales. Solo se permite con
  `rehydrate_output: true` o `force=true`, y nunca se aplica a lo que sale hacia
  Claude — solo a respuestas en local para el informe final.
- **Clave local del proxy**: cualquiera con `PROXY_LOCAL_API_KEY` puede usar el
  proxy y leer mappings. Cámbiala del valor por defecto y no la compartas.
- **Confía pero verifica**: este proxy reduce muchísimo la superficie de fuga,
  pero la responsabilidad final de revisar qué sale sigue siendo del pentester.
```
