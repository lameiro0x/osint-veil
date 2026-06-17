# osint-veil

> Un **velo de privacidad** entre tus herramientas OSINT y la IA: deja que Claude
> haga OSINT y auditorías casi solas **sin que los datos reales salgan de tu máquina**.

Privacy gateway local que se interpone entre tus herramientas OSINT/CTI y la API
de Claude. Recibe prompts o resultados de herramientas, **detecta información
sensible, anonimiza/tokeniza los identificadores, elimina los secretos**, guarda
las equivalencias en local (cifradas) y envía a Claude **solo una versión segura**.

<p align="left">
  <img alt="Python" src="https://img.shields.io/badge/python-3.10%2B-blue">
  <img alt="Tests" src="https://img.shields.io/badge/tests-67%20passing-brightgreen">
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

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 4. Configuración `.env`

```bash
cp .env.example .env
# genera una clave de cifrado y pégala en PROXY_ENCRYPTION_KEY
python -m proxy.keygen
```

| Variable               | Para qué                                                       |
| ---------------------- | -------------------------------------------------------------- |
| `ANTHROPIC_API_KEY`    | Tu clave de Anthropic (solo se usa al llamar a Claude).        |
| `ANTHROPIC_BASE_URL`   | `https://api.anthropic.com`.                                   |
| `ANTHROPIC_MODEL`      | Modelo por defecto (`claude-sonnet-4-6`; puedes usar opus).    |
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
./run.sh
# o:
uvicorn proxy.app:app --host 127.0.0.1 --port 8000
```

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
```

Herramientas integradas sin dependencias (`dns_resolve`, `http_headers`). Además,
**wrappers opcionales de binarios** se activan solos si están instalados:
pasivos (`subfinder`, `amass`, `whois`) y, con `--allow-active`, activos/intrusivos
(`nmap`, `amass -active`). Las activas solo bajo autorización del objetivo.

```bash
osint-veil audit --case c --target cliente.com --allow-active   # incluye nmap si está
```

**Despliegue (Docker, egress real, ZDR):** ver [`docs/DEPLOY.md`](docs/DEPLOY.md).

```bash
pip install -e .            # instala el CLI 'osint-veil'
# o:  docker compose up --build
```

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

**Secretos (se eliminan, nunca se almacenan):** `sk-`, `ghp_`, `github_pat_`,
`gho_/ghs_/ghu_`, `AKIA…`, JWT (`eyJ…`), `Authorization: Bearer …`,
`Cookie:` / `Set-Cookie:`, `client_secret=`, `password=`, `passwd=`,
`access_token=`, `refresh_token=`, claves privadas PEM (`BEGIN … PRIVATE KEY`).

**Identificadores (se tokenizan, con pista de relevancia):** email → `EMAIL_001`,
dominio → `DOMAIN_001`, subdominio → `SUBDOMAIN_001`, IP interna →
`INTERNAL_IP_001`, IP pública → `PUBLIC_IP_001`, repositorio → `REPO_001`, URL
privada → `URL_001`, GUID → `APP_ID_001`/`TENANT_ID_001` (según contexto), cuenta
de servicio → `SERVICE_ACCOUNT_001`, persona → `PERSON_001`, ruta interna →
`PATH_001`, palabra clave del caso → `KEYWORD_001`.

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
