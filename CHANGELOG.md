# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es/1.1.0/).
Versionado [SemVer](https://semver.org/lang/es/).

## [0.1.3] — 2026-06-23

### Cambiado
- **`.env.example` en modo ahorro por defecto**: `ANTHROPIC_MODEL` = Haiku 4.5
  (≈5× más barato) y `PROXY_SUMMARIZER=ollama` (resume en local antes de Claude).
  Documentado spend limit + `dry_run` para validar privacidad sin gastar API.
- **`make openosint`**: carga `openosint.env` y lanza la REPL de OpenOSINT enrutada
  por el proxy.

### Añadido
- **Instalador de un tirón `setup.sh`** (Kali/Debian/Ubuntu): deps de sistema +
  venv + paquete + `.env` con claves autogeneradas (idempotente, no pisa claves
  existentes). Flags `--tools/--ner/--ollama/--lockdown/--all`. Atajo `make bootstrap`.
- **Toolkit OSINT/recon del agente ampliado** en `proxy/tools_external.py`:
  pasivas `assetfinder`, `dig` (registros DNS), `dnsrecon`, `theHarvester` (crt.sh);
  activas (tras `--allow-active`) `whatweb`, `wafw00f`, `nuclei`. Mismo modelo de
  seguridad: sin shell, args como lista, target validado por regex estricto.

- **Go automático** en `setup.sh --tools`: si no está, instala `golang-go` antes de
  compilar subfinder/assetfinder/nuclei (ya no se omiten por falta de Go).
- **Aviso de API keys OSINT**: al instalar `--tools`/`--openosint`, el script revisa
  (sin pedirlas ni guardarlas) qué keys de terceros faltan (Shodan, VirusTotal,
  Censys, HIBP, AbuseIPDB, SecurityTrails, GitHub) y dónde sacarlas. No es bloqueante.
- **Integración con OpenOSINT** (`setup.sh --openosint`): instala OpenOSINT aislado
  con pipx y genera `openosint.env` que lo enruta como cliente OpenAI-compatible a
  través del proxy (`OPENAI_BASE_URL` → osint-veil). Así cada mensaje que OpenOSINT
  manda a la IA se sanitiza (tokeniza + sin secretos) antes de llegar a Claude. El
  `.gitignore` excluye `openosint.env` (contiene la clave local del proxy).

### Corregido
- `setup.sh`: el reemplazo de claves en `.env` usa callback en `re.sub` para que
  backslashes o `\1` dentro del valor no se interpreten como backreferences.
- `tools_external.py`: detección de binario tolerante a alias (p.ej.
  `theHarvester`/`theharvester`); mensajes de error muestran el binario real, no `sudo`.

## [0.1.2] — 2026-06-19

### Añadido
- **Summarizer local opcional** (`PROXY_SUMMARIZER=ollama`): condensa las salidas
  grandes de herramientas ANTES de enviarlas a Claude (menos tokens, mejor señal).
  Opt-in y sin dependencias nuevas (habla con la API HTTP local de Ollama). Opera
  solo sobre texto ya anonimizado (tokenizado, sin secretos), con re-escaneo de
  secretos del resumen y fail-safe: si Ollama no está, el pipeline sigue igual.

## [0.1.1] — 2026-06-19

### Añadido
- **Vault de secretos opt-in** (`store_secrets` por caso): los secretos hallados se
  guardan **en local, cifrados** (requiere `PROXY_ENCRYPTION_KEY`) para poder
  reportarlos en una auditoría. Garantías: nunca se envían a Claude, nunca se
  escriben en claro, nunca se tokenizan, y su valor completo solo se ve en local
  (`osint-veil secrets --reveal` / informe en archivo) — la API solo da vista previa.
- Comando CLI `secrets` y endpoint `GET /privacy/secrets/{case_id}` (redactado).

## [0.1.0] — 2026-06-18

Primera versión. Privacy gateway local para OSINT/auditorías con Claude sin
filtrar datos reales.

### Privacidad (núcleo)
- **Sanitizador**: elimina secretos (GitHub, OpenAI, AWS, Slack, Google, Stripe,
  SendGrid, GitLab, npm, Twilio, Azure, JWT, Bearer/Cookie, claves PEM/PGP,
  asignaciones `api_key=`/`password=`/…) y tokeniza identificadores (email,
  dominio/subdominio, IP interna/pública, repo, URL, GUID App/Tenant, cuenta de
  servicio, persona, ruta, tarjeta de crédito validada por Luhn, MAC, dirección
  cripto) con **pistas de relevancia** seguras (tokens anotados).
- **Vault local cifrado** (Fernet) por `case_id`; los secretos se destruyen, nunca
  se almacenan. Audit log solo con tipos y conteos.
- **Policy Engine** con modos `strict`/`balanced`/`reporting`.

### Orquestación segura
- **Loop OSINT client-side**: Claude decide, las herramientas corren en local; a
  Claude solo va la versión anonimizada. Budget (iteraciones/tokens/tiempo),
  kill-switch, defensa anti prompt-injection y scope guard.
- **Tool Gateway** con allowlist + validación de objetivo. Herramientas integradas
  (`dns_resolve`, `http_headers`) y wrappers externos opcionales (subfinder, amass,
  whois; nmap/amass-active tras `--allow-active`).

### Egress control
- Guard software + lockdown de red por usuario (`deploy/egress_lockdown.sh`): las
  herramientas externas corren como `PROXY_TOOLS_USER` (sin salida a la IA). Modo
  `enforce` que rechaza arrancar sin lockdown confirmado.

### Interfaces
- API FastAPI (compatible OpenAI `/v1/chat/completions`, `/privacy/*`, `/osint/*`
  con jobs en background y progreso SSE, `/health`).
- CLI con `rich` (`audit`, `report`, `review`, `tools`).

### Operación
- Docker + compose con dos usuarios y lockdown automático; `Makefile` (`make up`,
  `make secure-up`); manejo elegante de errores de la API; logging que redacta
  secretos; validación de configuración fail-fast.
- CI (ruff + pytest con cobertura ≥75% + pip-audit). 87 tests.

### Límites conocidos (por diseño)
- El objetivo investigado y las relaciones que se envían a Claude salen en claro.
- La no-retención requiere acuerdo ZDR con Anthropic.
- NER de personas requiere spaCy opcional; sin él, solo nombres de `sensitive_names`.
