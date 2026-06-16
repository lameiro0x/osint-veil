# Prompt para Claude Code: desarrollo de Privacy Proxy local para Claude API

Quiero que desarrolles un MVP funcional de un “Privacy Proxy” local para usar APIs de Claude de forma más segura en investigaciones OSINT/CTI.

## Objetivo del proyecto

Crear un proxy local que actúe como intermediario entre herramientas OSINT/scripts y la API de Claude/Anthropic. El proxy debe recibir prompts o resultados de herramientas, detectar información sensible, anonimizar/tokenizar datos identificativos, eliminar secretos, guardar equivalencias localmente y enviar a Claude solo una versión segura.

La regla principal es:

> Nada debe enviarse a Claude si antes no pasa por el proxy.

Si alguna dependencia complica demasiado el MVP, prioriza una versión simple y funcional.

## Funcionalidad principal del MVP

Crear una API local con endpoint compatible estilo OpenAI:

```text
POST /v1/chat/completions
```

La idea es que herramientas que soporten `OPENAI_BASE_URL` puedan apuntar a:

```text
http://127.0.0.1:8000/v1
```

Y el proxy internamente llame a Claude API.

## Flujo esperado

1. Recibir una petición tipo chat completion.
2. Extraer el contenido de los mensajes.
3. Detectar datos sensibles.
4. Tokenizar identificadores.
5. Eliminar secretos.
6. Guardar mapping local por `case_id`.
7. Enviar a Claude la versión anonimizada.
8. Recibir respuesta de Claude.
9. Devolver respuesta al cliente en formato compatible.
10. Guardar log local de qué se censuró, sin guardar secretos reales.

## Datos a tokenizar

Tokenizar este tipo de información:

```text
Email real        → EMAIL_001
Nombre persona    → PERSON_001
Dominio           → DOMAIN_001
Subdominio        → SUBDOMAIN_001
IP interna        → INTERNAL_IP_001
IP pública        → PUBLIC_IP_001
Cuenta servicio   → SERVICE_ACCOUNT_001
Repositorio       → REPO_001
Tenant ID         → TENANT_ID_001
App ID            → APP_ID_001
Ruta interna      → PATH_001
URL privada       → URL_001
```

## Secretos que deben eliminarse

No tokenices secretos. Elimínalos directamente.

Detectar y reemplazar por `SECRET_REMOVED`, `JWT_REMOVED`, `COOKIE_REMOVED`, etc.

Patrones mínimos:

```text
sk-
ghp_
github_pat_
AKIA
eyJ... JWT
Authorization: Bearer ...
Cookie:
Set-Cookie:
client_secret=
password=
passwd=
access_token=
refresh_token=
BEGIN RSA PRIVATE KEY
BEGIN OPENSSH PRIVATE KEY
BEGIN PRIVATE KEY
```

## Configuración por caso

Implementa soporte para un archivo YAML o JSON de configuración por auditoría, por ejemplo:

```yaml
case_id: cliente_a_2026
provider: claude
model: claude-sonnet-4-6
mode: strict
rehydrate_output: false

sensitive_domains:
  - cliente.com
  - cliente.local
  - corp.cliente.com

sensitive_keywords:
  - vpn
  - intranet
  - scannerprint
  - erpmail
  - payroll
  - admin
  - backup
  - dev
```

Si YAML complica el MVP, usa JSON.

## Modos de funcionamiento

Implementar al menos estos modos como estructura, aunque inicialmente todos puedan comportarse parecido:

```text
strict:
  No deja salir datos sensibles. Ideal para auditoría real.

balanced:
  Tokeniza lo sensible pero permite información pública de bajo riesgo.

reporting:
  Permite rehidratar localmente para generar informe final.
```

Por defecto debe usarse `strict`.

## Persistencia local

Guardar mappings por `case_id`.

Ejemplo:

```json
{
  "case_id": "cliente_a_2026",
  "mappings": {
    "EMAIL_001": "juan.perez@cliente.com",
    "SUBDOMAIN_001": "vpn.cliente.com",
    "REPO_001": "https://github.com/cliente/proyecto"
  }
}
```

Para el MVP puedes usar SQLite o JSON local.

Requisitos:

- No guardar secretos reales.
- Separar mappings por `case_id`.
- Guardar logs de privacidad indicando qué tipos se censuraron.
- Si puedes, cifrar el almacenamiento local con una clave en `.env`.

## Variables de entorno

Usar `.env` con:

```env
ANTHROPIC_API_KEY=
ANTHROPIC_BASE_URL=https://api.anthropic.com
ANTHROPIC_MODEL=claude-sonnet-4-6
PROXY_LOCAL_API_KEY=change-me
PROXY_CASE_ID=default_case
PROXY_STORAGE_PATH=./proxy_data
PROXY_ENCRYPTION_KEY=
PROXY_MODE=strict
```

## Seguridad del proxy

Implementar:

1. API key local para usar el proxy.
2. No permitir llamadas sin `Authorization: Bearer <PROXY_LOCAL_API_KEY>`.
3. No imprimir secretos en consola.
4. No guardar prompts brutos completos por defecto.
5. Guardar solo:
   - timestamp
   - case_id
   - tipos de datos censurados
   - número de ocurrencias
   - proveedor usado
6. Modo `dry-run` opcional para ver qué censuraría sin llamar a Claude.

## Endpoints mínimos

Crear estos endpoints:

```text
GET /health
POST /v1/chat/completions
POST /privacy/sanitize
POST /privacy/rehydrate
GET /privacy/mappings/{case_id}
GET /privacy/audit-log/{case_id}
```

### /privacy/sanitize

Entrada:

```json
{
  "case_id": "cliente_a_2026",
  "text": "texto con datos sensibles"
}
```

Salida:

```json
{
  "sanitized_text": "texto anonimizado",
  "findings": [
    {"type": "EMAIL", "token": "EMAIL_001"},
    {"type": "SECRET", "replacement": "SECRET_REMOVED"}
  ]
}
```

### /privacy/rehydrate

Solo debe rehidratar si `rehydrate_output=true` o si se pasa un flag explícito.

Entrada:

```json
{
  "case_id": "cliente_a_2026",
  "text": "EMAIL_001 está asociado a SUBDOMAIN_001"
}
```

Salida:

```json
{
  "rehydrated_text": "juan.perez@cliente.com está asociado a vpn.cliente.com"
}
```

## Adaptación a Claude API

El proxy recibe formato OpenAI-compatible, por ejemplo:

```json
{
  "model": "claude-sonnet-4-6",
  "messages": [
    {"role": "system", "content": "Eres un analista de seguridad"},
    {"role": "user", "content": "Analiza estos hallazgos..."}
  ],
  "temperature": 0.2,
  "max_tokens": 2000
}
```

Debe convertirlo al formato de Anthropic Messages API.

No hace falta que sea perfecto, pero debe funcionar para mensajes básicos system/user/assistant.

## Tests mínimos

Crear tests para verificar que:

1. Emails se tokenizan.
2. Dominios sensibles se tokenizan.
3. IPs internas se tokenizan.
4. GitHub tokens se eliminan.
5. JWTs se eliminan.
6. Bearer tokens se eliminan.
7. No se guardan secretos reales en mappings.
8. El mismo email mantiene el mismo token dentro del mismo case_id.
9. Distintos case_id tienen mappings separados.
10. `/privacy/sanitize` funciona.

## README

Genera un README con:

1. Qué es el proyecto.
2. Arquitectura.
3. Instalación.
4. Configuración `.env`.
5. Cómo arrancarlo.
6. Cómo probar `/health`.
7. Cómo probar `/privacy/sanitize`.
8. Cómo usarlo como OpenAI-compatible endpoint.
9. Limitaciones.
10. Riesgos residuales.

## Ejemplo de prueba con curl

Incluye en el README algo como:

```bash
curl -X POST http://127.0.0.1:8000/privacy/sanitize \
  -H "Authorization: Bearer change-me" \
  -H "Content-Type: application/json" \
  -d '{
    "case_id": "cliente_a_2026",
    "text": "El email juan.perez@cliente.com aparece en vpn.cliente.com con token ghp_xxxxxxxxx"
  }'
```

Respuesta esperada:

```json
{
  "sanitized_text": "El email EMAIL_001 aparece en SUBDOMAIN_001 con token SECRET_REMOVED",
  "findings": [...]
}
```

## Importante

Prioriza crear un MVP funcional antes que una arquitectura perfecta.

Hazlo en fases:

1. Crear estructura.
2. Implementar sanitizer/tokenizer.
3. Implementar storage local.
4. Implementar endpoints FastAPI.
5. Implementar cliente Claude.
6. Implementar endpoint OpenAI-compatible.
7. Añadir tests.
8. Añadir README.

No inventes dependencias innecesarias. Si algo queda pendiente, documentarlo claramente en `README.md` como TODO.

## Criterio de éxito

El MVP será válido si puedo:

1. Levantar el proxy en local.
2. Enviar un texto con emails, dominios, IPs y secretos.
3. Ver que el proxy tokeniza identificadores.
4. Ver que elimina secretos.
5. Ver que guarda mappings localmente.
6. Ver que llama a Claude solo con texto anonimizado.
7. Ver que devuelve una respuesta compatible.
8. Ver logs de privacidad sin datos sensibles.

## Instrucción final para Claude Code

Implementa ahora este MVP completo. Primero crea la estructura del proyecto y luego desarrolla archivo por archivo. No me expliques demasiado; escribe el código, tests y README. Si falta alguna decisión, toma la opción más simple y segura por defecto.
