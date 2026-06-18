# Política de seguridad

`osint-veil` es una herramienta de privacidad para usar IA en OSINT/auditorías
sin filtrar datos reales. La seguridad es el objetivo del proyecto, no un extra.

## Modelo de amenazas (resumen)

Garantías que el proyecto persigue (detalle en [`docs/DESIGN.md`](docs/DESIGN.md)):

- **Secretos** (claves, tokens, JWTs, contraseñas) → se **destruyen**: nunca se
  tokenizan, ni se guardan, ni salen hacia el proveedor de IA.
- **Identificadores** (emails, dominios, IPs, tarjetas, etc.) → se **tokenizan**;
  el valor real vive cifrado en un vault local y solo se rehidrata en local.
- **3 invariantes innegociables:** (1) el loop y las herramientas corren en local;
  (2) solo el proxy puede hablar con el proveedor de IA (egress bloqueado a nivel
  de red); (3) la salida de herramientas se trata como datos no confiables
  (defensa anti prompt-injection).

### Límites honestos (no son fallos)

- El **objetivo** investigado y las **relaciones** que el resumidor envía salen en
  claro a la IA por diseño — es lo necesario para que el OSINT sea útil.
- El **egress a nivel de red** es responsabilidad del despliegue
  (`deploy/egress_lockdown.sh` / Docker con `CAP_NET_ADMIN`). El software lo exige
  pero la garantía final la pone la red.
- La **no retención** por parte de Anthropic requiere un acuerdo **ZDR**; el código
  no puede forzarlo.

## Buenas prácticas de despliegue

Ver el checklist en [`docs/DEPLOY.md`](docs/DEPLOY.md). Mínimos:
`PROXY_LOCAL_API_KEY` cambiada, `PROXY_ENCRYPTION_KEY` configurada,
`PROXY_EGRESS=enforce` + lockdown aplicado, puerto solo en localhost.

## Reportar una vulnerabilidad

Si encuentras un fallo que pueda provocar una **fuga de datos** o saltarse alguna
invariante, repórtalo de forma privada (no abras un issue público con detalles de
explotación). Incluye: versión, pasos de reproducción y el dato que se filtraría.
