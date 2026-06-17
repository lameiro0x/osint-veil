#!/usr/bin/env bash
# Entrypoint del contenedor osint-veil.
#
# Si PROXY_APPLY_LOCKDOWN=1 y hay privilegios de red (CAP_NET_ADMIN), aplica el
# lockdown de egress sobre el usuario 'osinttools' y marca PROXY_EGRESS_LOCKED=1.
# Después baja privilegios y arranca el proxy como 'proxyuser'.
#
# Sin CAP_NET_ADMIN el lockdown de red no se puede aplicar: en modo enforce el
# OSINT autónomo se negará a arrancar (correcto y seguro).
set -euo pipefail

if [ "${PROXY_APPLY_LOCKDOWN:-0}" = "1" ]; then
  if PROXY_USER=proxyuser TOOLS_USER=osinttools deploy/egress_lockdown.sh; then
    export PROXY_EGRESS_LOCKED=1
    echo "[entrypoint] egress lockdown aplicado; PROXY_EGRESS_LOCKED=1"
  else
    echo "[entrypoint] AVISO: no se pudo aplicar el lockdown (¿falta CAP_NET_ADMIN?)." >&2
  fi
fi

# Baja a proxyuser para correr el servidor (gosu si está; si no, su).
if command -v gosu >/dev/null 2>&1; then
  exec gosu proxyuser "$@"
elif [ "$(id -u)" = "0" ]; then
  exec su proxyuser -c "$(printf '%q ' "$@")"
else
  exec "$@"
fi
